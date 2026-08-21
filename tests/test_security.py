"""Tests for security-ai package."""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from security_ai import (
    AuditLogger,
    ConfigValidator,
    EnvSecretsBackend,
    PolicyOverride,
    RotatingSecretsBackend,
    SecretsMask,
    SecretsBackend,
    ValidationResult,
    audit_logged,
    mask_secrets,
)


# -- ConfigValidator --------------------------------------------------------


class TestConfigValidator:
    def test_valid_config(self):
        schema = {"name": str, "count": int, "rate": float}
        validator = ConfigValidator(schema)
        result = validator.validate({"name": "test", "count": 5, "rate": 1.5})
        assert result.valid
        assert result.errors == []

    def test_missing_key(self):
        validator = ConfigValidator({"name": str, "count": int})
        result = validator.validate({"name": "test"})
        assert not result.valid
        assert any("missing required key: count" in e for e in result.errors)

    def test_wrong_type(self):
        validator = ConfigValidator({"name": str})
        result = validator.validate({"name": 123})
        assert not result.valid
        assert any("expected str, got int" in e for e in result.errors)

    def test_bool_not_accepted_as_int(self):
        """bool is a subclass of int in Python; validator should reject it."""
        validator = ConfigValidator({"count": int})
        result = validator.validate({"count": True})
        assert not result.valid
        assert any("got bool" in e for e in result.errors)

    def test_extra_keys_allowed(self):
        validator = ConfigValidator({"name": str})
        result = validator.validate({"name": "test", "extra": 42})
        assert result.valid


# -- SecretsMask ------------------------------------------------------------


class TestSecretsMask:
    def test_redacts_api_key(self):
        mask = SecretsMask()
        text = "api_key=sk-12345abcdef"
        result = mask.redact(text)
        assert "sk-12345abcdef" not in result
        assert "***REDACTED***" in result

    def test_redacts_bearer_token(self):
        mask = SecretsMask()
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        result = mask.redact(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_custom_placeholder(self):
        mask = SecretsMask(placeholder="[HIDDEN]")
        text = "password=hunter2"
        result = mask.redact(text)
        assert "[HIDDEN]" in result
        assert "hunter2" not in result

    def test_preserves_non_secret_text(self):
        mask = SecretsMask()
        text = "Hello, this is a normal message."
        assert mask.redact(text) == text


# -- AuditLogger ------------------------------------------------------------


class TestAuditLogger:
    def test_log_and_retrieve(self):
        logger = AuditLogger()
        entry = logger.log(actor="admin", action="login", resource="system")
        assert entry.actor == "admin"
        assert entry.action == "login"
        assert len(logger.entries) == 1

    def test_find_by_actor(self):
        logger = AuditLogger()
        logger.log(actor="alice", action="read", resource="file_a")
        logger.log(actor="bob", action="write", resource="file_b")
        logger.log(actor="alice", action="delete", resource="file_c")
        results = logger.find(actor="alice")
        assert len(results) == 2
        assert all(e.actor == "alice" for e in results)

    def test_find_by_action(self):
        logger = AuditLogger()
        logger.log(actor="admin", action="rotate_key", resource="key_1")
        logger.log(actor="admin", action="login", resource="system")
        results = logger.find(action="rotate_key")
        assert len(results) == 1

    def test_entries_are_copies(self):
        """Modifying the returned list should not affect internal state."""
        logger = AuditLogger()
        logger.log(actor="admin", action="test", resource="r")
        entries = logger.entries
        entries.clear()
        assert len(logger.entries) == 1


# -- PolicyOverride ---------------------------------------------------------


class TestPolicyOverride:
    def test_set_and_get_active(self):
        po = PolicyOverride()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        po.set("max_tokens", 2048, actor="admin", reason="test", expires_at=future)
        assert po.get("max_tokens") == 2048

    def test_expired_override_returns_none(self):
        po = PolicyOverride()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        po.set("max_tokens", 2048, actor="admin", reason="test", expires_at=past)
        assert po.get("max_tokens") is None

    def test_revoke(self):
        po = PolicyOverride()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        po.set("policy_a", True, actor="admin", reason="test", expires_at=future)
        assert po.revoke("policy_a") is True
        assert po.revoke("policy_a") is False
        assert po.get("policy_a") is None

    def test_active_overrides_excludes_expired(self):
        po = PolicyOverride()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        po.set("active_one", 1, actor="a", reason="r", expires_at=future)
        po.set("expired_one", 2, actor="a", reason="r", expires_at=past)
        active = po.active_overrides()
        assert len(active) == 1
        assert active[0].policy == "active_one"


# -- EnvSecretsBackend ------------------------------------------------------


class TestEnvSecretsBackend:
    @pytest.mark.asyncio
    async def test_in_memory_override(self):
        backend = EnvSecretsBackend(overrides={"MY_KEY": "my_value"})
        assert await backend.get("MY_KEY") == "my_value"

    @pytest.mark.asyncio
    async def test_set_and_get(self):
        backend = EnvSecretsBackend()
        await backend.set("NEW_KEY", "new_value")
        assert await backend.get("NEW_KEY") == "new_value"

    @pytest.mark.asyncio
    async def test_delete(self):
        backend = EnvSecretsBackend(overrides={"DEL_KEY": "val"})
        assert await backend.delete("DEL_KEY") is True
        assert await backend.get("DEL_KEY") is None
        assert await backend.delete("DEL_KEY") is False

    @pytest.mark.asyncio
    async def test_dotenv_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("FILE_SECRET=from_file\n")
            f.write("# comment line\n")
            f.write('QUOTED="quoted_value"\n')
            f.flush()
            path = f.name
        try:
            backend = EnvSecretsBackend(env_file=path)
            assert await backend.get("FILE_SECRET") == "from_file"
            assert await backend.get("QUOTED") == "quoted_value"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_prefix(self):
        backend = EnvSecretsBackend(prefix="APP_", overrides={"APP_KEY": "prefixed"})
        assert await backend.get("KEY") == "prefixed"

    @pytest.mark.asyncio
    async def test_list_names(self):
        backend = EnvSecretsBackend(overrides={"A": "1", "B": "2"})
        names = await backend.list_names()
        assert "A" in names
        assert "B" in names

    @pytest.mark.asyncio
    async def test_os_environ_fallback(self):
        unique_key = "_SECURITY_AI_TEST_ENV_VAR_"
        os.environ[unique_key] = "from_env"
        try:
            backend = EnvSecretsBackend()
            assert await backend.get(unique_key) == "from_env"
        finally:
            del os.environ[unique_key]


# -- RotatingSecretsBackend -------------------------------------------------


class TestRotatingSecretsBackend:
    @pytest.mark.asyncio
    async def test_fallback_chain(self):
        b1 = EnvSecretsBackend(overrides={"KEY_A": "from_b1"})
        b2 = EnvSecretsBackend(overrides={"KEY_B": "from_b2"})
        rotating = RotatingSecretsBackend(backends=[b1, b2])
        assert await rotating.get("KEY_A") == "from_b1"
        assert await rotating.get("KEY_B") == "from_b2"
        assert await rotating.get("MISSING") is None

    @pytest.mark.asyncio
    async def test_rotation(self):
        b1 = EnvSecretsBackend(overrides={"API_KEY": "old_value"})
        rotating = RotatingSecretsBackend(backends=[b1])
        rotating.rotate("API_KEY", "new_value")
        assert await rotating.get("API_KEY") == "new_value"

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        b1 = EnvSecretsBackend(overrides={"TTL_KEY": "value"})
        rotating = RotatingSecretsBackend(backends=[b1])
        rotating.set_ttl("TTL_KEY", 0)  # Expires immediately
        assert await rotating.get("TTL_KEY") is None

    @pytest.mark.asyncio
    async def test_validator(self):
        b1 = EnvSecretsBackend(overrides={"KEY": "short"})
        b2 = EnvSecretsBackend(overrides={"KEY": "long_enough_value"})
        rotating = RotatingSecretsBackend(
            backends=[b1, b2],
            validator=lambda name, val: len(val) > 10,
        )
        # b1's value is too short, should fall through to b2
        assert await rotating.get("KEY") == "long_enough_value"

    @pytest.mark.asyncio
    async def test_empty_backends_raises(self):
        with pytest.raises(ValueError, match="at least one backend"):
            RotatingSecretsBackend(backends=[])

    @pytest.mark.asyncio
    async def test_list_names_includes_rotated(self):
        b1 = EnvSecretsBackend(overrides={"A": "1"})
        rotating = RotatingSecretsBackend(backends=[b1])
        rotating.rotate("B", "2")
        names = await rotating.list_names()
        assert "A" in names
        assert "B" in names

    @pytest.mark.asyncio
    async def test_delete_clears_rotation(self):
        b1 = EnvSecretsBackend(overrides={"KEY": "original"})
        rotating = RotatingSecretsBackend(backends=[b1])
        rotating.rotate("KEY", "rotated")
        await rotating.delete("KEY")
        # Rotation cleared, and key deleted from backend
        assert await rotating.get("KEY") is None


# -- SecretsBackend Protocol ------------------------------------------------


class TestSecretsBackendProtocol:
    def test_env_backend_satisfies_protocol(self):
        backend = EnvSecretsBackend()
        assert isinstance(backend, SecretsBackend)

    def test_rotating_backend_satisfies_protocol(self):
        b1 = EnvSecretsBackend()
        backend = RotatingSecretsBackend(backends=[b1])
        assert isinstance(backend, SecretsBackend)


# -- @mask_secrets decorator ------------------------------------------------


class TestMaskSecretsDecorator:
    def test_redacts_matching_patterns(self):
        @mask_secrets(patterns=[r"sk-\S+"])
        def get_key():
            return "key is sk-abc123"

        assert "sk-abc123" not in get_key()
        assert "***REDACTED***" in get_key()

    def test_multiple_patterns(self):
        @mask_secrets(patterns=[r"sk-\S+", r"gsk_\S+"])
        def get_keys():
            return "keys: sk-abc123 and gsk_xyz789"

        result = get_keys()
        assert "sk-abc123" not in result
        assert "gsk_xyz789" not in result

    def test_custom_placeholder(self):
        @mask_secrets(patterns=[r"sk-\S+"], placeholder="[HIDDEN]")
        def get_key():
            return "key is sk-abc123"

        result = get_key()
        assert "[HIDDEN]" in result
        assert "sk-abc123" not in result

    def test_non_string_return_passes_through(self):
        @mask_secrets(patterns=[r"sk-\S+"])
        def get_number():
            return 42

        assert get_number() == 42

    def test_accepts_pre_built_mask(self):
        custom_mask = SecretsMask(
            patterns=[r"(token\s*[:=]\s*)\S+"],
            placeholder="[NOPE]",
        )

        @mask_secrets(mask=custom_mask)
        def get_config():
            return "token=secret123"

        result = get_config()
        assert "secret123" not in result
        assert "[NOPE]" in result

    @pytest.mark.asyncio
    async def test_async_function(self):
        @mask_secrets(patterns=[r"sk-\S+"])
        async def get_key():
            return "key is sk-abc123"

        result = await get_key()
        assert "sk-abc123" not in result
        assert "***REDACTED***" in result

    def test_preserves_function_name(self):
        @mask_secrets(patterns=[r"sk-\S+"])
        def my_function():
            """My docstring."""
            return "ok"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."


# -- @audit_logged decorator ------------------------------------------------


class TestAuditLoggedDecorator:
    def test_logs_successful_call(self):
        logger = AuditLogger()

        @audit_logged(action="api_call", logger=logger)
        def do_work():
            return "done"

        result = do_work()
        assert result == "done"
        assert len(logger.entries) == 1
        assert logger.entries[0].action == "api_call"
        assert logger.entries[0].outcome == "success"

    def test_logs_failure(self):
        logger = AuditLogger()

        @audit_logged(action="risky_op", logger=logger, actor="bot")
        def fail():
            raise ValueError("bad input")

        with pytest.raises(ValueError, match="bad input"):
            fail()

        assert len(logger.entries) == 1
        assert logger.entries[0].outcome == "failure"
        assert logger.entries[0].actor == "bot"
        assert "ValueError" in logger.entries[0].detail

    def test_custom_actor_and_resource(self):
        logger = AuditLogger()

        @audit_logged(
            action="read", logger=logger, actor="service-a", resource="db/users"
        )
        def read_users():
            return []

        read_users()
        entry = logger.entries[0]
        assert entry.actor == "service-a"
        assert entry.resource == "db/users"

    def test_default_resource_is_qualname(self):
        logger = AuditLogger()

        @audit_logged(action="test", logger=logger)
        def my_func():
            return True

        my_func()
        assert "my_func" in logger.entries[0].resource

    @pytest.mark.asyncio
    async def test_async_function(self):
        logger = AuditLogger()

        @audit_logged(action="async_call", logger=logger, actor="agent")
        async def async_work():
            return "async_done"

        result = await async_work()
        assert result == "async_done"
        assert len(logger.entries) == 1
        assert logger.entries[0].action == "async_call"
        assert logger.entries[0].outcome == "success"

    @pytest.mark.asyncio
    async def test_async_failure(self):
        logger = AuditLogger()

        @audit_logged(action="async_fail", logger=logger)
        async def async_fail():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await async_fail()

        assert logger.entries[0].outcome == "failure"
        assert "RuntimeError" in logger.entries[0].detail

    def test_preserves_function_name(self):
        logger = AuditLogger()

        @audit_logged(action="test", logger=logger)
        def named_function():
            """Docstring here."""
            return True

        assert named_function.__name__ == "named_function"
        assert named_function.__doc__ == "Docstring here."
