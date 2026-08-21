# security-ai

Standalone, zero-dependency security utilities for AI applications. Provides
config validation, secrets masking, audit logging, policy overrides,
environment-variable secrets management, and API-key rotation.

## Installation

```bash
pip install security-ai
```

For development (includes pytest):

```bash
pip install security-ai[dev]
```

## Quickstart

```python
import asyncio
from security_ai import (
    ConfigValidator,
    SecretsMask,
    AuditLogger,
    PolicyOverride,
    EnvSecretsBackend,
    RotatingSecretsBackend,
)

# Validate configuration
validator = ConfigValidator({"model": str, "temperature": float})
result = validator.validate({"model": "gpt-4", "temperature": 0.7})
assert result.valid

# Redact secrets from text
mask = SecretsMask()
safe = mask.redact("api_key=sk-12345 and token=abc")
# -> "api_key=***REDACTED*** and token=***REDACTED***"

# Audit logging
logger = AuditLogger()
logger.log(actor="admin", action="rotate_key", resource="openai_key")
print(logger.entries)

# Temporary policy overrides
policy = PolicyOverride()
policy.set("max_tokens", 2048, actor="admin", reason="testing",
           expires_at="2099-12-31T23:59:59+00:00")
print(policy.get("max_tokens"))  # 2048

# Environment secrets backend
async def demo():
    backend = EnvSecretsBackend(overrides={"API_KEY": "sk-test"})
    print(await backend.get("API_KEY"))  # "sk-test"

asyncio.run(demo())
```

## Decorators

Cross-cutting security decorators (ADR-0006) for applying masking and
audit logging declaratively:

```python
from security_ai import mask_secrets, audit_logged, AuditLogger, SecretsMask

# Redact secrets from return values
@mask_secrets(patterns=[r"sk-\S+", r"gsk_\S+"])
def get_config_dump():
    return "api_key: sk-abc123, other_key: gsk_xyz789"

print(get_config_dump())
# -> "api_key: ***REDACTED***, other_key: ***REDACTED***"

# Audit-log every call (logger must be provided explicitly)
logger = AuditLogger()

@audit_logged(action="api_call", logger=logger, actor="service-a")
def call_external_api():
    return {"status": "ok"}

call_external_api()
print(logger.entries[-1].action)  # "api_call"
```

Both decorators work with sync and async functions.

## API Overview

### `ConfigValidator`
Validate configuration dicts against a schema of required keys and types.

### `SecretsMask`
Redact sensitive values (API keys, tokens, passwords) from text using
configurable regex patterns.

### `AuditLogger`
Append-only, in-memory audit log for security-relevant events with
filtering by actor, action, or resource.

### `PolicyOverride`
Temporary policy overrides with automatic expiry timestamps.

### `EnvSecretsBackend`
Three-tier async secrets backend: in-memory overrides, `.env` file,
and `os.environ`.

### `RotatingSecretsBackend`
Fallback-chain secrets backend with key rotation, TTL expiry, and
optional validation callbacks.

### `SecretsBackend` (Protocol)
Async protocol defining the interface for all secrets backends:
`get()`, `set()`, `list_names()`.

### `@mask_secrets()`
Decorator that redacts secrets from string return values using
configurable regex patterns or a pre-built `SecretsMask`.

### `@audit_logged()`
Decorator that records audit entries on function invocation, tracking
success and failure outcomes.

## FlossWare Engineering Standards

This package complies with FlossWare Engineering Standards ADRs:

| ADR | Title | How |
|-----|-------|-----|
| ADR-0001 | Explicit Opt-In | All primitives require explicit instantiation; nothing activates on import |
| ADR-0006 | Cross-Cutting Decorators | `@mask_secrets()` and `@audit_logged()` decorators |
| ADR-0008 | Free-First | Zero external dependencies (stdlib only) |
| ADR-0009 | Core Principles | Modular, composable, contracts over implementations |
| ADR-0016 | Configuration as Source of Truth | All behavior driven by explicit config parameters |
| ADR-0017 | Agent-Neutral | No coupling to any agent runtime or framework |
| ADR-0019 | Agent Tool Security | Provides primitives for agent tool authorization systems |
| ADR-0020 | Capability-Protocol Separation | Transport-independent via `SecretsBackend` Protocol |

See [STANDARDS.md](STANDARDS.md) for full compliance details.

## License

MIT
