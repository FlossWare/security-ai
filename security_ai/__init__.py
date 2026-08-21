"""security-ai -- Standalone security utilities for AI applications.

Config validation, secrets masking, audit logging, policy overrides,
environment-variable secrets, API-key rotation, and cross-cutting
security decorators.
"""

from __future__ import annotations

__version__ = "0.1"

from security_ai.decorators import audit_logged, mask_secrets
from security_ai.env_secrets import EnvSecretsBackend
from security_ai.protocol import SecretsBackend
from security_ai.rotating_secrets import RotatingSecretsBackend
from security_ai.security import (
    AuditEntry,
    AuditLogger,
    ConfigValidator,
    Override,
    PolicyOverride,
    SecretsMask,
    ValidationResult,
)

__all__ = [
    "AuditEntry",
    "AuditLogger",
    "ConfigValidator",
    "EnvSecretsBackend",
    "Override",
    "PolicyOverride",
    "RotatingSecretsBackend",
    "SecretsMask",
    "SecretsBackend",
    "ValidationResult",
    "audit_logged",
    "mask_secrets",
]
