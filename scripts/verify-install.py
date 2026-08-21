#!/usr/bin/env python3
"""Verify security-ai installation."""
import sys


def main() -> int:
    try:
        from security_ai import (
            AuditLogger,
            SecretsMask,
            audit_logged,
            mask_secrets,
        )
    except ImportError as e:
        print(f"FAIL: Cannot import security-ai: {e}")
        print("Install: pip install 'git+https://github.com/FlossWare/security-ai.git'")
        return 1

    from security_ai import __version__

    print(f"security-ai v{__version__} installed successfully.")
    print(f"  SecretsMask:  {SecretsMask}")
    print(f"  AuditLogger:  {AuditLogger}")
    print(f"  Decorators:   @mask_secrets, @audit_logged")

    mask = SecretsMask(patterns=[r"(sk-)[a-zA-Z0-9]+"])
    result = mask.redact("key is sk-abc123xyz")
    assert "sk-abc123xyz" not in result, "Secret was not redacted!"
    print("  Smoke test:   PASS")

    return 0


if __name__ == "__main__":
    sys.exit(main())
