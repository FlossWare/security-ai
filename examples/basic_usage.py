#!/usr/bin/env python3
"""Basic security-ai usage example.

Demonstrates secret masking, audit logging, and the
decorator-based approach to securing LLM interactions.
"""
import asyncio

from security_ai import SecretsMask, AuditLogger, mask_secrets, audit_logged


mask = SecretsMask(patterns=[
    r"(sk-)[a-zA-Z0-9]+",
    r"(ghp_)[a-zA-Z0-9]+",
    r"(AKIA)[A-Z0-9]{16}",
])
logger = AuditLogger()


@mask_secrets(patterns=[r"(sk-)[a-zA-Z0-9]+"])
@audit_logged(actor="demo-agent", resource="llm", action="call")
async def call_llm(prompt: str) -> str:
    await asyncio.sleep(0.02)
    return f"Response (key: sk-secret1234abcd): {prompt}"


async def main() -> None:
    print("1. Decorator-based redaction")
    result = await call_llm("What is the weather?")
    print(f"   Result: {result}")
    print(f"   (API key automatically redacted)\n")

    print("2. Programmatic redaction")
    raw = "Config: OPENAI_KEY=sk-proj-abc123 AWS=AKIAIOSFODNN7EXAMPLE"
    clean = mask.redact(raw)
    print(f"   Raw:   {raw}")
    print(f"   Clean: {clean}\n")

    print("3. Audit logging")
    logger.log(actor="admin", action="config-update", resource="api-keys")
    logger.log(actor="agent", action="llm-call", resource="openai")
    print(f"   Entries: {len(logger.entries)}")
    for entry in logger.entries:
        print(f"   - {entry}")


if __name__ == "__main__":
    print("security-ai basic usage example")
    print("=" * 40)
    asyncio.run(main())
