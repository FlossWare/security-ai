# security-ai Integration Guide

Install:
```bash
pip install "git+https://github.com/FlossWare/security-ai.git"
```

---

## Claude Code

### CLAUDE.md snippet

```markdown
## Security

This project uses `security-ai` for output sanitization and audit logging.
Always redact secrets from LLM outputs and log security-relevant operations.

```python
from security_ai import mask_secrets, audit_logged

@mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+', r'(ghp_)[a-zA-Z0-9]+'])
async def call_llm(prompt: str) -> str:
    ...

@audit_logged(actor="agent", resource="config", action="modify")
async def update_config(key: str, value: str) -> None:
    ...
```
```

### Hooks

**Post-tool hook** (`hooks/post-tool-security.py`):
```python
#!/usr/bin/env python3
"""Claude Code hook: redact secrets from tool outputs."""
import json, sys
from security_ai import SecretsMask

mask = SecretsMask(patterns=[
    r'(sk-)[a-zA-Z0-9]{20,}',
    r'(ghp_)[a-zA-Z0-9]{20,}',
    r'(AKIA)[A-Z0-9]{16}',
    r'(password\s*[=:]\s*)[^\s]+',
])

event = json.load(sys.stdin)
output = event.get("tool_result", "")
if isinstance(output, str):
    redacted = mask.redact(output)
    if redacted != output:
        sys.stderr.write("WARNING: Secrets detected and redacted in tool output\n")

print(json.dumps({"decision": "approve"}))
```

### Skills

Create `.claude/skills/audit-check.md`:
```markdown
---
name: audit-check
description: Review the security audit log for recent operations
---

Use security-ai's AuditLogger to review recent security events.
Show who did what, when, and on which resources.
```

---

## OpenAI Codex

### AGENTS.md snippet
```markdown
## Security

All tool outputs must be sanitized with `security-ai`:

```python
from security_ai import mask_secrets, audit_logged, SecretsMask

@mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+'])
async def tool_call(prompt: str) -> str:
    ...
```
```

---

## Cursor

### .cursorrules snippet
```
Always sanitize LLM outputs with security-ai:
- @mask_secrets(patterns=[...]) to redact API keys, passwords, tokens
- @audit_logged(actor="agent", resource="name") for audit trail

Import from: from security_ai import mask_secrets, audit_logged, SecretsMask
Package: pip install "git+https://github.com/FlossWare/security-ai.git"

Common patterns to redact:
- r'(sk-)[a-zA-Z0-9]+'         # OpenAI keys
- r'(ghp_)[a-zA-Z0-9]+'        # GitHub tokens
- r'(AKIA)[A-Z0-9]{16}'        # AWS access keys
- r'(password\s*[=:]\s*)\S+'   # Passwords in configs
```

---

## Crush

### Configuration
```python
from crush import Agent
from security_ai import mask_secrets, audit_logged

class SecureAgent(Agent):
    @mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+'])
    @audit_logged(actor="crush-agent", resource="llm")
    async def call_model(self, prompt: str) -> str:
        return await self.backend.chat(prompt)
```

---

## Generic Python Agent

### asyncio integration
```python
from security_ai import (
    mask_secrets, audit_logged,
    SecretsMask, AuditLogger, EnvSecretsBackend,
)

# Decorator approach
@mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+'])
@audit_logged(actor="my-agent", resource="llm-call")
async def call_llm(prompt: str) -> str:
    ...

# Programmatic approach
mask = SecretsMask(patterns=[r'(sk-)[a-zA-Z0-9]+'])
logger = AuditLogger()

async def call_with_security(prompt: str) -> str:
    sanitized_prompt = mask.redact(prompt)
    result = await your_llm_call(sanitized_prompt)
    sanitized_result = mask.redact(result)
    logger.log(actor="agent", action="llm-call", resource="openai")
    return sanitized_result

# Secrets management
secrets = EnvSecretsBackend(prefix="MY_APP_")
api_key = secrets.get("API_KEY")  # reads MY_APP_API_KEY from env
```

---

## Cross-Package Integration

### With resilience-ai + observability-ai
```python
from resilience_ai import with_retry, with_circuit_breaker
from observability_ai import track_execution, ExecutionTelemetry
from security_ai import mask_secrets, audit_logged

telemetry = ExecutionTelemetry()

@with_retry(max_attempts=3)
@with_circuit_breaker(provider="openai", max_failures=5)
@track_execution(telemetry=telemetry, provider="openai")
@mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+'])
@audit_logged(actor="system", resource="llm")
async def secure_resilient_call(prompt: str) -> str:
    ...
```

### With model-router-ai
```python
from security_ai import mask_secrets, EnvSecretsBackend
from model_router_ai import CostAware

secrets = EnvSecretsBackend(prefix="LLM_")

@mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+'])
async def routed_call(prompt: str) -> str:
    api_key = secrets.get("OPENAI_KEY")
    router = CostAware(your_backend, prefer_free=True)
    return await router.chat(prompt)
```
