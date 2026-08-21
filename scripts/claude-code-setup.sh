#!/bin/bash
# Add security-ai integration to your CLAUDE.md
set -e

CLAUDE_MD="${CLAUDE_MD:-./CLAUDE.md}"

if [ ! -f "$CLAUDE_MD" ]; then
    echo "Creating $CLAUDE_MD..."
    touch "$CLAUDE_MD"
fi

cat >> "$CLAUDE_MD" << 'BLOCK'

## Security (security-ai)

This project uses [security-ai](https://github.com/FlossWare/security-ai) for output sanitization and audit logging.

**Redact secrets from all LLM outputs:**

```python
from security_ai import mask_secrets, audit_logged

@mask_secrets(patterns=[r'(sk-)[a-zA-Z0-9]+', r'(ghp_)[a-zA-Z0-9]+'])
async def call_llm(prompt: str) -> str:
    ...

@audit_logged(actor="agent", resource="config", action="modify")
async def update_config(key: str, value: str) -> None:
    ...
```

Install: `pip install "git+https://github.com/FlossWare/security-ai.git"`
BLOCK

echo "Added security-ai section to $CLAUDE_MD"
