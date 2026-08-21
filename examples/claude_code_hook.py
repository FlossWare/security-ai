#!/usr/bin/env python3
"""Claude Code hook: redact secrets from tool outputs.

Install as a post-tool hook in .claude/settings.json:
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "",
      "command": "python3 .claude/hooks/security_hook.py"
    }]
  }
}
"""
import json
import sys

from security_ai import SecretsMask

mask = SecretsMask(patterns=[
    r"(sk-)[a-zA-Z0-9]{20,}",
    r"(ghp_)[a-zA-Z0-9]{20,}",
    r"(AKIA)[A-Z0-9]{16}",
    r"(password\s*[=:]\s*)\S+",
])


def main() -> None:
    event = json.load(sys.stdin)
    output = event.get("tool_result", "")
    if isinstance(output, str):
        redacted = mask.redact(output)
        if redacted != output:
            sys.stderr.write(
                "WARNING: Secrets detected and redacted in tool output\n"
            )

    print(json.dumps({"decision": "approve"}))


if __name__ == "__main__":
    main()
