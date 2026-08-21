# FlossWare Engineering Standards Compliance

This package adheres to the following ADRs from
[FlossWare/engineering-standards](https://github.com/FlossWare/engineering-standards).

## ADR-0001: Explicit Opt-In

All security primitives require explicit instantiation. Nothing activates
automatically on import:

- `ConfigValidator` -- user supplies the schema
- `SecretsMask` -- user creates an instance (optionally with custom patterns)
- `AuditLogger` -- user creates an instance and calls `log()` explicitly
- `PolicyOverride` -- user creates an instance and sets overrides manually
- `EnvSecretsBackend` / `RotatingSecretsBackend` -- user constructs with
  explicit configuration
- `@mask_secrets()` / `@audit_logged()` -- decorators require explicit
  application and configuration (logger, patterns)

## ADR-0006: Cross-Cutting Decorators

Convenience decorators in `security_ai.decorators`:

- `@mask_secrets(patterns=[...])` -- redacts secrets from function return
  values using configurable regex patterns
- `@audit_logged(action="...", logger=logger)` -- records audit entries on
  function invocation with success/failure tracking

Both decorators support synchronous and asynchronous functions.

## ADR-0008: Free-First

Zero external dependencies. The entire package uses only the Python standard
library (>=3.11). Development dependencies (pytest, pytest-asyncio) are
optional and listed under `[project.optional-dependencies.dev]`.

## ADR-0009: Core Principles

- **Modular**: each module (`security`, `env_secrets`, `rotating_secrets`,
  `decorators`, `protocol`) is independently importable
- **Composable**: decorators compose with core classes; backends compose via
  `RotatingSecretsBackend` fallback chains
- **Contracts over implementations**: `SecretsBackend` Protocol defines the
  interface; any conforming class works without inheritance

## ADR-0016: Configuration as Source of Truth

Security configuration is driven by explicit parameters, not hardcoded values:

- `SecretsMask` accepts configurable `patterns` and `placeholder`
- `ConfigValidator` accepts a user-defined `schema`
- `EnvSecretsBackend` accepts `env_file`, `prefix`, and `overrides`
- `RotatingSecretsBackend` accepts `backends` list and `validator` callback
- `PolicyOverride` expiry is set per-override via `expires_at`
- `@mask_secrets()` accepts `patterns`, `placeholder`, or a pre-built `mask`

Default patterns exist for convenience but are always overridable.

## ADR-0017: Agent-Neutral

All classes and decorators are pure Python with no coupling to any specific
agent runtime, framework, or orchestration layer. They work equally well in
LangChain, CrewAI, AutoGen, custom agent loops, or plain scripts.

## ADR-0019: Agent Tool Security

This package provides security primitives usable by agent tool authorization
systems:

- **Config validation** -- validate tool configurations before execution
- **Secrets masking** -- redact sensitive data from tool inputs/outputs
- **Audit logging** -- record tool invocations for compliance and debugging
- **Policy overrides** -- temporarily adjust security policies for tool access
- **Secrets management** -- secure retrieval and rotation of API keys used
  by agent tools

These primitives can be composed into authorization middleware for any agent
tool execution pipeline.

## ADR-0020: Capability-Protocol Separation

Security capabilities are transport-independent:

- `SecretsBackend` Protocol separates the interface from implementation
- `EnvSecretsBackend` and `RotatingSecretsBackend` are interchangeable
  implementations of the same protocol
- No HTTP, gRPC, or message-queue assumptions -- capabilities work over
  any transport layer
- Decorators operate at the function level, independent of how functions
  are exposed (REST, CLI, MCP, direct call)
