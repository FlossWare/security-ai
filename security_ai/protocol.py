"""SecretsBackend protocol definition for security-ai.

Defines the async interface that all secrets backends must satisfy
via structural subtyping (``typing.Protocol``).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretsBackend(Protocol):
    """Async secrets backend interface.

    Any class that implements these three async methods satisfies the
    protocol via structural subtyping -- no explicit inheritance needed.
    """

    async def get(self, name: str) -> str | None:
        """Return the secret value for *name*, or ``None`` if absent."""
        ...

    async def set(self, name: str, value: str) -> bool:
        """Store a secret.  Returns ``True`` on success."""
        ...

    async def list_names(self) -> list[str]:
        """Return all known secret names."""
        ...
