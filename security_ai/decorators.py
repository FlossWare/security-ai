"""Cross-cutting security decorators (ADR-0006).

Provides convenience decorators that compose with the core security
primitives.  Each decorator requires explicit opt-in -- users must
supply the configuration or backing instance (ADR-0001).

Decorators
----------
mask_secrets -- redact secrets from function return values
audit_logged -- record audit entries on function calls
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

from security_ai.security import AuditLogger, SecretsMask

F = TypeVar("F", bound=Callable[..., Any])


def mask_secrets(
    *,
    patterns: list[str] | None = None,
    placeholder: str = "***REDACTED***",
    mask: SecretsMask | None = None,
) -> Callable[[F], F]:
    """Decorator that redacts secrets from string return values.

    Accepts either a pre-configured :class:`SecretsMask` instance via
    *mask*, or a list of regex *patterns* to construct one.  At least
    one of *patterns* or *mask* should be provided; if both are given,
    *mask* takes precedence.

    Patterns are regex strings that match secret values directly in
    text (e.g. ``r"sk-\\S+"`` matches any string starting with
    ``sk-``).  Each match is replaced with *placeholder*.

    Works with both synchronous and asynchronous functions.  Non-string
    return values pass through unmodified.

    Parameters
    ----------
    patterns:
        Regex patterns matching secret values to redact.
    placeholder:
        Replacement text for matched secrets.
    mask:
        A pre-configured :class:`SecretsMask` instance.  When provided,
        *patterns* and *placeholder* are ignored.

    Examples
    --------
    >>> @mask_secrets(patterns=[r"sk-\\S+", r"gsk_\\S+"])
    ... def get_config():
    ...     return "key is sk-abc123"
    >>> get_config()
    'key is ***REDACTED***'
    """
    if mask is not None:
        _mask = mask
    elif patterns is not None:
        # Wrap each pattern in a capturing group so SecretsMask
        # replacement logic works, or use raw patterns directly.
        # We build a simple SecretsMask with patterns that have no
        # label prefix -- the entire match is replaced.
        _mask = SecretsMask(patterns=patterns, placeholder=placeholder)
    else:
        _mask = SecretsMask(placeholder=placeholder)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            result = await func(*args, **kwargs)
            if isinstance(result, str):
                return _mask.redact(result)
            return result

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            result = func(*args, **kwargs)
            if isinstance(result, str):
                return _mask.redact(result)
            return result

        if inspect.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def audit_logged(
    *,
    action: str,
    logger: AuditLogger,
    actor: str = "system",
    resource: str = "",
) -> Callable[[F], F]:
    """Decorator that logs function calls to an :class:`AuditLogger`.

    Every invocation of the decorated function records an audit entry
    with the given *action*, *actor*, and *resource*.  The function
    name is included in the entry detail.  On success the outcome is
    ``"success"``; on exception it is ``"failure"`` (and the exception
    is re-raised).

    The *logger* parameter is required (ADR-0001: explicit opt-in).

    Works with both synchronous and asynchronous functions.

    Parameters
    ----------
    action:
        The action name recorded in the audit entry.
    logger:
        The :class:`AuditLogger` instance to write entries to.
    actor:
        The actor name recorded in the audit entry.
    resource:
        The resource name recorded in the audit entry.  Defaults to
        the decorated function's qualified name if empty.

    Examples
    --------
    >>> logger = AuditLogger()
    >>> @audit_logged(action="api_call", logger=logger)
    ... def call_api():
    ...     return "ok"
    >>> call_api()
    'ok'
    >>> logger.entries[0].action
    'api_call'
    """

    def decorator(func: F) -> F:
        _resource = resource or func.__qualname__

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                result = await func(*args, **kwargs)
            except Exception as exc:
                logger.log(
                    actor=actor,
                    action=action,
                    resource=_resource,
                    detail=f"{func.__name__} raised {type(exc).__name__}: {exc}",
                    outcome="failure",
                )
                raise
            logger.log(
                actor=actor,
                action=action,
                resource=_resource,
                detail=f"{func.__name__} completed",
                outcome="success",
            )
            return result

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                logger.log(
                    actor=actor,
                    action=action,
                    resource=_resource,
                    detail=f"{func.__name__} raised {type(exc).__name__}: {exc}",
                    outcome="failure",
                )
                raise
            logger.log(
                actor=actor,
                action=action,
                resource=_resource,
                detail=f"{func.__name__} completed",
                outcome="success",
            )
            return result

        if inspect.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator
