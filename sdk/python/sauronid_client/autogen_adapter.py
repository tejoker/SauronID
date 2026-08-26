"""AutoGen adapter — guard register_function-style callables with SauronID.

This module is purely additive. Importing it has no side effects on
existing :mod:`sauronid_client` behaviour. The autogen package is **not**
a runtime dependency: AutoGen registers plain Python callables
(``register_function(fn, caller=..., executor=..., name=...)``), so the
adapter only needs to wrap callables — no framework objects involved.
Use :func:`require_autogen` when you need the real framework; it raises
a helpful :class:`ImportError` when the extra is missing.

Public surface:

- :func:`guard_function` — wrap one callable with policy enforcement.
- :func:`guard_functions` — wrap a ``{name: callable}`` mapping.
- :func:`require_autogen` — lazy import guard for the optional dep.

The guarded callable keeps the original ``__name__`` / ``__doc__`` /
signature (via :func:`functools.wraps`), so AutoGen's schema generation
from type hints and docstrings still works on the wrapped function.

Denial surface: on a deny the wrapper returns a string of the form
``"Policy denied: <reason>"`` as the tool result so the conversation can
recover; ``raise_on_deny=True`` re-raises :class:`PolicyDeniedError`.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Mapping, Optional

from .enforcement import (
    ClassifyFn,
    Enforcer,
    OnDenyFn,
    PolicyDeniedError,
)
from .langchain import _deny_message

__all__ = [
    "guard_function",
    "guard_functions",
    "require_autogen",
]


def require_autogen() -> Any:
    """Import and return :mod:`autogen`, or raise a helpful error.

    The adapter itself never needs the framework (it wraps plain
    callables); use this only when you must access the real package.
    """

    try:
        import autogen as _autogen
    except ImportError as err:
        raise ImportError(
            "pyautogen is not installed. The sauronid-client AutoGen adapter "
            "wraps plain callables and does not require it, but this helper "
            "does. Install with: pip install 'sauronid-client[autogen]'"
        ) from err
    return _autogen


def guard_function(
    fn: Callable[..., Any],
    enforcer: Enforcer,
    *,
    name: Optional[str] = None,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
    raise_on_deny: bool = False,
) -> Callable[..., Any]:
    """Wrap ``fn`` with policy enforcement for AutoGen registration.

    The returned callable is a drop-in replacement for ``fn`` in
    ``autogen.register_function(...)`` / ``agent.register_for_execution()``.

    Args:
        fn: Original tool callable.
        enforcer: Pre-configured :class:`Enforcer`.
        name: LLM-facing tool name evaluated against the policy allowlist.
            Defaults to ``fn.__name__`` — pass explicitly when the
            AutoGen registration name differs from the Python name.
        classify_action: Optional action annotator, same shape as
            :func:`sauronid_client.enforcement.bind`'s ``classify_action``.
        on_deny: Optional hook fired before a denial surfaces to the LLM.
        raise_on_deny: ``True`` re-raises :class:`PolicyDeniedError`;
            ``False`` (default) returns a ``"Policy denied: ..."`` string.

    Returns:
        Guarded callable preserving ``fn``'s metadata.
    """

    tool_name = name or getattr(fn, "__name__", "anonymous") or "anonymous"

    # Thin closure so we can stamp __name__ even for bound methods (whose
    # __name__ is read-only), mirroring the other adapters.
    def _proxy(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    _proxy.__name__ = tool_name  # ensure Action.tool == name
    guarded = enforcer.bind(
        _proxy,
        classify_action=classify_action,
        on_deny=on_deny,
    )

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return guarded(*args, **kwargs)
        except PolicyDeniedError as err:
            if raise_on_deny:
                raise
            return _deny_message(err)

    wrapper.__name__ = tool_name
    return wrapper


def guard_functions(
    fns: Mapping[str, Callable[..., Any]],
    enforcer: Enforcer,
    *,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
    raise_on_deny: bool = False,
) -> Dict[str, Callable[..., Any]]:
    """Wrap every callable in a ``{name: fn}`` mapping.

    The mapping key is used as the LLM-facing tool name, matching how
    AutoGen resolves registered functions.

    Returns:
        New dict with the same keys and guarded callables as values.
    """

    return {
        tool_name: guard_function(
            fn,
            enforcer,
            name=tool_name,
            classify_action=classify_action,
            on_deny=on_deny,
            raise_on_deny=raise_on_deny,
        )
        for tool_name, fn in fns.items()
    }
