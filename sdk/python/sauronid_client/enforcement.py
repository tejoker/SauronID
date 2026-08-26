"""SauronID runtime enforcement layer (Python port).

This module mirrors the TypeScript SDK enforcement layer that lives in
``sdk/typescript/src/`` (policy-cache.ts, budget-tracker.ts, evaluator.ts,
tool-proxy.ts, enforcement.ts). The runtime contract — i.e. which
:class:`Action` is allowed against which :class:`CompiledPolicy` — is
byte-equivalent across the Rust server, the TypeScript client, and this
Python client.

Public surface:

- :class:`PolicyCache` — HTTP-backed compiled-policy cache with background
  refresh via :class:`threading.Timer`.
- :class:`BudgetTracker` — thread-safe in-memory spend + rate ledger.
- :func:`evaluate` — pure invariant evaluator (7 checks).
- :func:`bind` — wraps an arbitrary callable with policy enforcement.
- :func:`create_enforcer` — one-shot wiring of cache + budget + bind.

Errors:

- :class:`PolicyDeniedError` raised when a wrapped tool is blocked.
- :class:`PolicyNotLoadedError` raised when ``bind()`` is invoked before
  the policy has been loaded into the cache.

The module is purely additive — importing it has no effect on existing
:mod:`sauronid_client` behaviour. Users opt in by calling :func:`bind`
on the tools they hand to LangChain / OpenAI / Anthropic adapters.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union

import requests

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # py>=3.9
except ImportError:  # pragma: no cover - py<3.9
    ZoneInfo = None  # type: ignore[assignment]

    class ZoneInfoNotFoundError(Exception):  # type: ignore[no-redef]
        pass


__all__ = [
    "PolicyCache",
    "BudgetTracker",
    "BudgetState",
    "PendingSpendRecord",
    "PolicyDeniedError",
    "PolicyNotLoadedError",
    "Verdict",
    "Allow",
    "Deny",
    "Action",
    "EvaluationContext",
    "CompiledPolicy",
    "Enforcer",
    "evaluate",
    "bind",
    "create_enforcer",
    "compute_now_tz_hhmm",
]


_LOG = logging.getLogger("sauronid_client.enforcement")

RATE_WINDOW_SECS = 60
"""Width of the rate-limit sliding window. Must match the Rust + TS evaluators."""

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Allow:
    """Allow verdict — no invariant denied the action."""


@dataclass(frozen=True)
class Deny:
    """Deny verdict.

    Attributes:
        check: Invariant name that produced the deny (e.g. ``"budget"``).
        reason: Human-readable explanation. Safe to log / surface to operators.
    """

    check: str
    reason: str


Verdict = Union[Allow, Deny]
"""Allow / deny result of one local evaluation."""


# ---------------------------------------------------------------------------
# Action / EvaluationContext
# ---------------------------------------------------------------------------


@dataclass
class Action:
    """One tool invocation to evaluate. Mirrors the server ``Action`` struct.

    Attributes:
        action_id: Caller-supplied unique id (also used in receipts).
        tool: Tool / method to call (e.g. ``http_get``, ``sepa_payment_initiate``).
        amount_usd: USD amount if the action moves money. ``None`` means zero.
        data_classification: Data classification tag of the resource touched.
        signatures: Roles that have signed this action.
        delegation_depth: How many delegation hops from the root agent.
        timestamp: Unix-epoch seconds when the action was created. ``None`` means
            the evaluator should fill in ``time.time()`` at evaluation.
    """

    action_id: str
    tool: str
    amount_usd: Optional[float] = None
    data_classification: Optional[str] = None
    signatures: List[str] = field(default_factory=list)
    delegation_depth: int = 0
    timestamp: Optional[int] = None


@dataclass
class EvaluationContext:
    """Read-only context for one evaluation.

    Attributes:
        spend_total_usd: Cumulative USD spend observed so far.
        recent_call_timestamps: Unix-epoch *seconds* of recent calls
            (input to the rate-limit check).
        now_epoch: Current unix-epoch seconds. ``0`` -> use :func:`time.time`.
        now_tz_hhmm: ``HH:MM`` 24-hour in the policy's timezone.
            Empty string -> computed from the policy's ``time_window.timezone``.
    """

    spend_total_usd: float = 0.0
    recent_call_timestamps: List[int] = field(default_factory=list)
    now_epoch: int = 0
    now_tz_hhmm: str = ""


# ---------------------------------------------------------------------------
# CompiledPolicy
# ---------------------------------------------------------------------------


@dataclass
class CompiledPolicy:
    """Compiled policy as observed by the SDK.

    Attributes:
        policy_id: Server-assigned id (``pol_<32-hex>``).
        agent: Agent identifier.
        version: DSL version.
        binding: Decoded ``binding`` block (``allowed_tools``,
            ``max_budget_usd``, ``data_scope``, ``rate_limit``, ``time_window``,
            ``required_signatures``, ``delegation``).
        checks: Names of invariants this policy compiled into.
    """

    policy_id: str
    agent: str
    version: str
    binding: Dict[str, Any]
    checks: List[str]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PolicyDeniedError(Exception):
    """Raised when a wrapped tool is blocked by a local invariant.

    Attributes:
        check: Invariant name that produced the deny.
        reason: Human-readable explanation.
        policy_id: Policy id under which the action was evaluated.
        action_id: Action id that was denied.
    """

    def __init__(self, check: str, reason: str, policy_id: str, action_id: str) -> None:
        super().__init__(
            f"policy '{policy_id}' denied action '{action_id}' ({check}): {reason}"
        )
        self.check = check
        self.reason = reason
        self.policy_id = policy_id
        self.action_id = action_id


class PolicyNotLoadedError(Exception):
    """Raised when :func:`bind` is invoked before the policy has been loaded.

    Attributes:
        policy_id: Policy id that was missing from the cache.
    """

    def __init__(self, policy_id: str) -> None:
        super().__init__(
            f"policy '{policy_id}' not loaded - call cache.load() before bind()"
        )
        self.policy_id = policy_id


# ---------------------------------------------------------------------------
# PolicyCache
# ---------------------------------------------------------------------------


def _derive_checks(binding: Dict[str, Any]) -> List[str]:
    """Mirror of the TS ``checks`` derivation. Best-effort diagnostic list."""

    checks: List[str] = []
    if binding.get("allowed_tools") is not None:
        checks.append("allowlist")
    if isinstance(binding.get("max_budget_usd"), (int, float)):
        checks.append("budget")
    if binding.get("data_scope") is not None:
        checks.append("scope")
    if binding.get("rate_limit") is not None:
        checks.append("rate_limit")
    if binding.get("time_window") is not None:
        checks.append("time_window")
    req_sigs = binding.get("required_signatures")
    if isinstance(req_sigs, list) and len(req_sigs) > 0:
        checks.append("signatures")
    if binding.get("delegation") is not None:
        checks.append("delegation_depth")
    return checks


class PolicyCache:
    """In-memory compiled-policy cache with optional background refresh.

    The cache fetches via ``GET {core_url}/v1/policy/{policy_id}`` and
    stores the structured AST. A background :class:`threading.Timer`
    re-fetches each policy on a fixed interval; failed refreshes log a
    warning and keep the last good copy.
    """

    def __init__(
        self,
        *,
        core_url: str,
        admin_key: Optional[str] = None,
        refresh_interval_s: float = 60.0,
        http_session: Optional[requests.Session] = None,
        tenant_id: Optional[str] = None,
        timeout_s: float = 10.0,
    ) -> None:
        """Construct a policy cache.

        Args:
            core_url: Base URL of the core server (no trailing slash).
            admin_key: Admin bearer token; sent as ``Authorization: Bearer ...``
                when present.
            refresh_interval_s: Background refresh interval in seconds.
                ``0`` (or negative) disables refresh.
            http_session: Optional pre-configured :class:`requests.Session`.
                When omitted a private session is created.
            tenant_id: Sprint 11 multi-tenancy. When set, every outbound
                request to ``/v1/policy/*`` carries
                ``x-sauron-tenant-id: <tenant_id>``. When unset, the request
                is treated as the ``"default"`` tenant on the server side,
                preserving backwards compatibility with single-tenant
                deployments.
        """

        self._core_url = core_url.rstrip("/")
        self._admin_key = admin_key
        self._refresh_interval_s = float(refresh_interval_s)
        self._session = http_session if http_session is not None else requests.Session()
        self._tenant_id = tenant_id
        self._timeout_s = float(timeout_s)
        self._entries: Dict[str, CompiledPolicy] = {}
        self._timers: Dict[str, threading.Timer] = {}
        self._lock = threading.Lock()
        self._stopped = False

    # --- public API ----------------------------------------------------

    def load(self, policy_id: str) -> CompiledPolicy:
        """Load a policy by id.

        Fetches from the server, caches the result, and arms the refresh
        timer. Returns the cached entry on subsequent calls for the same
        id without a network roundtrip.

        Args:
            policy_id: Policy identifier (``pol_<hex>``).

        Returns:
            The :class:`CompiledPolicy` (either freshly fetched or cached).
        """

        with self._lock:
            existing = self._entries.get(policy_id)
        if existing is not None:
            return existing
        fresh = self._fetch_one(policy_id)
        with self._lock:
            self._entries[policy_id] = fresh
        self._arm_refresh(policy_id)
        return fresh

    def get(self, policy_id: str) -> Optional[CompiledPolicy]:
        """Return the cached entry or ``None`` on miss (no I/O)."""

        with self._lock:
            return self._entries.get(policy_id)

    def refresh(self, policy_id: str) -> None:
        """Force a fresh fetch.

        On failure, the cached entry is preserved and a warning is logged
        via :mod:`logging`.
        """

        try:
            fresh = self._fetch_one(policy_id)
        except Exception as err:  # noqa: BLE001 - top-level network boundary
            _LOG.warning("[PolicyCache] refresh %s failed: %s", policy_id, err)
            return
        with self._lock:
            self._entries[policy_id] = fresh

    def stop(self) -> None:
        """Cancel every background refresh timer. Idempotent."""

        with self._lock:
            self._stopped = True
            timers = list(self._timers.values())
            self._timers.clear()
        for t in timers:
            t.cancel()

    # --- internals -----------------------------------------------------

    def _fetch_one(self, policy_id: str) -> CompiledPolicy:
        """HTTP fetch + parse into :class:`CompiledPolicy`."""

        url = f"{self._core_url}/v1/policy/{requests.utils.quote(policy_id, safe='')}"
        headers: Dict[str, str] = {"accept": "application/json"}
        if self._admin_key:
            headers["authorization"] = f"Bearer {self._admin_key}"
        # Sprint 11: forward tenant header when configured. ADDITIVE only.
        if self._tenant_id:
            headers["x-sauron-tenant-id"] = self._tenant_id
        resp = self._session.get(url, headers=headers, timeout=self._timeout_s)
        if not resp.ok:
            raise RuntimeError(f"GET {url} -> {resp.status_code}")
        ast = resp.json()
        binding: Dict[str, Any] = ast.get("binding") or {}
        return CompiledPolicy(
            policy_id=policy_id,
            agent=ast.get("agent", ""),
            version=ast.get("version", ""),
            binding=binding,
            checks=_derive_checks(binding),
        )

    def _arm_refresh(self, policy_id: str) -> None:
        """(Re)arm the periodic refresh timer for ``policy_id``."""

        if self._refresh_interval_s <= 0:
            return
        with self._lock:
            if self._stopped:
                return
            old = self._timers.pop(policy_id, None)
        if old is not None:
            old.cancel()
        self._schedule_refresh(policy_id)

    def _schedule_refresh(self, policy_id: str) -> None:
        """Schedule one delayed refresh that re-arms itself."""

        with self._lock:
            if self._stopped or self._refresh_interval_s <= 0:
                return

        def _tick() -> None:
            self.refresh(policy_id)
            # Re-arm only if we're still live.
            with self._lock:
                if self._stopped:
                    return
            self._schedule_refresh(policy_id)

        timer = threading.Timer(self._refresh_interval_s, _tick)
        timer.daemon = True  # do not block process exit
        with self._lock:
            if self._stopped:
                return
            self._timers[policy_id] = timer
        timer.start()


# ---------------------------------------------------------------------------
# BudgetTracker
# ---------------------------------------------------------------------------


@dataclass
class PendingSpendRecord:
    """One queued spend record waiting for the next :meth:`BudgetTracker.flush`.

    Attributes:
        amount_usd: USD amount passed to :meth:`BudgetTracker.record`.
        action_id: Optional action id supplied by the caller.
        timestamp: Unix-epoch seconds when ``record`` was called.
    """

    amount_usd: float
    action_id: Optional[str]
    timestamp: int


@dataclass
class BudgetState:
    """Snapshot passed to a :class:`BudgetTracker` flush callback.

    Attributes:
        policy_id: Policy this tracker covers.
        total_usd: Running USD total at flush time.
        call_timestamps_s: Epoch-second timestamps of recent calls.
        pending: Records queued for this flush (one per :meth:`record` call
            since the last successful flush).
    """

    policy_id: str
    total_usd: float
    call_timestamps_s: List[int]
    pending: List[PendingSpendRecord]


FlushFn = Callable[[BudgetState], None]


class BudgetTracker:
    """Thread-safe in-memory spend + rate ledger with optional server flush.

    Sprint 3 keeps state in process memory; the Sprint 3 follow-up wires
    an optional ``flush_fn`` that drains queued :class:`PendingSpendRecord`
    entries to the server-side spend ledger. The default
    :meth:`BudgetTracker.server_push` builder POSTs each record to
    ``POST /v1/agents/:agent_id/spend`` so the server can hold the
    authoritative total (closes redteam A3 — local counter tampering).
    """

    def __init__(
        self,
        *,
        policy_id: str,
        flush_interval_s: float = 30.0,
        flush_fn: Optional[FlushFn] = None,
    ) -> None:
        """Construct a tracker.

        Args:
            policy_id: Policy id whose spend this tracker covers.
            flush_interval_s: Auto-flush interval in seconds. Default 30s.
                ``0`` disables the background timer; callers can still invoke
                :meth:`flush` manually.
            flush_fn: Hook invoked on each flush with a :class:`BudgetState`
                snapshot. When ``None``, pending records accumulate but are
                never sent anywhere (mirrors the legacy no-op behaviour).
                Use :meth:`BudgetTracker.server_push` to wire the
                authoritative ledger.
        """

        self._policy_id = policy_id
        self._total: float = 0.0
        self._calls: List[Tuple[int, str]] = []  # (epoch_seconds, action_id)
        self._pending: List[PendingSpendRecord] = []
        self._lock = threading.Lock()
        self._stopped = False
        self._flush_fn = flush_fn
        self._flush_interval_s = max(0.0, float(flush_interval_s))
        self._timer: Optional[threading.Timer] = None
        if self._flush_interval_s > 0:
            self._schedule_flush()

    # --- public API ----------------------------------------------------

    def record(self, amount_usd: float, action_id: Optional[str] = None) -> None:
        """Record one tool invocation.

        Increments the running total, appends a rate-window timestamp,
        and queues a :class:`PendingSpendRecord` for the next flush.

        Args:
            amount_usd: USD amount to add to the running total (0 if no spend).
            action_id: Optional action id; stored alongside the timestamp.
        """

        amount = float(amount_usd)
        with self._lock:
            self._total += amount
            now = int(time.time())
            self._calls.append((now, action_id or ""))
            # Cap history at last 1024 entries (mirrors TS bound).
            if len(self._calls) > 1024:
                self._calls = self._calls[-1024:]
            self._pending.append(
                PendingSpendRecord(amount_usd=amount, action_id=action_id, timestamp=now)
            )

    def total(self) -> float:
        """Return the current spend total in USD."""

        with self._lock:
            return self._total

    def pending_count(self) -> int:
        """Number of records waiting for the next flush."""

        with self._lock:
            return len(self._pending)

    def recent_calls(self, window_s: float) -> List[int]:
        """Return call timestamps (epoch seconds) within the last ``window_s``.

        Older entries are pruned as a side effect.
        """

        cutoff = int(time.time() - float(window_s))
        with self._lock:
            # Drop everything <= cutoff (matches TS ``> cutoff`` semantics).
            kept = [t for t in self._calls if t[0] > cutoff]
            self._calls = kept
            return [t for t, _ in kept]

    def flush(self) -> None:
        """Drain queued :class:`PendingSpendRecord` entries via ``flush_fn``.

        On failure the pending list is preserved so the next tick retries.
        When no ``flush_fn`` was configured this method drops pending
        records silently (mirrors the legacy no-op semantics).
        """

        with self._lock:
            snapshot = list(self._pending)
            total_usd = self._total
            timestamps = [t for t, _ in self._calls]
        if not snapshot:
            return
        if self._flush_fn is None:
            with self._lock:
                # Drop on the floor — there's no consumer wired.
                del self._pending[: len(snapshot)]
            return
        try:
            self._flush_fn(
                BudgetState(
                    policy_id=self._policy_id,
                    total_usd=total_usd,
                    call_timestamps_s=timestamps,
                    pending=snapshot,
                )
            )
        except Exception as err:  # noqa: BLE001 - top-level network boundary
            _LOG.warning(
                "[BudgetTracker] flush failed for %s: %s", self._policy_id, err
            )
            return
        with self._lock:
            # Drop only what we sent; new ones may have arrived during the call.
            del self._pending[: len(snapshot)]

    def stop(self) -> None:
        """Cancel the background timer and trigger a final flush. Idempotent."""

        with self._lock:
            self._stopped = True
            timer = self._timer
            self._timer = None
        if timer is not None:
            timer.cancel()
        # Always run one last flush so no pending record is lost.
        try:
            self.flush()
        except Exception:  # noqa: BLE001 - defensive
            pass

    # --- internals -----------------------------------------------------

    def _schedule_flush(self) -> None:
        with self._lock:
            if self._stopped or self._flush_interval_s <= 0:
                return

        def _tick() -> None:
            try:
                with self._lock:
                    has_pending = len(self._pending) > 0
                if has_pending:
                    self.flush()
            finally:
                with self._lock:
                    if self._stopped:
                        return
                self._schedule_flush()

        timer = threading.Timer(self._flush_interval_s, _tick)
        timer.daemon = True
        with self._lock:
            if self._stopped:
                return
            self._timer = timer
        timer.start()

    @staticmethod
    def server_push(
        *,
        core_url: str,
        admin_key: Optional[str],
        agent_id: str,
        policy_id: str,
        http_session: Optional[requests.Session] = None,
        tenant_id: Optional[str] = None,
    ) -> FlushFn:
        """Build a ``flush_fn`` that POSTs each pending record to
        ``POST /v1/agents/:agent_id/spend``.

        Args:
            core_url: Base URL of the SauronID core server (no trailing slash).
            admin_key: Admin bearer token. ``None`` skips the header.
            agent_id: Agent id whose ledger row should be incremented.
            policy_id: Policy id this tracker covers.
            http_session: Optional pre-configured :class:`requests.Session`.
            tenant_id: Sprint 11 multi-tenancy. When set, every POST carries
                ``x-sauron-tenant-id: <tenant_id>``. When unset, the server
                lands the row in the ``"default"`` tenant (back-compat).

        Returns:
            A callable suitable for :class:`BudgetTracker`'s ``flush_fn``.
        """

        sess = http_session if http_session is not None else requests.Session()
        url = f"{core_url.rstrip('/')}/v1/agents/{requests.utils.quote(agent_id, safe='')}/spend"
        headers: Dict[str, str] = {"content-type": "application/json"}
        if admin_key:
            headers["authorization"] = f"Bearer {admin_key}"
        if tenant_id:
            headers["x-sauron-tenant-id"] = tenant_id

        def _push(state: BudgetState) -> None:
            for rec in state.pending:
                payload: Dict[str, Any] = {
                    "policy_id": policy_id,
                    "amount_usd": rec.amount_usd,
                }
                if rec.action_id is not None:
                    payload["action_id"] = rec.action_id
                resp = sess.post(url, json=payload, headers=headers, timeout=10)
                if not resp.ok:
                    raise RuntimeError(f"POST {url} -> {resp.status_code}: {resp.text}")

        return _push


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


def compute_now_tz_hhmm(epoch_s: int, iana_tz: str) -> str:
    """Compute ``HH:MM`` in ``iana_tz`` from a unix-epoch second.

    Falls back to UTC if :mod:`zoneinfo` rejects the timezone name.

    Args:
        epoch_s: Unix-epoch seconds.
        iana_tz: IANA timezone (e.g. ``Europe/Paris``).

    Returns:
        ``HH:MM`` 24-hour string.
    """

    dt_utc = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
    if ZoneInfo is not None:
        try:
            local = dt_utc.astimezone(ZoneInfo(iana_tz))
            return local.strftime("%H:%M")
        except (ZoneInfoNotFoundError, ValueError, OSError):
            pass
    return dt_utc.strftime("%H:%M")


def _in_window(start: str, end: str, hhmm: str) -> bool:
    """Return ``True`` if ``hhmm`` is in ``[start, end]`` (wrap-around aware)."""

    if start <= end:
        return start <= hhmm <= end
    return hhmm >= start or hhmm <= end


def evaluate(
    policy: CompiledPolicy, action: Action, ctx: EvaluationContext
) -> Verdict:
    """Run every applicable check from ``policy.binding`` against ``action``.

    Returns the first :class:`Deny` verdict, or :class:`Allow` if all pass.

    Order mirrors ``core::policy::compiler::compile``: allowlist -> budget
    -> scope -> rate_limit -> time_window -> signatures -> delegation_depth.

    Args:
        policy: Compiled policy with the structured ``binding`` block.
        action: Action to evaluate. ``action.timestamp`` defaults to
            ``time.time()`` when ``None``.
        ctx: Surrounding evaluation context. ``ctx.now_epoch == 0`` is
            replaced by ``time.time()``; empty ``ctx.now_tz_hhmm`` is
            computed from the policy's ``time_window.timezone``.

    Returns:
        :class:`Allow` or :class:`Deny`.
    """

    b = policy.binding

    # Fill in defaults the same way the TS wrapper does.
    if action.timestamp is None:
        action.timestamp = int(time.time())
    now_epoch = ctx.now_epoch if ctx.now_epoch > 0 else int(time.time())

    # 1. allowlist (tool name)
    allowed = b.get("allowed_tools")
    if allowed is not None:
        if action.tool not in allowed:
            return Deny(
                check="allowlist",
                reason=f"tool '{action.tool}' not in allowlist",
            )

    # 2. budget
    cap = b.get("max_budget_usd")
    if isinstance(cap, (int, float)):
        amount = float(action.amount_usd) if action.amount_usd is not None else 0.0
        projected = float(ctx.spend_total_usd) + amount
        if projected > float(cap):
            return Deny(
                check="budget",
                reason=(
                    f"projected spend {projected:.2f} USD exceeds "
                    f"cap {float(cap):.2f} USD"
                ),
            )

    # 3. scope (data classification)
    scope = b.get("data_scope")
    if isinstance(scope, dict):
        raw = action.data_classification
        if raw is not None:
            tag = raw.lower()
            deny_list = [str(s).lower() for s in scope.get("deny", []) or []]
            allow_list = [str(s).lower() for s in scope.get("allow", []) or []]
            if tag in deny_list:
                return Deny(
                    check="scope",
                    reason=f"classification '{tag}' is on deny list",
                )
            if len(allow_list) > 0 and tag not in allow_list:
                # JSON-style array repr to mirror TS reason exactly.
                arr_repr = "[" + ",".join(f'"{x}"' for x in allow_list) + "]"
                return Deny(
                    check="scope",
                    reason=f"classification '{tag}' not in allow list {arr_repr}",
                )

    # 4. rate_limit
    rl = b.get("rate_limit")
    if isinstance(rl, dict):
        limit = int(rl.get("requests_per_minute", 0))
        lower = now_epoch - RATE_WINDOW_SECS
        count = 0
        for t in ctx.recent_call_timestamps:
            if t > lower and t <= now_epoch:
                count += 1
        if count >= limit:
            return Deny(
                check="rate_limit",
                reason=f"{count} calls in last 60s reached limit {limit}",
            )

    # 5. time_window
    tw = b.get("time_window")
    if isinstance(tw, dict):
        tz_name = tw.get("timezone", "UTC")
        hhmm = ctx.now_tz_hhmm or compute_now_tz_hhmm(now_epoch, tz_name)
        start = tw.get("start", "00:00")
        end = tw.get("end", "23:59")
        if not _in_window(start, end, hhmm):
            return Deny(
                check="time_window",
                reason=(
                    f"current time {hhmm} ({tz_name}) outside window "
                    f"[{start}, {end}]"
                ),
            )

    # 6. signatures (M-of-N per role)
    req_sigs = b.get("required_signatures")
    if isinstance(req_sigs, list):
        for req in req_sigs:
            role = req.get("role")
            threshold = int(req.get("threshold", 0))
            got = sum(1 for s in action.signatures if s == role)
            if got < threshold:
                return Deny(
                    check="signatures",
                    reason=(
                        f"role '{role}' has {got} of {threshold} "
                        "required signatures"
                    ),
                )

    # 7. delegation depth
    deleg = b.get("delegation")
    if isinstance(deleg, dict):
        max_depth = int(deleg.get("max_depth", 0))
        if action.delegation_depth > max_depth:
            return Deny(
                check="delegation_depth",
                reason=(
                    f"delegation_depth = {action.delegation_depth} "
                    f"exceeds max {max_depth}"
                ),
            )

    return Allow()


# ---------------------------------------------------------------------------
# bind / wrapper
# ---------------------------------------------------------------------------


ClassifyFn = Callable[[str, Tuple[Any, ...], Dict[str, Any]], Dict[str, Any]]
OnDenyFn = Callable[[Deny], None]


def bind(
    tool: Callable[..., T],
    *,
    agent_id: str,
    policy_id: str,
    cache: PolicyCache,
    budget_tracker: Optional[BudgetTracker] = None,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
) -> Callable[..., T]:
    """Wrap ``tool`` with policy enforcement.

    The returned callable has the same call signature. On each
    invocation it evaluates the policy locally before forwarding.

    Raises:
        PolicyNotLoadedError: If the policy is not in the cache when the
            wrapped function is invoked.
        PolicyDeniedError: When a local invariant denies the action. The
            original ``tool`` is NOT called in that case.

    Args:
        tool: Original callable.
        agent_id: Agent id this tool belongs to (echoed in audit).
        policy_id: Policy to evaluate against. Must be loaded in ``cache``.
        cache: Compiled-policy cache.
        budget_tracker: Optional spend / rate ledger. Absent => zero spend +
            empty call history per evaluation.
        classify_action: Optional classifier. Receives
            ``(tool_name, args, kwargs)`` and returns a dict of overrides
            applied to the synthesised :class:`Action` BEFORE evaluation.
            Recognised keys: ``amount_usd``, ``data_classification``,
            ``signatures``, ``delegation_depth``, ``timestamp``.
        on_deny: Hook fired BEFORE :class:`PolicyDeniedError` is raised
            (audit / metrics).

    Returns:
        A wrapper preserving the original tool's metadata via
        :func:`functools.wraps`.
    """

    @functools.wraps(tool)
    def wrapped(*args: Any, **kwargs: Any) -> T:
        policy = cache.get(policy_id)
        if policy is None:
            raise PolicyNotLoadedError(policy_id)

        tool_name = getattr(tool, "__name__", "anonymous") or "anonymous"
        action = Action(
            action_id=uuid.uuid4().hex,
            tool=tool_name,
            timestamp=int(time.time()),
        )
        if classify_action is not None:
            overrides = classify_action(tool_name, args, kwargs) or {}
            for key, value in overrides.items():
                if hasattr(action, key):
                    setattr(action, key, value)

        tw = policy.binding.get("time_window") or {}
        tz_name = tw.get("timezone", "UTC")
        spend_total = budget_tracker.total() if budget_tracker is not None else 0.0
        if budget_tracker is not None:
            recent = budget_tracker.recent_calls(RATE_WINDOW_SECS)
        else:
            recent = []

        ctx = EvaluationContext(
            spend_total_usd=spend_total,
            recent_call_timestamps=recent,
            now_epoch=action.timestamp or int(time.time()),
            now_tz_hhmm=compute_now_tz_hhmm(
                action.timestamp or int(time.time()), tz_name
            ),
        )

        verdict = evaluate(policy, action, ctx)
        if isinstance(verdict, Deny):
            if on_deny is not None:
                on_deny(verdict)
            raise PolicyDeniedError(
                check=verdict.check,
                reason=verdict.reason,
                policy_id=policy_id,
                action_id=action.action_id,
            )

        result = tool(*args, **kwargs)
        if budget_tracker is not None and action.amount_usd is not None:
            budget_tracker.record(float(action.amount_usd), action.action_id)
        # ``agent_id`` is captured by closure for forward-compat (audit /
        # receipts in S7). Intentionally unused at this point.
        return result

    return wrapped


# ---------------------------------------------------------------------------
# create_enforcer
# ---------------------------------------------------------------------------


@dataclass
class Enforcer:
    """Bundled enforcement context returned by :func:`create_enforcer`.

    Attributes:
        cache: Shared cache instance (one policy already loaded).
        budget: Spend ledger for the active policy.
        policy_id: Bound policy id.
        agent_id: Bound agent id.
    """

    cache: PolicyCache
    budget: BudgetTracker
    policy_id: str
    agent_id: str

    def bind(
        self,
        tool: Callable[..., T],
        *,
        classify_action: Optional[ClassifyFn] = None,
        on_deny: Optional[OnDenyFn] = None,
    ) -> Callable[..., T]:
        """Pre-bound :func:`bind` shorthand.

        Auto-passes ``cache``, ``budget_tracker``, ``policy_id``, ``agent_id``.
        """

        return bind(
            tool,
            agent_id=self.agent_id,
            policy_id=self.policy_id,
            cache=self.cache,
            budget_tracker=self.budget,
            classify_action=classify_action,
            on_deny=on_deny,
        )

    def stop(self) -> None:
        """Stop background timers (cache refresh + budget tracker)."""

        self.cache.stop()
        self.budget.stop()


def create_enforcer(
    *,
    core_url: str,
    admin_key: Optional[str],
    policy_id: str,
    agent_id: str,
    refresh_interval_s: float = 60.0,
    http_session: Optional[requests.Session] = None,
    server_side_spend: bool = True,
    budget_flush_interval_s: float = 30.0,
    tenant_id: Optional[str] = None,
) -> Enforcer:
    """One-shot wiring of cache + budget + ``bind`` for a single policy.

    Loads the policy synchronously, instantiates the cache + budget
    tracker, and returns an :class:`Enforcer` whose :meth:`Enforcer.bind`
    is pre-configured for the policy / agent.

    By default the budget tracker is wired to the server-side spend
    ledger via ``POST /v1/agents/:agent_id/spend`` so the in-memory total
    is no longer the source of truth. Pass ``server_side_spend=False`` for
    offline / test scenarios.

    Example:
        >>> enf = create_enforcer(
        ...     core_url="http://localhost:8080",
        ...     admin_key="dev",
        ...     policy_id="pol_abc",
        ...     agent_id="agent-1",
        ... )
        >>> guarded = enf.bind(my_tool)
        >>> guarded(args)  # raises PolicyDeniedError on invariant violation

    Args:
        core_url: Base URL of the core server.
        admin_key: Admin bearer token, when the server requires auth.
        policy_id: Policy id to bind against.
        agent_id: Agent id (echoed in audit + future receipts).
        refresh_interval_s: Background policy-refresh interval in seconds.
        http_session: Optional pre-configured :class:`requests.Session`.
        server_side_spend: When ``True`` (default), wires the
            :class:`BudgetTracker` to ``POST /v1/agents/:agent_id/spend``.
        budget_flush_interval_s: Background flush interval for the
            :class:`BudgetTracker`. Default 30s. ``0`` disables the timer;
            callers must invoke ``enf.budget.flush()`` manually.

    Returns:
        A live :class:`Enforcer`.
    """

    cache = PolicyCache(
        core_url=core_url,
        admin_key=admin_key,
        refresh_interval_s=refresh_interval_s,
        http_session=http_session,
        tenant_id=tenant_id,
    )
    cache.load(policy_id)
    flush_fn: Optional[FlushFn] = None
    if server_side_spend:
        flush_fn = BudgetTracker.server_push(
            core_url=core_url,
            admin_key=admin_key,
            agent_id=agent_id,
            policy_id=policy_id,
            http_session=http_session,
            tenant_id=tenant_id,
        )
    budget = BudgetTracker(
        policy_id=policy_id,
        flush_interval_s=budget_flush_interval_s,
        flush_fn=flush_fn,
    )
    return Enforcer(cache=cache, budget=budget, policy_id=policy_id, agent_id=agent_id)
