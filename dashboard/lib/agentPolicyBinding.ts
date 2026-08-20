// Agent → policy binding helpers.
//
// As of Sprint 10 this lives on the server in `agent_policy_bindings`
// (see core/src/policy/binding_handlers.rs). The browser talks to the
// proxy under `/api/agents/:id/policy_binding` which forwards to the
// admin-gated core route — admin key never reaches the browser.
//
// LEGACY localStorage helpers (the `_legacy*` exports below) remain so
// the UI can fall back to client-only state when the proxy is
// unreachable (e.g. demo running without the core attached). They are
// NOT authoritative; the runtime evaluator only consults the server row.

import {
  fetchAgentBinding,
  bindAgentPolicy,
  unbindAgentPolicy,
} from "./api";

const KEY = "sauron:agent-policy-binding";

interface BindingEntry {
  policyId: string;
  boundAt: number;
}
type BindingMap = Record<string, BindingEntry>;

function read(): BindingMap {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null) return {};
    return parsed as BindingMap;
  } catch {
    return {};
  }
}

function write(map: BindingMap): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(map));
  } catch {
    // Quota exceeded / disabled storage — silently ignore.
  }
}

/* ── Server-backed helpers (preferred) ─────────────────────────────── */

/**
 * Fetch the server-side binding for `agentId`.
 * Returns the policy id (string) on success, `null` if the agent is
 * unbound, and a thrown error only on unexpected network/proxy failures.
 *
 * Offline fallback: when the core is unreachable, returns whatever the
 * localStorage cache last saw so the UI keeps working in demos.
 */
export async function fetchAgentBindingPolicyId(
  agentId: string
): Promise<string | null> {
  const r = await fetchAgentBinding(agentId);
  if (r.ok) return r.data.policy_id;
  // 404 = unbound — explicit miss, not a network error.
  if (typeof r.error === "string" && r.error.includes("404")) return null;
  // Network / proxy failure: fall back to localStorage cache.
  return _legacyGetAgentPolicyBinding(agentId);
}

/**
 * Bind `agentId` to `policyId` via the server endpoint. On success the
 * localStorage cache mirrors the new binding so an offline read returns
 * the same value. Throws when the server rejects the bind.
 */
export async function bindAgentToPolicy(
  agentId: string,
  policyId: string
): Promise<void> {
  const r = await bindAgentPolicy(agentId, policyId);
  if (!r.ok) {
    // Surface the server error to the caller — the legacy localStorage
    // path is NOT a substitute for a missing policy or unknown agent.
    throw new Error(r.error);
  }
  _legacySetAgentPolicyBinding(agentId, policyId);
}

/**
 * Unbind the server-side row and clear the localStorage cache. Idempotent.
 */
export async function unbindAgentFromPolicy(agentId: string): Promise<void> {
  const r = await unbindAgentPolicy(agentId);
  if (!r.ok) {
    throw new Error(r.error);
  }
  _legacyClearAgentPolicyBinding(agentId);
}

/* ── Legacy localStorage helpers (offline fallback only) ───────────── */

/** @deprecated use `fetchAgentBindingPolicyId` (server-backed). */
export function _legacyGetAgentPolicyBinding(agentId: string): string | null {
  const map = read();
  return map[agentId]?.policyId ?? null;
}

/** @deprecated use `bindAgentToPolicy` (server-backed). */
export function _legacySetAgentPolicyBinding(
  agentId: string,
  policyId: string
): void {
  const map = read();
  map[agentId] = { policyId, boundAt: Date.now() };
  write(map);
}

/** @deprecated use `unbindAgentFromPolicy` (server-backed). */
export function _legacyClearAgentPolicyBinding(agentId: string): void {
  const map = read();
  delete map[agentId];
  write(map);
}
