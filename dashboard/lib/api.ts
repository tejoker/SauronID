// All public fetchers hit the SAME-ORIGIN Next.js /api/* surface. The dashboard's
// /api routes proxy to the SauronID core /admin/* surface server-side. The
// browser never knows the core URL — no CORS, no env leakage.
//
// Tenant context (S11.6): every browser-originated fetch attaches the
// `X-Sauron-Tenant-Id` header so the proxy can forward it to the core. The
// header is sourced from `currentTenant()` which reads the cookie set by the
// in-page tenant switcher. Server-side calls (Server Components, route
// handlers) rely on the middleware to copy the cookie onto the request
// header, so we only stamp the header here when running in the browser.

import { currentTenant, TENANT_COOKIE, TENANT_HEADER } from "./tenant";
import { SESSION_COOKIE } from "./session";

/* ── Types ─────────────────────────────────────────────────────────── */

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

export interface AgentStatus {
  id: string;
  name: string;
  agent_type: string;
  status: "active" | "idle" | "revoked";
  registered_at: string;
  last_call_at: string | null;
  total_calls: number;
  config_digest: string;
  allowed_intents: string[];
}

export interface ProtectedEvent {
  id: string;
  agent_id: string;
  agent_name: string;
  reason: string;
  reason_code: "replay" | "scope" | "signature" | "nonce" | "revoked" | "expired";
  timestamp: string;
  detail: Record<string, unknown>;
}

export interface ActivityCall {
  id: string;
  agent_id: string;
  agent_name: string;
  action: string;
  intent: string;
  result: "allowed" | "stopped";
  latency_ms: number;
  timestamp: string;
  detail: {
    body_hash?: string;
    nonce?: string;
    jti?: string;
    dpop_binding?: string;
  };
}

export interface AnchorStats {
  /// "opentimestamps" | "mock" | "disabled" | "unknown"
  bitcoin_provider: string;
  bitcoin_network: string;
  /// Anchors written by the mock provider: synthetic txid, on no chain.
  bitcoin_synthetic: number;
  bitcoin_total: number;
  bitcoin_pending: number;
  bitcoin_confirmed: number;
  bitcoin_last_batch_at: string | null;
  solana_total: number;
  solana_unconfirmed: number;
  solana_confirmed: number;
  solana_last_batch_at: string | null;
  agent_action_batches: number;
}

export interface OverviewStats {
  total_agents: number;
  active_agents: number;
  calls_today: number;
  protected_today: number;
}

export interface Company {
  id: string;
  name: string;
  created_at: string;
  agent_count: number;
}

export interface Person {
  id: string;
  name: string;
  email: string;
  company_id: string;
  company_name: string;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  agent_id: string;
  event_type: "call" | "mandate_check" | "config_change" | "revocation" | "registration";
  result: "allowed" | "stopped" | "info";
  timestamp: string;
  anchor_id: string | null;
  anchor_chain: "bitcoin" | "solana" | null;
  anchor_ref: string | null;
  detail: Record<string, unknown>;
}

export interface SystemHealth {
  core_reachable: boolean;
  last_seen_at: string | null;
  agent_count: number;
}

/* ── Fetch helpers ─────────────────────────────────────────────────── */

// Server-side fetches (Server Components, route handlers) need absolute URLs.
// Browser fetches use relative URLs (same-origin proxy).
function absolutize(path: string): string {
  if (typeof window !== "undefined") return path; // browser: relative is fine
  const port = process.env.PORT ?? "3000";
  return `http://127.0.0.1:${port}${path}`;
}

/**
 * Build the per-request header set. Browser-only — server-side calls let
 * Next.js middleware add the tenant header from the cookie. Returns an
 * empty object when running on the server so the existing call sites keep
 * working without forcing every fetcher to thread a Request through.
 */
function tenantHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const id = currentTenant();
  if (!id) return {};
  return { [TENANT_HEADER]: id };
}

/// Server Components fetch the same-origin /api/* surface, and those routes
/// require the signed operator session — but a server-side `fetch` starts with
/// no cookies, so every one of them came back 401 and each page fell back to its
/// empty state. The console home page therefore read "No agents registered yet"
/// on a deployment with 369 agents, while the client-rendered header on the same
/// page showed the real count. Forward the operator's own cookie so a Server
/// Component sees exactly what that operator is authorized to see — no more.
async function serverAuthHeaders(): Promise<Record<string, string>> {
  if (typeof window !== "undefined") return {};
  try {
    const { cookies } = await import("next/headers");
    const jar = await cookies();
    const forwarded = [SESSION_COOKIE, TENANT_COOKIE]
      .map((name) => {
        const value = jar.get(name)?.value;
        return value ? `${name}=${value}` : "";
      })
      .filter(Boolean)
      .join("; ");
    return forwarded ? { cookie: forwarded } : {};
  } catch {
    // Outside a request scope (build-time prerender, scripts): nothing to forward.
    return {};
  }
}

async function get<T>(url: string): Promise<ApiResult<T>> {
  try {
    const serverHeaders = await serverAuthHeaders();
    const res = await fetch(absolutize(url), {
      // No shared cache: the response is scoped to the operator session and the
      // tenant it authorizes, so a cached entry could be served to a different
      // operator on the next request.
      cache: "no-store",
      headers: { ...tenantHeaders(), ...serverHeaders },
    });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as T;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── Public API functions (all same-origin) ────────────────────────── */

export async function fetchOverview(): Promise<ApiResult<OverviewStats>> {
  return get<OverviewStats>(`/api/overview`);
}

export async function fetchAgents(): Promise<ApiResult<AgentStatus[]>> {
  return get<AgentStatus[]>(`/api/agents`);
}

export async function fetchAgent(id: string): Promise<ApiResult<AgentStatus>> {
  return get<AgentStatus>(`/api/agents/${id}`);
}

export async function fetchAgentAudit(
  id: string,
  params?: { from?: string; to?: string }
): Promise<ApiResult<AuditEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.from) qs.set("from", params.from);
  if (params?.to) qs.set("to", params.to);
  const query = qs.toString() ? `?${qs}` : "";
  return get<AuditEvent[]>(`/api/agents/${id}/audit${query}`);
}

export async function fetchProtected(params?: {
  limit?: number;
}): Promise<ApiResult<ProtectedEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ProtectedEvent[]>(`/api/protected${query}`);
}

export async function fetchActivity(params?: {
  filter?: "all" | "allowed" | "stopped";
  agent_id?: string;
  limit?: number;
}): Promise<ApiResult<ActivityCall[]>> {
  const qs = new URLSearchParams();
  if (params?.filter && params.filter !== "all") qs.set("result", params.filter);
  if (params?.agent_id) qs.set("agent_id", params.agent_id);
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ActivityCall[]>(`/api/activity${query}`);
}

export async function fetchProofs(): Promise<ApiResult<AnchorStats>> {
  return get<AnchorStats>(`/api/proofs`);
}

export interface AnchorBatch {
  anchor_id: string;
  root: string;
  n_actions: number;
  created_at: string;
  btc_confirmed: boolean;
  btc_anchor_id: string;
  /// Provider that wrote THIS row: "opentimestamps" (a real, downloadable proof)
  /// or "mock" (synthetic txid, nothing to download, on no chain).
  btc_provider: string;
}

export async function fetchAnchorBatches(): Promise<ApiResult<AnchorBatch[]>> {
  return get<AnchorBatch[]>(`/api/proofs/batches`);
}

export async function fetchCompanies(): Promise<ApiResult<Company[]>> {
  return get<Company[]>(`/api/clients`);
}

export async function fetchCompany(id: string): Promise<ApiResult<Company>> {
  return get<Company>(`/api/clients/${id}`);
}

export async function fetchPeople(): Promise<ApiResult<Person[]>> {
  return get<Person[]>(`/api/users`);
}

export async function fetchCompanyPeople(companyId: string): Promise<ApiResult<Person[]>> {
  return get<Person[]>(`/api/users?company_id=${encodeURIComponent(companyId)}`);
}

export async function fetchHealth(): Promise<ApiResult<SystemHealth>> {
  return get<SystemHealth>(`/api/health`);
}

export async function revokeAgent(id: string): Promise<ApiResult<{ revoked: true }>> {
  try {
    const res = await fetch(absolutize(`/api/agents/${id}/revoke`), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...tenantHeaders() },
    });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    return { ok: true, data: { revoked: true } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── Policy DSL (Sprint 10) ────────────────────────────────────────── */

// PolicySummary matches `core::policy::store::PolicySummary`. NOTE: the server
// returns `updated_at` as a Unix-epoch SECOND count (i64), not an ISO string.
export interface PolicySummary {
  policy_id: string;
  agent: string;
  version: string;
  /** Unix epoch seconds (i64) — convert with `new Date(updated_at * 1000)`. */
  updated_at: number;
}

export interface PolicyBinding {
  allowed_tools?: string[];
  max_budget_usd?: number;
  data_scope?: { allow?: string[]; deny?: string[] };
  rate_limit?: { requests_per_minute: number };
  time_window?: { start: string; end: string; timezone: string };
  required_signatures?: Array<{ role: string; threshold: number }>;
  delegation?: { max_depth: number; allowed_subagents?: string[] };
}

export interface PolicyFull {
  version: string;
  agent: string;
  description?: string;
  binding: PolicyBinding;
  invariants: string[];
  metadata?: Record<string, unknown>;
}

export interface PolicyUploadResponse {
  policy_id: string;
  agent: string;
  checks: string[];
}

export type PolicyVerdict =
  | { kind: "allow" }
  | { kind: "deny"; check: string; reason: string };

export interface EvaluateTraceEntry {
  check: string;
  verdict: PolicyVerdict;
}

export interface EvaluateResult {
  verdict: PolicyVerdict;
  trace: EvaluateTraceEntry[];
  spend_total_usd: number;
  simulator: boolean;
  simulator_warning?: string;
}

export interface EvaluateBody {
  action: Record<string, unknown>;
  context_overrides?: Record<string, unknown>;
  agent_id?: string;
}

export async function fetchPolicies(): Promise<ApiResult<PolicySummary[]>> {
  return get<PolicySummary[]>(`/api/policies`);
}

export async function fetchPolicy(id: string): Promise<ApiResult<PolicyFull>> {
  return get<PolicyFull>(`/api/policies/${encodeURIComponent(id)}`);
}

export async function uploadPolicy(
  yamlOrJson: string,
  contentType: "application/yaml" | "application/json"
): Promise<ApiResult<PolicyUploadResponse>> {
  try {
    const body =
      contentType === "application/json"
        ? JSON.stringify({ raw_yaml: yamlOrJson })
        : yamlOrJson;
    const res = await fetch(absolutize(`/api/policies`), {
      method: "POST",
      headers: { "Content-Type": contentType, ...tenantHeaders() },
      body,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, error: text || `HTTP ${res.status}` };
    }
    const data = (await res.json()) as PolicyUploadResponse;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

export async function deletePolicy(
  id: string
): Promise<ApiResult<{ deleted: true }>> {
  try {
    const res = await fetch(absolutize(`/api/policies/${encodeURIComponent(id)}`), {
      method: "DELETE",
      headers: { ...tenantHeaders() },
    });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    return { ok: true, data: { deleted: true } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── S10: server-side agent → policy binding ────────────────────────── */

/** Wire shape of the `/v1/agents/:id/policy_binding` core route. */
export interface AgentPolicyBindingRecord {
  agent_id: string;
  policy_id: string;
  /** Unix-epoch seconds (i64) — convert with `new Date(bound_at * 1000)`. */
  bound_at: number;
}

/**
 * GET the server-side binding for `agentId`. Returns `ok:false` with a
 * `"404"`-shaped error when no binding exists (callers can treat that as
 * "unbound").
 */
export async function fetchAgentBinding(
  agentId: string
): Promise<ApiResult<AgentPolicyBindingRecord>> {
  try {
    const res = await fetch(
      absolutize(`/api/agents/${encodeURIComponent(agentId)}/policy_binding`),
      { cache: "no-store", headers: { ...tenantHeaders() } }
    );
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as AgentPolicyBindingRecord;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/**
 * POST a new (or replacement) binding. Idempotent — re-binding the same
 * agent to a different policy is a last-write-wins update on the core.
 */
export async function bindAgentPolicy(
  agentId: string,
  policyId: string
): Promise<ApiResult<AgentPolicyBindingRecord>> {
  try {
    const res = await fetch(
      absolutize(`/api/agents/${encodeURIComponent(agentId)}/policy_binding`),
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...tenantHeaders() },
        body: JSON.stringify({ policy_id: policyId }),
      }
    );
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, error: text || `HTTP ${res.status}` };
    }
    const data = (await res.json()) as AgentPolicyBindingRecord;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/** DELETE the server-side binding for `agentId`. */
export async function unbindAgentPolicy(
  agentId: string
): Promise<ApiResult<{ unbound: true }>> {
  try {
    const res = await fetch(
      absolutize(`/api/agents/${encodeURIComponent(agentId)}/policy_binding`),
      { method: "DELETE", headers: { ...tenantHeaders() } }
    );
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    return { ok: true, data: { unbound: true } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── Sprint 19-20: ZK audit reports ────────────────────────────────── */

/** Typed evidence enum mirroring `core::audit::types::SectionEvidence`. */
export type AuditSectionEvidence =
  | {
      kind: "SpendBound";
      circuit: string;
      public_inputs: string[];
      claim: string;
    }
  | {
      kind: "ToolAllowlist";
      allowlist: string[];
      attempted_violations: number;
    }
  | {
      kind: "TimeWindow";
      window_start: string;
      window_end: string;
      violations: number;
    }
  | {
      kind: "AnchorChain";
      btc_root: string | null;
      btc_block: number | null;
      solana_sig: string | null;
      solana_slot: number | null;
    }
  | {
      kind: "StatsCommitment";
      metric_id: string;
      value: number;
      n_records: number;
      vk_id: string;
    }
  | {
      kind: "PolicyEvaluations";
      allowed: number;
      denied: number;
      denial_breakdown: Record<string, number>;
    };

/** Mirror of `core::audit::types::SectionVerdict`. */
export type AuditSectionVerdict =
  | { state: "Confirmed" }
  | { state: "Partial"; gaps: string[] }
  | { state: "Insufficient"; reason: string };

/** Mirror of `core::audit::report::AuditSection`. */
export interface AuditSection {
  heading: string;
  statement: string;
  evidence: AuditSectionEvidence;
  verdict: AuditSectionVerdict;
}

/** Mirror of `core::audit::report::AttachedProof`. */
export interface AuditAttachedProof {
  circuit: string;
  public_inputs: string[];
  proof_b64: string;
  vk_id: string;
}

/** Mirror of `core::audit::types::AnchorEvidence`. */
export interface AuditAnchorEvidence {
  merkle_root: string;
  bitcoin_ots_receipt_b64: string | null;
  bitcoin_block_height: number | null;
  solana_signature: string | null;
  solana_slot: number | null;
}

/** Mirror of `core::audit::types::ComplianceSummary`. */
export interface AuditComplianceSummary {
  policy_ids_evaluated: string[];
  total_actions: number;
  allowed: number;
  denied: number;
  policy_violation_rate: number;
}

/** Mirror of `core::audit::report::AuditReport`. */
export interface AuditReport {
  report_id: string;
  tenant_id: string;
  agent_ids: string[];
  period_start: number;
  period_end: number;
  generated_at: number;
  merkle_root: string;
  sections: AuditSection[];
  anchors: AuditAnchorEvidence;
  zk_proofs: AuditAttachedProof[];
  raw_receipts_count: number;
  policy_compliance_summary: AuditComplianceSummary;
}

export interface CreateAuditReportBody {
  agent_ids?: string[];
  period_start: number;
  period_end: number;
}

export async function fetchAuditReports(): Promise<ApiResult<AuditReport[]>> {
  return get<AuditReport[]>(`/api/audit/reports`);
}

export async function fetchAuditReport(
  id: string
): Promise<ApiResult<AuditReport>> {
  return get<AuditReport>(`/api/audit/reports/${encodeURIComponent(id)}`);
}

export async function createAuditReport(
  body: CreateAuditReportBody
): Promise<ApiResult<{ report: AuditReport; signature: string }>> {
  try {
    const res = await fetch(absolutize(`/api/audit/reports`), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...tenantHeaders() },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, error: text || `HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      report: AuditReport;
      signature: string;
    };
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

export async function evaluatePolicy(
  policyId: string,
  body: EvaluateBody
): Promise<ApiResult<EvaluateResult>> {
  try {
    const res = await fetch(
      absolutize(`/api/policies/${encodeURIComponent(policyId)}/evaluate`),
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...tenantHeaders() },
        body: JSON.stringify(body),
      }
    );
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, error: text || `HTTP ${res.status}` };
    }
    const data = (await res.json()) as EvaluateResult;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}
