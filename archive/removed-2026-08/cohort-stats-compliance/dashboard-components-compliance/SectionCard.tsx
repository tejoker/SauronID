// Sprint 19-20: per-section renderer for an audit report.
//
// Dispatches on the typed `SectionEvidence` enum from the core. Each
// variant renders its own widget — proof-verify button, anchor
// badges, stats commitment values, policy-evaluation bars.

import { Badge } from "../ui/Badge";
import { Card, CardBody, CardHeader } from "../ui/Card";
import type {
  AuditSection,
  AuditSectionEvidence,
  AuditSectionVerdict,
} from "../../lib/api";
import { AnchorChainBadge } from "./AnchorChainBadge";
import { ProofVerifyButton } from "./ProofVerifyButton";

interface SectionCardProps {
  section: AuditSection;
  /** Merkle root the report's proofs anchor against — passed to the
   * Verify-proof button as the expected root. */
  merkleRoot: string;
}

function verdictBadge(v: AuditSectionVerdict) {
  switch (v.state) {
    case "Confirmed":
      return <Badge variant="ok">confirmed</Badge>;
    case "Partial":
      return <Badge variant="warning">partial</Badge>;
    case "Insufficient":
      return <Badge variant="stopped">insufficient</Badge>;
  }
}

function verdictDetail(v: AuditSectionVerdict): string | null {
  switch (v.state) {
    case "Confirmed":
      return null;
    case "Partial":
      return v.gaps.length > 0 ? v.gaps.join("; ") : null;
    case "Insufficient":
      return v.reason;
  }
}

function EvidenceView({
  evidence,
  merkleRoot,
}: {
  evidence: AuditSectionEvidence;
  merkleRoot: string;
}) {
  switch (evidence.kind) {
    case "SpendBound":
      return (
        <div className="space-y-3" data-testid="section-spend-bound">
          <p className="text-sm text-[var(--text-secondary)]">
            {evidence.claim}
          </p>
          <p className="text-mono-sm text-[var(--text-muted)]">
            circuit: {evidence.circuit}
          </p>
          {evidence.public_inputs.length > 0 && (
            <ProofVerifyButton
              circuit={evidence.circuit}
              publicInputs={evidence.public_inputs}
              expectedRootHex={merkleRoot}
            />
          )}
        </div>
      );
    case "ToolAllowlist":
      return (
        <div className="space-y-2" data-testid="section-tool-allowlist">
          <p className="text-mono-sm text-[var(--text-muted)]">
            attempted violations: {evidence.attempted_violations}
          </p>
          {evidence.allowlist.length > 0 && (
            <p className="text-mono-sm text-[var(--text-muted)]">
              allowlist: {evidence.allowlist.join(", ")}
            </p>
          )}
        </div>
      );
    case "TimeWindow":
      return (
        <div className="space-y-2" data-testid="section-time-window">
          <p className="text-mono-sm text-[var(--text-muted)]">
            window: {evidence.window_start || "—"} →{" "}
            {evidence.window_end || "—"}
          </p>
          <p className="text-mono-sm text-[var(--text-muted)]">
            violations: {evidence.violations}
          </p>
        </div>
      );
    case "AnchorChain":
      return (
        <AnchorChainBadge
          btcRoot={evidence.btc_root}
          btcBlock={evidence.btc_block}
          solanaSig={evidence.solana_sig}
          solanaSlot={evidence.solana_slot}
        />
      );
    case "StatsCommitment":
      return (
        <div className="space-y-2" data-testid="section-stats-commitment">
          <p className="text-sm text-[var(--text-primary)]">
            {evidence.metric_id}:{" "}
            <span className="font-mono">{evidence.value.toFixed(3)}</span>{" "}
            <span className="text-mono-sm text-[var(--text-muted)]">
              ({evidence.n_records} records)
            </span>
          </p>
          <p className="text-mono-sm text-[var(--text-muted)]">
            vk: {evidence.vk_id}
          </p>
        </div>
      );
    case "PolicyEvaluations": {
      const total = evidence.allowed + evidence.denied;
      const allowedPct =
        total === 0 ? 0 : Math.round((evidence.allowed / total) * 100);
      return (
        <div className="space-y-3" data-testid="section-policy-evals">
          <div className="flex items-center gap-3">
            <span className="text-mono-sm text-[var(--status-ok)]">
              allowed: {evidence.allowed}
            </span>
            <span className="text-mono-sm text-[var(--status-stopped)]">
              denied: {evidence.denied}
            </span>
          </div>
          {/* Plain HTML bar — no chart.js dep required for the bar */}
          <div
            className="h-2 rounded-full bg-[var(--bg-elevated)] overflow-hidden"
            role="progressbar"
            aria-label="allowed share"
            aria-valuenow={allowedPct}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            <div
              className="h-full bg-[var(--status-ok)]"
              style={{ width: `${allowedPct}%` }}
            />
          </div>
          {Object.keys(evidence.denial_breakdown).length > 0 && (
            <ul className="text-mono-sm text-[var(--text-muted)] space-y-1">
              {Object.entries(evidence.denial_breakdown).map(([check, count]) => (
                <li key={check}>
                  {check}: {count}
                </li>
              ))}
            </ul>
          )}
        </div>
      );
    }
  }
}

export function SectionCard({ section, merkleRoot }: SectionCardProps) {
  const detail = verdictDetail(section.verdict);
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">
              {section.heading}
            </h3>
            <p className="text-mono-sm text-[var(--text-muted)] mt-1">
              {section.statement}
            </p>
          </div>
          {verdictBadge(section.verdict)}
        </div>
        {detail && (
          <p className="text-mono-sm text-[var(--text-muted)] mt-2">
            {detail}
          </p>
        )}
      </CardHeader>
      <CardBody>
        <EvidenceView evidence={section.evidence} merkleRoot={merkleRoot} />
      </CardBody>
    </Card>
  );
}
