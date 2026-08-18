import { Card, CardBody } from "@/components/ui/Card";

interface PrivacyNoticeProps {
  /** Epsilon spent across the published metrics. */
  epsilon: number;
  /** Delta failure probability. */
  delta?: number;
  /** k-anonymity threshold — cohorts with fewer tenants are suppressed. */
  kAnonymity?: number;
  /** Optional verbatim privacy_notice from the server. */
  notice?: string;
}

/**
 * Explains the differential-privacy guarantees attached to a cohort
 * publication. Shows the ε used, δ failure probability, and the k-anonymity
 * suppression threshold. Kept text-only — no clickable links — so it can
 * render server-side without a hydration boundary.
 */
export function PrivacyNotice({
  epsilon,
  delta = 1e-6,
  kAnonymity = 5,
  notice,
}: PrivacyNoticeProps) {
  return (
    <Card>
      <CardBody>
        <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
          Privacy guarantee
        </p>
        <dl className="grid grid-cols-3 gap-4 mb-3 text-sm">
          <div>
            <dt className="text-mono-sm text-[var(--text-muted)] uppercase">
              ε spent
            </dt>
            <dd className="text-[var(--text-primary)] font-mono">{epsilon.toFixed(2)}</dd>
          </div>
          <div>
            <dt className="text-mono-sm text-[var(--text-muted)] uppercase">δ</dt>
            <dd className="text-[var(--text-primary)] font-mono">
              {delta.toExponential(0)}
            </dd>
          </div>
          <div>
            <dt className="text-mono-sm text-[var(--text-muted)] uppercase">
              k-anon
            </dt>
            <dd className="text-[var(--text-primary)] font-mono">≥ {kAnonymity}</dd>
          </div>
        </dl>
        <p className="text-sm text-[var(--text-secondary)]">
          {notice ??
            `Cohort statistics are released under (ε, δ)-differential privacy. ` +
              `Gaussian noise is added at publication time. Buckets with fewer ` +
              `than k=${kAnonymity} tenants are suppressed entirely so no ` +
              `individual contribution can be recovered.`}
        </p>
      </CardBody>
    </Card>
  );
}
