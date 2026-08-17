import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";

import { T } from "./copy";
export default function AuditabilityView({ locale }: { locale: Locale }) {
  const t = T[locale];
  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">{t.lede}</p>
        </div>
      </section>

      {/* The full trail */}
      <section className="section section-cloud">
        <div className="container">
          <div className="section-head">
            <h2>
              <span className="kind">{t.trailKind}</span> {t.trailH2}
            </h2>
            <p className="lede">{t.trailLede}</p>
          </div>
          <div className="split split-start">
            <div className="trail">
              <div className="trail-node">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                  >
                    <circle cx="8" cy="8" r="6.4" />
                    <circle cx="8" cy="8" r="2.2" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.intentTitle}</h4>
                  <p>{t.intentBody}</p>
                  <div className="evidence">{t.intentEvidence}</div>
                </div>
              </div>
              <div className="trail-node">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <rect x="2.5" y="2.5" width="11" height="11" rx="2.5" />
                    <path d="M5.5 6h5M5.5 8.5h5M5.5 11h3" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.policyTitle}</h4>
                  <p>{t.policyBody}</p>
                  <div className="evidence">{t.policyEvidence}</div>
                </div>
              </div>
              <div className="trail-node">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                  >
                    <path d="M3 8h8M8.5 4.5L12 8l-3.5 3.5" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.requestTitle}</h4>
                  <p>{t.requestBody}</p>
                  <div className="evidence">{t.requestEvidence}</div>
                </div>
              </div>
              <div className="trail-node t-review">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                  >
                    <path d="M8 5.5v3.5M8 11.4v.1" />
                    <circle cx="8" cy="8" r="6.4" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.decisionTitle}</h4>
                  <p>{t.decisionBody}</p>
                  <div className="evidence">{t.decisionEvidence}</div>
                </div>
              </div>
              <div className="trail-node t-review">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M8 8.5a2.6 2.6 0 100-5.2 2.6 2.6 0 000 5.2zM3 13.5c.7-2.3 2.7-3.5 5-3.5s4.3 1.2 5 3.5" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.approvalTitle}</h4>
                  <p>{t.approvalBody}</p>
                  <div className="evidence">{t.approvalEvidence}</div>
                </div>
              </div>
              <div className="trail-node t-allowed">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                  >
                    <path d="M4.5 8.4l2.4 2.4 4.6-5.2" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.executionTitle}</h4>
                  <p>{t.executionBody}</p>
                  <div className="evidence">{t.executionEvidence}</div>
                </div>
              </div>
              <div className="trail-node t-allowed">
                <div className="trail-dot" aria-hidden="true">
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M4 2.5h6l3 3v8a1 1 0 01-1 1H4a1 1 0 01-1-1v-10a1 1 0 011-1zM10 2.5v3h3" />
                  </svg>
                </div>
                <div className="trail-body">
                  <h4>{t.evidenceTitle}</h4>
                  <p>{t.evidenceBody}</p>
                  <div className="evidence">{t.evidenceEvidence}</div>
                </div>
              </div>
            </div>
            <div>
              <div className="panel">
                <h3>{t.panelChainTitle}</h3>
                <p className="small muted">{t.panelChainBody1}</p>
                <p className="small muted">{t.panelChainBody2}</p>
              </div>
              <div className="panel panel-soft mt-3">
                <h3>{t.panelStoppedTitle}</h3>
                <p className="small muted">{t.panelStoppedBody}</p>
                <div className="evidence mt-2">{t.panelStoppedEvidence}</div>
              </div>
            </div>
          </div>
          <p className="small faint mt-4">{t.trailFootnote}</p>
        </div>
      </section>

      {/* Who it serves */}
      <section className="section">
        <div className="container">
          <div className="section-head">
            <h2>
              <span className="kind">{t.whoKind}</span> {t.whoH2}
            </h2>
            <p className="lede">{t.whoLede}</p>
          </div>
          <dl className="deflist">
            <div>
              <dt>{t.dtInternal}</dt>
              <dd>{t.ddInternal}</dd>
            </div>
            <div>
              <dt>{t.dtCompliance}</dt>
              <dd>{t.ddCompliance}</dd>
            </div>
            <div>
              <dt>{t.dtSecurity}</dt>
              <dd>{t.ddSecurity}</dd>
            </div>
            <div>
              <dt>{t.dtIncident}</dt>
              <dd>{t.ddIncident}</dd>
            </div>
            <div>
              <dt>{t.dtManagement}</dt>
              <dd>{t.ddManagement}</dd>
            </div>
            <div>
              <dt>{t.dtCustomers}</dt>
              <dd>{t.ddCustomers}</dd>
            </div>
          </dl>
        </div>
      </section>

      {/* Closing */}
      <section className="section dark center">
        <div className="container">
          <h2 style={{ maxWidth: "38rem", marginInline: "auto" }}>
            {t.closingH2}
          </h2>
          <div className="cta-row mt-3" style={{ justifyContent: "center" }}>
            <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
              {t.ctaPrimary}{" "}
              <span className="arrow" aria-hidden="true">
                →
              </span>
            </Link>
            <Link className="btn btn-secondary" href={localeHref(locale, "/compliance")}>
              {t.ctaSecondary}
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
