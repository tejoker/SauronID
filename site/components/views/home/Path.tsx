import Link from "next/link";
import Image from "next/image";
import BoundaryDemo from "@/components/interactive/BoundaryDemo";
import Checkpoint from "@/components/interactive/Checkpoint";
import logo from "@/public/sauronid-logo.png";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function Path({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["path"] }) {
  return (
    <section className="section-tight" id="path">
      <div className="container">
        <div className="section-head">
          <h2>{t.h2}</h2>
          <p className="lede">{t.lede}</p>
        </div>
        <div className="path">
          <Checkpoint index={1} kind={t.cp1.kind}>
            <h2>
              <span className="kind">{t.cp1.kind}.</span> {t.cp1.h2Rest}
            </h2>
            <div className="split split-start">
              <p className="lede">{t.cp1.lede}</p>
              <div className="intent-card">
                <div
                  className="intent-label"
                  style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}
                >
                  <Image src={logo} alt="" width={14} height={14} />
                  {t.cp1.intentLabel}
                </div>
                <div className="intent-text">
                  {t.cp1.intentText}
                  <span className="intent-caret" aria-hidden="true" />
                </div>
                <div className="intent-meta">{t.cp1.intentMeta}</div>
              </div>
            </div>
          </Checkpoint>

          <Checkpoint index={2} kind={t.cp2.kind}>
            <h2>
              <span className="kind">{t.cp2.kind}.</span> {t.cp2.h2Rest}
            </h2>
            <div className="split split-start">
              <p className="lede">{t.cp2.lede}</p>
              <div className="connect-grid connect-grid-col">
                <div className="connect-item">
                  {t.cp2.connect[0].item}
                  <span className="conn-state">{t.cp2.connect[0].state}</span>
                </div>
                <div className="connect-item">
                  {t.cp2.connect[1].item}
                  <span className="conn-state">{t.cp2.connect[1].state}</span>
                </div>
                <div className="connect-item">
                  {t.cp2.connect[2].item}
                  <span className="conn-state">{t.cp2.connect[2].state}</span>
                </div>
                <div className="connect-item denied">
                  {t.cp2.connect[3].item}
                  <span className="conn-state">{t.cp2.connect[3].state}</span>
                </div>
              </div>
            </div>
          </Checkpoint>

          <Checkpoint index={3} kind={t.cp3.kind}>
            <h2>
              <span className="kind">{t.cp3.kind}.</span> {t.cp3.h2Rest}
            </h2>
            <p className="lede">{t.cp3.lede}</p>
            <div className="contrast-pair">
              <div className="panel">
                <h3>{t.cp3.panelReview.h3}</h3>
                <div className="boundary-list mt-2">
                  {t.cp3.panelReview.boundaries.map((boundary) => (
                    <div className="boundary boundary-review" key={boundary.rule}>
                      <span className="rule">{boundary.rule}</span>
                      <span className="val">{boundary.val}</span>
                    </div>
                  ))}
                </div>
                <p className="small muted mt-2">{t.cp3.panelReview.note}</p>
              </div>
              <div className="panel">
                <h3>{t.cp3.panelLimits.h3}</h3>
                <div className="boundary-list mt-2">
                  <div className="boundary">
                    <span className="rule">{t.cp3.panelLimits.boundaries[0].rule}</span>
                    <span className="val">{t.cp3.panelLimits.boundaries[0].val}</span>
                  </div>
                  <div className="boundary">
                    <span className="rule">{t.cp3.panelLimits.boundaries[1].rule}</span>
                    <span className="val">{t.cp3.panelLimits.boundaries[1].val}</span>
                  </div>
                  <div className="boundary boundary-stopped">
                    <span className="rule">{t.cp3.panelLimits.boundaries[2].rule}</span>
                    <span className="val">{t.cp3.panelLimits.boundaries[2].val}</span>
                  </div>
                </div>
                <p className="small muted mt-2">{t.cp3.panelLimits.note}</p>
              </div>
            </div>
          </Checkpoint>

          <Checkpoint index={4} kind={t.cp4.kind}>
            <h2>
              <span className="kind">{t.cp4.kind}.</span> {t.cp4.h2Rest}
            </h2>
            <p className="lede">{t.cp4.lede}</p>
            <BoundaryDemo locale={locale} />
          </Checkpoint>

          <Checkpoint index={5} kind={t.cp5.kind} proof>
            <h2>
              <span className="kind">{t.cp5.kind}.</span> {t.cp5.h2Rest}
            </h2>
            <p className="lede">{t.cp5.lede}</p>
            <div className="split split-start mt-3">
              <div className="panel">
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
                        <path d="M8 2v6l3.5 2.5" />
                        <circle cx="8" cy="8" r="6.4" />
                      </svg>
                    </div>
                    <div className="trail-body">
                      <h4>{t.cp5.trail[0].h4}</h4>
                      <p>{t.cp5.trail[0].p}</p>
                      <div className="evidence">{t.cp5.trail[0].evidence}</div>
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
                        <path d="M8 5.5v3.5M8 11.4v.1" />
                        <circle cx="8" cy="8" r="6.4" />
                      </svg>
                    </div>
                    <div className="trail-body">
                      <h4>{t.cp5.trail[1].h4}</h4>
                      <p>{t.cp5.trail[1].p}</p>
                      <div className="evidence">{t.cp5.trail[1].evidence}</div>
                    </div>
                  </div>
                  <div className="trail-node t-stopped">
                    <div className="trail-dot" aria-hidden="true">
                      <svg
                        viewBox="0 0 16 16"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.6"
                        strokeLinecap="round"
                      >
                        <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" />
                        <circle cx="8" cy="8" r="6.4" />
                      </svg>
                    </div>
                    <div className="trail-body">
                      <h4>{t.cp5.trail[2].h4}</h4>
                      <p>{t.cp5.trail[2].p}</p>
                      <div className="evidence">{t.cp5.trail[2].evidence}</div>
                    </div>
                  </div>
                </div>
              </div>
              <div>
                <div className="proof-points">
                  {t.cp5.proofPoints.map((point) => (
                    <div className="proof-point" key={point.title}>
                      <strong>{point.title}</strong>
                      <span>{point.text}</span>
                    </div>
                  ))}
                </div>
                <p className="proof-note">{t.cp5.proofNote}</p>
                <div className="cta-row mt-4">
                  <Link className="btn btn-secondary" href={localeHref(locale, "/auditability")}>
                    {t.cp5.ctaAudit}
                  </Link>
                  <Link className="btn btn-secondary" href={localeHref(locale, "/compliance")}>
                    {t.cp5.ctaCompliance}
                  </Link>
                </div>
              </div>
            </div>
          </Checkpoint>
        </div>
      </div>
    </section>
  );
}
