import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";

import { T } from "./copy";
export default function SecurityView({ locale }: { locale: Locale }) {
  const t = T[locale];

  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">{t.lede1}</p>
        </div>
      </section>

      {/* The enforcement path */}
      <section className="section section-cloud">
        <div className="container">
          <div className="section-head">
            <h2>
              {locale === "fr" ? (
                <>
                  <span className="kind">Application.</span> Le chemin que
                  suit chaque action
                </>
              ) : (
                <>
                  <span className="kind">Enforcement.</span> The path every
                  action walks
                </>
              )}
            </h2>
            <p className="lede">{t.trailLede}</p>
          </div>
          <div className="trail maxw">
            <div className="trail-node">
              <div className="trail-dot" aria-hidden="true">
                <svg
                  viewBox="0 0 16 16"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  strokeLinecap="round"
                >
                  <path d="M8 1.8l5 2.2v3.4c0 3.3-2.1 5.7-5 6.8-2.9-1.1-5-3.5-5-6.8V4z" />
                </svg>
              </div>
              <div className="trail-body">
                <h4>{t.trail[0].h4}</h4>
                <p>{t.trail[0].p}</p>
                <div className="evidence">{t.trail[0].ev}</div>
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
                  <circle cx="8" cy="8" r="6.4" />
                  <path d="M5.5 8.2l1.8 1.8 3.4-3.8" />
                </svg>
              </div>
              <div className="trail-body">
                <h4>{t.trail[1].h4}</h4>
                <p>{t.trail[1].p}</p>
                <div className="evidence">{t.trail[1].ev}</div>
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
                  <path d="M3 8h10M8 3v10" />
                  <circle cx="8" cy="8" r="6.4" />
                </svg>
              </div>
              <div className="trail-body">
                <h4>{t.trail[2].h4}</h4>
                <p>{t.trail[2].p}</p>
                <div className="evidence">{t.trail[2].ev}</div>
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
                  <path d="M5.5 8h5M8 5.5v5" />
                </svg>
              </div>
              <div className="trail-body">
                <h4>{t.trail[3].h4}</h4>
                <p>{t.trail[3].p}</p>
                <div className="evidence">{t.trail[3].ev}</div>
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
                  <path d="M2.5 8c1.8-3.2 9.2-3.2 11 0-1.8 3.2-9.2 3.2-11 0z" />
                  <circle cx="8" cy="8" r="1.7" />
                </svg>
              </div>
              <div className="trail-body">
                <h4>{t.trail[4].h4}</h4>
                <p>{t.trail[4].p}</p>
                <div className="evidence">{t.trail[4].ev}</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Controls in operator language */}
      <section className="section">
        <div className="container">
          <div className="section-head">
            <h2>{t.operatorHead}</h2>
          </div>
          <dl className="deflist">
            {t.operatorList.map((item) => (
              <div key={item.dt}>
                <dt>{item.dt}</dt>
                <dd>{item.dd}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      {/* Threat model */}
      <section className="section dark">
        <div className="container">
          <div className="section-head">
            <h2>
              {locale === "fr" ? (
                <>
                  <span className="kind">Modèle de menace.</span> Honnêtement
                </>
              ) : (
                <>
                  <span className="kind">Threat model.</span> Honestly
                </>
              )}
            </h2>
            <p className="lede">{t.threatLede}</p>
          </div>
          <div className="split split-start">
            <div>
              <h3>{t.protectsHead}</h3>
              <dl className="deflist">
                {t.protects.map((item) => (
                  <div key={item.dt}>
                    <dt>{item.dt}</dt>
                    <dd>{item.dd}</dd>
                  </div>
                ))}
              </dl>
              <p
                className="small mt-3"
                style={{ color: "var(--sid-on-dark-3)" }}
              >
                {t.redTeamNote}
              </p>
            </div>
            <div>
              <h3>{t.doesNotHead}</h3>
              <dl className="deflist">
                {t.doesNot.map((item) => (
                  <div key={item.dt}>
                    <dt>{item.dt}</dt>
                    <dd>{item.dd}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
          <div className="notice mt-4">{t.validatorsNotice}</div>
        </div>
      </section>

      {/* Evidence details */}
      <section className="section">
        <div className="container">
          <div className="split split-start">
            <div>
              <h2>{t.proofHead}</h2>
              <p className="lede">{t.proofLede}</p>
              <p>{t.proofP}</p>
              <p className="mt-3">
                <Link href={localeHref(locale, "/auditability")}>
                  {t.auditLink}
                </Link>
              </p>
            </div>
            <div className="panel panel-soft">
              <h3>{t.integrationHead}</h3>
              <p className="small muted">{t.integrationLede}</p>
              <ul className="plan-list">
                {t.integration.map((line) => (
                  <li className="small muted" key={line}>
                    {line}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="section section-cloud center">
        <div className="container">
          <h2 style={{ maxWidth: "34rem", marginInline: "auto" }}>
            {t.ctaHead}
          </h2>
          <div className="cta-row mt-3" style={{ justifyContent: "center" }}>
            <Link
              className="btn btn-primary"
              href={localeHref(locale, "/early-access")}
            >
              {t.ctaPrimary}{" "}
              <span className="arrow" aria-hidden="true">
                →
              </span>
            </Link>
            <Link
              className="btn btn-secondary"
              href={localeHref(locale, "/compliance")}
            >
              {t.ctaSecondary}
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
