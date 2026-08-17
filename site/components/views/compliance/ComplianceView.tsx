import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";
import MapTable from "@/components/ui/MapTable";

import { T } from "./copy";
export default function ComplianceView({ locale }: { locale: Locale }) {
  const t = T[locale];

  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">
            {t.ledeParts.pre}
            <strong>{t.ledeParts.controls}</strong>
            {t.ledeParts.mid}
            <strong>{t.ledeParts.evidence}</strong>
            {t.ledeParts.post}
          </p>
          <p className="cta-row mt-3">
            <span className="chip chip-now">{t.chipGdpr}</span>
            <span className="chip chip-now">{t.chipAiAct}</span>
            <span className="chip chip-later">{t.chipNoCert}</span>
          </p>
        </div>
      </section>

      {/* The five questions */}
      <section className="section section-cloud">
        <div className="container">
          <div className="section-head">
            <h2>
              {locale === "fr" ? (
                <>
                  <span className="kind">Preuve.</span> Les questions
                  auxquelles votre organisation doit pouvoir répondre
                </>
              ) : (
                <>
                  <span className="kind">Evidence.</span> The questions your
                  organisation must be able to answer
                </>
              )}
            </h2>
            <p className="lede">{t.questionsLede}</p>
          </div>
          <MapTable headers={t.questionsHeaders} rows={[...t.questionsRows]} />
        </div>
      </section>

      {/* GDPR */}
      <section className="section" id="gdpr">
        <div className="container">
          <div className="section-head">
            <h2>
              {locale === "fr" ? (
                <>
                  <span className="kind">RGPD.</span> Une responsabilité que
                  vous pouvez démontrer
                </>
              ) : (
                <>
                  <span className="kind">GDPR.</span> Accountability you can
                  demonstrate
                </>
              )}
            </h2>
            <p className="lede">{t.gdprLede}</p>
          </div>
          <MapTable headers={t.gdprHeaders} rows={[...t.gdprRows]} />
          <p className="small faint mt-3">{t.gdprFootnote}</p>
        </div>
      </section>

      {/* EU AI Act */}
      <section className="section section-cloud" id="eu-ai-act">
        <div className="container">
          <div className="section-head">
            <h2>
              {locale === "fr" ? (
                <>
                  <span className="kind">AI Act.</span> Les thèmes de
                  gouvernance, mis en correspondance
                </>
              ) : (
                <>
                  <span className="kind">EU AI Act.</span> Governance themes,
                  mapped
                </>
              )}
            </h2>
            <p className="lede">{t.aiActLede}</p>
          </div>
          <MapTable headers={t.aiActHeaders} rows={[...t.aiActRows]} />
          <p className="small faint mt-3">
            {t.aiActFootnotePre}
            <a
              href="https://eur-lex.europa.eu/eli/reg/2024/1689/oj"
              rel="noopener"
            >
              {t.aiActFootnoteLinkLabel}
            </a>
            {t.aiActFootnotePost}
          </p>
        </div>
      </section>

      {/* Other frameworks */}
      <section className="section">
        <div className="container">
          <div className="split split-start">
            <div>
              <h2>{t.otherHead}</h2>
              <p>{t.otherP1}</p>
              <p>{t.otherP2}</p>
            </div>
            <div className="panel panel-soft">
              <h3>{t.languageHead}</h3>
              <div className="boundary-list mt-2">
                {t.languageUsed.map((rule) => (
                  <div className="boundary boundary-allowed" key={rule}>
                    <span className="rule">{rule}</span>
                    <span className="val">{t.usedLabel}</span>
                  </div>
                ))}
                {t.languageRefused.map((rule) => (
                  <div className="boundary boundary-stopped" key={rule}>
                    <span className="rule">{rule}</span>
                    <span className="val">{t.refusedLabel}</span>
                  </div>
                ))}
              </div>
              <p className="small muted mt-2">{t.languageFootnote}</p>
            </div>
          </div>
        </div>
      </section>

      {/* Why it matters commercially */}
      <section className="section dark section-gate">
        <div className="container">
          <div className="section-head">
            <h2>
              {locale === "fr" ? (
                <>
                  <span className="kind">Confiance.</span> Construit pour la
                  personne qui doit dire oui
                </>
              ) : (
                <>
                  <span className="kind">Trust.</span> Built for the person
                  who has to say yes
                </>
              )}
            </h2>
            <p className="lede">{t.commercialLede}</p>
          </div>
          <div className="proof-points proof-points-grid">
            {t.proofPoints.map((point) => (
              <div className="proof-point" key={point.strong}>
                <strong>{point.strong}</strong>
                <span>{point.span}</span>
              </div>
            ))}
          </div>
          <div className="cta-row mt-4">
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
              href={localeHref(locale, "/auditability")}
            >
              {t.ctaSecondary}
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
