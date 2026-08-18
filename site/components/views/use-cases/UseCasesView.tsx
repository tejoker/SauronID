import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";

import { T, SCENARIOS_EN, SCENARIOS_FR } from "./copy";
export default function UseCasesView({ locale }: { locale: Locale }) {
  const t = T[locale];
  const scenarios = locale === "fr" ? SCENARIOS_FR : SCENARIOS_EN;
  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">{t.lede}</p>
        </div>
      </section>

      <section className="section-tight section-cloud">
        <div className="container">
          <div className="plans" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(22rem, 1fr))" }}>
            {scenarios.map((scenario) => (
              <article className="usecase" key={scenario.title}>
                <span className="u-for">
                  {t.forLabel} {scenario.team.toLowerCase()}
                </span>
                <h3>{scenario.title}</h3>
                <p className="u-benefit">{scenario.benefit}</p>
                <div className="boundary-list">
                  {scenario.rules.map((rule) => (
                    <div className={`boundary boundary-${rule.kind}`} key={rule.rule}>
                      <span className="rule">{rule.rule}</span>
                      <span className="val">{rule.val}</span>
                    </div>
                  ))}
                </div>
                <p className="small muted" style={{ marginTop: "0.25rem" }}>
                  {scenario.why}
                </p>
              </article>
            ))}
          </div>
          <p className="small faint mt-3">{t.gridFootnote}</p>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="split split-start">
            <div>
              <h2>
                <span className="kind">{t.whyKind}</span> {t.whyH2}
              </h2>
              <p>{t.whyBody1}</p>
              <p>{t.whyBody2}</p>
            </div>
            <div>
              <h2>
                <span className="kind">{t.startKind}</span> {t.startH2}
              </h2>
              <p>{t.startBody}</p>
              <div className="cta-row mt-3">
                <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
                  {t.ctaPrimary}{" "}
                  <span className="arrow" aria-hidden="true">
                    →
                  </span>
                </Link>
                <Link className="btn btn-secondary" href={localeHref(locale, "/security")}>
                  {t.ctaSecondary}
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
