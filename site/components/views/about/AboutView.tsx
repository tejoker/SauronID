import Link from "next/link";
import { type Locale, localeHref } from "@/lib/i18n";

import { T } from "./copy";
export default function AboutView({ locale }: { locale: Locale }) {
  const t = T[locale];
  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">{t.lede}</p>
        </div>
      </section>

      <section className="section section-cloud">
        <div className="container">
          <div className="split split-start">
            <div>
              <h2>
                <span className="kind">{t.whatKind}</span> {t.whatTitle}
              </h2>
              <p className="lede">{t.what1}</p>
              <p>{t.what2}</p>
            </div>
            <div>
              <h2>
                <span className="kind">{t.whyKind}</span> {t.whyTitle}
              </h2>
              <p className="lede">{t.why1}</p>
              <p>{t.why2}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="section-head">
            <h2>{t.believeTitle}</h2>
          </div>
          <div className="proof-points-light proof-points-grid">
            {t.beliefs.map((belief) => (
              <div className="proof-point" key={belief.title}>
                <strong>{belief.title}</strong>
                <span>{belief.text}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section dark section-gate">
        <div className="container">
          <h2>
            <span className="kind">{t.todayKind}</span> {t.todayTitle}
          </h2>
          <p className="lede">{t.today1}</p>
          <p>{t.today2}</p>
          <div className="cta-row mt-4">
            <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
              {t.cta}{" "}
              <span className="arrow" aria-hidden="true">
                →
              </span>
            </Link>
            <Link className="btn btn-secondary" href={localeHref(locale, "/")}>
              {t.cta2}
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
