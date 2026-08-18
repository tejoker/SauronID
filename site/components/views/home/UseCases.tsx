import Link from "next/link";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function UseCases({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["useCases"] }) {
  return (
    <section className="section section-cloud">
      <div className="container">
        <div className="section-head">
          <h2>{t.h2}</h2>
          <p className="lede">{t.lede}</p>
        </div>
        <div className="plans">
          {t.items.map((item) => (
            <article className="usecase" key={item.h3}>
              <span className="u-for">{item.for}</span>
              <h3>{item.h3}</h3>
              <p className="u-benefit">{item.benefit}</p>
              <div className="boundary-list">
                <div className="boundary boundary-allowed">
                  <span className="rule">{item.boundaries[0].rule}</span>
                  <span className="val">{item.boundaries[0].val}</span>
                </div>
                <div className="boundary boundary-review">
                  <span className="rule">{item.boundaries[1].rule}</span>
                  <span className="val">{item.boundaries[1].val}</span>
                </div>
                <div className="boundary boundary-stopped">
                  <span className="rule">{item.boundaries[2].rule}</span>
                  <span className="val">{item.boundaries[2].val}</span>
                </div>
              </div>
            </article>
          ))}
        </div>
        <div className="cta-row mt-4">
          <Link className="btn btn-secondary" href={localeHref(locale, "/use-cases")}>
            {t.ctaExplore}{" "}
            <span className="arrow" aria-hidden="true">
              →
            </span>
          </Link>
          <span className="small faint">{t.note}</span>
        </div>
      </div>
    </section>
  );
}
