import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";

import { T } from "./copy";
export default function PricingView({ locale }: { locale: Locale }) {
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
          <div className="plans">
            <article className="plan featured">
              <p>
                <span className="chip chip-ea">{t.chipEa}</span>
              </p>
              <h3>{t.planLocal}</h3>
              <p className="price">{t.priceFree}</p>
              <p className="small muted">{t.localDesc}</p>
              <ul>
                <li>{t.localItem1}</li>
                <li>{t.localItem2}</li>
                <li>{t.localItem3}</li>
                <li>{t.localItem4}</li>
                <li>{t.localItem5}</li>
              </ul>
              <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
                {t.ctaLocal}
              </Link>
            </article>
            <article className="plan">
              <p>
                <span className="chip chip-later">{t.chipLater}</span>
              </p>
              <h3>{t.planCloud}</h3>
              <p className="price">{t.priceCloud}</p>
              <p className="small muted">{t.cloudDesc}</p>
              <ul>
                <li className="muted">{t.cloudItem1}</li>
                <li className="muted">{t.cloudItem2}</li>
                <li className="muted">{t.cloudItem3}</li>
                <li className="muted">{t.cloudItem4}</li>
              </ul>
              <Link className="btn btn-secondary" href={localeHref(locale, "/cloud")}>
                {t.ctaCloud}
              </Link>
            </article>
            <article className="plan">
              <p>
                <span className="chip chip-later">{t.chipLater}</span>
              </p>
              <h3>{t.planTeams}</h3>
              <p className="price">{t.priceTeams}</p>
              <p className="small muted">{t.teamsDesc}</p>
              <ul>
                <li className="muted">{t.teamsItem1}</li>
                <li className="muted">{t.teamsItem2}</li>
                <li className="muted">{t.teamsItem3}</li>
                <li className="muted">{t.teamsItem4}</li>
              </ul>
              <a
                className="btn btn-secondary"
                href="mailto:nicolas@eurotech-federation.com?subject=SauronID%20teams"
              >
                {t.ctaTeams}
              </a>
            </article>
          </div>
          <p className="small faint mt-4">{t.footnote}</p>
        </div>
      </section>

      <section className="section center">
        <div className="container">
          <h2 style={{ maxWidth: "34rem", marginInline: "auto" }}>
            <span className="kind">{t.closingKind}</span> {t.closingH2}
          </h2>
          <div className="cta-row mt-3" style={{ justifyContent: "center" }}>
            <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
              {t.ctaFinal}{" "}
              <span className="arrow" aria-hidden="true">
                →
              </span>
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
