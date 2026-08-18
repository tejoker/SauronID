import Link from "next/link";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function Gate({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["finalCta"] }) {
  return (
    <section className="section dark center">
      <div className="container">
        <h2 style={{ maxWidth: "36rem", marginInline: "auto" }}>{t.h2}</h2>
        <p className="lede" style={{ margin: "1rem auto 2rem" }}>
          {t.lede}
        </p>
        <div className="cta-row" style={{ justifyContent: "center" }}>
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
    </section>
  );
}
