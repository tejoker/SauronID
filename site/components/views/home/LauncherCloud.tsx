import Link from "next/link";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function LauncherCloud({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["launcher"] }) {
  return (
    <section className="section">
      <div className="container">
        <div className="section-head">
          <h2>{t.h2}</h2>
          <p className="lede">{t.lede}</p>
        </div>
        <div className="split split-stretch">
          <div className="panel">
            <p>
              <span className="chip chip-ea">{t.launcherPanel.chip}</span>
            </p>
            <h3 className="mt-2">{t.launcherPanel.h3}</h3>
            <ul className="plan-list">
              {t.launcherPanel.items.map((item) => (
                <li className="small muted" key={item}>
                  {item}
                </li>
              ))}
            </ul>
            <div className="cta-row mt-3">
              <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
                {t.launcherPanel.cta}
              </Link>
            </div>
          </div>
          <div className="panel">
            <p>
              <span className="chip chip-later">{t.cloudPanel.chip}</span>
            </p>
            <h3 className="mt-2">{t.cloudPanel.h3}</h3>
            <ul className="plan-list">
              {t.cloudPanel.items.map((item) => (
                <li className="small muted" key={item}>
                  {item}
                </li>
              ))}
            </ul>
            <div className="cta-row mt-3">
              <Link className="btn btn-secondary" href={localeHref(locale, "/cloud")}>
                {t.cloudPanel.cta}
              </Link>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
