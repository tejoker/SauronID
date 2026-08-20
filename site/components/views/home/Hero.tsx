import Link from "next/link";
import Image from "next/image";
import logo from "@/public/sauronid-logo.png";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function Hero({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["hero"] }) {
  return (
    <section className="hero">
      <div className="container hero-grid">
        <div>
          <h1>
            {t.h1First}&nbsp;{t.h1Last}
          </h1>
          <p className="lede">{t.lede}</p>
          <div className="cta-row">
            <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
              {t.ctaPrimary}{" "}
              <span className="arrow" aria-hidden="true">
                →
              </span>
            </Link>
            <a className="btn btn-secondary" href="#path">
              {t.ctaSecondary}
            </a>
          </div>
        </div>
        <div className="hero-visual">
          <div className="window">
            <div className="window-bar">
              <span className="title">
                <Image src={logo} alt="" width={18} height={18} />
                {t.windowTitle}
              </span>
              <span className="status status-running">{t.status}</span>
            </div>
            <div className="window-body">
              <div className="agent-field">
                <div className="label">{t.jobLabel}</div>
                <div className="value">{t.jobValue}</div>
              </div>
              <div className="agent-field">
                <div className="label">{t.capabilitiesLabel}</div>
                <div className="pills">
                  {t.pills.map((pill) => (
                    <span className="pill" key={pill}>
                      {pill}
                    </span>
                  ))}
                </div>
              </div>
              <div className="agent-field">
                <div className="label">{t.boundariesLabel}</div>
                <div className="boundary-list">
                  {t.boundaries.map((boundary, index) => (
                    <div
                      className={`boundary${index === 1 ? " boundary-review" : index === 2 ? " boundary-stopped" : ""}`}
                      key={boundary.rule}
                    >
                      <span className="rule">{boundary.rule}</span>
                      <span className="val">{boundary.val}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
