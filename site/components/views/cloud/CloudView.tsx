import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";

import { T } from "./copy";
export default function CloudView({ locale }: { locale: Locale }) {
  const t = T[locale];
  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">{t.lede}</p>
          <p className="mt-3">
            <span className="chip chip-later">{t.chipLater}</span>
          </p>
        </div>
      </section>

      <section className="section section-cloud">
        <div className="container">
          <div className="section-head">
            <h2>
              <span className="kind">{t.portableKind}</span> {t.portableH2}
            </h2>
            <p className="lede">{t.portableLede}</p>
          </div>
          <div className="contrast-pair">
            <div className="panel">
              <p>
                <span className="chip chip-ea">{t.nowChip}</span>
              </p>
              <ul className="plan-list">
                <li className="small muted">{t.nowItem1}</li>
                <li className="small muted">{t.nowItem2}</li>
                <li className="small muted">{t.nowItem3}</li>
                <li className="small muted">{t.nowItem4}</li>
              </ul>
            </div>
            <div className="panel">
              <p>
                <span className="chip chip-later">{t.laterChip}</span>
              </p>
              <ul className="plan-list">
                <li className="small muted">{t.laterItem1}</li>
                <li className="small muted">{t.laterItem2}</li>
                <li className="small muted">{t.laterItem3}</li>
                <li className="small muted">{t.laterItem4}</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="section-head">
            <h2>
              <span className="kind">{t.addKind}</span> {t.addH2}
            </h2>
          </div>
          <dl className="deflist">
            <div>
              <dt>{t.dtHosted}</dt>
              <dd>{t.ddHosted}</dd>
            </div>
            <div>
              <dt>{t.dtSchedules}</dt>
              <dd>{t.ddSchedules}</dd>
            </div>
            <div>
              <dt>{t.dtModels}</dt>
              <dd>{t.ddModels}</dd>
            </div>
            <div>
              <dt>{t.dtTeam}</dt>
              <dd>{t.ddTeam}</dd>
            </div>
            <div>
              <dt>{t.dtPolicies}</dt>
              <dd>{t.ddPolicies}</dd>
            </div>
            <div>
              <dt>{t.dtGovernance}</dt>
              <dd>{t.ddGovernance}</dd>
            </div>
            <div>
              <dt>{t.dtSecrets}</dt>
              <dd>{t.ddSecrets}</dd>
            </div>
          </dl>
          <p className="notice mt-4">
            <strong>{t.noticeStrong}</strong>
            {t.noticeBody}
          </p>
        </div>
      </section>

      <section className="section dark center">
        <div className="container">
          <h2 style={{ maxWidth: "36rem", marginInline: "auto" }}>
            {t.closingH2}
          </h2>
          <p className="lede" style={{ margin: "1rem auto 2rem" }}>
            {t.closingLede}
          </p>
          <div className="cta-row" style={{ justifyContent: "center" }}>
            <Link className="btn btn-primary" href={localeHref(locale, "/early-access")}>
              {t.cta}{" "}
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
