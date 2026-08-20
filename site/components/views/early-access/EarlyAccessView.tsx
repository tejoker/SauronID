import Link from "next/link";
import Image from "next/image";
import EarlyAccessForm from "@/components/interactive/EarlyAccessForm";
import logo from "@/public/sauronid-logo.png";
import type { Locale } from "@/lib/i18n";
import { localeHref } from "@/lib/i18n";

import { T } from "./copy";
export default function EarlyAccessView({ locale }: { locale: Locale }) {
  const t = T[locale];
  return (
    <>
      <section className="page-hero">
        <div className="container">
          <h1>{t.h1}</h1>
          <p className="lede">{t.lede}</p>
          <p className="mt-3">
            <span className="chip chip-ea">{t.chipEa}</span>
          </p>
        </div>
      </section>

      {/* What the path looks like */}
      <section className="section section-cloud">
        <div className="container">
          <div className="split split-start">
            <div>
              <h2>
                <span className="kind">{t.firstHourKind}</span> {t.firstHourH2}
              </h2>
              <ol className="numbered mt-3">
                <li>
                  <div>
                    <strong>{t.step1Title}</strong>
                    <span>{t.step1Body}</span>
                  </div>
                </li>
                <li>
                  <div>
                    <strong>{t.step2Title}</strong>
                    <span>{t.step2Body}</span>
                  </div>
                </li>
                <li>
                  <div>
                    <strong>{t.step3Title}</strong>
                    <span>{t.step3Body}</span>
                  </div>
                </li>
                <li>
                  <div>
                    <strong>{t.step4Title}</strong>
                    <span>{t.step4Body}</span>
                  </div>
                </li>
                <li>
                  <div>
                    <strong>{t.step5Title}</strong>
                    <span>{t.step5Body}</span>
                  </div>
                </li>
                <li>
                  <div>
                    <strong>{t.step6Title}</strong>
                    <span>{t.step6Body}</span>
                  </div>
                </li>
                <li>
                  <div>
                    <strong>{t.step7Title}</strong>
                    <span>{t.step7Body}</span>
                  </div>
                </li>
              </ol>
            </div>
            <div>
              <div className="window">
                <div className="window-bar">
                  <span className="title">
                    <Image src={logo} alt="" width={18} height={18} />
                    {t.windowTitle}
                  </span>
                  <span className="status status-running">{t.windowStatus}</span>
                </div>
                <div className="window-body">
                  <div className="agent-field">
                    <div className="label">{t.fieldLabel}</div>
                    <div className="value">{t.fieldValue}</div>
                  </div>
                  <div className="boundary-list">
                    <div className="boundary boundary-allowed">
                      <span className="rule">{t.boundaryLocal}</span>
                      <span className="val">{t.boundaryLocalVal}</span>
                    </div>
                    <div className="boundary">
                      <span className="rule">{t.boundaryAnthropic}</span>
                      <span className="val">{t.boundaryAnthropicVal}</span>
                    </div>
                    <div className="boundary">
                      <span className="rule">{t.boundaryOpenai}</span>
                      <span className="val">{t.boundaryOpenaiVal}</span>
                    </div>
                  </div>
                  <p className="small faint mt-2">{t.keyNote}</p>
                </div>
              </div>
              <p className="small faint mt-2">{t.mockNote}</p>
            </div>
          </div>
        </div>
      </section>

      {/* Today vs coming */}
      <section className="section">
        <div className="container">
          <div className="section-head">
            <h2>
              <span className="kind">{t.existsKind}</span> {t.existsH2}
            </h2>
            <p className="lede">{t.existsLede}</p>
          </div>
          <div className="contrast-pair">
            <div className="panel">
              <p>
                <span className="chip chip-now">{t.chipNow}</span>
              </p>
              <ul className="plan-list">
                <li className="small muted">{t.nowItem1}</li>
                <li className="small muted">{t.nowItem2}</li>
                <li className="small muted">{t.nowItem3}</li>
              </ul>
            </div>
            <div className="panel">
              <p>
                <span className="chip chip-ea">{t.chipEa}</span>
              </p>
              <ul className="plan-list">
                <li className="small muted">{t.eaItem1}</li>
                <li className="small muted">{t.eaItem2}</li>
                <li className="small muted">{t.eaItem3}</li>
              </ul>
            </div>
          </div>
          <p className="notice mt-3">
            <strong>{t.noticeStrong}</strong>
            {t.noticeBody}
            <Link href={localeHref(locale, "/cloud")}>{t.noticeLink}</Link>
          </p>
        </div>
      </section>

      {/* The form */}
      <section className="section section-cloud" id="join">
        <div className="container">
          <div className="split split-start">
            <div>
              <h2>
                <span className="kind">{t.joinKind}</span> {t.joinH2}
              </h2>
              <p className="lede">{t.joinLede}</p>
              <p className="small muted">{t.joinNote}</p>
            </div>
            <EarlyAccessForm locale={locale} />
          </div>
        </div>
      </section>
    </>
  );
}
