import Link from "next/link";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function Faq({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["faq"] }) {
  return (
    <section className="section section-cloud">
      <div className="container">
        <div className="section-head">
          <h2>{t.h2}</h2>
        </div>
        <div className="faq faq-wide">
          <details>
            <summary>{t.items[0].q}</summary>
            <div className="faq-a">
              <p>{t.items[0].a}</p>
            </div>
          </details>
          <details>
            <summary>{t.items[1].q}</summary>
            <div className="faq-a">
              <p>
                {t.items[1].aBefore}{" "}
                <Link href={localeHref(locale, "/security")}>{t.items[1].link}</Link>
              </p>
            </div>
          </details>
          <details>
            <summary>{t.items[2].q}</summary>
            <div className="faq-a">
              <p>{t.items[2].a}</p>
            </div>
          </details>
          <details>
            <summary>{t.items[3].q}</summary>
            <div className="faq-a">
              <p>{t.items[3].a}</p>
            </div>
          </details>
          <details>
            <summary>{t.items[4].q}</summary>
            <div className="faq-a">
              <p>
                {t.items[4].aBefore}{" "}
                <Link href={localeHref(locale, "/pricing")}>{t.items[4].link}</Link>
              </p>
            </div>
          </details>
          <details>
            <summary>{t.items[5].q}</summary>
            <div className="faq-a">
              <p>{t.items[5].a}</p>
            </div>
          </details>
          <details>
            <summary>{t.items[6].q}</summary>
            <div className="faq-a">
              <p>
                {t.items[6].aBefore}{" "}
                <Link href={localeHref(locale, "/compliance")}>{t.items[6].link}</Link>
              </p>
            </div>
          </details>
        </div>
      </div>
    </section>
  );
}
