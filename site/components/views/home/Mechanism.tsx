import Link from "next/link";
import RingSeal from "@/components/interactive/RingSeal";
import { type Locale, localeHref } from "@/lib/i18n";
import type { T } from "./copy";

export default function Mechanism({ locale, t }: { locale: Locale; t: (typeof T)[Locale]["mechanism"] }) {
  return (
    <section className="section">
      <div className="container">
        <div className="split">
          <div>
            <h2>{t.h2}</h2>
            <p className="lede">{t.lede}</p>
            <div className="proof-points-light mt-3">
              {t.points.map((point) => (
                <div className="proof-point" key={point.title}>
                  <strong>{point.title}</strong>
                  <span>{point.text}</span>
                </div>
              ))}
            </div>
            <p className="mt-3">
              <Link href={localeHref(locale, "/security")}>{t.link}</Link>
            </p>
          </div>
          <RingSeal locale={locale} />
        </div>
      </div>
    </section>
  );
}
