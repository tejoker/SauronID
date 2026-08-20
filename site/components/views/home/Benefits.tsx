import type { Locale } from "@/lib/i18n";
import type { T } from "./copy";

export default function Benefits({ t }: { t: (typeof T)[Locale]["benefits"] }) {
  return (
    <section>
      <div className="container benefits">
        <div className="benefit">
          <span className="benefit-icon" aria-hidden="true">
            <svg viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="16" height="16" rx="4.5" />
              <circle cx="11" cy="11" r="2.6" />
            </svg>
          </span>
          <strong>{t[0].title}</strong>
          <p>{t[0].text}</p>
        </div>
        <div className="benefit">
          <span className="benefit-icon" aria-hidden="true">
            <svg viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M6 3.5h7.5l4 4V18.5a1.2 1.2 0 01-1.2 1.2H6a1.2 1.2 0 01-1.2-1.2V4.7A1.2 1.2 0 016 3.5z" />
              <path d="M13.5 3.5v4h4" />
              <path d="M8 12h6M8 15.2h4" />
            </svg>
          </span>
          <strong>{t[1].title}</strong>
          <p>{t[1].text}</p>
        </div>
        <div className="benefit">
          <span className="benefit-icon" aria-hidden="true">
            <svg viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="2.4" />
              <circle cx="4.5" cy="5" r="1.9" />
              <circle cx="17.5" cy="5" r="1.9" />
              <circle cx="11" cy="18.2" r="1.9" />
              <path d="M6 6.3l3.1 2.9M16 6.3l-3.1 2.9M11 13.4v2.9" />
            </svg>
          </span>
          <strong>{t[2].title}</strong>
          <p>{t[2].text}</p>
        </div>
      </div>
    </section>
  );
}
