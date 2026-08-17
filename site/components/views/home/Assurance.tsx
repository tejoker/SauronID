import type { Locale } from "@/lib/i18n";
import type { T } from "./copy";

export default function Assurance({ t }: { t: (typeof T)[Locale]["assurance"] }) {
  return (
    <section className="section-cloud">
      <div className="container assurance">
        <div className="assurance-item">
          <svg className="emblem" viewBox="0 0 44 44" fill="currentColor" aria-hidden="true">
            <circle cx="22" cy="22" r="21" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <polygon points="22.00,5.40 22.42,6.42 23.52,6.51 22.68,7.22 22.94,8.29 22.00,7.72 21.06,8.29 21.32,7.22 20.48,6.51 21.58,6.42" />
              <polygon points="29.50,7.41 29.92,8.43 31.02,8.52 30.18,9.23 30.44,10.30 29.50,9.73 28.56,10.30 28.82,9.23 27.98,8.52 29.08,8.43" />
              <polygon points="34.99,12.90 35.41,13.92 36.51,14.01 35.68,14.72 35.93,15.79 34.99,15.22 34.05,15.79 34.31,14.72 33.47,14.01 34.57,13.92" />
              <polygon points="37.00,20.40 37.42,21.42 38.52,21.51 37.68,22.22 37.94,23.29 37.00,22.72 36.06,23.29 36.32,22.22 35.48,21.51 36.58,21.42" />
              <polygon points="34.99,27.90 35.41,28.92 36.51,29.01 35.68,29.72 35.93,30.79 34.99,30.22 34.05,30.79 34.31,29.72 33.47,29.01 34.57,28.92" />
              <polygon points="29.50,33.39 29.92,34.41 31.02,34.50 30.18,35.21 30.44,36.28 29.50,35.71 28.56,36.28 28.82,35.21 27.98,34.50 29.08,34.41" />
              <polygon points="22.00,35.40 22.42,36.42 23.52,36.51 22.68,37.22 22.94,38.29 22.00,37.72 21.06,38.29 21.32,37.22 20.48,36.51 21.58,36.42" />
              <polygon points="14.50,33.39 14.92,34.41 16.02,34.50 15.18,35.21 15.44,36.28 14.50,35.71 13.56,36.28 13.82,35.21 12.98,34.50 14.08,34.41" />
              <polygon points="9.01,27.90 9.43,28.92 10.53,29.01 9.69,29.72 9.95,30.79 9.01,30.22 8.07,30.79 8.32,29.72 7.49,29.01 8.59,28.92" />
              <polygon points="7.00,20.40 7.42,21.42 8.52,21.51 7.68,22.22 7.94,23.29 7.00,22.72 6.06,23.29 6.32,22.22 5.48,21.51 6.58,21.42" />
              <polygon points="9.01,12.90 9.43,13.92 10.53,14.01 9.69,14.72 9.95,15.79 9.01,15.22 8.07,15.79 8.32,14.72 7.49,14.01 8.59,13.92" />
              <polygon points="14.50,7.41 14.92,8.43 16.02,8.52 15.18,9.23 15.44,10.30 14.50,9.73 13.56,10.30 13.82,9.23 12.98,8.52 14.08,8.43" />
            <text x="22" y="26" textAnchor="middle" className="emblem-text">GDPR</text>
          </svg>
          <span>
            <span className="a-name">{t[0].name}</span>
            <br />
            <span className="a-sub">{t[0].sub}</span>
          </span>
        </div>
        <div className="assurance-item">
          <svg className="emblem" viewBox="0 0 44 44" fill="currentColor" aria-hidden="true">
            <circle cx="22" cy="22" r="21" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <polygon points="22.00,5.40 22.42,6.42 23.52,6.51 22.68,7.22 22.94,8.29 22.00,7.72 21.06,8.29 21.32,7.22 20.48,6.51 21.58,6.42" />
              <polygon points="29.50,7.41 29.92,8.43 31.02,8.52 30.18,9.23 30.44,10.30 29.50,9.73 28.56,10.30 28.82,9.23 27.98,8.52 29.08,8.43" />
              <polygon points="34.99,12.90 35.41,13.92 36.51,14.01 35.68,14.72 35.93,15.79 34.99,15.22 34.05,15.79 34.31,14.72 33.47,14.01 34.57,13.92" />
              <polygon points="37.00,20.40 37.42,21.42 38.52,21.51 37.68,22.22 37.94,23.29 37.00,22.72 36.06,23.29 36.32,22.22 35.48,21.51 36.58,21.42" />
              <polygon points="34.99,27.90 35.41,28.92 36.51,29.01 35.68,29.72 35.93,30.79 34.99,30.22 34.05,30.79 34.31,29.72 33.47,29.01 34.57,28.92" />
              <polygon points="29.50,33.39 29.92,34.41 31.02,34.50 30.18,35.21 30.44,36.28 29.50,35.71 28.56,36.28 28.82,35.21 27.98,34.50 29.08,34.41" />
              <polygon points="22.00,35.40 22.42,36.42 23.52,36.51 22.68,37.22 22.94,38.29 22.00,37.72 21.06,38.29 21.32,37.22 20.48,36.51 21.58,36.42" />
              <polygon points="14.50,33.39 14.92,34.41 16.02,34.50 15.18,35.21 15.44,36.28 14.50,35.71 13.56,36.28 13.82,35.21 12.98,34.50 14.08,34.41" />
              <polygon points="9.01,27.90 9.43,28.92 10.53,29.01 9.69,29.72 9.95,30.79 9.01,30.22 8.07,30.79 8.32,29.72 7.49,29.01 8.59,28.92" />
              <polygon points="7.00,20.40 7.42,21.42 8.52,21.51 7.68,22.22 7.94,23.29 7.00,22.72 6.06,23.29 6.32,22.22 5.48,21.51 6.58,21.42" />
              <polygon points="9.01,12.90 9.43,13.92 10.53,14.01 9.69,14.72 9.95,15.79 9.01,15.22 8.07,15.79 8.32,14.72 7.49,14.01 8.59,13.92" />
              <polygon points="14.50,7.41 14.92,8.43 16.02,8.52 15.18,9.23 15.44,10.30 14.50,9.73 13.56,10.30 13.82,9.23 12.98,8.52 14.08,8.43" />
            <text x="22" y="24" textAnchor="middle" className="emblem-text emblem-text-sm">AI</text>
            <text x="22" y="30" textAnchor="middle" className="emblem-text emblem-text-xs">ACT</text>
          </svg>
          <span>
            <span className="a-name">{t[1].name}</span>
            <br />
            <span className="a-sub">{t[1].sub}</span>
          </span>
        </div>
        <div className="assurance-item">
          <svg className="emblem" viewBox="0 0 44 44" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="22" cy="22" r="21" strokeWidth="1.5" />
            <rect x="14" y="20" width="16" height="11" rx="2.5" />
            <path d="M17.5 20v-3a4.5 4.5 0 019 0v3" />
          </svg>
          <span>
            <span className="a-name">{t[2].name}</span>
            <br />
            <span className="a-sub">{t[2].sub}</span>
          </span>
        </div>
        <div className="assurance-item">
          <svg className="emblem" viewBox="0 0 44 44" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="22" cy="22" r="21" strokeWidth="1.5" />
            <path d="M14 27.5V18l8-4.5 8 4.5v9.5l-8 4.5z" />
            <path d="M14 18l8 4.5 8-4.5M22 22.5v9" />
          </svg>
          <span>
            <span className="a-name">{t[3].name}</span>
            <br />
            <span className="a-sub">{t[3].sub}</span>
          </span>
        </div>
        <div className="assurance-item">
          <svg className="emblem" viewBox="0 0 44 44" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="22" cy="22" r="21" strokeWidth="1.5" />
            <path d="M17 15l-6 7 6 7M27 15l6 7-6 7" />
          </svg>
          <span>
            <span className="a-name">{t[4].name}</span>
            <br />
            <span className="a-sub">{t[4].sub}</span>
          </span>
        </div>
      </div>
    </section>
  );
}
