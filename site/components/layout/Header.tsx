"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Image from "next/image";
import { usePathname, useRouter } from "next/navigation";
import logo from "@/public/sauronid-logo.png";
import {
  LOCALES,
  LOCALE_NAMES,
  type Locale,
  basePathname,
  localeFromPathname,
  localeHref,
  matchBrowserLocale,
} from "@/lib/i18n";

const LOCALE_STORAGE_KEY = "sid-locale";

const NAV_LABELS: Record<Locale, { href: string; label: string }[]> = {
  en: [
    { href: "/", label: "Product" },
    { href: "/security", label: "Security" },
    { href: "/compliance", label: "Compliance" },
    { href: "/auditability", label: "Auditability" },
    { href: "/pricing", label: "Pricing" },
  ],
  fr: [
    { href: "/", label: "Produit" },
    { href: "/security", label: "Sécurité" },
    { href: "/compliance", label: "Conformité" },
    { href: "/auditability", label: "Auditabilité" },
    { href: "/pricing", label: "Tarifs" },
  ],
};

const CTA_LABEL: Record<Locale, string> = {
  en: "Get early access",
  fr: "Obtenir l'accès anticipé",
};

function isCurrent(basePath: string, href: string): boolean {
  if (href === "/") return basePath === "/";
  return basePath === href || basePath.startsWith(href + "/");
}

export default function Header() {
  const [isOpen, setIsOpen] = useState(false);
  const [isLangOpen, setIsLangOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const locale = localeFromPathname(pathname);
  const basePath = basePathname(pathname);

  useEffect(() => {
    const onScroll = () => setIsScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  /* Every page change lands at the very top (anchor links keep their target). */
  useEffect(() => {
    if (!window.location.hash) {
      window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    }
  }, [pathname]);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  /* First visit: follow the browser language once, then respect the choice. */
  useEffect(() => {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (stored) return;
    const preferred = matchBrowserLocale(navigator.language || "");
    if (preferred !== locale) {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, preferred);
      router.replace(localeHref(preferred, basePath));
    } else {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!isLangOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!(event.target as Element | null)?.closest(".lang-menu")) {
        setIsLangOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setIsLangOpen(false);
    };
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isLangOpen]);

  function switchTo(target: Locale) {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, target);
    setIsLangOpen(false);
  }

  return (
    <header className={`site-header${isScrolled ? " scrolled" : ""}`}>
      <div className="container">
        <Link className="brand" href={localeHref(locale, "/")}>
          <Image src={logo} alt="" width={30} height={30} />
          SauronID
        </Link>
        <button
          className="nav-toggle"
          aria-expanded={isOpen}
          aria-controls="site-nav"
          aria-label="Menu"
          onClick={() => setIsOpen((open) => !open)}
        >
          <svg
            viewBox="0 0 20 20"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            aria-hidden="true"
          >
            <path d="M3 5.5h14M3 10h14M3 14.5h14" />
          </svg>
        </button>
        <nav
          className={`site-nav${isOpen ? " open" : ""}`}
          id="site-nav"
          aria-label="Main"
          onClick={() => setIsOpen(false)}
        >
          {NAV_LABELS[locale].map((item) => (
            <Link
              key={item.href}
              href={localeHref(locale, item.href)}
              aria-current={isCurrent(basePath, item.href) ? "page" : undefined}
            >
              {item.label}
            </Link>
          ))}
          <div className="lang-menu">
            <button
              type="button"
              className="lang-button"
              aria-haspopup="menu"
              aria-expanded={isLangOpen}
              aria-label={locale === "fr" ? "Changer de langue" : "Change language"}
              onClick={(event) => {
                event.stopPropagation();
                setIsLangOpen((open) => !open);
              }}
            >
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" aria-hidden="true">
                <circle cx="8" cy="8" r="6.5" />
                <ellipse cx="8" cy="8" rx="3" ry="6.5" />
                <path d="M1.8 5.8h12.4M1.8 10.2h12.4" />
              </svg>
              {locale.toUpperCase()}
              <svg className="chev" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M2.5 3.8L5 6.4l2.5-2.6" />
              </svg>
            </button>
            {isLangOpen && (
              <div className="lang-list" role="menu">
                {LOCALES.map((option) => (
                  <Link
                    key={option}
                    role="menuitem"
                    href={localeHref(option, basePath)}
                    aria-current={option === locale ? "true" : undefined}
                    onClick={() => switchTo(option)}
                  >
                    {LOCALE_NAMES[option]}
                    {option === locale && (
                      <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M2.5 6.4l2.3 2.3 4.7-5" />
                      </svg>
                    )}
                  </Link>
                ))}
              </div>
            )}
          </div>
          <Link
            className="btn btn-primary btn-sm"
            href={localeHref(locale, "/early-access")}
            aria-current={
              isCurrent(basePath, "/early-access") ? "page" : undefined
            }
          >
            {CTA_LABEL[locale]}
          </Link>
        </nav>
      </div>
    </header>
  );
}
