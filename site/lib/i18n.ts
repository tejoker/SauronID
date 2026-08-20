export const LOCALES = ["en", "fr"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

/** Native display names, used by the language menu. */
export const LOCALE_NAMES: Record<Locale, string> = {
  en: "English",
  fr: "Français",
};

const PREFIXED = LOCALES.filter((locale) => locale !== DEFAULT_LOCALE);

/** The default locale lives at the root; others are prefixed (/fr/...). */
export function localeFromPathname(pathname: string): Locale {
  for (const locale of PREFIXED) {
    if (pathname === `/${locale}` || pathname.startsWith(`/${locale}/`)) {
      return locale;
    }
  }
  return DEFAULT_LOCALE;
}

/** Strip any locale prefix, returning the canonical path. */
export function basePathname(pathname: string): string {
  for (const locale of PREFIXED) {
    if (pathname === `/${locale}`) return "/";
    if (pathname.startsWith(`/${locale}/`)) {
      return pathname.slice(locale.length + 1) || "/";
    }
  }
  return pathname;
}

/** Build an href for a canonical path in the given locale. */
export function localeHref(locale: Locale, path: string): string {
  const clean = path.startsWith("/") ? path : `/${path}`;
  if (locale === DEFAULT_LOCALE) return clean;
  return clean === "/" ? `/${locale}` : `/${locale}${clean}`;
}

/** Best supported locale for a browser language tag. */
export function matchBrowserLocale(language: string): Locale {
  const lower = language.toLowerCase();
  for (const locale of LOCALES) {
    if (lower === locale || lower.startsWith(`${locale}-`)) return locale;
  }
  return DEFAULT_LOCALE;
}
