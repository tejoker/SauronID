"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import logo from "@/public/sauronid-logo.png";
import { type Locale, localeFromPathname, localeHref } from "@/lib/i18n";

const T: Record<
  Locale,
  {
    tagline: string;
    product: string;
    productLinks: { href: string; label: string }[];
    trust: string;
    trustLinks: { href: string; label: string }[];
    contact: string;
    aboutLabel: string;
    email: string;
    legal: string;
  }
> = {
  en: {
    tagline: "The agent platform with boundaries built in.",
    product: "Product",
    productLinks: [
      { href: "/", label: "Overview" },
      { href: "/use-cases", label: "Use cases" },
      { href: "/early-access", label: "Early access" },
      { href: "/pricing", label: "Pricing" },
    ],
    trust: "Trust",
    trustLinks: [
      { href: "/security", label: "Security & control" },
      { href: "/compliance", label: "Compliance & governance" },
      { href: "/auditability", label: "Auditability" },
    ],
    contact: "Company",
    aboutLabel: "About us",
    email: "Email us",
    legal:
      "SauronID enforces the boundaries you define on protected agent actions and records the evidence. It does not, by itself, guarantee legal compliance, prevent every possible failure, or replace network isolation, endpoint security, or human judgment.",
  },
  fr: {
    tagline: "La plateforme d'agents avec des limites intégrées.",
    product: "Produit",
    productLinks: [
      { href: "/", label: "Vue d'ensemble" },
      { href: "/use-cases", label: "Cas d'usage" },
      { href: "/early-access", label: "Accès anticipé" },
      { href: "/pricing", label: "Tarifs" },
    ],
    trust: "Confiance",
    trustLinks: [
      { href: "/security", label: "Sécurité & contrôle" },
      { href: "/compliance", label: "Conformité & gouvernance" },
      { href: "/auditability", label: "Auditabilité" },
    ],
    contact: "Société",
    aboutLabel: "À propos",
    email: "Écrivez-nous",
    legal:
      "SauronID applique les limites que vous définissez sur les actions protégées des agents et en conserve la trace. Il ne garantit pas, à lui seul, la conformité légale, n'empêche pas toute défaillance possible et ne remplace ni l'isolation réseau, ni la sécurité des postes, ni le jugement humain.",
  },
};

export default function Footer() {
  const pathname = usePathname();
  const locale = localeFromPathname(pathname);
  const t = T[locale];

  return (
    <footer className="site-footer">
      <div className="container">
        <div className="footer-grid">
          <div>
            <Link className="brand" href={localeHref(locale, "/")}>
              <Image src={logo} alt="" width={30} height={30} />
              SauronID
            </Link>
            <p className="tagline">{t.tagline}</p>
          </div>
          <div>
            <h4>{t.product}</h4>
            <ul>
              {t.productLinks.map((link) => (
                <li key={link.href}>
                  <Link href={localeHref(locale, link.href)}>{link.label}</Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h4>{t.trust}</h4>
            <ul>
              {t.trustLinks.map((link) => (
                <li key={link.href}>
                  <Link href={localeHref(locale, link.href)}>{link.label}</Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h4>{t.contact}</h4>
            <ul>
              <li>
                <Link href={localeHref(locale, "/about")}>{t.aboutLabel}</Link>
              </li>
              <li>
                <a href="mailto:nicolas@eurotech-federation.com">{t.email}</a>
              </li>
            </ul>
          </div>
        </div>
        <div className="footer-legal">
          <p>{t.legal}</p>
          <span>© 2026 SauronID</span>
        </div>
      </div>
    </footer>
  );
}
