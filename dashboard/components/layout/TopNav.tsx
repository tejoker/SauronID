"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { SystemStatus } from "./SystemStatus";
import { TenantSwitcher } from "./TenantSwitcher";
import { ThemeToggle } from "./ThemeToggle";
import { LocaleSwitcher } from "./LocaleSwitcher";

const NAV_LINKS = [
  { key: "home",      href: "/" },
  { key: "welcome",   href: "/welcome" },
  { key: "protected", href: "/protected" },
  { key: "activity",  href: "/activity" },
  { key: "policies",  href: "/policies" },
  { key: "compliance", href: "/compliance" },
  { key: "proofs",    href: "/proofs" },
  { key: "explorer",  href: "/explorer" },
  { key: "try",       href: "/try" },
  { key: "onboard",   href: "/onboard" },
  { key: "settings",  href: "/settings" },
] as const;

export function TopNav() {
  const t = useTranslations("nav");
  const pathname = usePathname();

  return (
    <header className="fixed top-0 inset-x-0 z-50 h-12 flex items-center px-6 bg-[var(--bg)] border-b border-[var(--border)]">
      {/* Logo */}
      <Link href="/" className="flex items-center gap-2 mr-8 flex-shrink-0">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/logo.svg"
          alt="SauronID"
          className="h-6 w-6 object-contain"
        />
        <span
          className="text-sm font-semibold tracking-tight"
          style={{ fontFamily: "var(--font-sans)" }}
        >
          Sauron<span className="text-[var(--accent-text)]">ID</span>
        </span>
      </Link>

      {/* Nav links */}
      <nav className="flex items-center gap-1 flex-1" aria-label="Main navigation">
        {NAV_LINKS.map(({ key, href }) => {
          const isActive =
            key === "home" ? pathname === "/" : pathname.startsWith(href);

          return (
            <Link
              key={key}
              href={href}
              className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out ${
                isActive
                  ? "text-[var(--text-primary)]"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              {t(key)}
            </Link>
          );
        })}
      </nav>

      {/* Right side */}
      <div className="flex items-center gap-4 ml-auto flex-shrink-0">
        <SystemStatus />
        <TenantSwitcher />
        <LocaleSwitcher />
        <ThemeToggle />
      </div>
    </header>
  );
}
