"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { SITES, useWallet } from "../context/WalletContext";

const NAV = [
  { href: "/",     label: "Admin"   },
  { href: "/site", label: "Treasury" },
  { href: "/user", label: "User"    },
];

export default function NavBar() {
  const pathname = usePathname();
  const { activeSite, setActiveSite } = useWallet();

  return (
    <header className="border-b border-neutral-200 bg-white sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 flex items-center gap-0 h-12">
        <div className="mr-8 flex-shrink-0">
          <span className="text-neutral-900 font-bold tracking-tight text-sm">Sauron</span>
        </div>

        <nav className="flex items-stretch h-full flex-1 gap-0">
          {NAV.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center px-4 text-xs border-b-2 transition-colors ${
                  active
                    ? "border-neutral-900 text-neutral-900 font-semibold"
                    : "border-transparent text-neutral-400 hover:text-neutral-700"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
