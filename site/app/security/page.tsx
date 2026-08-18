import type { Metadata } from "next";
import SecurityView from "@/components/views/security/SecurityView";

export const metadata: Metadata = {
  title: "Security & Control",
  description:
    "How SauronID enforces agent boundaries: owner-signed mandates, per-action signatures, server-side policy, one-use capabilities, revocation, and an honest threat model.",
  alternates: {
    languages: {
      en: "/security",
      fr: "/fr/security",
    },
  },
};

export default function SecurityPage() {
  return <SecurityView locale="en" />;
}
