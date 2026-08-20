import type { Metadata } from "next";
import ComplianceView from "@/components/views/compliance/ComplianceView";

export const metadata: Metadata = {
  title: "Compliance & Governance",
  description:
    "How SauronID controls map to GDPR accountability and EU AI Act governance themes: the evidence your organisation can produce, and the claims we deliberately do not make.",
  alternates: {
    languages: {
      en: "/compliance",
      fr: "/fr/compliance",
    },
  },
};

export default function CompliancePage() {
  return <ComplianceView locale="en" />;
}
