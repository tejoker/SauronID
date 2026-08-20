import type { Metadata } from "next";
import AuditabilityView from "@/components/views/auditability/AuditabilityView";

export const metadata: Metadata = {
  title: "Auditability",
  description:
    "Every SauronID agent action leaves evidence: intent, policy, decision, approval, execution. Each record is chained, inspectable, and anchored so it can be proven months later.",
  alternates: {
    languages: {
      en: "/auditability",
      fr: "/fr/auditability",
    },
  },
};

export default function AuditabilityPage() {
  return <AuditabilityView locale="en" />;
}
