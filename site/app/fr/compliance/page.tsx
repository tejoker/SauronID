import type { Metadata } from "next";
import ComplianceView from "@/components/views/compliance/ComplianceView";

export const metadata: Metadata = {
  title: "Conformité et gouvernance",
  description:
    "Comment les contrôles de SauronID s'inscrivent dans les thèmes de responsabilité RGPD et de gouvernance du règlement européen sur l'IA : les preuves que votre organisation peut produire, et les affirmations que nous ne faisons délibérément pas.",
  alternates: {
    languages: {
      en: "/compliance",
      fr: "/fr/compliance",
    },
  },
};

export default function CompliancePageFr() {
  return <ComplianceView locale="fr" />;
}
