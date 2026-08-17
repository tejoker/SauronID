import type { Metadata } from "next";
import AuditabilityView from "@/components/views/auditability/AuditabilityView";

export const metadata: Metadata = {
  title: "Auditabilité",
  description:
    "Chaque action d'un agent SauronID laisse une preuve : intention, politique, décision, approbation, exécution. Chaque enregistrement est chaîné, inspectable et ancré pour pouvoir être prouvé des mois plus tard.",
  alternates: {
    languages: {
      en: "/auditability",
      fr: "/fr/auditability",
    },
  },
};

export default function AuditabilityPageFr() {
  return <AuditabilityView locale="fr" />;
}
