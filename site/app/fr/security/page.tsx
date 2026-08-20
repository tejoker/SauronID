import type { Metadata } from "next";
import SecurityView from "@/components/views/security/SecurityView";

export const metadata: Metadata = {
  title: "Sécurité et contrôle",
  description:
    "Comment SauronID applique les limites des agents : mandats signés par le propriétaire, signatures par action, politique côté serveur, capacités à usage unique, révocation, et un modèle de menace honnête.",
  alternates: {
    languages: {
      en: "/security",
      fr: "/fr/security",
    },
  },
};

export default function SecurityPageFr() {
  return <SecurityView locale="fr" />;
}
