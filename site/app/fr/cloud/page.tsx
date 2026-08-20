import type { Metadata } from "next";
import CloudView from "@/components/views/cloud/CloudView";

export const metadata: Metadata = {
  title: { absolute: "SauronID Cloud — Plus tard" },
  description:
    "SauronID Cloud est le mode d'exécution géré prévu : même agent, mêmes limites, un environnement d'exécution différent. Exécution hébergée, planifications, politiques d'équipe et audit centralisé arriveront plus tard.",
  alternates: {
    languages: {
      en: "/cloud",
      fr: "/fr/cloud",
    },
  },
};

export default function CloudPageFr() {
  return <CloudView locale="fr" />;
}
