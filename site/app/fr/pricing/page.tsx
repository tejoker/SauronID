import type { Metadata } from "next";
import PricingView from "@/components/views/pricing/PricingView";

export const metadata: Metadata = {
  title: "Tarifs",
  description:
    "Tarifs SauronID : l'exécution locale est gratuite avec votre propre modèle ou clé API. Les offres Cloud et équipe arriveront plus tard, tarifées quand elles seront réelles.",
  alternates: {
    languages: {
      en: "/pricing",
      fr: "/fr/pricing",
    },
  },
};

export default function PricingPageFr() {
  return <PricingView locale="fr" />;
}
