import type { Metadata } from "next";
import HomeView from "@/components/views/home/HomeView";

export const metadata: Metadata = {
  title: { absolute: "SauronID — Construisez des agents que vous pouvez vraiment laisser agir" },
  description:
    "SauronID est la plateforme d'agents avec des limites intégrées. Confiez à un agent une vraie mission, choisissez les modèles et les outils qu'il peut utiliser, et fixez les limites qu'il ne peut pas franchir.",
  alternates: {
    languages: {
      en: "/",
      fr: "/fr",
    },
  },
};

export default function HomePageFr() {
  return <HomeView locale="fr" />;
}
