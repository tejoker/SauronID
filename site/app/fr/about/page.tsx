import type { Metadata } from "next";
import AboutView from "@/components/views/about/AboutView";

export const metadata: Metadata = {
  title: { absolute: "À propos de SauronID" },
  description:
    "Pourquoi SauronID existe : rendre les agents IA utiles accessibles sans demander à quiconque d'abandonner le contrôle. Ce que nous construisons, pourquoi, et ce à quoi nous nous tenons.",
  alternates: { languages: { en: "/about", fr: "/fr/about" } },
};

export default function AboutPageFr() {
  return <AboutView locale="fr" />;
}
