import type { Metadata } from "next";
import UseCasesView from "@/components/views/use-cases/UseCasesView";

export const metadata: Metadata = {
  title: "Cas d'usage d'agents IA — de vraies missions, avec des limites",
  description:
    "Des exemples concrets d'agents IA effectuant un vrai travail dans une entreprise — ventes, support, finance, recrutement, IT, marketing — et les limites qui rendent chacun sûr à exécuter.",
  alternates: {
    languages: {
      en: "/use-cases",
      fr: "/fr/use-cases",
    },
  },
};

export default function UseCasesPageFr() {
  return <UseCasesView locale="fr" />;
}
