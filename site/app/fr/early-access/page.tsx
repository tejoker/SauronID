import type { Metadata } from "next";
import EarlyAccessView from "@/components/views/early-access/EarlyAccessView";

export const metadata: Metadata = {
  title: { absolute: "Accès anticipé — Launcher SauronID" },
  description:
    "Rejoignez l'accès anticipé de SauronID : un Launcher de bureau téléchargeable qui construit et exécute un agent borné en local, sans GitHub, Docker ni terminal.",
  alternates: {
    languages: {
      en: "/early-access",
      fr: "/fr/early-access",
    },
  },
};

export default function EarlyAccessPageFr() {
  return <EarlyAccessView locale="fr" />;
}
