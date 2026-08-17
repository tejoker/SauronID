import type { Metadata } from "next";
import UseCasesView from "@/components/views/use-cases/UseCasesView";

export const metadata: Metadata = {
  title: "AI agent use cases — real jobs, with boundaries",
  description:
    "Concrete examples of AI agents doing real work inside a company — sales, support, finance, recruiting, IT, marketing — and the boundaries that make each one safe to run.",
  alternates: {
    languages: {
      en: "/use-cases",
      fr: "/fr/use-cases",
    },
  },
};

export default function UseCasesPage() {
  return <UseCasesView locale="en" />;
}
