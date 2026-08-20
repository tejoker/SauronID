import type { Metadata } from "next";
import PricingView from "@/components/views/pricing/PricingView";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "SauronID pricing: local execution is free with your own model or API key. Cloud and team plans arrive later, priced when they are real.",
  alternates: {
    languages: {
      en: "/pricing",
      fr: "/fr/pricing",
    },
  },
};

export default function PricingPage() {
  return <PricingView locale="en" />;
}
