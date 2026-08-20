import type { Metadata } from "next";
import EarlyAccessView from "@/components/views/early-access/EarlyAccessView";

export const metadata: Metadata = {
  title: { absolute: "Early Access — SauronID Launcher" },
  description:
    "Join SauronID early access: a downloadable desktop Launcher that builds and runs a bounded agent locally, without GitHub, Docker, or a terminal.",
  alternates: {
    languages: {
      en: "/early-access",
      fr: "/fr/early-access",
    },
  },
};

export default function EarlyAccessPage() {
  return <EarlyAccessView locale="en" />;
}
