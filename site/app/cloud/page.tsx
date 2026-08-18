import type { Metadata } from "next";
import CloudView from "@/components/views/cloud/CloudView";

export const metadata: Metadata = {
  title: { absolute: "SauronID Cloud — Coming later" },
  description:
    "SauronID Cloud is the planned managed execution mode: same agent, same boundaries, different runtime. Hosted execution, schedules, team policies, and centralised audit are coming later.",
  alternates: {
    languages: {
      en: "/cloud",
      fr: "/fr/cloud",
    },
  },
};

export default function CloudPage() {
  return <CloudView locale="en" />;
}
