import type { Metadata } from "next";
import HomeView from "@/components/views/home/HomeView";

export const metadata: Metadata = {
  title: "SauronID — Build agents you can actually let act",
  description:
    "SauronID is the agent platform with boundaries built in. Give an agent a real job, choose the models and tools it can use, and set the boundaries it cannot cross.",
  alternates: {
    languages: {
      en: "/",
      fr: "/fr",
    },
  },
};

export default function HomePage() {
  return <HomeView locale="en" />;
}
