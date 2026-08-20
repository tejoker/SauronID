import type { Metadata } from "next";
import AboutView from "@/components/views/about/AboutView";

export const metadata: Metadata = {
  title: "About SauronID",
  description:
    "Why SauronID exists: making useful AI agents accessible without asking anyone to surrender control. What we build, why we build it, and what we hold ourselves to.",
  alternates: { languages: { en: "/about", fr: "/fr/about" } },
};

export default function AboutPage() {
  return <AboutView locale="en" />;
}
