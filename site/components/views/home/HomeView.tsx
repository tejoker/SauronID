import type { Locale } from "@/lib/i18n";
import { T } from "./copy";
import Hero from "./Hero";
import Benefits from "./Benefits";
import Assurance from "./Assurance";
import Path from "./Path";
import Mechanism from "./Mechanism";
import UseCases from "./UseCases";
import LauncherCloud from "./LauncherCloud";
import Faq from "./Faq";
import Gate from "./Gate";

export default function HomeView({ locale }: { locale: Locale }) {
  const t = T[locale];

  return (
    <>
      {/* Hero — the offer and the proof object */}
      <Hero locale={locale} t={t.hero} />

      {/* Three reasons, in plain words */}
      <Benefits t={t.benefits} />

      {/* Assurance band — drawn neutral emblems, defensible claims only */}
      <Assurance t={t.assurance} />

      {/* The path — every agent is built along the same five checkpoints */}
      <Path locale={locale} t={t.path} />

      {/* The mechanism, made touchable */}
      <Mechanism locale={locale} t={t.mechanism} />

      {/* Use cases — see yourself in one */}
      <UseCases locale={locale} t={t.useCases} />

      {/* Launcher now, cloud later */}
      <LauncherCloud locale={locale} t={t.launcher} />

      {/* FAQ */}
      <Faq locale={locale} t={t.faq} />

      {/* Final CTA */}
      <Gate locale={locale} t={t.finalCta} />
    </>
  );
}
