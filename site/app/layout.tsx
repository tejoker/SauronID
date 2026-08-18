import type { Metadata } from "next";
import { Inter, Inter_Tight, IBM_Plex_Mono } from "next/font/google";
import Header from "@/components/layout/Header";
import Footer from "@/components/layout/Footer";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const interTight = Inter_Tight({
  subsets: ["latin"],
  variable: "--font-inter-tight",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: "500",
  variable: "--font-plex-mono",
});

export const metadata: Metadata = {
  title: {
    default: "SauronID — Build agents you can actually let act",
    template: "%s — SauronID",
  },
  description:
    "SauronID is the agent platform with boundaries built in. Give an agent a real job, choose the models and tools it can use, and set the boundaries it cannot cross.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${interTight.variable} ${plexMono.variable}`}
    >
      <body>
        {/*
        THESIS: The platform for building agents you can actually let act — usefulness plus controlled autonomy leads; refuses the fear-first security landing page and the generic SaaS feature grid.
        OWN-WORLD: Light Cloud/White canvas, Ink text, Signal Blue action, Midnight reserved for proof moments; boundary rails, paths and checkpoints as the visual grammar; Inter Tight display, IBM Plex Mono only as evidence.
        STORY: An operator understands in seconds they can build an agent, give it real capabilities, define exactly what it may do, and safely let it act — then joins early access.
        FIRST VIEWPORT: Headline left with two CTAs and trust line; right, a launcher window showing one agent, its job, its tools and three visible boundaries.
        FORM: Checkpoint-path structure — the home is organized along one continuous rail whose five checkpoints ARE the product grammar (Intent, Capabilities, Boundaries, Run, Proof); index 5 of a 6-structure shortlist, chosen by external roll. World stays brand-pinned (brand system v2). Motion: the path draws and checkpoints light on first view; the run demo animates; nothing else moves.
        FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md
        */}
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <Header />
        <main id="main">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
