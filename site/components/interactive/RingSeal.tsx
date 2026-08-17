"use client";

import { useState } from "react";
import logo from "@/public/sauronid-logo.png";
import { type Locale } from "@/lib/i18n";

/**
 * The ring seal, explained by touching it. Five parts of a sensitive action
 * are signed together as one ring; tampering with any one breaks the seal
 * and the gateway rejects the request. This is the mechanism behind the
 * product's name, drawn instead of described.
 */

interface Segment {
  label: string;
  value: string;
}

const SEGMENTS: Segment[] = [
  { label: "action", value: "payment" },
  { label: "resource", value: "invoice #2481" },
  { label: "destination", value: "Nordwind GmbH" },
  { label: "amount", value: "€25,000" },
  { label: "nonce", value: "used once" },
];

const CX = 160;
const CY = 160;
const RADIUS = 108;
const GAP_DEGREES = 7;
const SEGMENT_DEGREES = 360 / SEGMENTS.length;

function polar(angleDegrees: number, radius: number): [number, number] {
  const rad = ((angleDegrees - 90) * Math.PI) / 180;
  return [CX + radius * Math.cos(rad), CY + radius * Math.sin(rad)];
}

function arcPath(startDegrees: number, endDegrees: number): string {
  const [x1, y1] = polar(startDegrees, RADIUS);
  const [x2, y2] = polar(endDegrees, RADIUS);
  const large = endDegrees - startDegrees > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${RADIUS} ${RADIUS} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

const T = {
  en: {
    ariaLabel:
      "A ring of five sealed segments: action, resource, destination, amount, nonce. Tampering with one segment breaks the seal.",
    labels: { action: "action", resource: "resource", destination: "destination", amount: "amount", nonce: "nonce" },
    tampered: "tampered",
    sealBroken: "Seal broken",
    sealIntact: "Seal intact",
    requestRejected: "request rejected",
    actionAllowed: "action allowed",
    hintBroken:
      "One segment changed, so the whole seal fails. The gateway rejects the request before it reaches your tools.",
    hintIntact: "Tap any segment to tamper with it, the way an attacker would.",
    resetButton: "Seal it again",
  },
  fr: {
    ariaLabel:
      "Un anneau de cinq segments scellés : action, ressource, destination, montant, nonce. Falsifier un segment brise le scellé.",
    labels: { action: "action", resource: "ressource", destination: "destination", amount: "montant", nonce: "nonce" },
    tampered: "modifié",
    sealBroken: "Sceau brisé",
    sealIntact: "Sceau intact",
    requestRejected: "requête rejetée",
    actionAllowed: "action autorisée",
    hintBroken:
      "Un segment a changé, donc tout le sceau échoue. La passerelle rejette la requête avant qu'elle n'atteigne vos outils.",
    hintIntact: "Touchez un segment pour le falsifier, comme le ferait un attaquant.",
    resetButton: "Sceller à nouveau",
  },
} as const;

const LABEL_KEYS = ["action", "resource", "destination", "amount", "nonce"] as const;

const VALUES: Record<Locale, string[]> = {
  en: ["payment", "invoice #2481", "Nordwind GmbH", "€25,000", "used once"],
  fr: ["paiement", "facture #2481", "Nordwind GmbH", "25 000 €", "usage unique"],
};

export default function RingSeal({ locale = "en" }: { locale?: Locale }) {
  const t = T[locale];
  const [brokenIndex, setBrokenIndex] = useState<number | null>(null);
  const isBroken = brokenIndex !== null;

  return (
    <div className={`ring-seal${isBroken ? " broken" : ""}`}>
      <svg
        viewBox="0 0 320 320"
        role="img"
        aria-label={t.ariaLabel}
      >
        {SEGMENTS.map((segment, index) => {
          const start = index * SEGMENT_DEGREES + GAP_DEGREES / 2;
          const end = (index + 1) * SEGMENT_DEGREES - GAP_DEGREES / 2;
          const mid = (start + end) / 2;
          const [lx, ly] = polar(mid, RADIUS + 30);
          const [ox, oy] = polar(mid, 14);
          const normalized = ((mid % 360) + 360) % 360;
          let anchor: "start" | "middle" | "end" = "middle";
          if (normalized > 25 && normalized < 155) anchor = "start";
          else if (normalized > 205 && normalized < 335) anchor = "end";
          const isTampered = brokenIndex === index;
          return (
            <g
              key={segment.label}
              className={`ring-segment${isTampered ? " tampered" : ""}`}
              style={{
                transform: isTampered
                  ? `translate(${(ox - CX).toFixed(1)}px, ${(oy - CY).toFixed(1)}px)`
                  : undefined,
              }}
              onClick={() => setBrokenIndex(isTampered ? null : index)}
            >
              <path className="ring-arc" d={arcPath(start, end)} />
              <path className="ring-hit" d={arcPath(start, end)} />
              <text x={lx} y={ly - 6} className="ring-label" textAnchor={anchor}>
                {t.labels[LABEL_KEYS[index]]}
              </text>
              <text x={lx} y={ly + 10} className="ring-value" textAnchor={anchor}>
                {isTampered ? t.tampered : VALUES[locale][index]}
              </text>
            </g>
          );
        })}
        <image href={logo.src} x={CX - 13} y={CY - 44} width="26" height="26" />
        <text x={CX} y={CY + 2} className="ring-state" textAnchor="middle">
          {isBroken ? t.sealBroken : t.sealIntact}
        </text>
        <text x={CX} y={CY + 24} className="ring-verdict" textAnchor="middle">
          {isBroken ? t.requestRejected : t.actionAllowed}
        </text>
      </svg>
      <p className="ring-hint small">
        {isBroken ? (
          <>
            {t.hintBroken}{" "}
            <button
              type="button"
              className="ring-reset"
              onClick={() => setBrokenIndex(null)}
            >
              {t.resetButton}
            </button>
          </>
        ) : (
          <>{t.hintIntact}</>
        )}
      </p>
    </div>
  );
}
