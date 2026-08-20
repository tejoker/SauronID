"use client";

import { useEffect, useRef, useState } from "react";
import { type Locale } from "@/lib/i18n";

type StatusKind = "allowed" | "review" | "stopped";

interface Attempt {
  action: string;
  detail: string;
  status: StatusKind;
  statusLabel: string;
  why: string;
  rule: string;
}

const STATUS_CLASS: Record<StatusKind, string> = {
  allowed: "status-allowed",
  review: "status-review",
  stopped: "status-stopped",
};

const ATTEMPTS_BY_LOCALE: Record<Locale, Attempt[]> = {
  en: [
    {
      action: "Read CRM account",
      detail: "Fetch “Nordwind Logistics” to prepare enrichment",
      status: "allowed",
      statusLabel: "Allowed",
      why: "Reading CRM records is inside the agent's granted capabilities and data scope, so the action goes through.",
      rule: "capability: crm.read — granted\ndata scope: accounts assigned to you\ndecision: allowed",
    },
    {
      action: "Update qualified lead",
      detail: "Write industry and research notes to the account",
      status: "allowed",
      statusLabel: "Allowed",
      why: "The agent may update exactly the fields you approved: industry, size, and notes. This update touches only those.",
      rule: "capability: crm.update — fields: industry, size, notes\nrequested fields: industry, notes\ndecision: allowed",
    },
    {
      action: "Export entire customer database",
      detail: "Download all 48,000 contact records",
      status: "stopped",
      statusLabel: "Stopped",
      why: "Bulk export is not in the agent's capabilities, so the request never reaches your CRM. The attempt is recorded with the rule that stopped it.",
      rule: "requested: crm.export — all records\nboundary: exports are not granted to this agent\ndecision: stopped · recorded in Activity",
    },
    {
      action: "Send €25,000 payment",
      detail: "Settle the “Nordwind” onboarding invoice",
      status: "review",
      statusLabel: "Needs approval",
      why: "Payments above your €500 threshold pause and wait for a human. Nothing is sent until you approve it, and your decision becomes part of the record.",
      rule: "requested: payment — €25,000\nboundary: payments above €500 require approval\ndecision: paused · waiting for you",
    },
  ],
  fr: [
    {
      action: "Lire un compte CRM",
      detail: "Récupérer « Nordwind Logistics » pour préparer l'enrichissement",
      status: "allowed",
      statusLabel: "Autorisé",
      why: "La lecture des fiches CRM fait partie des capacités et du périmètre de données accordés à l'agent, l'action passe donc.",
      rule: "capability: crm.read — granted\ndata scope: accounts assigned to you\ndecision: allowed",
    },
    {
      action: "Mettre à jour un lead qualifié",
      detail: "Écrire le secteur et les notes de recherche sur le compte",
      status: "allowed",
      statusLabel: "Autorisé",
      why: "L'agent peut mettre à jour exactement les champs que vous avez approuvés : secteur, taille et notes. Cette mise à jour ne touche qu'à ceux-là.",
      rule: "capability: crm.update — fields: industry, size, notes\nrequested fields: industry, notes\ndecision: allowed",
    },
    {
      action: "Exporter toute la base clients",
      detail: "Télécharger les 48 000 fiches contact",
      status: "stopped",
      statusLabel: "Bloqué",
      why: "L'export en masse ne fait pas partie des capacités de l'agent, la requête n'atteint donc jamais votre CRM. La tentative est enregistrée avec la règle qui l'a bloquée.",
      rule: "requested: crm.export — all records\nboundary: exports are not granted to this agent\ndecision: stopped · recorded in Activity",
    },
    {
      action: "Envoyer un paiement de 25 000 €",
      detail: "Régler la facture d'intégration « Nordwind »",
      status: "review",
      statusLabel: "Approbation requise",
      why: "Les paiements au-dessus de votre seuil de 500 € se mettent en pause et attendent un humain. Rien n'est envoyé tant que vous n'avez pas approuvé, et votre décision fait partie de la trace.",
      rule: "requested: payment — €25,000\nboundary: payments above €500 require approval\ndecision: paused · waiting for you",
    },
  ],
};

const UI_TEXT: Record<Locale, { replay: string; selectHint: string; hint: string }> = {
  en: {
    replay: "Replay the run",
    selectHint: "Select any action to see the exact rule behind the decision.",
    hint: "Every decision points back to a rule you wrote, not to a model's mood.",
  },
  fr: {
    replay: "Rejouer l'exécution",
    selectHint: "Sélectionnez une action pour voir la règle exacte derrière la décision.",
    hint: "Chaque décision renvoie à une règle que vous avez écrite, pas à l'humeur d'un modèle.",
  },
};

export default function BoundaryDemo({ locale = "en" }: { locale?: Locale }) {
  const ATTEMPTS = ATTEMPTS_BY_LOCALE[locale];
  const ui = UI_TEXT[locale];
  const [decidedCount, setDecidedCount] = useState(0);
  const [checkingIndex, setCheckingIndex] = useState<number | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [isReplaying, setIsReplaying] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const hasAutoplayedRef = useRef(false);

  function clearTimers() {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
  }

  function run(stepMs: number) {
    clearTimers();
    setIsReplaying(true);
    setDecidedCount(0);
    setCheckingIndex(null);
    ATTEMPTS.forEach((_, index) => {
      timersRef.current.push(
        setTimeout(() => setCheckingIndex(index), index * stepMs)
      );
      timersRef.current.push(
        setTimeout(() => {
          setCheckingIndex(null);
          setDecidedCount(index + 1);
          setSelectedIndex(index);
          if (index === ATTEMPTS.length - 1) setIsReplaying(false);
        }, index * stepMs + stepMs * 0.55)
      );
    });
  }

  function replay() {
    const reduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;
    run(reduced ? 0 : 850);
  }

  useEffect(() => {
    const root = rootRef.current;
    if (!root || !("IntersectionObserver" in window)) {
      setDecidedCount(ATTEMPTS.length);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && !hasAutoplayedRef.current) {
            hasAutoplayedRef.current = true;
            const reduced = window.matchMedia(
              "(prefers-reduced-motion: reduce)"
            ).matches;
            run(reduced ? 0 : 850);
            observer.disconnect();
          }
        });
      },
      { threshold: 0.4 }
    );
    observer.observe(root);
    return () => {
      observer.disconnect();
      clearTimers();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function selectAttempt(index: number) {
    clearTimers();
    setIsReplaying(false);
    setCheckingIndex(null);
    setDecidedCount(ATTEMPTS.length);
    setSelectedIndex(index);
  }

  const selected = ATTEMPTS[selectedIndex];

  return (
    <div ref={rootRef}>
      <div className="demo-run">
        <button
          className="btn btn-secondary btn-sm"
          type="button"
          onClick={replay}
        >
          {ui.replay}
        </button>
        <span className="small muted">{ui.selectHint}</span>
      </div>
      <div className="demo">
        <div className="attempts">
          {ATTEMPTS.map((attempt, index) => {
            const isDecided = index < decidedCount;
            const classes = [
              "attempt",
              isDecided ? "decided" : "",
              checkingIndex === index ? "pending-check" : "",
              selectedIndex === index && isDecided ? "selected" : "",
            ]
              .filter(Boolean)
              .join(" ");
            return (
              <button
                key={attempt.action}
                className={classes}
                type="button"
                onClick={() => selectAttempt(index)}
              >
                <span>
                  <span className="action">{attempt.action}</span>
                  <br />
                  <span className="detail">{attempt.detail}</span>
                </span>
                <span className={`status ${STATUS_CLASS[attempt.status]}`}>
                  {attempt.statusLabel}
                </span>
              </button>
            );
          })}
        </div>
        {/* Live announcements stay off during the automated replay;
            user-initiated selections are announced. */}
        <div
          className="verdict-panel"
          aria-live={isReplaying ? undefined : "polite"}
        >
          <span className={`status ${STATUS_CLASS[selected.status]}`}>
            {selected.statusLabel}
          </span>
          <p className="why">{selected.why}</p>
          <pre className="rule-quote">{selected.rule}</pre>
          <p className="hint">{ui.hint}</p>
        </div>
      </div>
    </div>
  );
}
