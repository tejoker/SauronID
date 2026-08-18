"use client";

import { useState } from "react";
import type { Locale } from "@/lib/i18n";
import {
  LAUNCHER_URL,
  isSignupBackendConfigured,
  submitSignup,
} from "@/lib/earlyAccess";

const EA_TO = "nicolas@eurotech-federation.com";

type Status = "idle" | "submitting" | "stored" | "mailto" | "error";

const T = {
  en: {
    labelName: "Name",
    labelEmail: "Work email",
    labelRole: "Role / company",
    optional: "optional",
    labelOs: "Operating system",
    choose: "Choose…",
    labelWorkflow: "The workflow you want to automate",
    workflowPlaceholder:
      "e.g. Research inbound leads and keep our CRM enriched, without letting the agent email anyone on its own.",
    labelTools: "Tools involved",
    toolsPlaceholder: "CRM, helpdesk, spreadsheets…",
    labelModel: "Current model / provider",
    modelPlaceholder: "Claude, GPT, local…",
    labelCall: "Open to a 20-minute feedback call?",
    yes: "Yes",
    no: "No",
    submit: "Join early access",
    submitting: "Sending…",
    storedDownload: (
      <>
        You&apos;re in. Your Launcher download has started; if it didn&apos;t,{" "}
        <a href={LAUNCHER_URL}>download it here</a>.
      </>
    ),
    storedQueue: (
      <>
        You&apos;re in. We&apos;ll email your download link when your cohort
        opens.
      </>
    ),
    error: (
      <>
        Something went wrong on our side and your signup was not saved. Please
        try again, or write to <a href={`mailto:${EA_TO}`}>{EA_TO}</a>.
      </>
    ),
    mailtoNote: (
      <>
        This opens a pre-filled email in your mail app — send it and
        you&apos;re in the queue. If nothing opened, write to{" "}
        <a href={`mailto:${EA_TO}`}>{EA_TO}</a>.
      </>
    ),
  },
  fr: {
    labelName: "Nom",
    labelEmail: "Email professionnel",
    labelRole: "Fonction / entreprise",
    optional: "facultatif",
    labelOs: "Système d'exploitation",
    choose: "Choisir…",
    labelWorkflow: "Le workflow que vous souhaitez automatiser",
    workflowPlaceholder:
      "ex. Rechercher les prospects entrants et enrichir notre CRM, sans laisser l'agent envoyer d'emails de sa propre initiative.",
    labelTools: "Outils concernés",
    toolsPlaceholder: "CRM, support client, tableurs…",
    labelModel: "Modèle / fournisseur actuel",
    modelPlaceholder: "Claude, GPT, local…",
    labelCall: "Disponible pour un appel de 20 minutes pour échanger vos retours ?",
    yes: "Oui",
    no: "Non",
    submit: "Rejoindre l'accès anticipé",
    submitting: "Envoi…",
    storedDownload: (
      <>
        C&apos;est bon, vous êtes inscrit. Le téléchargement du Launcher a
        démarré ; si ce n&apos;est pas le cas,{" "}
        <a href={LAUNCHER_URL}>téléchargez-le ici</a>.
      </>
    ),
    storedQueue: (
      <>
        C&apos;est bon, vous êtes inscrit. Vous recevrez votre lien de
        téléchargement par email à l&apos;ouverture de votre cohorte.
      </>
    ),
    error: (
      <>
        Une erreur est survenue de notre côté et votre inscription n&apos;a
        pas été enregistrée. Réessayez, ou écrivez à{" "}
        <a href={`mailto:${EA_TO}`}>{EA_TO}</a>.
      </>
    ),
    mailtoNote: (
      <>
        Ceci ouvre un email pré-rempli dans votre application de messagerie :
        envoyez-le et vous êtes dans la file. Si rien ne s&apos;est ouvert,
        écrivez à <a href={`mailto:${EA_TO}`}>{EA_TO}</a>.
      </>
    ),
  },
};

function openMailto(form: HTMLFormElement) {
  const data = new FormData(form);
  const lines: string[] = [];
  data.forEach((value, key) => {
    if (String(value).trim() !== "") {
      lines.push(`${key}: ${value}`);
    }
  });
  const subject = "SauronID early access request";
  window.location.href =
    `mailto:${EA_TO}?subject=${encodeURIComponent(subject)}` +
    `&body=${encodeURIComponent(lines.join("\n"))}`;
}

export default function EarlyAccessForm({
  locale = "en",
}: {
  locale?: Locale;
}) {
  const [status, setStatus] = useState<Status>("idle");
  const t = T[locale];

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;

    if (!isSignupBackendConfigured) {
      openMailto(form);
      setStatus("mailto");
      return;
    }

    setStatus("submitting");
    const data = new FormData(form);
    try {
      await submitSignup({
        name: String(data.get("Name") ?? ""),
        email: String(data.get("Email") ?? ""),
        role_company: String(data.get("Role and company") ?? ""),
        os: String(data.get("Operating system") ?? ""),
        workflow: String(data.get("Workflow") ?? ""),
        tools: String(data.get("Tools") ?? ""),
        model_provider: String(data.get("Model or provider") ?? ""),
        feedback_call: String(data.get("Feedback call") ?? ""),
        locale,
      });
      setStatus("stored");
      form.reset();
      if (LAUNCHER_URL) {
        window.location.href = LAUNCHER_URL;
      }
    } catch {
      setStatus("error");
    }
  }

  const note =
    status === "stored"
      ? LAUNCHER_URL
        ? t.storedDownload
        : t.storedQueue
      : status === "error"
        ? t.error
        : status === "mailto"
          ? t.mailtoNote
          : null;

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="ea-name">{t.labelName}</label>
          <input id="ea-name" name="Name" type="text" autoComplete="name" maxLength={200} required />
        </div>
        <div className="field">
          <label htmlFor="ea-email">{t.labelEmail}</label>
          <input id="ea-email" name="Email" type="email" autoComplete="email" maxLength={320} required />
        </div>
        <div className="field">
          <label htmlFor="ea-role">
            {t.labelRole} <span className="opt">{t.optional}</span>
          </label>
          <input
            id="ea-role"
            name="Role and company"
            type="text"
            autoComplete="organization-title"
            maxLength={300}
          />
        </div>
        <div className="field">
          <label htmlFor="ea-os">{t.labelOs}</label>
          <select id="ea-os" name="Operating system" required defaultValue="">
            <option value="" disabled>
              {t.choose}
            </option>
            <option>macOS</option>
            <option>Windows</option>
            <option>Linux</option>
          </select>
        </div>
        <div className="field wide">
          <label htmlFor="ea-workflow">{t.labelWorkflow}</label>
          <textarea
            id="ea-workflow"
            name="Workflow"
            placeholder={t.workflowPlaceholder}
            maxLength={4000}
            required
          />
        </div>
        <div className="field">
          <label htmlFor="ea-tools">
            {t.labelTools} <span className="opt">{t.optional}</span>
          </label>
          <input
            id="ea-tools"
            name="Tools"
            type="text"
            placeholder={t.toolsPlaceholder}
            maxLength={1000}
          />
        </div>
        <div className="field">
          <label htmlFor="ea-model">
            {t.labelModel} <span className="opt">{t.optional}</span>
          </label>
          <input
            id="ea-model"
            name="Model or provider"
            type="text"
            placeholder={t.modelPlaceholder}
            maxLength={300}
          />
        </div>
        <div className="field wide">
          <label htmlFor="ea-call">{t.labelCall}</label>
          <select id="ea-call" name="Feedback call" defaultValue="Yes">
            <option>{t.yes}</option>
            <option>{t.no}</option>
          </select>
        </div>
      </div>
      <div className="cta-row mt-3">
        <button
          className="btn btn-primary"
          type="submit"
          disabled={status === "submitting"}
        >
          {status === "submitting" ? t.submitting : t.submit}{" "}
          <span className="arrow" aria-hidden="true">
            →
          </span>
        </button>
      </div>
      {note && (
        <p className="small mt-2" role="status" aria-live="polite">
          {note}
        </p>
      )}
    </form>
  );
}
