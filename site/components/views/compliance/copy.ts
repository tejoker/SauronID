export const T = {
  en: {
    h1: "Evidence and controls that support your obligations",
    ledeParts: {
      pre: "No software makes an organisation compliant. What SauronID does is narrower and more useful: it produces the ",
      controls: "controls",
      mid: " regulators expect around AI agents, and the ",
      evidence: "evidence",
      post: " that those controls actually ran.",
    },
    chipGdpr: "Supports GDPR accountability controls",
    chipAiAct: "Designed to support EU AI Act governance",
    chipNoCert: "No certifications claimed",
    questionsHead: "The questions your organisation must be able to answer",
    questionsLede:
      "When an AI agent acts inside a company, someone is accountable for it. These are the questions an auditor, a regulator, a security team, or your own management will ask, and where SauronID's answer comes from.",
    questionsHeaders: ["Question", "SauronID control", "Evidence produced"] as [
      string,
      string,
      string,
    ],
    questionsRows: [
      {
        req: "What did this agent have permission to do?",
        ctrl: "Explicit capabilities and server-side policy defined before the agent's first run",
        ev: "agent record · capability grants · policy document",
      },
      {
        req: "Who authorised it?",
        ctrl: "Owner-signed mandate binding a named owner to the agent, its intent, and a time limit",
        ev: "signed mandate · owner identity · TTL",
      },
      {
        req: "Under which policy?",
        ctrl: "Versioned policy bindings: every decision references the policy that produced it",
        ev: "policy binding on each receipt",
      },
      {
        req: "What actually happened?",
        ctrl: "Default-deny gateway: every protected action is allowed, paused, or stopped, and recorded either way",
        ev: "hash-chained receipts · stopped-action log",
      },
      {
        req: "Was human approval required, and given?",
        ctrl: "Approval checkpoints on the actions you designate",
        ev: "approval record: approver, time, action",
      },
      {
        req: "Can we prove it six months later?",
        ctrl: "Receipt batches anchored to public timestamps no one can rewrite, including us",
        ev: "Bitcoin OpenTimestamps · Solana anchor · independent verification",
      },
    ],
    gdprLede:
      "The GDPR asks controllers not only to be responsible, but to be able to demonstrate responsibility. When agents touch personal data, SauronID's controls map onto that demand.",
    gdprHeaders: ["GDPR theme", "SauronID control", "Evidence produced"] as [
      string,
      string,
      string,
    ],
    gdprRows: [
      {
        req: "Accountability",
        ctrl: "Every agent has a named human owner, a signed mandate, and a defined authority. Nothing acts anonymously",
        ev: "owner-signed mandate",
      },
      {
        req: "Data protection by design and by default",
        ctrl: "Agents start with zero access; data scopes, tools, and destinations are granted deliberately before the first run",
        ev: "capability grants · policy document",
      },
      {
        req: "Controlled access",
        ctrl: "Data-scope allow/deny classification and destination controls, enforced server-side on every protected call",
        ev: "policy evaluation on each receipt",
      },
      {
        req: "Purpose limitation, where technically applicable",
        ctrl: "The agent's intent is encoded in its credential; capabilities are granted against that intent, and drift is rejected",
        ev: "intent-bound credential · config digest check",
      },
      {
        req: "Traceability and audit records",
        ctrl: "Hash-chained receipts for allowed and stopped actions; a separate tamper-evident security audit log",
        ev: "receipt chain · audit log · anchor proofs",
      },
      {
        req: "Human governance",
        ctrl: "Approval checkpoints, immediate revocation, and time-limited mandates keep humans in charge of authority",
        ev: "approval records · revocation events",
      },
    ],
    gdprFootnote:
      "Your GDPR obligations (lawful basis, data subject rights, DPIAs, processor agreements) remain your organisation's responsibility. SauronID contributes controls and records; it does not replace your privacy programme or legal counsel.",
    aiActLede:
      "The EU AI Act asks organisations deploying AI systems for human oversight, record keeping, transparency, and defined intended use. SauronID's product model was built around exactly those requirements, before there was a regulation named after them.",
    aiActHeaders: ["AI Act theme", "SauronID control", "Evidence produced"] as [
      string,
      string,
      string,
    ],
    aiActRows: [
      {
        req: "Human oversight",
        ctrl: "Approval gates pause designated actions for a human decision; revocation stops an agent immediately",
        ev: "approval records · revocation events",
      },
      {
        req: "Logging and record keeping",
        ctrl: "Automatic, tamper-evident records of every protected action: allowed, paused, and stopped",
        ev: "hash-chained receipts · audit log",
      },
      {
        req: "Transparency",
        ctrl: "Every decision is explainable: the action, the rule that applied, and the outcome are readable by a non-engineer",
        ev: "decision + rule on each record",
      },
      {
        req: "Defined intended use",
        ctrl: "An agent's intent is declared at creation and bound into its credential, so the agent cannot silently repurpose itself",
        ev: "intent-bound credential · mandate",
      },
      {
        req: "Operational constraints",
        ctrl: "Budgets, rates, time windows, tool allowlists, and data scopes enforced outside the model",
        ev: "policy document · enforcement receipts",
      },
      {
        req: "Monitoring and traceability",
        ctrl: "Live activity view of allowed and stopped actions; batches anchored for later independent verification",
        ev: "activity dashboard · anchor proofs",
      },
    ],
    aiActFootnotePre:
      "Whether the AI Act applies to your deployment, and in which risk class, is a legal determination for your organisation. See the official text at ",
    aiActFootnoteLinkLabel: "EUR-Lex (Regulation (EU) 2024/1689)",
    aiActFootnotePost:
      ". SauronID provides governance controls that support the obligations above; it does not classify your system or certify conformity.",
    otherHead: "Other frameworks: what we deliberately do not claim",
    otherP1:
      "SauronID holds no external security or compliance certification today: no SOC 2, no ISO 27001, and none in progress that we would market before completion. Independent cryptographic review is a gate we apply to our own production releases: a discipline, not a badge.",
    otherP2:
      "If your security team runs a questionnaire, we answer with the same material you see here. Where a framework has no defensible mapping, the honest answer is “not covered,” and that is the answer you will get.",
    languageHead: "Language we use and refuse",
    languageUsed: [
      "“Supports GDPR accountability controls”",
      "“Designed to support EU AI Act governance”",
      "“Audit-ready evidence”",
    ],
    languageRefused: [
      "“Certified” / “audited” / “compliant”",
      "“Makes you compliant”",
    ],
    usedLabel: "used",
    refusedLabel: "refused",
    languageFootnote:
      "A vendor's compliance language is itself a signal. Ours is bounded on purpose.",
    commercialLede:
      "Every agent deployment has two audiences: the operator who builds it, and the person who must later approve, audit, or defend it. SauronID is designed so the second conversation is short.",
    proofPoints: [
      {
        strong: "Policy before execution",
        span: "Authority is defined and signed before the agent acts, not reconstructed afterwards from logs and goodwill.",
      },
      {
        strong: "Evidence after execution",
        span: "Receipts, approvals, and stopped actions accumulate automatically. Preparing for an audit is exporting, not archaeology.",
      },
      {
        strong: "Every decision is attributable",
        span: "A named owner authorised the agent. A named approver cleared the sensitive action. A specific rule stopped the bad one.",
      },
      {
        strong: "Governance that scales with adoption",
        span: "The same boundary model that governs one local agent is designed to govern a team's agents under shared policies when Cloud and Workspace arrive.",
      },
    ],
    ctaPrimary: "Get early access",
    ctaSecondary: "See the audit trail",
  },
  fr: {
    h1: "Des preuves et des contrôles qui appuient vos obligations",
    ledeParts: {
      pre: "Aucun logiciel ne rend une organisation conforme. Ce que fait SauronID est plus précis et plus utile : il produit les ",
      controls: "contrôles",
      mid: " que les régulateurs attendent autour des agents IA, et les ",
      evidence: "preuves",
      post: " que ces contrôles ont réellement fonctionné.",
    },
    chipGdpr: "Prend en charge les contrôles de responsabilité RGPD",
    chipAiAct:
      "Conçu pour soutenir la gouvernance du règlement européen sur l'IA (AI Act)",
    chipNoCert: "Aucune certification revendiquée",
    questionsHead: "Les questions auxquelles votre organisation doit pouvoir répondre",
    questionsLede:
      "Quand un agent IA agit à l'intérieur d'une entreprise, quelqu'un en est responsable. Voici les questions qu'un auditeur, un régulateur, une équipe de sécurité ou votre propre direction poseront, et d'où vient la réponse de SauronID.",
    questionsHeaders: ["Question", "Contrôle SauronID", "Preuve produite"] as [
      string,
      string,
      string,
    ],
    questionsRows: [
      {
        req: "Qu'est-ce que cet agent était autorisé à faire ?",
        ctrl: "Capacités explicites et politique côté serveur définies avant la première exécution de l'agent",
        ev: "agent record · capability grants · policy document",
      },
      {
        req: "Qui l'a autorisé ?",
        ctrl: "Mandat signé par le propriétaire, liant un propriétaire nommé à l'agent, à son intention et à une limite de temps",
        ev: "signed mandate · owner identity · TTL",
      },
      {
        req: "Sous quelle politique ?",
        ctrl: "Liaisons de politique versionnées : chaque décision référence la politique qui l'a produite",
        ev: "policy binding on each receipt",
      },
      {
        req: "Que s'est-il réellement passé ?",
        ctrl: "Passerelle à refus par défaut : chaque action protégée est autorisée, mise en pause ou bloquée, et enregistrée dans tous les cas",
        ev: "hash-chained receipts · stopped-action log",
      },
      {
        req: "Une approbation humaine était-elle requise, et a-t-elle été donnée ?",
        ctrl: "Points de contrôle d'approbation sur les actions que vous désignez",
        ev: "approval record: approver, time, action",
      },
      {
        req: "Pouvons-nous le prouver six mois plus tard ?",
        ctrl: "Lots de reçus ancrés sur des horodatages publics que personne ne peut réécrire, y compris nous",
        ev: "Bitcoin OpenTimestamps · Solana anchor · independent verification",
      },
    ],
    gdprLede:
      "Le RGPD demande aux responsables de traitement non seulement d'être responsables, mais de pouvoir démontrer cette responsabilité. Quand des agents touchent des données personnelles, les contrôles de SauronID répondent à cette exigence.",
    gdprHeaders: ["Thème RGPD", "Contrôle SauronID", "Preuve produite"] as [
      string,
      string,
      string,
    ],
    gdprRows: [
      {
        req: "Responsabilité",
        ctrl: "Chaque agent a un propriétaire humain nommé, un mandat signé et une autorité définie. Rien n'agit anonymement",
        ev: "owner-signed mandate",
      },
      {
        req: "Protection des données dès la conception et par défaut",
        ctrl: "Les agents démarrent sans aucun accès ; portées de données, outils et destinations sont accordés délibérément avant la première exécution",
        ev: "capability grants · policy document",
      },
      {
        req: "Accès contrôlé",
        ctrl: "Classification d'autorisation/refus par portée de données et contrôles de destination, appliqués côté serveur à chaque appel protégé",
        ev: "policy evaluation on each receipt",
      },
      {
        req: "Limitation de la finalité, quand techniquement applicable",
        ctrl: "L'intention de l'agent est encodée dans son identifiant ; les capacités sont accordées en fonction de cette intention, et toute dérive est rejetée",
        ev: "intent-bound credential · config digest check",
      },
      {
        req: "Traçabilité et enregistrements d'audit",
        ctrl: "Reçus chaînés par hachage pour les actions autorisées et bloquées ; un journal d'audit de sécurité séparé et inviolable",
        ev: "receipt chain · audit log · anchor proofs",
      },
      {
        req: "Gouvernance humaine",
        ctrl: "Points de contrôle d'approbation, révocation immédiate et mandats à durée limitée maintiennent les humains aux commandes de l'autorité",
        ev: "approval records · revocation events",
      },
    ],
    gdprFootnote:
      "Vos obligations RGPD (base légale, droits des personnes concernées, AIPD, contrats sous-traitants) restent de la responsabilité de votre organisation. SauronID apporte des contrôles et des enregistrements : il ne remplace pas votre programme de confidentialité ni votre conseil juridique.",
    aiActLede:
      "Le règlement européen sur l'IA (AI Act) demande aux organisations qui déploient des systèmes d'IA une supervision humaine, une conservation des enregistrements, de la transparence et un usage prévu défini. Le modèle de produit de SauronID a été construit exactement autour de ces principes, avant même qu'un règlement ne porte leur nom.",
    aiActHeaders: ["Thème AI Act", "Contrôle SauronID", "Preuve produite"] as [
      string,
      string,
      string,
    ],
    aiActRows: [
      {
        req: "Supervision humaine",
        ctrl: "Des points d'approbation mettent en pause les actions désignées pour une décision humaine ; la révocation bloque un agent immédiatement",
        ev: "approval records · revocation events",
      },
      {
        req: "Journalisation et conservation des enregistrements",
        ctrl: "Enregistrements automatiques et inviolables de chaque action protégée : autorisée, mise en pause ou bloquée",
        ev: "hash-chained receipts · audit log",
      },
      {
        req: "Transparence",
        ctrl: "Chaque décision est explicable : l'action, la règle appliquée et le résultat sont lisibles par un non-ingénieur",
        ev: "decision + rule on each record",
      },
      {
        req: "Usage prévu défini",
        ctrl: "L'intention d'un agent est déclarée à sa création et liée à son identifiant, de sorte que l'agent ne peut pas se redétourner silencieusement",
        ev: "intent-bound credential · mandate",
      },
      {
        req: "Contraintes opérationnelles",
        ctrl: "Budgets, débits, fenêtres temporelles, listes d'outils autorisés et portées de données appliqués en dehors du modèle",
        ev: "policy document · enforcement receipts",
      },
      {
        req: "Surveillance et traçabilité",
        ctrl: "Vue d'activité en direct des actions autorisées et bloquées ; lots ancrés pour une vérification indépendante ultérieure",
        ev: "activity dashboard · anchor proofs",
      },
    ],
    aiActFootnotePre:
      "Savoir si l'AI Act s'applique à votre déploiement, et dans quelle classe de risque, relève d'une détermination légale propre à votre organisation. Voir le texte officiel sur ",
    aiActFootnoteLinkLabel: "EUR-Lex (règlement (UE) 2024/1689)",
    aiActFootnotePost:
      ". SauronID fournit des contrôles de gouvernance qui appuient les obligations ci-dessus ; il ne classe pas votre système et ne certifie pas sa conformité.",
    otherHead: "Autres référentiels : ce que nous ne revendiquons délibérément pas",
    otherP1:
      "SauronID ne détient aujourd'hui aucune certification de sécurité ou de conformité externe : ni SOC 2, ni ISO 27001, et aucune en cours que nous mettrions en avant avant son aboutissement. La revue cryptographique indépendante est une condition que nous appliquons à nos propres versions de production : une discipline, pas un badge.",
    otherP2:
      "Si votre équipe de sécurité fait passer un questionnaire, nous répondons avec le même matériel que celui présenté ici. Quand un référentiel n'a pas de correspondance défendable, la réponse honnête est « non couvert », et c'est la réponse que vous obtiendrez.",
    languageHead: "Le langage que nous utilisons et celui que nous refusons",
    languageUsed: [
      "« Prend en charge les contrôles de responsabilité RGPD »",
      "« Conçu pour soutenir la gouvernance du règlement européen sur l'IA »",
      "« Preuves prêtes pour l'audit »",
    ],
    languageRefused: ["« Certifié » / « audité » / « conforme »", "« Vous rend conforme »"],
    usedLabel: "utilisé",
    refusedLabel: "refusé",
    languageFootnote:
      "Le langage de conformité d'un fournisseur est un signal en soi. Le nôtre est volontairement borné.",
    commercialLede:
      "Chaque déploiement d'agent a deux audiences : l'opérateur qui le construit, et la personne qui devra ensuite l'approuver, l'auditer ou le défendre. SauronID est conçu pour que la seconde conversation soit courte.",
    proofPoints: [
      {
        strong: "La politique avant l'exécution",
        span: "L'autorité est définie et signée avant que l'agent n'agisse, et non reconstituée après coup à partir de journaux et de bonne volonté.",
      },
      {
        strong: "La preuve après l'exécution",
        span: "Reçus, approbations et actions bloquées s'accumulent automatiquement. Se préparer pour un audit consiste à exporter, pas à faire de l'archéologie.",
      },
      {
        strong: "Chaque décision est attribuable",
        span: "Un propriétaire nommé a autorisé l'agent. Un approbateur nommé a validé l'action sensible. Une règle précise a bloqué celle qui posait problème.",
      },
      {
        strong: "Une gouvernance qui s'adapte à l'adoption",
        span: "Le même modèle de limites qui gouverne un agent local est conçu pour gouverner les agents d'une équipe sous des politiques partagées quand Cloud et Workspace arriveront.",
      },
    ],
    ctaPrimary: "Obtenir l'accès anticipé",
    ctaSecondary: "Voir la piste d'audit",
  },
} as const;

