export const T = {
  en: {
    hero: {
      h1First: "Build agents you can actually let",
      h1Last: "act.",
      lede: "Give an agent a real job, choose the models and tools it can use, and set the boundaries it cannot cross. Then let it work: every sensitive action is checked against your rules and recorded.",
      ctaPrimary: "Get early access",
      ctaSecondary: "See how it works",
      windowTitle: "Lead research agent",
      status: "Running",
      jobLabel: "Job",
      jobValue: "Research inbound companies and update the approved CRM fields before the Monday pipeline review.",
      capabilitiesLabel: "Capabilities",
      pills: ["Claude · your API key", "Web research", "CRM · read & update"],
      boundariesLabel: "Boundaries",
      boundaries: [
        { rule: "CRM fields it may edit", val: "industry, size, notes" },
        { rule: "Outbound email", val: "needs your approval" },
        { rule: "Delete or export records", val: "never" },
      ],
    },
    benefits: [
      {
        title: "Bounded agents",
        text: "Your agent works inside rules it cannot rewrite: what it may touch, spend, and send.",
      },
      {
        title: "Everything auditable",
        text: "Every action it takes, or gets stopped from taking, is recorded with the rule that decided it.",
      },
      {
        title: "Any supported model",
        text: "Use your own AI subscription or a local model. No code needed; developer tools are there if you want them.",
      },
    ],
    assurance: [
      { name: "GDPR", sub: "supports accountability controls" },
      { name: "EU AI Act", sub: "designed to support governance" },
      { name: "Ed25519 signatures", sub: "every protected action signed" },
      { name: "Local-first", sub: "your data stays on your machine" },
      { name: "Source available", sub: "inspect the enforcement yourself" },
    ],
    path: {
      h2: "Every agent walks the same path",
      lede: "You write the job, grant the tools, set the rules, run it, and keep the receipts. At the end of the fifth checkpoint you have an agent you can leave alone with real work.",
      cp1: {
        kind: "Intent",
        h2Rest: "Give it a job, not a personality",
        lede: "Start by writing what the agent should accomplish, in plain language. That sentence becomes part of the agent's signed identity, so the agent you approved is the agent that runs. It can't drift into something else.",
        intentLabel: "This agent's job",
        intentText: "Keep our CRM enriched and flag accounts worth a call.",
        intentMeta: "intent bound to credential · signed by owner · valid 90 days",
      },
      cp2: {
        kind: "Capabilities",
        h2Rest: "You hand it every tool yourself",
        lede: "A new agent can't touch anything. You grant each model, tool, and data source yourself, and the Launcher tells you what a grant lets the agent do before you say yes.",
        connect: [
          { item: "Claude · your API key", state: "connected" },
          { item: "Web research", state: "granted" },
          { item: "CRM · read & update", state: "granted · 3 fields" },
          { item: "Email · send", state: "not granted" },
        ],
      },
      cp3: {
        kind: "Boundaries",
        h2Rest: "Rules the agent cannot rewrite",
        lede: "Every rule reads like a sentence and enforces like a contract: the rule, its current value, and what happens when it is crossed. The checks run in a gateway outside the model, so a clever prompt changes nothing.",
        panelReview: {
          h3: "Human approval when it matters",
          boundaries: [
            { rule: "Payments above €500", val: "pause for approval" },
            { rule: "Outbound email", val: "pause for approval" },
          ],
          note: "The run pauses at the checkpoint. You approve or decline in one click, and your decision is written into the record.",
        },
        panelLimits: {
          h3: "Limits it cannot exceed",
          boundaries: [
            { rule: "Daily model spend", val: "≤ €50 / day" },
            { rule: "API requests", val: "≤ 60 / minute" },
            { rule: "Destinations outside the approved list", val: "stopped" },
          ],
          note: "Budgets, rates, and destinations are enforced by the gateway on every protected call, not suggested to the model and hoped for.",
        },
      },
      cp4: {
        kind: "Run",
        h2Rest: "Useful when it stays in scope. Stopped when it does not.",
        lede: "Here is the moment that matters: one agent, four attempted actions, one set of rules. Select any action to see the exact rule behind its decision.",
      },
      cp5: {
        kind: "Proof",
        h2Rest: "Every action leaves evidence",
        lede: "When someone asks what this agent was allowed to do and what it actually did, you answer with records.",
        trail: [
          {
            h4: "14:02 · Update qualified lead",
            p: "Within capability and data scope.",
            evidence: "allowed · receipt #4,182 · chained to #4,181",
          },
          {
            h4: "14:07 · Send invoice payment",
            p: "€25,000 exceeds the €500 approval threshold.",
            evidence: "paused · approved by C. Moreau at 14:31",
          },
          {
            h4: "14:44 · Export all contact records",
            p: "Exports are not granted to this agent.",
            evidence: "stopped · rule: crm.export not granted",
          },
        ],
        proofPoints: [
          {
            title: "Receipts chain together",
            text: "Edit one record and every record after it shows the break.",
          },
          {
            title: "Stopped actions are records too",
            text: "Proof the control fired, not just that nothing went wrong.",
          },
          {
            title: "History no one can rewrite",
            text: "Record batches are stamped on public timestamp networks. Not even we can edit the past.",
          },
        ],
        proofNote: "illustrative run · anchor networks: Bitcoin (OpenTimestamps) · Solana · used as public clocks only, no crypto needed on your side",
        ctaAudit: "See the full audit trail",
        ctaCompliance: "Compliance & governance",
      },
    },
    mechanism: {
      h2: "What actually stops it?",
      lede: "We keep saying the agent cannot act outside what you approved. Here is the mechanism, made touchable.",
      points: [
        {
          title: "Every sensitive action is sealed as a ring",
          text: "Five facts signed together as one seal, valid exactly once: what it does, on what, to whom, for how much, and a one-time nonce.",
        },
        {
          title: "The seal is checked outside the model",
          text: "The gateway verifies it before the action reaches your tools. A clever prompt cannot talk past it.",
        },
        {
          title: "A broken seal is a rejected request",
          text: "Change any one fact and the whole seal fails. The rejection is recorded. That seal is where SauronID gets its name.",
        },
      ],
      link: "Read the full enforcement architecture →",
    },
    useCases: {
      h2: "What would you let it do?",
      lede: "Early access opens with templates for jobs like these. Each one shows the same thing: real work gets done, and the risky moves stay in your hands.",
      items: [
        {
          for: "For sales & revenue ops",
          h3: "Your pipeline is enriched before Monday",
          benefit: "The agent researches inbound companies overnight and fills in the CRM fields you chose. You arrive to a clean pipeline.",
          boundaries: [
            { rule: "Update industry, size, notes", val: "allowed" },
            { rule: "Send outreach email", val: "waits for you" },
            { rule: "Export your customer base", val: "stopped" },
          ],
        },
        {
          for: "For support teams",
          h3: "Your queue is triaged before you sit down",
          benefit: "Tickets get classified and answers drafted from your own documentation. Small fixes happen; sensitive ones wait.",
          boundaries: [
            { rule: "Refund under your threshold", val: "allowed" },
            { rule: "Refund above it", val: "waits for you" },
            { rule: "Read other customers' data", val: "stopped" },
          ],
        },
        {
          for: "For finance ops",
          h3: "Your invoices reconcile themselves",
          benefit: "The agent matches invoices, flags discrepancies, and lines up the payment run. Money only moves when you approve it.",
          boundaries: [
            { rule: "Match invoices to payments", val: "allowed" },
            { rule: "Execute a payment", val: "waits for you" },
            { rule: "Pay an unknown supplier", val: "stopped" },
          ],
        },
      ],
      ctaExplore: "And many more: explore use cases",
      note: "Scenarios describe the early-access product direction.",
    },
    launcher: {
      h2: "Your agent. Your model. Your machine.",
      lede: "Early access is a desktop app with a guided setup: your first bounded agent runs on your computer, no technical skills needed. Cloud and team plans follow, with the same boundaries.",
      launcherPanel: {
        chip: "Early access",
        h3: "SauronID Launcher",
        items: [
          "A guided setup: describe the job, pick the tools, set the rules.",
          "Works with your own AI subscription or a model on your computer.",
          "Free to run. You see everything the agent did, and everything it was stopped from doing.",
          "Supported models depend on your machine and provider.",
        ],
        cta: "Join early access",
      },
      cloudPanel: {
        chip: "Coming later",
        h3: "SauronID Cloud",
        items: [
          "Hosted execution: agents that run without your computer being on.",
          "Broader model access, schedules, and background runs.",
          "Team workspaces, shared policies, approval routing, centralised audit.",
          "Same agent definition. Same boundary model. Different runtime.",
        ],
        cta: "What Cloud will be",
      },
    },
    faq: {
      h2: "Questions operators actually ask",
      items: [
        {
          q: "Do I need to be a developer?",
          a: "No. The Launcher is a guided desktop application: you describe the job in plain language, connect a model, pick tools, and set boundaries with readable controls. Technical depth (policies, signatures, receipts) stays available for whoever validates the setup, but it is never the front door.",
        },
        {
          q: "What stops the agent from ignoring its rules?",
          aBefore: "The rules live in a gateway between the agent and your tools, so a protected action that breaks one is rejected before it reaches the tool. The rejection is recorded along with the rule that caused it. One honest limit: in production, the deployment must also prevent the agent from reaching the network around the gateway.",
          link: "The security page spells this out.",
        },
        {
          q: "Which models can I use?",
          a: "Early access supports a defined set of local models and API providers, using your own key. We publish the exact supported list with the Launcher rather than promising “any model, anywhere.” Model availability depends on your provider, operating system, and hardware.",
        },
        {
          q: "Where does my API key live?",
          a: "On your machine. The Launcher validates the key when you enter it, masks it afterwards, and never prints it in logs. You can delete or rotate it at any time.",
        },
        {
          q: "What does early access cost?",
          aBefore: "Local execution is free: you bring your own model or API key, so your only costs are your provider's. Paid plans arrive with SauronID Cloud, later.",
          link: "See pricing.",
        },
        {
          q: "Can I stop an agent immediately?",
          a: "Yes. Revoking an agent makes its next protected action fail. There is no grace period, and the revocation itself becomes part of the record.",
        },
        {
          q: "Does SauronID make my company compliant?",
          aBefore: "No tool does. SauronID produces the controls and evidence that support your obligations: defined authority, human oversight, and verifiable records. Your policies, processes, and legal review remain yours.",
          link: "See exactly what maps where.",
        },
      ],
    },
    finalCta: {
      h2: "Build the first agent your team can actually let work.",
      lede: "Join early access and get the SauronID Launcher when your cohort opens. Local execution stays free, with your own model or API key. Cloud execution and team plans come next.",
      ctaPrimary: "Get early access",
      ctaSecondary: "Read the architecture",
    },
  },
  fr: {
    hero: {
      h1First: "Construisez des agents que vous pouvez vraiment laisser",
      h1Last: "agir.",
      lede: "Confiez à un agent un vrai travail, choisissez les modèles et les outils qu'il peut utiliser, et fixez les limites qu'il ne peut pas franchir. Ensuite, laissez-le travailler : chaque action sensible est vérifiée par rapport à vos règles et enregistrée.",
      ctaPrimary: "Accès anticipé",
      ctaSecondary: "Voir comment ça marche",
      windowTitle: "Agent de recherche commerciale",
      status: "En cours",
      jobLabel: "Mission",
      jobValue: "Rechercher les entreprises entrantes et mettre à jour les champs CRM approuvés avant la revue de pipeline du lundi.",
      capabilitiesLabel: "Capacités",
      pills: ["Claude · votre clé API", "Recherche web", "CRM · lecture et mise à jour"],
      boundariesLabel: "Limites",
      boundaries: [
        { rule: "Champs CRM qu'il peut modifier", val: "industry, size, notes" },
        { rule: "E-mail sortant", val: "attend votre accord" },
        { rule: "Supprimer ou exporter des données", val: "jamais" },
      ],
    },
    benefits: [
      {
        title: "Agents encadrés",
        text: "Votre agent travaille selon des règles qu'il ne peut pas réécrire : ce qu'il peut toucher, dépenser et envoyer.",
      },
      {
        title: "Tout est auditable",
        text: "Chaque action qu'il effectue, ou qu'il est empêché d'effectuer, est enregistrée avec la règle qui a décidé.",
      },
      {
        title: "Tout modèle pris en charge",
        text: "Utilisez votre propre abonnement IA ou un modèle local. Aucun code nécessaire ; les SDK sont là si vous en voulez.",
      },
    ],
    assurance: [
      { name: "RGPD", sub: "prend en charge les contrôles de responsabilité" },
      { name: "Règlement IA de l'UE", sub: "conçu pour soutenir la gouvernance" },
      { name: "Signatures Ed25519", sub: "chaque action protégée est signée" },
      { name: "Local d'abord", sub: "vos données restent sur votre machine" },
      { name: "Code source accessible", sub: "vérifiez vous-même l'application des règles" },
    ],
    path: {
      h2: "Chaque agent suit le même chemin",
      lede: "Vous rédigez la mission, accordez les outils, fixez les règles, lancez l'exécution, et conservez les reçus. Au terme du cinquième point de contrôle, vous avez un agent que vous pouvez laisser seul avec un vrai travail.",
      cp1: {
        kind: "Intention",
        h2Rest: "Donnez-lui une mission, pas une personnalité",
        lede: "Commencez par écrire, en langage clair, ce que l'agent doit accomplir. Cette phrase fait partie de l'identifiant de l'agent : l'agent que vous avez approuvé est celui qui s'exécute. Il ne peut pas dériver vers autre chose.",
        intentLabel: "La mission de cet agent",
        intentText: "Enrichissez notre CRM et signalez les comptes à appeler.",
        intentMeta: "intent bound to credential · signed by owner · valid 90 days",
      },
      cp2: {
        kind: "Capacités",
        h2Rest: "Vous lui confiez chaque outil vous-même",
        lede: "Un nouvel agent ne peut rien toucher. Vous accordez vous-même chaque modèle, outil et source de données, et le Launcher vous explique ce qu'une autorisation permet avant que vous ne disiez oui.",
        connect: [
          { item: "Claude · votre clé API", state: "connecté" },
          { item: "Recherche web", state: "accordé" },
          { item: "CRM · lecture et mise à jour", state: "accordé · 3 champs" },
          { item: "E-mail · envoi", state: "non accordé" },
        ],
      },
      cp3: {
        kind: "Limites",
        h2Rest: "Des règles que l'agent ne peut pas réécrire",
        lede: "Chaque règle se lit comme une phrase et s'applique comme un contrat : la règle, sa valeur actuelle, et ce qui se passe si elle est franchie. Les vérifications s'exécutent dans une passerelle en dehors du modèle, si bien qu'une invite habile ne change rien.",
        panelReview: {
          h3: "Une validation humaine quand cela compte",
          boundaries: [
            { rule: "Paiements au-dessus de 500 €", val: "en pause pour approbation" },
            { rule: "E-mail sortant", val: "en pause pour approbation" },
          ],
          note: "L'exécution se met en pause au point de contrôle. Vous approuvez ou refusez en un clic, et votre décision est inscrite dans l'enregistrement.",
        },
        panelLimits: {
          h3: "Des limites qu'il ne peut pas dépasser",
          boundaries: [
            { rule: "Dépense modèle quotidienne", val: "≤ 50 € / jour" },
            { rule: "Requêtes API", val: "≤ 60 / minute" },
            { rule: "Destinations hors de la liste approuvée", val: "bloqué" },
          ],
          note: "Budgets, débits et destinations sont appliqués côté serveur à chaque appel protégé, pas simplement suggérés au modèle en espérant qu'il obéisse.",
        },
      },
      cp4: {
        kind: "Exécution",
        h2Rest: "Utile tant qu'il reste dans le cadre. Bloqué dès qu'il en sort.",
        lede: "Voici le moment qui compte : un agent, quatre tentatives d'action, un seul jeu de règles. Sélectionnez une action pour voir la règle exacte derrière sa décision.",
      },
      cp5: {
        kind: "Preuve",
        h2Rest: "Chaque action laisse une preuve",
        lede: "Quand on vous demande ce que cet agent était autorisé à faire et ce qu'il a réellement fait, vous répondez avec des preuves.",
        trail: [
          {
            h4: "14:02 · Mise à jour d'un lead qualifié",
            p: "Dans le périmètre de capacité et de données.",
            evidence: "allowed · receipt #4,182 · chained to #4,181",
          },
          {
            h4: "14:07 · Envoi du paiement de facture",
            p: "25 000 € dépasse le seuil d'approbation de 500 €.",
            evidence: "paused · approved by C. Moreau at 14:31",
          },
          {
            h4: "14:44 · Export de tous les contacts",
            p: "Les exports ne sont pas accordés à cet agent.",
            evidence: "stopped · rule: crm.export not granted",
          },
        ],
        proofPoints: [
          {
            title: "Les reçus s'enchaînent",
            text: "Modifiez un enregistrement et tous ceux qui suivent révèlent la rupture.",
          },
          {
            title: "Les actions bloquées sont aussi des preuves",
            text: "La preuve que le contrôle s'est déclenché, pas seulement que rien ne s'est mal passé.",
          },
          {
            title: "Un historique que personne ne peut réécrire",
            text: "Les lots de reçus sont horodatés sur des réseaux publics. Même nous ne pouvons pas modifier le passé.",
          },
        ],
        proofNote: "illustrative run · anchor networks: Bitcoin (OpenTimestamps) · Solana · used as public clocks only, no crypto needed on your side",
        ctaAudit: "Voir la piste d'audit complète",
        ctaCompliance: "Conformité et gouvernance",
      },
    },
    mechanism: {
      h2: "Qu'est-ce qui l'arrête vraiment ?",
      lede: "Nous répétons que l'agent ne peut pas agir en dehors de ce que vous avez approuvé. Voici le mécanisme, à tester vous-même.",
      points: [
        {
          title: "Chaque action sensible est scellée dans un anneau",
          text: "Cinq faits signés ensemble en un seul sceau, valable une seule fois : ce qu'il fait, sur quoi, vers qui, pour quel montant, et un nonce à usage unique.",
        },
        {
          title: "Le sceau est vérifié en dehors du modèle",
          text: "La passerelle le vérifie avant que l'action n'atteigne vos outils. Une invite habile ne peut pas la contourner.",
        },
        {
          title: "Un sceau brisé est une requête rejetée",
          text: "Changez un seul fait et tout le sceau échoue. Le rejet est enregistré. Ce sceau est à l'origine du nom de SauronID.",
        },
      ],
      link: "Lire l'architecture d'application complète →",
    },
    useCases: {
      h2: "Que lui laisseriez-vous faire ?",
      lede: "L'accès anticipé s'ouvre avec des modèles pour des missions comme celles-ci. Chacune montre la même chose : le vrai travail avance, et les décisions risquées restent entre vos mains.",
      items: [
        {
          for: "Pour les ventes et le revenue ops",
          h3: "Votre pipeline est enrichi avant lundi",
          benefit: "L'agent recherche les entreprises entrantes pendant la nuit et remplit les champs CRM que vous avez choisis. Vous arrivez devant un pipeline propre.",
          boundaries: [
            { rule: "Mettre à jour secteur, taille, notes", val: "autorisé" },
            { rule: "Envoyer un e-mail de prospection", val: "attend votre accord" },
            { rule: "Exporter votre base clients", val: "bloqué" },
          ],
        },
        {
          for: "Pour les équipes support",
          h3: "Votre file est triée avant que vous ne commenciez",
          benefit: "Les tickets sont classés et les réponses rédigées à partir de votre propre documentation. Les corrections mineures se font ; les cas sensibles attendent.",
          boundaries: [
            { rule: "Remboursement sous votre seuil", val: "autorisé" },
            { rule: "Remboursement au-dessus", val: "attend votre accord" },
            { rule: "Lire les données d'autres clients", val: "bloqué" },
          ],
        },
        {
          for: "Pour la finance",
          h3: "Vos factures se rapprochent d'elles-mêmes",
          benefit: "L'agent rapproche les factures, signale les écarts, et prépare le cycle de paiement. L'argent ne bouge que lorsque vous l'approuvez.",
          boundaries: [
            { rule: "Rapprocher factures et paiements", val: "autorisé" },
            { rule: "Exécuter un paiement", val: "attend votre accord" },
            { rule: "Payer un fournisseur inconnu", val: "bloqué" },
          ],
        },
      ],
      ctaExplore: "Et bien d'autres : explorez les cas d'usage",
      note: "Les scénarios décrivent l'orientation produit de l'accès anticipé.",
    },
    launcher: {
      h2: "Votre agent. Votre modèle. Votre machine.",
      lede: "L'accès anticipé est une application de bureau avec une configuration guidée : votre premier agent encadré fonctionne sur votre machine, sans compétences techniques. Le cloud et les offres d'équipe suivent, avec les mêmes limites.",
      launcherPanel: {
        chip: "Accès anticipé",
        h3: "SauronID Launcher",
        items: [
          "Une configuration guidée : décrivez la mission, choisissez les outils, fixez les règles.",
          "Fonctionne avec votre propre abonnement IA ou un modèle sur votre machine.",
          "Gratuit à l'usage. Vous voyez tout ce que l'agent a fait, et tout ce qu'il a été empêché de faire.",
          "Les modèles pris en charge dépendent de votre machine et de votre fournisseur.",
        ],
        cta: "Rejoindre l'accès anticipé",
      },
      cloudPanel: {
        chip: "Plus tard",
        h3: "SauronID Cloud",
        items: [
          "Exécution hébergée : des agents qui tournent sans que votre machine soit allumée.",
          "Accès élargi aux modèles, planifications et exécutions en arrière-plan.",
          "Espaces d'équipe, politiques partagées, circuits d'approbation, audit centralisé.",
          "Même définition d'agent. Même modèle de limites. Exécution différente.",
        ],
        cta: "Ce que sera Cloud",
      },
    },
    faq: {
      h2: "Les questions que se posent vraiment les opérateurs",
      items: [
        {
          q: "Dois-je être développeur ?",
          a: "Non. Le Launcher est une application de bureau guidée : vous décrivez la mission en langage clair, connectez un modèle, choisissez des outils, et fixez des limites avec des contrôles lisibles. La profondeur technique (politiques, signatures, reçus) reste accessible à qui valide la configuration, mais elle n'est jamais le point d'entrée.",
        },
        {
          q: "Qu'est-ce qui empêche l'agent d'ignorer ses règles ?",
          aBefore: "Les règles vivent dans une passerelle entre l'agent et vos outils, si bien qu'une action protégée qui en enfreint une est rejetée avant d'atteindre l'outil. Le rejet est enregistré avec la règle qui l'a causé. Une limite honnête : en production, le déploiement doit aussi empêcher l'agent d'atteindre le réseau autour de la passerelle.",
          link: "La page sécurité l'explique en détail.",
        },
        {
          q: "Quels modèles puis-je utiliser ?",
          a: "L'accès anticipé prend en charge un ensemble défini de modèles locaux et de fournisseurs d'API, avec votre propre clé. Nous publions la liste exacte prise en charge avec le Launcher plutôt que de promettre « n'importe quel modèle, n'importe où ». La disponibilité des modèles dépend de votre fournisseur, de votre système d'exploitation et de votre matériel.",
        },
        {
          q: "Où vit ma clé API ?",
          a: "Sur votre machine. Le Launcher valide la clé quand vous la saisissez, la masque ensuite, et ne l'affiche jamais dans les journaux. Vous pouvez la supprimer ou la renouveler à tout moment.",
        },
        {
          q: "Combien coûte l'accès anticipé ?",
          aBefore: "L'exécution locale est gratuite : vous apportez votre propre modèle ou clé API, vos seuls coûts sont donc ceux de votre fournisseur. Les offres payantes arrivent avec SauronID Cloud, plus tard.",
          link: "Voir les tarifs.",
        },
        {
          q: "Puis-je arrêter un agent immédiatement ?",
          a: "Oui. Révoquer un agent fait échouer sa prochaine action protégée. Il n'y a pas de délai de grâce, et la révocation elle-même fait partie de l'enregistrement.",
        },
        {
          q: "SauronID rend-il mon entreprise conforme ?",
          aBefore: "Aucun outil ne le fait. SauronID produit les contrôles et les preuves qui soutiennent vos obligations : autorité définie, supervision humaine et enregistrements vérifiables. Vos politiques, vos processus et votre revue juridique restent les vôtres.",
          link: "Voyez exactement ce qui correspond à quoi.",
        },
      ],
    },
    finalCta: {
      h2: "Construisez le premier agent que votre équipe peut vraiment laisser travailler.",
      lede: "Rejoignez l'accès anticipé et obtenez le SauronID Launcher à l'ouverture de votre cohorte. L'exécution locale reste gratuite, avec votre propre modèle ou clé API. L'exécution cloud et les offres d'équipe arrivent ensuite.",
      ctaPrimary: "Accès anticipé",
      ctaSecondary: "Lire l'architecture",
    },
  },
} as const;

