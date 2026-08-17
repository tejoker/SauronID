type RuleKind = "allowed" | "review" | "stopped";
type Rule = { rule: string; val: string; kind: RuleKind };
interface Scenario {
  team: string;
  title: string;
  benefit: string;
  why: string;
  rules: Rule[];
}

export const SCENARIOS_EN: Scenario[] = [
  {
    team: "Sales & revenue ops",
    title: "Your pipeline is enriched before Monday",
    benefit:
      "The agent researches inbound companies overnight and fills in the CRM fields you chose. You arrive to a clean pipeline.",
    why: "CRM write access is where enrichment agents usually get refused. Field-level grants and a hard stop on exports are what make the approval conversation short.",
    rules: [
      { rule: "Update industry, size, notes", val: "allowed", kind: "allowed" },
      { rule: "Send outreach email", val: "waits for you", kind: "review" },
      { rule: "Export your customer base", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "Support teams",
    title: "Your queue is triaged before you sit down",
    benefit:
      "Tickets get classified and answers drafted from your own documentation. Small fixes happen; sensitive ones wait.",
    why: "A support agent sees customer data all day. Scoping it to the ticket's own customer is the difference between a helpful tool and a privacy incident.",
    rules: [
      { rule: "Refund under your threshold", val: "allowed", kind: "allowed" },
      { rule: "Refund above it", val: "waits for you", kind: "review" },
      { rule: "Read other customers' data", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "Finance ops",
    title: "Your invoices reconcile themselves",
    benefit:
      "The agent matches invoices, flags discrepancies, and lines up the payment run. Money only moves when you approve it.",
    why: "Payments are the clearest case for approval gates: the agent does all the preparation, and the irreversible step stays human.",
    rules: [
      { rule: "Match invoices to payments", val: "allowed", kind: "allowed" },
      { rule: "Execute a payment", val: "waits for you", kind: "review" },
      { rule: "Pay an unknown supplier", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "Recruiting",
    title: "Your inbox of applications is screened by morning",
    benefit:
      "The agent reads applications against your criteria, shortlists, and drafts personalised replies for your review.",
    why: "Hiring decisions carry legal weight. Keeping the agent on drafting and shortlisting, with a human sending every message, keeps it defensible.",
    rules: [
      { rule: "Screen and shortlist applications", val: "allowed", kind: "allowed" },
      { rule: "Reply to a candidate", val: "waits for you", kind: "review" },
      { rule: "Reject a candidate on its own", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "Marketing",
    title: "Your content calendar fills itself",
    benefit:
      "The agent drafts posts and variations in your voice, lines them up for the week, and nothing ships without a look.",
    why: "Publishing is the outward-facing action. Draft freely, publish through a checkpoint: the brand stays yours.",
    rules: [
      { rule: "Draft posts and variations", val: "allowed", kind: "allowed" },
      { rule: "Publish to your channels", val: "waits for you", kind: "review" },
      { rule: "Reply publicly to customers", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "E-commerce ops",
    title: "Your catalogue stays clean without you",
    benefit:
      "The agent rewrites product descriptions, fixes categorisation, and flags inventory anomalies for review.",
    why: "Catalogue edits are reversible; price changes are revenue. Splitting the two into different permission levels is what makes the agent trustworthy.",
    rules: [
      { rule: "Edit descriptions and tags", val: "allowed", kind: "allowed" },
      { rule: "Change a price", val: "waits for you", kind: "review" },
      { rule: "Unpublish a product line", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "Executive assistance",
    title: "Your inbox is sorted and your replies are drafted",
    benefit:
      "The agent triages email, drafts responses in your tone, and proposes calendar moves. You confirm, it executes.",
    why: "An assistant agent touches everything you touch. Send-on-approval is what lets it read broadly without ever speaking for you uninvited.",
    rules: [
      { rule: "Triage and draft replies", val: "allowed", kind: "allowed" },
      { rule: "Send an email as you", val: "waits for you", kind: "review" },
      { rule: "Delete or forward threads", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "IT & internal support",
    title: "Your ticket backlog handles the routine itself",
    benefit:
      "The agent resolves the repetitive requests, access checks, how-tos, standard resets, and routes the rest with context attached.",
    why: "Internal IT agents fail reviews on privilege escalation. Explicit deny on admin-level changes is the control your security team will ask about first.",
    rules: [
      { rule: "Answer how-tos, prepare resets", val: "allowed", kind: "allowed" },
      { rule: "Grant a standard access", val: "waits for you", kind: "review" },
      { rule: "Change admin permissions", val: "stopped", kind: "stopped" },
    ],
  },
  {
    team: "Research & analysis",
    title: "Your weekly report writes its first draft",
    benefit:
      "The agent pulls from the sources you granted, aggregates, and drafts the analysis. You keep the judgment.",
    why: "Analysis agents want broad read access. Bounding what leaves the environment, no raw exports, no external sends, is what makes broad reads acceptable.",
    rules: [
      { rule: "Read granted sources, aggregate", val: "allowed", kind: "allowed" },
      { rule: "Share outside the team", val: "waits for you", kind: "review" },
      { rule: "Export raw records", val: "stopped", kind: "stopped" },
    ],
  },
];

export const SCENARIOS_FR: Scenario[] = [
  {
    team: "Ventes & revenue ops",
    title: "Votre pipeline est enrichi avant lundi",
    benefit:
      "L'agent recherche les entreprises entrantes pendant la nuit et remplit les champs CRM que vous avez choisis. Vous arrivez face à un pipeline propre.",
    why: "L'accès en écriture au CRM est souvent ce qui fait refuser les agents d'enrichissement. Des droits au niveau du champ et un blocage strict sur les exports rendent la conversation d'approbation courte.",
    rules: [
      { rule: "Mettre à jour secteur, taille, notes", val: "autorisé", kind: "allowed" },
      { rule: "Envoyer un email de prospection", val: "attend votre accord", kind: "review" },
      { rule: "Exporter votre base clients", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "Équipes support",
    title: "Votre file est triée avant que vous ne vous asseyiez",
    benefit:
      "Les tickets sont classés et des réponses rédigées à partir de votre propre documentation. Les petites corrections se font ; les sensibles attendent.",
    why: "Un agent support voit des données clients toute la journée. Le limiter au client propre au ticket fait la différence entre un outil utile et un incident de confidentialité.",
    rules: [
      { rule: "Remboursement sous votre seuil", val: "autorisé", kind: "allowed" },
      { rule: "Remboursement au-delà", val: "attend votre accord", kind: "review" },
      { rule: "Lire les données d'autres clients", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "Finance ops",
    title: "Vos factures se rapprochent d'elles-mêmes",
    benefit:
      "L'agent rapproche les factures, signale les écarts et prépare le cycle de paiement. L'argent ne bouge que lorsque vous approuvez.",
    why: "Les paiements sont le cas le plus clair pour les points d'approbation : l'agent fait toute la préparation, et l'étape irréversible reste humaine.",
    rules: [
      { rule: "Rapprocher factures et paiements", val: "autorisé", kind: "allowed" },
      { rule: "Exécuter un paiement", val: "attend votre accord", kind: "review" },
      { rule: "Payer un fournisseur inconnu", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "Recrutement",
    title: "Votre boîte de candidatures est triée dès le matin",
    benefit:
      "L'agent lit les candidatures selon vos critères, présélectionne, et rédige des réponses personnalisées pour votre relecture.",
    why: "Les décisions de recrutement ont un poids juridique. Cantonner l'agent à la rédaction et la présélection, avec un humain qui envoie chaque message, garde la démarche défendable.",
    rules: [
      { rule: "Trier et présélectionner les candidatures", val: "autorisé", kind: "allowed" },
      { rule: "Répondre à un candidat", val: "attend votre accord", kind: "review" },
      { rule: "Rejeter un candidat de son propre chef", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "Marketing",
    title: "Votre calendrier de contenu se remplit tout seul",
    benefit:
      "L'agent rédige des publications et des variantes dans votre ton, les prépare pour la semaine, et rien ne sort sans relecture.",
    why: "La publication est l'action tournée vers l'extérieur. Rédiger librement, publier via un point de contrôle : la marque reste la vôtre.",
    rules: [
      { rule: "Rédiger publications et variantes", val: "autorisé", kind: "allowed" },
      { rule: "Publier sur vos canaux", val: "attend votre accord", kind: "review" },
      { rule: "Répondre publiquement aux clients", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "E-commerce ops",
    title: "Votre catalogue reste propre sans vous",
    benefit:
      "L'agent réécrit les descriptions produits, corrige la catégorisation et signale les anomalies de stock pour relecture.",
    why: "Les modifications de catalogue sont réversibles ; les changements de prix touchent au revenu. Séparer les deux en niveaux de permission différents rend l'agent fiable.",
    rules: [
      { rule: "Modifier descriptions et étiquettes", val: "autorisé", kind: "allowed" },
      { rule: "Changer un prix", val: "attend votre accord", kind: "review" },
      { rule: "Dépublier une gamme de produits", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "Assistance de direction",
    title: "Votre boîte mail est triée et vos réponses rédigées",
    benefit:
      "L'agent trie les emails, rédige des réponses dans votre ton, et propose des déplacements de rendez-vous. Vous confirmez, il exécute.",
    why: "Un agent assistant touche à tout ce que vous touchez. L'envoi sur approbation lui permet de lire largement sans jamais parler en votre nom sans y être invité.",
    rules: [
      { rule: "Trier et rédiger les réponses", val: "autorisé", kind: "allowed" },
      { rule: "Envoyer un email en votre nom", val: "attend votre accord", kind: "review" },
      { rule: "Supprimer ou transférer des fils", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "IT & support interne",
    title: "Votre backlog de tickets gère le routinier lui-même",
    benefit:
      "L'agent résout les demandes répétitives, vérifications d'accès, tutoriels, réinitialisations standards, et route le reste avec le contexte joint.",
    why: "Les agents IT internes échouent aux relectures sur l'élévation de privilèges. Un refus explicite sur les changements de niveau administrateur est le contrôle que votre équipe sécurité demandera en premier.",
    rules: [
      { rule: "Répondre aux tutoriels, préparer les réinitialisations", val: "autorisé", kind: "allowed" },
      { rule: "Accorder un accès standard", val: "attend votre accord", kind: "review" },
      { rule: "Modifier les permissions administrateur", val: "bloqué", kind: "stopped" },
    ],
  },
  {
    team: "Recherche & analyse",
    title: "Votre rapport hebdomadaire rédige son premier brouillon",
    benefit:
      "L'agent puise dans les sources que vous avez autorisées, agrège, et rédige l'analyse. Vous gardez le jugement.",
    why: "Les agents d'analyse veulent un accès en lecture large. Limiter ce qui sort de l'environnement, aucun export brut, aucun envoi externe, est ce qui rend les lectures larges acceptables.",
    rules: [
      { rule: "Lire les sources autorisées, agréger", val: "autorisé", kind: "allowed" },
      { rule: "Partager en dehors de l'équipe", val: "attend votre accord", kind: "review" },
      { rule: "Exporter des enregistrements bruts", val: "bloqué", kind: "stopped" },
    ],
  },
];

export const T = {
  en: {
    h1: "How teams put bounded agents to work",
    lede: (
      <>
        Concrete examples of AI agents doing a real job inside a company, and
        the boundaries that make each one safe enough to actually run. Every
        scenario follows the same shape: useful actions are allowed,
        sensitive ones wait for a human, dangerous ones are stopped and
        recorded.
      </>
    ),
    forLabel: "For",
    gridFootnote: (
      <>
        Scenarios describe the early-access product direction. Available
        tools and connectors depend on launcher support at release.
      </>
    ),
    whyKind: "Structural.",
    whyH2: "Why the boundaries are the point",
    whyBody1: (
      <>
        Most teams do not lack ideas for agents. They lack a way to say yes
        to one. The moment an agent can write to a CRM, send an email, or
        move money, someone in the company has to answer for what it might
        do. A system prompt is not an answer.
      </>
    ),
    whyBody2: (
      <>
        Every scenario on this page works because the risky step is kept
        separate from the useful ones. It is enforced by a gateway outside
        the model, and recorded either way. That is what turns
        &quot;we should try agents&quot; into an approved project.
      </>
    ),
    startKind: "Start.",
    startH2: "Start with one job",
    startBody: (
      <>
        Pick the scenario closest to your week and narrow it to one recurring
        task. Give the agent the smallest set of grants that gets it done,
        and add an approval gate on anything outward-facing. You can widen
        the boundaries once the activity record has earned it.
      </>
    ),
    ctaPrimary: "Get early access",
    ctaSecondary: "How enforcement works",
  },
  fr: {
    h1: "Comment les équipes mettent des agents bornés au travail",
    lede: (
      <>
        Des exemples concrets d&apos;agents IA effectuant un vrai travail
        dans une entreprise, et les limites qui rendent chacun suffisamment
        sûr pour être réellement exécuté. Chaque scénario suit la même
        forme : les actions utiles sont autorisées, les sensibles attendent
        un humain, les dangereuses sont bloquées et enregistrées.
      </>
    ),
    forLabel: "Pour",
    gridFootnote: (
      <>
        Les scénarios décrivent l&apos;orientation produit de l&apos;accès
        anticipé. Les outils et connecteurs disponibles dépendent de la prise
        en charge du launcher au lancement.
      </>
    ),
    whyKind: "Structurel.",
    whyH2: "Pourquoi les limites sont le point central",
    whyBody1: (
      <>
        La plupart des équipes ne manquent pas d&apos;idées d&apos;agents.
        Elles manquent d&apos;un moyen d&apos;en approuver un. Dès qu&apos;un
        agent peut écrire dans un CRM, envoyer un email, ou déplacer de
        l&apos;argent, quelqu&apos;un dans l&apos;entreprise doit répondre de
        ce qu&apos;il pourrait faire, et un system prompt n&apos;est pas une
        réponse.
      </>
    ),
    whyBody2: (
      <>
        Chaque scénario de cette page fonctionne parce que l&apos;étape
        risquée est structurellement séparée des étapes utiles : appliquée
        par une passerelle extérieure au modèle, enregistrée dans les deux
        cas. C&apos;est ce qui transforme « nous devrions essayer les
        agents » en projet approuvé.
      </>
    ),
    startKind: "Départ.",
    startH2: "Commencez par une seule tâche",
    startBody: (
      <>
        Choisissez le scénario le plus proche de votre semaine, réduisez-le à
        une tâche récurrente, et donnez à l&apos;agent le plus petit
        ensemble de droits qui suffit à l&apos;accomplir. Ajoutez un point
        d&apos;approbation sur tout ce qui est tourné vers l&apos;extérieur.
        Vous pourrez élargir les limites une fois que l&apos;historique
        d&apos;activité l&apos;aura mérité.
      </>
    ),
    ctaPrimary: "Accéder à l'accès anticipé",
    ctaSecondary: "Comment fonctionne l'application des règles",
  },
};

