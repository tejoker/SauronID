export const T = {
  en: {
    h1: "Security is the architecture, not the pitch",
    lede1:
      "SauronID does not ask a model to behave. It checks every protected action against rules the agent cannot change, in a gateway the agent cannot argue with. This page explains the real mechanisms, and states plainly what they do not cover.",
    trailLede:
      "A protected action travels through five checks before it touches your tools. Failing any one of them stops the action and records why.",
    trail: [
      {
        h4: "1 · Owner-signed mandate",
        p: "A human owner signs the agent's authority: which tenant, which agent key, which intent, and for how long. The platform operator cannot mint or widen a grant, because they do not hold the owner's signing key. Revocation ends the authority immediately.",
        ev: "mandate binds: owner · tenant · agent key · intent · time-to-live",
      },
      {
        h4: "2 · Identity that cannot drift",
        p: "Each agent holds its own Ed25519 key, generated on the client, never derived by the server. The agent's configuration is fingerprinted at registration; if the running agent's configuration drifts from what was registered, its calls are rejected.",
        ev: "per-agent Ed25519 proof-of-possession · configuration digest checked on every protected call",
      },
      {
        h4: "3 · Per-action signatures, default-deny",
        p: "Every protected call is signed over exactly what it does, and sensitive actions are additionally sealed as a ring signature over five facts: action, resource, destination, amount, nonce. That ring is the mechanism behind the name. The gateway enforces all of this globally and rejects replayed nonces, modified bodies, wrong keys, and expired credentials.",
        ev: "signature binds: tenant · method · path · query · audience · body digest · timestamp · nonce · credential · config digest",
      },
      {
        h4: "4 · Server-side policy",
        p: "Tool allowlists, spend caps, rate limits, data-scope allow/deny tags, time windows, and delegation depth are evaluated by the gateway, not by the model. The spend ledger is authoritative on the server: anything the SDK claims is re-checked.",
        ev: "allowed_tools · max_budget_usd · rate_limit · data_scope · time_window · delegation depth",
      },
      {
        h4: "5 · One-use egress capability",
        p: "An approved external action gets a short-lived capability for exactly one host, method, path, body, and byte limit. The proxy consumes it once. It cannot be replayed or stretched to a different destination. The egress path pins DNS, refuses redirects, filters headers, and caps response size.",
        ev: "one-use capability: exact host · method · path · body digest · disclosure contract · byte limit",
      },
    ],
    operatorHead: "What that means for the person running the agent",
    operatorList: [
      {
        dt: "Least privilege by construction",
        dd: "An agent starts with nothing. Every tool, data scope, and action is granted deliberately. There is no “full access” default to walk back later.",
      },
      {
        dt: "Allow / deny you can read",
        dd: "Policies are readable documents: which tools are allowed, which data is in scope, which destinations are permitted. What is not granted does not happen through the protected path.",
      },
      {
        dt: "Limits and budgets",
        dd: "Spend caps, request rates, payload constraints, and time windows are enforced on every call, with the server keeping the authoritative ledger.",
      },
      {
        dt: "Human approval gates",
        dd: "Actions above the thresholds you choose pause and wait. The approval (who, when, for what) becomes part of the permanent record.",
      },
      {
        dt: "Secrets handling",
        dd: "Protected egress can inject credentials server-side, so the agent never holds the secret for those calls. In the Launcher, your API key stays on your machine, masked, and never appears in logs.",
      },
      {
        dt: "Kill and revoke",
        dd: "Revoking an agent invalidates its authority immediately: the next protected action fails. Mandates also expire on their own: authority has a time-to-live, not a memory leak.",
      },
      {
        dt: "Failure modes",
        dd: "The gateway fails closed. An unsigned call, an unknown credential, a drifted configuration, or an unavailable policy check results in rejection, never in a silent pass-through.",
      },
      {
        dt: "Logging",
        dd: "Hash-chained receipts plus a separate tamper-evident security log. Rejections are recorded, not hidden.",
      },
      {
        dt: "Local execution",
        dd: "Early access runs on your machine with your model or key. The same enforcement travels with the agent when managed execution arrives later.",
      },
    ],
    threatLede:
      "A security page that only lists strengths is marketing. This is the model our engineering works against, including the boundary of what SauronID can and cannot see.",
    protectsHead: "What SauronID protects against",
    protects: [
      {
        dt: "Replayed or forged actions",
        dd: "Captured, replayed, or tampered requests are rejected: every action is signed and single-use.",
      },
      {
        dt: "Agents exceeding their grant",
        dd: "Anything outside the grant, wrong tool, over budget, out of scope, is stopped server-side and recorded with the rule.",
      },
      {
        dt: "Silent drift and impersonation",
        dd: "An agent whose code or configuration changed after registration fails the check. It cannot quietly become a different agent.",
      },
      {
        dt: "Unauthorised grants",
        dd: "Only the owner's signature can widen what an agent may do. Not the operator, and not us.",
      },
      {
        dt: "Tampered history",
        dd: "Receipts are chained and publicly anchored, so any edit to the past shows.",
      },
    ],
    redTeamNote:
      "These behaviours are exercised by the red-team suite in the source release: 16 of 16 empirical invariant scenarios pass, and 18 of the 20 scenarios in the adversarial matrix run as live dynamic tests.",
    doesNotHead: "What SauronID does not claim to protect against",
    doesNot: [
      {
        dt: "Traffic around the gateway",
        dd: "Production still needs a deny-by-default network boundary around the agent, and we say so instead of hiding it.",
      },
      {
        dt: "A compromised host or stolen keys",
        dd: "An attacker holding your machine, your signing key, or your secrets backend. SauronID is not endpoint security.",
      },
      {
        dt: "Bad judgment inside a wide grant",
        dd: "A harmful action your own policy allows. Boundaries enforce your decisions; they do not improve them.",
      },
      {
        dt: "Unwise intent and untrue data",
        dd: "SauronID proves what the agent was allowed to do and what it did, not that either was a good idea.",
      },
      {
        dt: "Everything else security is",
        dd: "It is not a sandbox, an antivirus, or a promise of zero risk. It governs protected agent actions, verifiably.",
      },
    ],
    validatorsNotice: (
      <>
        <strong>For technical validators:</strong> the threat model, policy
        DSL, and red-team matrix ship with the source release. Independent
        cryptographic review is a release gate we hold ourselves to, not a
        certification. No SOC 2 or ISO 27001 held today.
      </>
    ),
    proofHead: "Proof you can check without trusting us",
    proofLede:
      "Trust that depends on the vendor's word is not trust. The evidence layer is designed so a third party can verify it independently.",
    proofP:
      "Finalized receipt batches are stamped on public timestamp networks (Bitcoin via OpenTimestamps, optionally Solana) that no one, including us, can rewrite. These networks act as public clocks only: you hold no cryptocurrency and need none. Selected operational statements can also be proven with transparent STARK proofs, reproducible byte-for-byte in CI.",
    auditLink: "How the audit trail works →",
    integrationHead: "Integration surface",
    integrationLede: "For the team that validates the runtime:",
    integration: [
      "Rust core gateway, operator dashboard",
      "TypeScript, Python, and Go clients with the same signed-call flow",
      "Adapters and examples for LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI and Anthropic tool use, Vercel AI",
      "MCP server: status, register, payment, protected fetch, egress log, receipts, revoke",
      "Opt-in RFC 9449 DPoP compatibility mode",
    ],
    ctaHead: "Boundaries you can verify, not believe",
    ctaPrimary: "Get early access",
    ctaSecondary: "Compliance & governance",
  },
  fr: {
    h1: "La sécurité est l'architecture, pas l'argument de vente",
    lede1:
      "SauronID ne demande pas à un modèle de bien se comporter. Il vérifie chaque action protégée contre des règles que l'agent ne peut pas changer, dans une passerelle avec laquelle l'agent ne peut pas discuter. Cette page explique les mécanismes réels et indique clairement ce qu'ils ne couvrent pas.",
    trailLede:
      "Une action protégée traverse cinq contrôles avant de toucher vos outils. Échouer à l'un d'eux arrête l'action et enregistre pourquoi.",
    trail: [
      {
        h4: "1 · Mandat signé par le propriétaire",
        p: "Un propriétaire humain signe l'autorité de l'agent : quel tenant, quelle clé d'agent, quelle intention, et pour combien de temps. L'opérateur de la plateforme ne peut pas créer ni élargir une autorisation, car il ne détient pas la clé de signature du propriétaire. La révocation met fin à l'autorité immédiatement.",
        ev: "le mandat lie : propriétaire · tenant · clé d'agent · intention · durée de vie",
      },
      {
        h4: "2 · Une identité qui ne peut pas dériver",
        p: "Chaque agent détient sa propre clé Ed25519, générée côté client, jamais dérivée par le serveur. La configuration de l'agent est empreinte numériquement à l'enregistrement ; si la configuration de l'agent en cours d'exécution dérive de ce qui a été enregistré, ses appels sont rejetés.",
        ev: "preuve de possession Ed25519 par agent · empreinte de configuration vérifiée à chaque appel protégé",
      },
      {
        h4: "3 · Signatures par action, refus par défaut",
        p: "Chaque appel protégé est signé sur exactement ce qu'il fait, et les actions sensibles sont en plus scellées comme une signature en anneau portant sur cinq faits : action, ressource, destination, montant, nonce. Cet anneau est le mécanisme derrière le nom. La passerelle applique tout cela globalement et rejette les nonces rejoués, les corps modifiés, les mauvaises clés et les identifiants expirés.",
        ev: "la signature lie : tenant · méthode · chemin · requête · audience · empreinte du corps · horodatage · nonce · identifiant · empreinte de configuration",
      },
      {
        h4: "4 · Politique côté serveur",
        p: "Les listes d'outils autorisés, plafonds de dépense, limites de débit, étiquettes d'autorisation/refus de portée des données, fenêtres temporelles et profondeur de délégation sont évalués par la passerelle, pas par le modèle. Le registre de dépenses fait autorité côté serveur : tout ce que revendique le SDK est revérifié.",
        ev: "allowed_tools · max_budget_usd · rate_limit · data_scope · time_window · delegation depth",
      },
      {
        h4: "5 · Capacité de sortie à usage unique",
        p: "Une action externe approuvée reçoit une capacité de courte durée pour exactement un hôte, une méthode, un chemin, un corps et une limite d'octets. Le proxy la consomme une seule fois. Elle ne peut être rejouée ni étendue à une autre destination. Le chemin de sortie fixe le DNS, refuse les redirections, filtre les en-têtes et plafonne la taille de réponse.",
        ev: "capacité à usage unique : hôte exact · méthode · chemin · empreinte du corps · contrat de divulgation · limite d'octets",
      },
    ],
    operatorHead: "Ce que cela signifie pour la personne qui exploite l'agent",
    operatorList: [
      {
        dt: "Moindre privilège par construction",
        dd: "Un agent démarre sans rien. Chaque outil, portée de données et action est accordé délibérément. Il n'existe pas d'accès complet par défaut à restreindre ensuite.",
      },
      {
        dt: "Autorisations et refus lisibles",
        dd: "Les politiques sont des documents lisibles : quels outils sont autorisés, quelles données sont dans le périmètre, quelles destinations sont permises. Ce qui n'est pas accordé ne se produit pas via le chemin protégé.",
      },
      {
        dt: "Limites et budgets",
        dd: "Plafonds de dépense, débits de requêtes, contraintes de charge utile et fenêtres temporelles sont appliqués à chaque appel, le serveur conservant le registre faisant autorité.",
      },
      {
        dt: "Points d'approbation humaine",
        dd: "Les actions au-delà des seuils que vous choisissez se mettent en pause et attendent. L'approbation (qui, quand, pour quoi) fait partie de l'enregistrement permanent.",
      },
      {
        dt: "Gestion des secrets",
        dd: "La sortie protégée peut injecter les identifiants côté serveur, de sorte que l'agent ne détient jamais le secret pour ces appels. Dans le Launcher, votre clé API reste sur votre machine, masquée, et n'apparaît jamais dans les journaux.",
      },
      {
        dt: "Arrêt et révocation",
        dd: "Révoquer un agent invalide son autorité immédiatement : l'action protégée suivante échoue. Les mandats expirent aussi d'eux-mêmes : l'autorité a une durée de vie, pas une fuite de mémoire.",
      },
      {
        dt: "Modes de défaillance",
        dd: "La passerelle échoue de façon fermée. Un appel non signé, un identifiant inconnu, une configuration ayant dérivé ou un contrôle de politique indisponible entraînent un rejet, jamais un passage silencieux.",
      },
      {
        dt: "Journalisation",
        dd: "Des reçus chaînés par hachage plus un journal de sécurité séparé et inviolable. Les rejets sont enregistrés, pas cachés.",
      },
      {
        dt: "Exécution locale",
        dd: "L'accès anticipé s'exécute sur votre machine, avec votre modèle ou votre clé. La même application voyage avec l'agent quand l'exécution gérée arrivera plus tard.",
      },
    ],
    threatLede:
      "Une page de sécurité qui ne liste que des forces relève du marketing. Voici le modèle contre lequel travaille notre ingénierie, y compris la limite de ce que SauronID peut et ne peut pas voir.",
    protectsHead: "Ce contre quoi SauronID protège",
    protects: [
      {
        dt: "Actions rejouées ou forgées",
        dd: "Les requêtes capturées, rejouées ou modifiées sont rejetées : chaque action est signée et à usage unique.",
      },
      {
        dt: "Agents dépassant leur autorisation",
        dd: "Tout ce qui sort de l'autorisation, mauvais outil, dépense au-delà du budget, hors périmètre, est arrêté côté serveur et enregistré avec la règle concernée.",
      },
      {
        dt: "Dérive silencieuse et usurpation",
        dd: "Un agent dont le code ou la configuration a changé après l'enregistrement échoue au contrôle. Il ne peut pas devenir discrètement un autre agent.",
      },
      {
        dt: "Autorisations non légitimes",
        dd: "Seule la signature du propriétaire peut élargir ce qu'un agent est autorisé à faire. Ni l'opérateur, ni nous.",
      },
      {
        dt: "Historique falsifié",
        dd: "Les reçus sont chaînés et ancrés publiquement, de sorte que toute modification du passé se voit.",
      },
    ],
    redTeamNote:
      "Ces comportements sont exercés par la suite de red team de la version source : 16 scénarios d'invariants empiriques sur 16 passent, et 18 des 20 scénarios de la matrice adverse s'exécutent comme des tests dynamiques réels.",
    doesNotHead: "Ce que SauronID ne prétend pas protéger",
    doesNot: [
      {
        dt: "Le trafic contournant la passerelle",
        dd: "La production a toujours besoin d'une limite réseau par défaut refusant tout autour de l'agent, et nous le disons au lieu de le cacher.",
      },
      {
        dt: "Un hôte compromis ou des clés volées",
        dd: "Un attaquant disposant de votre machine, de votre clé de signature ou de votre backend de secrets. SauronID n'est pas une sécurité de poste de travail.",
      },
      {
        dt: "Un mauvais jugement à l'intérieur d'une autorisation large",
        dd: "Une action nuisible que votre propre politique autorise. Les limites appliquent vos décisions ; elles ne les améliorent pas.",
      },
      {
        dt: "Une intention malavisée et des données fausses",
        dd: "SauronID prouve ce que l'agent était autorisé à faire et ce qu'il a fait, pas que l'un ou l'autre était une bonne idée.",
      },
      {
        dt: "Tout ce que la sécurité recouvre par ailleurs",
        dd: "Ce n'est ni un bac à sable, ni un antivirus, ni une promesse de risque zéro. Il gouverne les actions protégées des agents, de façon vérifiable.",
      },
    ],
    validatorsNotice: (
      <>
        <strong>Pour les validateurs techniques :</strong> le modèle de
        menace, le DSL de politique et la matrice de red team sont livrés avec
        la version source. La revue cryptographique indépendante est une
        condition de sortie que nous nous imposons, pas une certification.
        Aucun SOC 2 ni ISO 27001 détenu à ce jour.
      </>
    ),
    proofHead: "Une preuve que vous pouvez vérifier sans nous faire confiance",
    proofLede:
      "Une confiance qui dépend de la parole du fournisseur n'est pas une confiance. La couche de preuve est conçue pour qu'un tiers puisse la vérifier de façon indépendante.",
    proofP:
      "Les lots de reçus finalisés sont horodatés sur des réseaux d'horodatage publics (Bitcoin via OpenTimestamps, en option Solana) que personne, y compris nous, ne peut réécrire. Ces réseaux servent uniquement d'horloges publiques : vous ne détenez aucune cryptomonnaie et n'en avez besoin d'aucune. Certaines affirmations opérationnelles peuvent aussi être prouvées par des preuves STARK transparentes, reproductibles octet pour octet en CI.",
    auditLink: "Comment fonctionne la piste d'audit →",
    integrationHead: "Surface d'intégration",
    integrationLede: "Pour l'équipe qui valide le runtime :",
    integration: [
      "Passerelle cœur en Rust, tableau de bord opérateur",
      "Clients TypeScript, Python et Go avec le même flux d'appel signé",
      "Adaptateurs et exemples pour LangChain, LlamaIndex, CrewAI, AutoGen, l'usage d'outils OpenAI et Anthropic, Vercel AI",
      "Serveur MCP : statut, enregistrement, paiement, requête protégée, journal de sortie, reçus, révocation",
      "Mode de compatibilité DPoP RFC 9449, en option",
    ],
    ctaHead: "Des limites que vous pouvez vérifier, pas croire",
    ctaPrimary: "Accès anticipé",
    ctaSecondary: "Conformité et gouvernance",
  },
} as const;

