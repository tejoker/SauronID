export const T = {
  en: {
    h1: "Every action leaves evidence",
    lede: (
      <>
        Don&apos;t just control your agents. Be able to prove how they were
        controlled. In SauronID, the audit trail isn&apos;t a log file
        someone remembers to grep. It is the shape of every action the agent
        takes.
      </>
    ),
    trailKind: "Evidence.",
    trailH2: "One action, from intent to proof",
    trailLede: (
      <>
        Follow a single sensitive action, a €25,000 supplier payment, through
        the trail it leaves. Every step below is a record, not a narration.
      </>
    ),
    intentTitle: "Intent",
    intentBody: (
      <>
        The agent exists to reconcile invoices and prepare supplier payments.
        That job was declared at creation and bound into the agent&apos;s
        credential.
      </>
    ),
    intentEvidence: (
      <>
        intent: “reconcile invoices, prepare payments” · signed by owner N.
        Laurent · valid 90 days
      </>
    ),
    policyTitle: "Policy",
    policyBody: (
      <>
        The rules that govern this agent, written before it ever ran:
        approved suppliers only, payments capped, approval above €500.
      </>
    ),
    policyEvidence: (
      <>
        policy v3 · suppliers: approved list · max €30,000 · approval &gt;
        €500
      </>
    ),
    requestTitle: "Requested action",
    requestBody: (
      <>
        The agent requests the payment. The request is signed over exactly
        what it is (amount, destination, time), so what was asked can never
        be disputed later.
      </>
    ),
    requestEvidence: (
      <>
        payment €25,000 → Nordwind GmbH · signed request · nonce single-use
      </>
    ),
    decisionTitle: "Decision",
    decisionBody: (
      <>
        The gateway checks the request against policy. Supplier: approved.
        Amount: within cap, but above the approval threshold. The run pauses.
      </>
    ),
    decisionEvidence: (
      <>
        decision: needs approval · rule: payments &gt; €500 require human
        approval
      </>
    ),
    approvalTitle: "Approval",
    approvalBody: (
      <>
        A human reviews the paused action and approves it. The record shows
        who approved, when, and exactly what they saw.
      </>
    ),
    approvalEvidence: <>approved by C. Moreau · 14:31 · scope: this payment only</>,
    executionTitle: "Execution",
    executionBody: (
      <>
        The approved action receives a one-use capability for this exact
        payment, nothing else, and executes through the protected path.
      </>
    ),
    executionEvidence: (
      <>executed 14:32 · capability consumed · response recorded</>
    ),
    evidenceTitle: "Evidence",
    evidenceBody: (
      <>
        The whole sequence becomes a receipt, hash-chained to every receipt
        before it. Batches are anchored to public timestamps, so even we
        cannot rewrite the history.
      </>
    ),
    evidenceEvidence: (
      <>
        receipt #4,183 · chained to #4,182 · batch anchored: Bitcoin + Solana
      </>
    ),
    panelChainTitle: "Why the chain matters",
    panelChainBody1: (
      <>
        An ordinary log can be edited by whoever holds the database. A hash
        chain cannot be edited quietly: each record contains a fingerprint of
        the one before it, so removing or altering any entry breaks every
        entry after it.
      </>
    ),
    panelChainBody2: (
      <>
        Anchoring goes one step further. The chain&apos;s fingerprint is
        stamped on public timestamp networks (Bitcoin via OpenTimestamps,
        optionally Solana) that no company, including ours, controls. They
        act as public clocks only: you hold no cryptocurrency and need none.
        Six months later, anyone can verify the records existed, unaltered,
        at that time.
      </>
    ),
    panelStoppedTitle: "Stopped actions are evidence too",
    panelStoppedBody: (
      <>
        Most audit systems record what happened. SauronID also records what{" "}
        <em>didn&apos;t</em>: every stopped action, with the rule that
        stopped it. For an auditor, a stopped action is often the most
        valuable record there is: it shows the control actually fired.
      </>
    ),
    panelStoppedEvidence: (
      <>stopped · crm.export — all records · rule: exports not granted · 14:44</>
    ),
    trailFootnote: (
      <>
        Names and figures above are illustrative. The receipt chain, approval
        records, stopped-action log, and public anchoring are the shipped
        mechanism, verifiable in the source release.
      </>
    ),
    whoKind: "Shared.",
    whoH2: "The same trail, read by different people",
    whoLede: (
      <>
        Auditability is not a feature for one team. The same records answer
        questions across the organisation, each in the reader&apos;s own
        language.
      </>
    ),
    dtInternal: "Internal audit",
    ddInternal: (
      <>
        A complete, tamper-evident population of agent actions to sample
        from, including the rejections that prove controls operate.
      </>
    ),
    dtCompliance: "Compliance teams",
    ddCompliance: (
      <>
        Evidence mapped to obligations, who authorised, under which policy,
        with which oversight, exportable directly rather than pieced
        together after the fact.
      </>
    ),
    dtSecurity: "Security teams",
    ddSecurity: (
      <>
        Signed, bound records of every protected call: replay- resistant,
        drift-detected, with a separate tamper-evident security log.
      </>
    ),
    dtIncident: "Incident investigation",
    ddIncident: (
      <>
        When something goes wrong, the trail shows what was attempted, what
        was allowed, what was stopped, and by which rule, in order, with
        timestamps that hold up.
      </>
    ),
    dtManagement: "Management",
    ddManagement: (
      <>
        A defensible answer to “what are our agents actually doing?”,
        grounded in records rather than reassurance.
      </>
    ),
    dtCustomers: "Your customers",
    ddCustomers: (
      <>
        When they ask how your AI is governed, you can show the mechanism
        instead of describing an intention.
      </>
    ),
    closingH2: (
      <>
        Don&apos;t just control your agents. Prove how they were controlled.
      </>
    ),
    ctaPrimary: "Get early access",
    ctaSecondary: "Compliance & governance",
  },
  fr: {
    h1: "Chaque action laisse une preuve",
    lede: (
      <>
        Ne vous contentez pas de contrôler vos agents. Soyez en mesure de
        prouver comment ils ont été contrôlés. Chez SauronID, la piste
        d&apos;audit n&apos;est pas un fichier de logs que quelqu&apos;un
        pense à consulter. C&apos;est la forme même de chaque action que
        l&apos;agent entreprend.
      </>
    ),
    trailKind: "Preuve.",
    trailH2: "Une action, de l'intention à la preuve",
    trailLede: (
      <>
        Suivez une action sensible unique, un paiement fournisseur de
        25 000 €, à travers la piste qu&apos;elle laisse. Chaque étape
        ci-dessous est un enregistrement, pas un récit.
      </>
    ),
    intentTitle: "Intention",
    intentBody: (
      <>
        L&apos;agent existe pour rapprocher les factures et préparer les
        paiements fournisseurs. Cette mission a été déclarée à sa création et
        liée à l&apos;identifiant de l&apos;agent.
      </>
    ),
    intentEvidence: (
      <>
        intention : « rapprocher les factures, préparer les paiements » ·
        signée par le propriétaire N. Laurent · valable 90 jours
      </>
    ),
    policyTitle: "Politique",
    policyBody: (
      <>
        Les règles qui régissent cet agent, écrites avant qu&apos;il ne
        s&apos;exécute jamais : fournisseurs approuvés uniquement, paiements
        plafonnés, approbation au-delà de 500 €.
      </>
    ),
    policyEvidence: (
      <>
        politique v3 · fournisseurs : liste approuvée · max 30 000 € ·
        approbation &gt; 500 €
      </>
    ),
    requestTitle: "Action demandée",
    requestBody: (
      <>
        L&apos;agent demande le paiement. La requête est signée sur
        exactement ce qu&apos;elle est (montant, destination, horodatage),
        afin que ce qui a été demandé ne puisse jamais être contesté plus
        tard.
      </>
    ),
    requestEvidence: (
      <>
        paiement 25 000 € → Nordwind GmbH · requête signée · nonce à usage
        unique
      </>
    ),
    decisionTitle: "Décision",
    decisionBody: (
      <>
        La passerelle vérifie la requête par rapport à la politique.
        Fournisseur : approuvé. Montant : dans le plafond, mais au-dessus du
        seuil d&apos;approbation. L&apos;exécution est mise en pause.
      </>
    ),
    decisionEvidence: (
      <>
        décision : attend votre accord · règle : les paiements &gt; 500 €
        requièrent une approbation humaine
      </>
    ),
    approvalTitle: "Approbation",
    approvalBody: (
      <>
        Un humain examine l&apos;action en attente et l&apos;approuve.
        L&apos;enregistrement indique qui a approuvé, quand, et exactement ce
        qu&apos;il a vu.
      </>
    ),
    approvalEvidence: (
      <>approuvé par C. Moreau · 14:31 · portée : ce paiement uniquement</>
    ),
    executionTitle: "Exécution",
    executionBody: (
      <>
        L&apos;action approuvée reçoit une capacité à usage unique pour ce
        paiement précis, rien d&apos;autre, et s&apos;exécute via le chemin
        protégé.
      </>
    ),
    executionEvidence: (
      <>exécuté 14:32 · capacité consommée · réponse enregistrée</>
    ),
    evidenceTitle: "Preuve",
    evidenceBody: (
      <>
        L&apos;ensemble de la séquence devient un reçu, chaîné par hachage à
        chaque reçu précédent. Les lots sont ancrés sur des horodatages
        publics, de sorte que même nous ne pouvons réécrire
        l&apos;historique.
      </>
    ),
    evidenceEvidence: (
      <>
        reçu n° 4 183 · chaîné au n° 4 182 · lot ancré : Bitcoin + Solana
      </>
    ),
    panelChainTitle: "Pourquoi la chaîne compte",
    panelChainBody1: (
      <>
        Un log ordinaire peut être modifié par quiconque détient la base de
        données. Une chaîne de hachage ne peut pas être modifiée
        discrètement : chaque enregistrement contient une empreinte de celui
        qui le précède, donc supprimer ou altérer une entrée casse toutes les
        entrées suivantes.
      </>
    ),
    panelChainBody2: (
      <>
        L&apos;ancrage va plus loin. L&apos;empreinte de la chaîne est
        estampillée sur des réseaux d&apos;horodatage publics (Bitcoin via
        OpenTimestamps, Solana en option) qu&apos;aucune société, y compris
        la nôtre, ne contrôle. Ils servent uniquement d&apos;horloges
        publiques : vous ne détenez aucune cryptomonnaie et n&apos;en avez
        besoin d&apos;aucune. Six mois plus tard, n&apos;importe qui peut
        vérifier que les enregistrements existaient, inaltérés, à cette date.
      </>
    ),
    panelStoppedTitle: "Les actions bloquées sont aussi des preuves",
    panelStoppedBody: (
      <>
        La plupart des systèmes d&apos;audit enregistrent ce qui s&apos;est
        passé. SauronID enregistre aussi ce qui ne{" "}
        <em>s&apos;est pas passé</em> : chaque action bloquée, avec la règle
        qui l&apos;a bloquée. Pour un auditeur, une action bloquée est
        souvent l&apos;enregistrement le plus précieux qui soit : il montre
        que le contrôle a réellement fonctionné.
      </>
    ),
    panelStoppedEvidence: (
      <>
        bloqué · crm.export — tous les enregistrements · règle : exports non
        autorisés · 14:44
      </>
    ),
    trailFootnote: (
      <>
        Les noms et chiffres ci-dessus sont illustratifs. La chaîne de reçus,
        les enregistrements d&apos;approbation, le journal des actions
        bloquées et l&apos;ancrage public sont le mécanisme livré,
        vérifiable dans la version source.
      </>
    ),
    whoKind: "Partagée.",
    whoH2: "La même piste, lue par des publics différents",
    whoLede: (
      <>
        L&apos;auditabilité n&apos;est pas une fonctionnalité pour une seule
        équipe. Les mêmes enregistrements répondent à des questions dans
        toute l&apos;organisation, chacun dans le langage de son lecteur.
      </>
    ),
    dtInternal: "Audit interne",
    ddInternal: (
      <>
        Une population complète et infalsifiable des actions des agents à
        échantillonner, y compris les rejets qui prouvent que les contrôles
        fonctionnent.
      </>
    ),
    dtCompliance: "Équipes conformité",
    ddCompliance: (
      <>
        Des preuves associées aux obligations, indiquant qui a autorisé, sous
        quelle politique, avec quelle supervision, exportables directement
        plutôt que reconstituées après coup.
      </>
    ),
    dtSecurity: "Équipes sécurité",
    ddSecurity: (
      <>
        Des enregistrements signés et liés de chaque appel protégé :
        résistants au rejeu, avec détection de dérive, et un journal de
        sécurité infalsifiable séparé.
      </>
    ),
    dtIncident: "Investigation d'incident",
    ddIncident: (
      <>
        Quand quelque chose tourne mal, la piste montre ce qui a été tenté,
        ce qui a été autorisé, ce qui a été bloqué, et par quelle règle, dans
        l&apos;ordre, avec des horodatages qui tiennent la route.
      </>
    ),
    dtManagement: "Direction",
    ddManagement: (
      <>
        Une réponse défendable à « que font réellement nos agents ? »,
        fondée sur des enregistrements plutôt que sur des rassurances.
      </>
    ),
    dtCustomers: "Vos clients",
    ddCustomers: (
      <>
        Quand ils demandent comment votre IA est gouvernée, vous pouvez
        montrer le mécanisme au lieu de décrire une intention.
      </>
    ),
    closingH2: (
      <>
        Ne vous contentez pas de contrôler vos agents. Prouvez comment ils
        ont été contrôlés.
      </>
    ),
    ctaPrimary: "Accéder à l'accès anticipé",
    ctaSecondary: "Conformité et gouvernance",
  },
};

