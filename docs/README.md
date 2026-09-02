# Documentation SauronID

Six dossiers, six rôles distincts. Si tu hésites entre deux, c'est que le
fichier est mal découpé.

| Dossier | Il répond à | Ce qui y va | Ce qui n'y va pas |
|---|---|---|---|
| [`company-brain/`](company-brain/README.md) | pourquoi le produit existe | problème, solution, produit, features, marché, business model, prix | tout ce qui décrit une implémentation |
| [`design/`](design/design-system.md) | à quoi ça ressemble et comment on l'assemble | tokens appliqués, grammaire de composants, règles de mise en page et de motion | l'identité et la voix, qui sont dans `company-brain/brand/` |
| [`architecture/`](architecture/tech-stack-overview.md) | comment le système fonctionne | la pile, les routes vivantes, les schémas, les specs de sous-système | ce qu'on aimerait construire |
| [`integration/`](integration/sdk-integration.md) | comment on s'y branche | SDK, adaptateurs de runtime, connecteurs | la doc publique, qui est dans `site/` |
| [`security/`](security/threat-model.md) | ce qui est protégé, et ce qui ne l'est pas | modèle de menaces, red team, secrets, crypto, périmètre d'évaluation | les promesses commerciales |
| [`site/`](site/docs.json) | ce que lit un développeur externe | la source Mintlify du site de documentation | les documents internes |

## `company-brain/`, la référence

C'est le seul dossier qui décide. Le reste exécute.

- [README.md](company-brain/README.md) : comment on opère, l'arborescence
  `0x`/`1x`/`2x`/`3x`, et le framework appliqué par fichier (24 Steps du MIT,
  Jobs to be Done, 7 Powers, Five Forces, template Sequoia)
- [01-problemes.md](company-brain/01-problemes.md) : les problèmes, chiffrés
- [02-solution.md](company-brain/02-solution.md) : l'approche, et ce qu'elle ne fait pas
- [03-produit.md](company-brain/03-produit.md) : ce que le client achète, et son cycle de vie
- [04-features.md](company-brain/04-features.md) : les capacités, les connecteurs, l'ordre de construction
- [10-segment-cible.md](company-brain/10-segment-cible.md) : par qui on commence, et qui on exclut
- [11-positionnement.md](company-brain/11-positionnement.md) : la catégorie, les alternatives, ce que le site ne dit jamais
- [research/](company-brain/research/README.md) : les preuves, chaque chiffre
  noté A, B ou C selon ce qui a réellement été lu
- [brand/](company-brain/brand/brand-system.md) : identité, voix, messaging,
  gouvernance des claims, plus les tokens canoniques (`tokens.css`,
  `tokens.json`, préfixe `--sid-`), le logo et le brand book
- `raw/` : file d'attente. Trois documents de l'ancienne organisation à replier
  dans les fichiers numérotés (`product-truth.md` vers 02 et 03,
  `market-positioning-fr.md` vers 11 et 12, `website-brief.md` vers le brief du
  site). Le dossier disparaît quand c'est fait. Rien ne s'y ajoute.

## `design/` et `brand/`, la frontière

Question légitime, les deux parlent de couleurs. La règle :

- **`company-brain/brand/`** porte la décision : qui on est, comment on parle,
  quelle est la palette canonique, quel claim a le droit d'être écrit. C'est
  une décision d'entreprise, elle vit avec le reste du company brain et
  s'aligne sur le positionnement (fichier 11) et l'unfair advantage (13).
- **`design/`** porte l'application : comment ces valeurs deviennent une
  interface. Grammaire rail/path/checkpoint, hiérarchie, élévation, composants,
  motion, ce qu'on fait et ce qu'on ne fait pas. C'est ce qu'un agent lit avant
  de toucher à un composant, d'où sa place en haut de l'arbre plutôt qu'enfoui
  dans le company brain.

Les valeurs canoniques ont une seule source : `brand/tokens.css` et
`brand/tokens.json`. Aujourd'hui les sections 11 à 15 de `brand-system.md`
redéfinissent des couleurs et une typographie que `design-system.md` décrit
aussi. Cette duplication est connue et se résout quand on écrira le fichier 11.

## `architecture/`

- [tech-stack-overview.md](architecture/tech-stack-overview.md) : la carte, quoi et pourquoi
- [tech-stack-deep.md](architecture/tech-stack-deep.md) : la référence détaillée
- [active-route-map.md](architecture/active-route-map.md) : les routes vivantes
- [multi-tenancy.md](architecture/multi-tenancy.md)
- [policy-dsl.md](architecture/policy-dsl.md)
- [postgres-port-status.md](architecture/postgres-port-status.md)
- [agent-egress-gateway.md](architecture/agent-egress-gateway.md)
- [anonymous-ring-policy.md](architecture/anonymous-ring-policy.md)
- [credential-broker.md](architecture/credential-broker.md)
- [sauron-tech-stack.pdf](architecture/sauron-tech-stack.pdf)

## `security/`

- [threat-model.md](security/threat-model.md)
- [redteam-matrix.md](security/redteam-matrix.md)
- [secrets.md](security/secrets.md)
- [key-rotation.md](security/key-rotation.md)
- [verifying-what-you-run.md](security/verifying-what-you-run.md)
- [crypto/](security/crypto/crypto-migration-boundary.md) : frontière de migration, hypothèses cryptographiques
- [assessment/](security/assessment/README.md) : le périmètre à remettre à un évaluateur indépendant

## `integration/`

Aujourd'hui deux fichiers, tous les deux sur le SDK :

- [sdk-integration.md](integration/sdk-integration.md) : l'enforcement local au
  moment de l'appel d'outil
- [sdk-llm-adapters.md](integration/sdk-llm-adapters.md) : LangChain, OpenAI
  Assistants, Anthropic Computer Use
- [agent-action-envelope.md](integration/agent-action-envelope.md) : la
  **spécification** de ce qu'une signature d'action dit, en octets — encodage
  canonique, champs enregistrés, algorithme de vérification, vecteurs de test
  publiés. Version 2 vérifiée dans le dépôt, champs v3 (mandat, plan, SBOM)
  déclarés direction produit.
- [ecosystem-candidates.md](integration/ecosystem-candidates.md) : ce qui existe
  autour de la passerelle et pourrait s'y brancher — red team, observabilité,
  eval, sandboxing, guardrails, gateway modèle, protocole A2A. Chiffres relevés
  sur l'API GitHub, note A ; chaque « pourquoi » est une hypothèse, rien n'a été
  audité au-delà des métadonnées.

C'est une liste de candidats, pas un catalogue de connecteurs. Ce qu'on branche
et dans quel ordre se décide dans le fichier 04 du company brain.

## `site/`

- [docs.json](site/docs.json) : la navigation
- [concepts.md](site/concepts.md), [api-reference.md](site/api-reference.md)
- quickstarts : [python](site/quickstart-python.md), [typescript](site/quickstart-typescript.md), [go](site/quickstart-go.md)
- [guides/](site/guides/policies.md) : politiques, paiements, egress, SIEM
- `img/` : les captures du dashboard utilisées par le README racine

## Ce qui n'est plus ici

Les sous-systèmes retirés en août 2026 (confidentialité différentielle et
statistiques de cohorte, attestation matérielle, Groth16) sont dans
[`archive/removed-2026-08/`](../archive/removed-2026-08/), conception et code
ensemble. `tee-deployment.md` a rejoint `attestation-scope.md` dans
`hardware-attestation/` : quatre fichiers de ce dossier le citent, un document
de sous-système suit son code.

Les dossiers `demo/`, `operations/`, `planning/`, `sales/`, `compliance/` et
`web/` ont été supprimés le 23 août 2026 : des fichiers écrits avant que le
problème ne soit posé. L'historique git les garde. Ce qui vaut d'être réécrit le
sera à partir du company brain, un fichier à la fois.

## Règle

Six dossiers, c'est un plafond. Un dossier qui dépasse huit fichiers cache un
sous-dossier. Un fichier dont le nom ne décrit pas un sujet unique est à
découper. Un fichier déplacé se déplace avec ses références entrantes, dans le
même commit.
