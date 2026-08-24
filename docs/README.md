# Documentation SauronID

`docs/` est technique : ce que le système fait, comment il est protégé, comment
on s'y branche. Le raisonnement produit et commercial — problème, marché,
positionnement, business model, prix — n'est pas versionné dans ce dépôt.

Cinq dossiers, cinq rôles distincts. Si tu hésites entre deux, c'est que le
fichier est mal découpé.

| Dossier | Il répond à | Ce qui y va | Ce qui n'y va pas |
|---|---|---|---|
| [`architecture/`](architecture/tech-stack-overview.md) | comment le système fonctionne | la pile, les routes vivantes, les schémas, les specs de sous-système | ce qu'on aimerait construire |
| [`security/`](security/threat-model.md) | ce qui est protégé, et ce qui ne l'est pas | modèle de menaces, red team, secrets, crypto, périmètre d'évaluation | les promesses commerciales |
| [`integration/`](integration/sdk-integration.md) | comment on s'y branche | SDK, adaptateurs de runtime, connecteurs | la doc publique, qui est dans `site/` |
| [`design/`](design/design-system.md) | à quoi ça ressemble et comment on l'assemble | tokens appliqués, grammaire de composants, règles de mise en page et de motion | l'identité de marque et la voix |
| [`site/`](site/docs.json) | ce que lit un développeur externe | la source Mintlify du site de documentation | les documents internes |

## `architecture/`

- [tech-stack-overview.md](architecture/tech-stack-overview.md) : la carte, quoi et pourquoi
- [tech-stack-deep.md](architecture/tech-stack-deep.md) : la référence détaillée
- [active-route-map.md](architecture/active-route-map.md) : les routes vivantes
- [multi-tenancy.md](architecture/multi-tenancy.md) : la frontière entre tenants et ses limites connues
- [policy-dsl.md](architecture/policy-dsl.md)
- [postgres-port-status.md](architecture/postgres-port-status.md) : l'état du dual-backend, chiffres tenus par le build
- [agent-egress-gateway.md](architecture/agent-egress-gateway.md)
- [anonymous-ring-policy.md](architecture/anonymous-ring-policy.md)
- [credential-broker.md](architecture/credential-broker.md)
- [sauron-tech-stack.pdf](architecture/sauron-tech-stack.pdf)

## `security/`

- [threat-model.md](security/threat-model.md)
- [redteam-matrix.md](security/redteam-matrix.md)
- [secrets.md](security/secrets.md) : la précédence Vault / KMS / env
- [key-rotation.md](security/key-rotation.md)
- [verifying-what-you-run.md](security/verifying-what-you-run.md) : la procédure à remettre à un client qui ne lit pas ce code
- [crypto/](security/crypto/crypto-migration-boundary.md) : frontière de migration, hypothèses cryptographiques
- [assessment/](security/assessment/README.md) : le périmètre à remettre à un évaluateur indépendant

## `integration/`

- [sdk-integration.md](integration/sdk-integration.md) : l'enforcement local au
  moment de l'appel d'outil
- [sdk-llm-adapters.md](integration/sdk-llm-adapters.md) : LangChain, OpenAI
  Assistants, Anthropic Computer Use

## `design/`

- [design-system.md](design/design-system.md) : grammaire rail/path/checkpoint,
  hiérarchie, élévation, composants, motion. À lire avant de toucher un
  composant.

Les valeurs appliquées vivent avec le code qui les consomme :
`site/styles/tokens.css` pour le site, `dashboard/app/globals.css` pour la
console. Il n'y a pas de copie canonique dans `docs/` — une copie que personne
n'importe n'est pas canonique, elle dérive.

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
ensemble.

Les dossiers `demo/`, `operations/`, `planning/`, `sales/`, `compliance/` et
`web/` ont été supprimés le 23 août 2026, et `company-brain/` le 24 août :
documents écrits avant que le problème ne soit posé, plus le raisonnement
produit et commercial, qui n'appartient pas à un dépôt technique. L'historique
git les garde.

## Règle

Cinq dossiers, c'est un plafond. Un dossier qui dépasse huit fichiers cache un
sous-dossier. Un fichier dont le nom ne décrit pas un sujet unique est à
découper. Un fichier déplacé se déplace avec ses références entrantes, dans le
même commit ; un fichier supprimé emporte les références qui pointaient vers
lui, y compris celles qui vivent dans un commentaire Rust.
