# Documentation SauronID

Un dossier par domaine. Un fichier par sujet. Rien à la racine.

Chaque fichier ci-dessous est un lien. Si tu cherches un document par son ancien
nom à plat, il est dans le dossier de son domaine : la réorganisation a déplacé
les 40 fichiers qui traînaient à la racine de `docs/`.

## `company-brain/`

la référence : vérité produit, système de design, marque, positionnement

- [README.md](company-brain/README.md)
- [brand-system.md](company-brain/brand-system.md)
- [design-system.md](company-brain/design-system.md)
- [market-positioning-fr.md](company-brain/market-positioning-fr.md)
- [product-truth.md](company-brain/product-truth.md)
- [website-brief.md](company-brain/website-brief.md)

## `company-brain/research/`

la recherche d'entreprise, dans l'ordre : problème avant solution, preuves notées A, B ou C

- [README.md](company-brain/research/README.md)
- [problem-landscape.md](company-brain/research/problem-landscape.md)
- [copilot-vs-agent.md](company-brain/research/copilot-vs-agent.md)
- [sources.md](company-brain/research/sources.md)

## `company-brain/brand/`

les fichiers canoniques de la marque, servis par le brand book

- [tokens.css](company-brain/brand/tokens.css)
- [tokens.json](company-brain/brand/tokens.json)
- [logo.svg](company-brain/brand/logo.svg)
- [brand-book.pdf](company-brain/brand/brand-book.pdf)
- [build-brand-book.js](company-brain/brand/build-brand-book.js)

## `architecture/`

pile technique, carte des routes, DSL de politiques, multi-tenancy, modèle de confidentialité

- [active-route-map.md](architecture/active-route-map.md)
- [multi-tenancy.md](architecture/multi-tenancy.md)
- [policy-dsl.md](architecture/policy-dsl.md)
- [privacy-model.md](architecture/privacy-model.md)
- [sauron-tech-stack.pdf](architecture/sauron-tech-stack.pdf)
- [tech-stack-deep.md](architecture/tech-stack-deep.md)
- [tech-stack-overview.md](architecture/tech-stack-overview.md)

## `security/`

modèle de menaces, matrice red team, secrets, rotation de clés, périmètre d'attestation

- [attestation-scope.md](security/attestation-scope.md)
- [key-rotation.md](security/key-rotation.md)
- [redteam-matrix.md](security/redteam-matrix.md)
- [secrets.md](security/secrets.md)
- [threat-model.md](security/threat-model.md)
- [verifying-what-you-run.md](security/verifying-what-you-run.md)

## `security/crypto/`

hypothèses cryptographiques, frontière de migration, revue crypto

- [crypto-migration-boundary.md](security/crypto/crypto-migration-boundary.md)
- [crypto-review-attestation.md](security/crypto/crypto-review-attestation.md)
- [crypto-review-attestation.pdf](security/crypto/crypto-review-attestation.pdf)
- [cryptographic-assumptions.md](security/crypto/cryptographic-assumptions.md)

## `security/assessment/`

périmètre à remettre à un évaluateur indépendant, et comment son verdict est vérifié

- [README.md](security/assessment/README.md)
- [assessment-brief.md](security/assessment/assessment-brief.md)

## `operations/`

exploitation, reprise après sinistre, préparation à la production, tests de charge, SIEM, TEE

- [disaster-recovery.md](operations/disaster-recovery.md)
- [load-test.md](operations/load-test.md)
- [operations.md](operations/operations.md)
- [postgres-port-status.md](operations/postgres-port-status.md)
- [production-readiness.md](operations/production-readiness.md)
- [release-readiness.md](operations/release-readiness.md)
- [siem-integration.md](operations/siem-integration.md)
- [tee-deployment.md](operations/tee-deployment.md)

## `compliance/`

réponse à réquisition, audits, soumission de statistiques

- [AUDIT-2026-06-25.md](compliance/AUDIT-2026-06-25.md)
- [multi-tenancy-audit.md](compliance/multi-tenancy-audit.md)
- [stats-submission.md](compliance/stats-submission.md)
- [subpoena-response.md](compliance/subpoena-response.md)

## `integration/`

intégration des SDK, adapters LLM

- [sdk-integration.md](integration/sdk-integration.md)
- [sdk-llm-adapters.md](integration/sdk-llm-adapters.md)

## `demo/`

scripts et runbooks de démonstration

- [demo-anchoring.md](demo/demo-anchoring.md)
- [demo-cloud-and-agent.md](demo/demo-cloud-and-agent.md)
- [demo-prep.md](demo/demo-prep.md)
- [demo-runbook.md](demo/demo-runbook.md)
- [demo-script.md](demo/demo-script.md)

## `planning/`

feuille de route, plan de remédiation, comparatifs concurrentiels

- [competitive-benchmark.md](planning/competitive-benchmark.md)
- [empirical-comparison.md](planning/empirical-comparison.md)
- [remediation-plan.md](planning/remediation-plan.md)
- [roadmap.md](planning/roadmap.md)

## `design/`

briefs de conception par sous-système

- [agent-egress-gateway.md](design/agent-egress-gateway.md)
- [anonymous-ring-policy.md](design/anonymous-ring-policy.md)
- [credential-broker.md](design/credential-broker.md)
- [postgres-port-brief.md](design/postgres-port-brief.md)

## `zk/`

journaux d'action à divulgation nulle, chemins Solana

- [solana-free-paths.md](zk/solana-free-paths.md)
- [zk-action-logs.md](zk/zk-action-logs.md)

## `web/`

propriétés web

- [web-properties.md](web/web-properties.md)

## `sales/`

one-pager, brief de pilote, questionnaire sécurité

- [SauronID-investor-one-pager.pdf](sales/SauronID-investor-one-pager.pdf)
- [investor-one-pager.html](sales/investor-one-pager.html)
- [one-pager.md](sales/one-pager.md)
- [pilot-brief.md](sales/pilot-brief.md)
- [security-questionnaire.md](sales/security-questionnaire.md)

## `site/`

source de la documentation publique

- [api-reference.md](site/api-reference.md)
- [concepts.md](site/concepts.md)
- [docs.json](site/docs.json)
- [quickstart-go.md](site/quickstart-go.md)
- [quickstart-python.md](site/quickstart-python.md)
- [quickstart-typescript.md](site/quickstart-typescript.md)

## `site/guides/`

les guides par sujet du site public, dans l'ordre du groupe « Guides » de
[`site/docs.json`](site/docs.json)

- [payments.md](site/guides/payments.md)
- [egress.md](site/guides/egress.md)
- [policies.md](site/guides/policies.md)
- [siem.md](site/guides/siem.md)

## `ideas/`

pistes non tranchées

- [blackbox-encrypted-inference.md](ideas/blackbox-encrypted-inference.md)

## `img/`

captures utilisées par la documentation

- [dashboard-agent.png](img/dashboard-agent.png)
- [dashboard-explorer.png](img/dashboard-explorer.png)
- [dashboard-overview.png](img/dashboard-overview.png)
- [dashboard-proofs.png](img/dashboard-proofs.png)
- [dashboard-welcome.png](img/dashboard-welcome.png)

## Règle

Un dossier qui dépasse huit fichiers cache un sous-dossier. Un fichier dont le
nom ne décrit pas un sujet unique est à découper.
