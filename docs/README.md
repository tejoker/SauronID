# Documentation SauronID

Un dossier par domaine. Un fichier par sujet. Rien à la racine.

| Dossier | Contenu |
|---|---|
| `company-brain/` | référence produit, système de design, guidelines de marque, logo et brand book |
| `architecture/` | pile technique, carte des routes, DSL de politiques, multi-tenancy, modèle de confidentialité |
| `security/` | modèle de menaces, matrice red team, secrets, rotation de clés, périmètre d'attestation |
| `security/crypto/` | hypothèses cryptographiques, frontière de migration, revue crypto |
| `operations/` | exploitation, reprise après sinistre, préparation à la production, tests de charge, SIEM, déploiement TEE |
| `compliance/` | réponse à réquisition, audits, soumission de statistiques |
| `integration/` | intégration des SDK, adapters LLM |
| `demo/` | scripts et runbooks de démonstration |
| `planning/` | feuille de route, plan de remédiation, comparatifs concurrentiels |
| `zk/` | journaux d'action à divulgation nulle, chemins Solana |
| `web/` | propriétés web |
| `design/` | briefs de conception par sous-système |
| `sales/` | one-pager, brief de pilote |
| `site/` | documentation du site vitrine |
| `ideas/` | pistes non tranchées |
| `img/` | images utilisées par la documentation |

## Règle

Un dossier qui dépasse huit fichiers cache un sous-dossier. Un fichier dont le
nom ne décrit pas un sujet unique est à découper.
