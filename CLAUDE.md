# CLAUDE.md

Instructions de projet pour tout agent qui travaille dans ce dépôt. Ce fichier
dit où est la vérité et dans quel ordre la lire. Il ne remplace pas les règles
globales, il les précise pour SauronID.

`docs/` est technique. Le raisonnement produit et commercial — problème, marché,
positionnement, business model, prix — n'est pas versionné ici : il vit hors du
dépôt. Un claim commercial ne se décide donc pas dans `docs/`, et un fichier de
stratégie n'y entre pas.

## Avant d'écrire quoi que ce soit

| Ce que tu t'apprêtes à faire | À lire d'abord, sans exception |
|---|---|
| Du code serveur, une route, un schéma, une migration | [`docs/architecture/tech-stack-overview.md`](docs/architecture/tech-stack-overview.md) puis [`active-route-map.md`](docs/architecture/active-route-map.md) |
| Toucher à l'auth, aux secrets, à l'egress, à la crypto | [`docs/security/threat-model.md`](docs/security/threat-model.md) et [`docs/security/crypto/crypto-migration-boundary.md`](docs/security/crypto/crypto-migration-boundary.md) |
| Une interface, un composant, une couleur, une animation | [`docs/design/design-system.md`](docs/design/design-system.md) |
| Le SDK, un adaptateur, un connecteur | [`docs/integration/`](docs/integration/sdk-integration.md) |
| La documentation publique | [`docs/site/docs.json`](docs/site/docs.json) pour la navigation |
| Le dual-backend SQLite / Postgres | [`docs/architecture/postgres-port-status.md`](docs/architecture/postgres-port-status.md) |

Carte complète des dossiers et de leur rôle : [`docs/README.md`](docs/README.md).

## La hiérarchie de la vérité

**Le code a raison sur ce qui existe.** `docs/` décrit ce que le code fait
aujourd'hui, pas ce qu'on aimerait qu'il fasse. Une divergence entre les deux se
corrige en lisant le code, jamais en lisant une version antérieure de la doc.

Trois conséquences pratiques :

1. Un document qui cite un fichier source doit le citer par module et par
   symbole (`core/src/admin/auth.rs::build_admin_auth_config`), pas par numéro
   de ligne. Un symbole survit au prochain découpage, un numéro de ligne non.
2. Un sous-système retiré emporte sa documentation. Les quatre retirés en août
   2026 sont dans [`archive/removed-2026-08/`](archive/removed-2026-08/),
   conception et code ensemble. Ne réintroduis pas un claim sur ces chemins
   depuis une révision plus ancienne d'un document.
3. Un chiffre qui décrit le dépôt (nombre de routes, de tables, de sites
   d'appel) vient d'une commande ou d'un test, pas d'une lecture. Voir
   `core/tests/postgres_dispatch_coverage.rs` et
   `scripts/ci/check-openapi-routes.py` : le build tient le chiffre, la doc le
   cite.

## Ce que ce dépôt refuse

- Un claim de capacité présenté comme vérifié alors qu'il ne l'est pas. Ce qui
  est partiel se dit partiel ; ce qui est absent se dit absent, pas « en cours ».
- Un message d'erreur qui propose une action impossible. Si un `enum` a trois
  variantes, le hint n'en nomme pas cinq.
- Un fichier de documentation qui double un fichier existant. Si le sujet a déjà
  un fichier, on l'édite.
- Un nouveau dossier dans `docs/`. Il y en a cinq, c'est un plafond, pas un point
  de départ.
- Un document de stratégie, de positionnement ou de prix. Ce dépôt est technique.

## Vérifier avant de dire que c'est fait

```bash
bash scripts/ops/check-schema-parity.sh      # parité SQLite / Postgres, sans base
python3 scripts/ci/check-openapi-routes.py   # openapi.yaml contre le router
cd core && cargo fmt --all -- --check && cargo test --lib
```

Les liens de la documentation doivent rester valides : un fichier déplacé se
déplace avec ses références entrantes, dans le même commit. Un fichier supprimé
emporte les références qui pointaient vers lui, dans le même commit aussi — y
compris celles qui vivent dans un commentaire Rust.
