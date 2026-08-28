# CLAUDE.md

Instructions de projet pour tout agent qui travaille dans ce dépôt. Ce fichier
dit où est la vérité et dans quel ordre la lire. Il ne remplace pas les règles
globales, il les précise pour SauronID.

## Avant d'écrire quoi que ce soit

| Ce que tu t'apprêtes à faire | À lire d'abord, sans exception |
|---|---|
| Un claim produit, une page, un texte commercial, un prix | [`docs/company-brain/README.md`](docs/company-brain/README.md) puis le fichier numéroté concerné |
| Une interface, un composant, une couleur, une animation | [`docs/design/design-system.md`](docs/design/design-system.md), et [`docs/company-brain/brand/`](docs/company-brain/brand/brand-system.md) pour la voix et l'identité |
| Du code serveur, une route, un schéma, une migration | [`docs/architecture/tech-stack-overview.md`](docs/architecture/tech-stack-overview.md) puis [`active-route-map.md`](docs/architecture/active-route-map.md) |
| Toucher à l'auth, aux secrets, à l'egress, à la crypto | [`docs/security/threat-model.md`](docs/security/threat-model.md) et [`docs/security/crypto/crypto-migration-boundary.md`](docs/security/crypto/crypto-migration-boundary.md) |
| Le SDK, un adaptateur, un connecteur | [`docs/integration/`](docs/integration/sdk-integration.md) |
| La documentation publique | [`docs/site/docs.json`](docs/site/docs.json) pour la navigation |

Carte complète des dossiers et de leur rôle : [`docs/README.md`](docs/README.md).

## Deux dépôts, une seule session

SauronID tient dans deux dépôts et se travaille depuis un seul poste.

| Dépôt | Chemin local | Contient | Visibilité |
|---|---|---|---|
| `tejoker/SauronID` | `~/code/SauronID` | Le produit : passerelle, console, SDK, preuves, docs, marque | Public |
| `clement-sporrer/SauronID-Landing` | `~/code/sauronid-site` | `www.sauronid.eu`, le site public, Next.js sur Vercel | Privé |

Celui-ci est le centre. On démarre ici. C'est ici que les décisions se prennent
et que les claims deviennent vrais avant d'apparaître ailleurs.

Où aller selon ce qu'on veut toucher :

| Travailler sur | Aller dans |
|---|---|
| La passerelle, le chemin d'application | `core/` |
| La console produit, l'interface connectée | `dashboard/` |
| Ce qu'écrit un intégrateur | `sdk/`, `examples/` |
| La preuve que les claims tiennent | `redteam/`, `transparent-zk/` |
| La documentation publique développeur | `docs/site/` |
| Le site vitrine | l'autre dépôt, `~/code/sauronid-site` |

Attention à l'homonymie : `docs/site/` est la source Mintlify de la
documentation développeur et reste ici. `site/` à la racine n'est plus qu'un
pointeur vers le dépôt du site vitrine, voir [`site/README.md`](site/README.md).

Pour voir les deux dans la même session, depuis une session ouverte ici :

```
/add-dir ~/code/sauronid-site
```

La session lit la vérité produit ici et écrit le site là-bas, dans le même tour.
Sur cette machine le dossier est déjà déclaré dans `.claude/settings.local.json`,
qui est gitignoré et personnel. Sur une machine neuve, cloner d'abord :

```bash
git clone git@github.com:clement-sporrer/SauronID-Landing.git ~/code/sauronid-site
```

Ne reconstruis pas de page marketing dans cet arbre. Il n'existe qu'une copie
vivante du site.

## La hiérarchie de la vérité

1. **`docs/company-brain/`** décide. Problème, solution, produit, features,
   marché, business model, prix. Rien ne se décide ailleurs.
2. **`docs/design/` et `docs/company-brain/brand/`** traduisent cette décision
   en interface et en langage.
3. **Le code** exécute. Un claim qui n'existe que dans un composant, une couleur
   qui n'existe que dans une feuille de style, un prix qui n'existe que dans un
   deck : ce ne sont pas des décisions, ce sont des accidents à corriger.

Si le code et le company brain se contredisent, le company brain a raison sur
l'intention et le code a raison sur ce qui existe aujourd'hui. On corrige les
deux, on ne choisit pas.

## Le company brain s'écrit dans l'ordre

Numérotation par dizaines, une dizaine par phase du raisonnement : `0x` le
socle, `1x` le marché, `2x` l'entreprise, `3x` l'exécution et le récit. Chaque
fichier déclare le framework qu'il applique (24 Steps du MIT, Jobs to be Done,
7 Powers, Five Forces, template Sequoia, entre autres).

Un fichier à la fois. On écrit, on valide, on passe au suivant. N'écris pas
`02-solution.md` si `01-problemes.md` n'est pas validé, et n'invente jamais un
chiffre : chaque donnée vient de [`docs/company-brain/research/`](docs/company-brain/research/README.md)
avec sa note A, B ou C.

## Ce que ce dépôt refuse

- Un claim produit présenté comme disponible alors qu'il est en cours. Les trois
  labels (vérifié dans le dépôt, direction produit, hypothèse) sont obligatoires.
- Un chiffre sans source ni note de qualité.
- Un fichier de documentation qui double un fichier existant. Si le sujet a déjà
  un fichier, on l'édite.
- Un nouveau dossier dans `docs/`. Il y en a six, c'est un plafond, pas un point
  de départ.

## Vérifier avant de dire que c'est fait

```bash
bash scripts/ops/check-schema-parity.sh   # parité SQLite / Postgres, sans base
cargo test --lib                          # depuis core/
```

Les liens de la documentation doivent rester valides : un fichier déplacé se
déplace avec ses références entrantes, dans le même commit.
