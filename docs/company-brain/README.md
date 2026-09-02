# Company brain

La référence de l'entreprise. Un claim produit ne se formule pas dans un
composant, une couleur ne se choisit pas dans une feuille de style, un prix ne
se décide pas dans un deck. Tout se décide ici, puis se propage au code, au
site, au discours commercial et à la marque.

## Comment on opère

Cinq règles, sans exception.

1. **Un fichier à la fois, dans l'ordre.** On écrit, on valide, on passe au
   suivant. Un fichier écrit avant celui dont il dépend est faux par
   construction.
2. **On part du problème, jamais de la solution.** `01-problemes.md` ne
   mentionne pas SauronID. Tout ce qui suit doit s'y rattacher explicitement.
3. **Chaque chiffre porte sa source et sa note.** A : source primaire lue.
   B : enquête sérieuse, commanditaire connu. C : à vérifier. Un chiffre sans
   note ne rentre pas.
4. **On applique un framework connu, on ne réinvente pas.** Chaque fichier
   déclare celui qu'il suit, ci-dessous. Le framework donne la structure, pas
   les réponses.
5. **Court.** Un fichier qui dépasse deux écrans est à découper. Un fichier
   qu'on n'ouvre plus n'a pas besoin d'exister.

## La ligne logique

Un problème fort et quantifié, une solution qui y répond point par point, un
produit qui incarne la solution, des features qui servent le produit. Puis à
qui on le vend, contre qui, et pourquoi nous. Puis comment ça gagne de
l'argent. Puis comment on l'exécute et comment on le raconte.

Le branding, le positionnement, les couleurs et le ton s'alignent en bout de
chaîne. Jamais l'inverse.

## L'arborescence

Numérotation par dizaines : chaque dizaine est une phase du raisonnement. On
peut insérer un fichier dans une dizaine sans renuméroter le reste.

### 0x, le socle

| Fichier | Question | Framework appliqué | État |
|---|---|---|---|
| [`01-problemes.md`](01-problemes.md) | quels problèmes, comment ils se chiffrent | Jobs to be Done (Clayton Christensen, HBS) pour la formulation, notation A/B/C des sources pour la preuve | écrit |
| [`02-solution.md`](02-solution.md) | ce qu'on y répond, et pourquoi ça tient | Quantified Value Proposition, étapes 8 et 9 des 24 Steps (Bill Aulet, MIT Martin Trust Center) | écrit |
| [`03-produit.md`](03-produit.md) | ce qu'un client achète, concrètement | High-Level Product Specification et Full Life Cycle Use Case (24 Steps, MIT) | écrit |
| [`04-features.md`](04-features.md) | les capacités réelles, les connecteurs | Core et Product Plan (24 Steps, MIT), croisé avec [`../integration/`](../integration/sdk-integration.md) | écrit |

### 1x, le marché

| Fichier | Question | Framework appliqué | État |
|---|---|---|---|
| [`10-segment-cible.md`](10-segment-cible.md) | qui exactement, en premier | Market Segmentation, Beachhead Market, End User Profile, Persona (24 Steps, MIT) et Customer Development (Steve Blank, Stanford) | écrit |
| [`11-positionnement.md`](11-positionnement.md) | à quoi on nous compare, dans quelle catégorie | Positioning (April Dunford, *Obviously Awesome*) : alternatives, attributs uniques, valeur, qui s'en soucie, catégorie | écrit |
| `12-concurrents.md` | qui fait quoi, ce qu'ils ne font pas | Five Forces (Michael Porter, HBS) pour la structure du marché, matrice attaque par attaque pour la preuve technique | à écrire |
| `13-unfair-advantage.md` | pourquoi nous et pas un autre dans deux ans | 7 Powers (Hamilton Helmer) : scale economies, network economies, counter positioning, switching costs, branding, cornered resource, process power | à écrire |

### 2x, l'entreprise

| Fichier | Question | Framework appliqué | État |
|---|---|---|---|
| [`20-business-model.md`](20-business-model.md) | comment la valeur se capture | Business Model Canvas (Osterwalder et Pigneur) et Design a Business Model, étape 15 des 24 Steps (MIT) | écrit |
| `21-pricing.md` | combien, sur quelle unité, pourquoi — **bloqué** : l'unité comptée se décide en 20, section « L'unité de facturation », et rien ne se chiffre avant | Pricing Framework (24 Steps, MIT), *Monetizing Innovation* (Ramanujam et Tacke) pour la mesure du consentement à payer | à écrire |
| `22-unit-economics.md` | est-ce que ça tient à l'échelle | LTV et COCA (24 Steps, MIT), 16 Startup Metrics (a16z) pour les définitions communes avec les investisseurs | à écrire |

### 3x, l'exécution et le récit

| Fichier | Question | Framework appliqué | État |
|---|---|---|---|
| `30-playbook.md` | du premier contact à l'agent en production | Process to Acquire a Paying Customer et Sales Process (24 Steps, MIT) | à écrire |
| `31-hypotheses.md` | ce qu'on croit sans l'avoir prouvé, et comment on le teste | Identify et Test Key Assumptions, étapes 20 et 21 des 24 Steps (MIT), MVBP | à écrire |
| `32-investisseurs.md` | le récit, dans l'ordre où un fonds le lit | Sequoia Business Plan template : purpose, problem, solution, why now, market size, competition, product, business model, team, financials | à écrire |

## Les dossiers

- [`research/`](research/README.md) : les preuves. Chaque chiffre noté A, B ou
  C selon ce qui a réellement été lu. Aucun fichier numéroté n'avance un chiffre
  qui n'est pas ici.
- [`brand/`](brand/brand-system.md) : identité, voix, tokens canoniques
  (préfixe `--sid-`), logo, brand book. S'aligne sur 11 et 13, pas l'inverse.
  L'arbitrage est fait en fin de [`11-positionnement.md`](11-positionnement.md) :
  le lanceur en libre-service et le cloud géré tombent, la raison d'être et les
  principes restent.
- `raw/` : matière première de l'ancienne organisation
  ([`product-truth.md`](raw/product-truth.md),
  [`market-positioning-fr.md`](raw/market-positioning-fr.md),
  [`website-brief.md`](raw/website-brief.md)). À replier dans les fichiers
  numérotés au fur et à mesure, puis à supprimer. Rien ne s'ajoute ici.

Le système de design vit dans [`../design/design-system.md`](../design/design-system.md),
parce que c'est la référence que l'agent lit avant de toucher à une interface.

## Sortie

Cette arborescence est faite pour être exportée telle quelle vers Notion : une
page par fichier, l'ordre des numéros donne l'ordre des pages, la colonne
framework donne la méthode à qui reprend le dossier.
