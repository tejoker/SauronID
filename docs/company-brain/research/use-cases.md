# Cas d'usage : ce qui est déployé, ce qui rapporte, ce qui reste ouvert

**Étape 0, recherche documentaire. 23 août 2026.**
**Question posée :** quels processus d'entreprise sont réellement confiés à
l'IA, lesquels rapportent, et lesquels restent ouverts à quelqu'un qui sait
faire exécuter un agent sans surveillance humaine permanente.

Ce document ne choisit pas de cible. Il établit ce qui est mesuré. Le choix du
marché de tête se fait en `10-segment-cible.md`.

Notes A, B, C définies dans [`README.md`](README.md). Sources détaillées dans
[`sources.md`](sources.md).

## 1. Où l'IA est déjà installée

Eurostat, enquête 2025 sur les entreprises de 10 salariés ou plus, lue à la
source (note A) :

| Mesure | Chiffre |
|---|---|
| Entreprises de l'UE utilisant l'IA | 19,95%, contre 13,5% en 2024 |
| Petites entreprises | 17% |
| Entreprises moyennes | 30,4% |
| Grandes entreprises | 55,0% |
| Finalité citée, marketing et vente | 34,7% |
| Finalité citée, administration et gestion | 31,1% |
| Technologie la plus utilisée, fouille de texte | 11,8% |

Côté grandes organisations, l'enquête reprise par le AI Index 2026 donne 88%
d'organisations utilisant l'IA dans au moins une fonction en 2025 (78% en 2024),
et plus de la moitié dans trois fonctions ou plus (note A).

L'écart entre 20% chez Eurostat et 88% dans l'enquête McKinsey n'est pas une
contradiction : populations et questions différentes, l'une couvrant toutes les
entreprises européennes de plus de dix salariés, l'autre des organisations
grandes et déjà engagées.

## 2. Où les agents sont réellement à l'échelle

AI Index 2026, chapitre 4, lu à la source (note A) :

- **L'usage d'agents à l'échelle est à un seul chiffre dans presque toutes les
  fonctions.**
- Même dans les fonctions les plus actives, informatique et gestion des
  connaissances, **deux tiers ou plus des répondants déclarent aucun usage**.
- Le secteur technologique fait exception, avec un usage d'agents à l'échelle de
  24% en génie logiciel, 22% en informatique et 21% en opérations de service.

Autrement dit : hors du secteur tech, la place est vide. Ce n'est pas un marché
à conquérir contre des concurrents installés, c'est un marché où presque
personne n'a encore réussi à mettre un agent en production.

## 3. Où la valeur est attribuée

Même source, même enquête (note A). Ce que les répondants associent à l'IA :

| Type de gain | Fonctions les plus citées |
|---|---|
| Économies de coût | génie logiciel et production industrielle, 56% |
| Gains de revenu | marketing et vente 67%, stratégie et finance 65%, développement produit 62% |

À lire avec la réserve que le AI Index pose lui-même : le nombre de répondants
estimant que l'IA a amélioré un indicateur est souvent proche du nombre estimant
qu'elle n'a rien changé. Les effets négatifs restent rares, au plus 7% sur les
indicateurs de coût.

## 4. Ce que les fournisseurs déclarent, par cas d'usage

Enquête Anthropic et Material, plus de 500 responsables techniques américains
(note B, le commanditaire vend les modèles) :

| Cas d'usage | Chiffre déclaré |
|---|---|
| Analyse de données et reporting | 60% le citent comme le plus impactant hors code |
| Automatisation de processus internes | 48% |
| Agents de code sur du code de production | 86% |
| Workflows multi-étapes | 57%, dont 16% transverses à plusieurs équipes |

Chiffres de fournisseurs de solutions, tous en note C, aucun rapport primaire
consulté : 70 à 90% de réduction du temps de traitement d'une facture, 70% des
demandes de support de niveau 1 traitées de bout en bout, retour sur
investissement en 3 à 6 mois sur les cas à fort volume, 8 à 14 mois sinon. Ces
chiffres sont des arguments de vente, pas des mesures. Ils indiquent où les
éditeurs pensent que l'argent est, ce qui reste une information.

## 5. Le classement

Trois critères, dans cet ordre.

**Valeur** : ce que le processus coûte aujourd'hui et ce qu'on peut lui retirer.
**Ouverture** : est-ce que la place est prise par des éditeurs installés.
**Conséquence** : est-ce que l'agent commet des actions à effet réel (un
paiement, une écriture dans un système de référence, un envoi à un tiers, un
droit d'accès accordé). C'est le critère qui décide si un contrôle d'exécution
change quelque chose ou non : sur un cas d'usage sans action à effet réel, notre
différenciant ne se paie pas.

| Cas d'usage | Valeur | Ouverture | Conséquence | Verdict |
|---|---|---|---|---|
| Factures fournisseurs, de la réception au paiement | élevée, poste chiffrable en ETP | large, éditeurs verticaux mais peu d'agents en production | forte, un paiement part | **prioritaire** |
| Recouvrement et relance client | élevée, effet direct sur la trésorerie | large | forte, un message part chez un client | **prioritaire** |
| Tickets informatiques, droits et provisionnement | élevée | fonction la plus avancée hors tech, mais deux tiers sans usage | forte, un droit d'accès est accordé | **prioritaire** |
| Achats, revue de contrats et de fournisseurs | élevée | large | forte, un engagement est pris | **prioritaire** |
| Prospection et relance commerciale | élevée, côté revenu (67% citent marketing et vente) | encombrée d'outils, peu d'exécution réelle | moyenne, un envoi part | secondaire |
| Automatisation de processus internes divers | moyenne à élevée, 48% la citent | large | variable | secondaire, dépend du processus |
| Analyse de données et reporting | déclarée la plus impactante (60%) | large | faible, l'agent produit un document | à éviter en amorçage, notre contrôle n'y sert presque à rien |
| Support client de niveau 1 | mesurée, +14 à 15% de tickets par heure (note A) | saturée, tous les éditeurs de CRM ont leur agent | moyenne | à éviter, on arrive après |
| Génération et revue de code | mesurée, +26% de pull requests (note A) | saturée, 86% l'utilisent déjà | moyenne | à éviter, budget déjà pris et acheteur technique |
| Tri de candidatures et recrutement | déclarée élevée (note C) | large | forte | à éviter pour l'instant, classé haut risque à l'annexe III de l'AI Act, cycle de vente long |

## 6. Ce que ce classement dit

**Les cas d'usage les plus mesurés sont les plus saturés.** Code et support
niveau 1 sont les deux seuls endroits où la valeur est établie par des études
contrôlées, et ce sont exactement les deux où chaque éditeur a déjà poussé son
agent. La mesure a attiré la concurrence.

**Les cas d'usage à forte conséquence sont les moins servis.** Payer une
facture, relancer un client, accorder un droit d'accès, engager un achat : ce
sont des actions qu'une entreprise ne confie pas à un système qu'elle ne peut
pas borner. C'est précisément là que la place est vide, et c'est le seul endroit
où un contrôle d'exécution se paie.

**Le reporting est un piège d'amorçage.** C'est le cas d'usage le plus cité
comme impactant, il est facile à vendre et facile à livrer, et il ne produit
aucune action à effet réel. Un client qui achète ça n'a aucune raison de payer
pour un contrôle.

## 7. Ce qui manque

- Aucune statistique publique ne ventile l'IA par processus d'entreprise.
  Eurostat s'arrête à la finalité (marketing, administration), le AI Index à la
  fonction (informatique, gestion des connaissances). Le niveau « traitement des
  factures fournisseurs » n'existe dans aucune source officielle.
- Aucune mesure indépendante du gain d'un agent autonome par cas d'usage. Tout
  ce qui circule vient d'éditeurs.
- Aucun chiffre non commercial sur le coût de traitement d'un processus avant
  automatisation, ce qui est exactement le chiffre dont dépend toute
  démonstration de retour.

Ces trois manques se comblent en entretien et sur les premiers déploiements, pas
en recherche documentaire. Ils sont la matière de l'étape 2.
