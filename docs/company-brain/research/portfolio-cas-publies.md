# Portfolio : les cas publiés par les laboratoires et les cabinets

**Relevé le 1er septembre 2026.** Ce que les éditeurs de modèles et les grands
cabinets publient eux-mêmes comme déploiements d'agents, avec chiffres, pour
servir de référence externe à notre portfolio.

## Pourquoi ce fichier existe

Nous n'avons aucun client déployé. Un portfolio de nos résultats est donc
impossible sans mentir. Un portfolio de ce que les autres ont publié est
possible, vérifiable, et il répond à la même question du prospect : est-ce que
ça marche vraiment quelque part.

La règle qui va avec, et elle n'est pas négociable : **on cite, on ne
s'approprie pas.** Chaque carte nomme l'entreprise, l'éditeur qui a publié, et
le fait que ce n'est pas notre résultat. Un prospect qui découvre en réunion
qu'un chiffre affiché n'est pas le nôtre ne signe plus rien.

## La note de qualité de tout ce fichier : B

Sans exception. Ces études sont publiées par ceux qui vendent le modèle utilisé.
Le déploiement est réel, l'entreprise est nommée, le chiffre a une source
primaire lisible. Mais personne n'a publié le cas où ça n'a pas marché, aucune
méthode de mesure n'est détaillée, et aucune n'est auditée par un tiers.

Note B veut dire : citable dans un document client **avec le commanditaire
nommé**, jamais présenté comme une mesure indépendante.

## Ce que la recherche a réellement trouvé, contradictions d'abord

**Les laboratoires publient très peu de chiffres de processus.** C'est le
résultat le plus important de ce relevé, et il va contre l'idée de départ.
Mistral affiche 42 clients dont AXA, BNP Paribas, CMA CGM, SNCF, Orange, Veolia,
TotalEnergies, France Travail et Ardian : la meilleure liste de logos
européens du marché, et **zéro résultat chiffré**. Ce sont des annonces de
partenariat, pas des études de cas.

**Aucun cas ne concerne une entreprise de 100 à 1 500 salariés.** DXC compte
14 000 personnes sur sa seule activité assurance, eSentire est un opérateur de
sécurité managée, le client Deloitte est un groupe mondial de biens de
consommation. Décision prise : **on les prend quand même.** Un cas net chez un
grand groupe vaut mieux qu'un exemple théorique chez une entreprise de la bonne
taille. Le prospect veut savoir si le processus tient en production, pas si son
voisin de taille l'a fait. La seule règle est de ne jamais laisser croire que le
chiffre est le sien : on affiche l'échelle du déploiement à côté du résultat.

**Les chiffres qui circulent le plus sont les moins solides.** 171% de retour
moyen, Klarna à 60 M$, JPMorgan à 360 000 heures d'avocat : tout ça vient de
blogs agrégateurs sans méthode consultable. Note C, à ne jamais afficher.

**Quatre éditeurs refusent la lecture automatisée.** openai.com renvoie 403 sur
toutes les pages `/index/`, bcg.com un 403, mckinsey.com un timeout, y compris
sur ses PDF publics. Les cas d'OpenAI (Hebbia sur le travail financier et
juridique), de BCG (quatre entreprises et la transformation de coûts) et de
McKinsey (mémos de crédit bancaire) sont connus par extraits de recherche
seulement, donc **note C**, donc pas affichables. À reprendre à la main.

Le chiffre McKinsey le plus cité, 20 à 60% de productivité d'analyste crédit et
30% de délai de décision en moins, entre dans cette catégorie tant qu'il n'a pas
été lu dans l'article. Il n'est pas dans les cartes retenues.

## Les cas retenus

Quatre critères de sélection, tous éliminatoires : l'entreprise est nommée,
l'éditeur publie lui-même, un acte réel est posé (pas seulement une suggestion),
et un chiffre est donné. Ce qui reste tient en peu de lignes.

### Un groupe mondial de biens de consommation, factures fournisseurs

Publié par Deloitte. C'est le cas le plus directement utile, parce que c'est
exactement la porte 1 (voir
[`porte-1-factures-exception.md`](porte-1-factures-exception.md)).

L'agent lit la facture, y compris manuscrite ou non standard, identifie le
fournisseur, l'entité, la devise, la date et l'imputation comptable, produit un
indice de confiance, relance les factures ouvertes, et traite les lignes de taxe
étrangères.

| Mesure publiée | Valeur |
|---|---|
| Taux de traitement sans intervention | 92%, cible proche de 99% |
| Temps de traitement | de 30 minutes environ par facture à quelques minutes ou secondes, soit 50 à 75% de moins |
| Effectifs affectés au traitement | divisé par deux |
| Ce qui reste humain | vérifier les recommandations, décider d'une revue supplémentaire selon l'indice de confiance, analyser les causes racines, traiter les cas aberrants |

Deux choses à en tirer, et la deuxième compte plus que la première.

La première : 92% sans intervention, c'est le chiffre qui fait taire l'objection
« ça ne marchera jamais sur nos factures ». La seconde : ce qui reste à l'humain
est nommé, et c'est **l'exception et la cause racine**. Le déploiement le plus
abouti publié sur ce processus confirme la thèse de la porte 1. Le volume part,
le jugement reste, et c'est l'indice de confiance qui trace la frontière.

### DXC, assurance, traitement des sinistres

Publié par Anthropic. L'agent classe le document, extrait les données, signale
l'exception, route vers la bonne personne, et journalise la décision pour la
conformité.

| Mesure publiée | Valeur |
|---|---|
| File d'attente d'entrée | de plusieurs jours à quelques minutes |
| Classement d'un document | moins d'une seconde |
| Intégration d'une nouvelle règle réglementaire | quelques jours, contre 12 à 18 mois |
| Exactitude au premier passage sur le calcul d'indemnité | 80% |
| **Part des dossiers exigeant un jugement humain** | **de 70% à 20%** |

C'est le cas le plus utile qu'on ait, et pas pour la raison évidente. La
dernière ligne mesure exactement notre thèse : l'agent absorbe le volume, la
personne garde l'exception, et le résultat se lit dans le déplacement de la
frontière entre les deux. Ce n'est pas nous qui l'affirmons, c'est publié.

### eSentire, sécurité managée, investigation d'alertes

Publié par Anthropic. Douze mois de production.

| Mesure publiée | Valeur |
|---|---|
| Investigations autonomes | plus de 120 000 |
| Appels d'outils | plus de 5 millions, soit 468 000 heures d'expert équivalentes |
| Durée moyenne d'une investigation | 6 minutes |
| Attaques confirmées détectées par client | +41% |
| Volume d'alertes | -11% |
| Accord avec le verdict d'un analyste senior | plus de 90% |
| Ce qui reste humain | un analyste senior revoit et agit sur chaque conclusion critique |

Le chiffre à retenir n'est pas 120 000. C'est la dernière ligne : douze mois de
production autonome **avec** une revue humaine sur les cas critiques. Personne
n'a supprimé l'humain, on a déplacé ce qu'il regarde.

### Rocket Money, finance grand public, actions sur comptes

Publié par Anthropic. L'agent résilie des abonnements et négocie des factures,
donc pose des actes à conséquence financière.

Les chiffres publiés portent sur la vitesse de développement, pas sur le
processus. Ce qui est utile ici est architectural : **une action financière
exige l'accord explicite de l'utilisateur**, et un classifieur route vers des
sous-agents spécialisés. C'est la même frontière que la nôtre, décrite par
quelqu'un d'autre.

### Les cas cités sans être retenus

| Cas | Chiffre publié | Pourquoi pas retenu |
|---|---|---|
| Spellbook, revue de contrats | 530 000 revues par mois | l'agent produit un avis, pas un acte. Sans action réelle, notre couche ne sert à rien (voir [`use-cases.md`](use-cases.md) section 5) |
| EvenUp, rédaction juridique | 15 heures à 15 minutes | même raison, production de document |
| Vega, cybersécurité | 67% du temps des analystes rendu | du temps rendu, pas un coût retiré. C'est le plafond du copilote décrit dans [`copilot-vs-agent.md`](copilot-vs-agent.md) |
| League, santé | cycles produit divisés par deux | processus interne d'éditeur, non transposable |
| Palantir AIP, contrôle de factures | vérifie une facture contre un contrat, signale l'écart, approuve dans la limite de la politique | tiré de la documentation produit, aucun client nommé, aucun chiffre |
| Détaillant Palantir, ruptures de stock | -50% | publié par un intégrateur tiers, pas par Palantir. Note C |
| PwC GL.ai, revue du grand livre | milliards d'écritures analysées, anomalies signalées | détection, pas action. L'outil signale, un auditeur décide. Utile comme preuve que la finance accepte l'IA sur ses écritures, pas comme cas d'agent |
| EY, 150 agents pour 80 000 fiscalistes | aucun résultat de processus publié | une taille de flotte n'est pas un résultat |
| Mémos de crédit bancaire, McKinsey | 20 à 60% de productivité, 30% de délai en moins | article non lisible automatiquement, chiffre connu par extrait de recherche. Note C tant qu'il n'est pas lu. Et un mémo est un document, pas un acte |

Palantir mérite une note à part : la description de leur fonction de contrôle de
facture est **presque mot pour mot notre argumentaire**. Approuver dans la limite
d'une politique, signaler l'écart. La différence tient à ce qui reste après :
chez eux la politique et la trace vivent dans leur plateforme, chez nous la
trace est vérifiable par un tiers sans nous croire. C'est un concurrent, pas une
référence à citer.

## Ce que ce relevé change pour le site

1. **Le portfolio s'ouvre sur quatre cartes, pas quinze.** Le client Deloitte
   sur les factures, DXC sur les sinistres, eSentire sur les alertes, Rocket
   Money sur les actions de compte. Quatre cas chiffrés, publiés par l'éditeur
   ou le cabinet, chacun avec son lien.
2. **La carte Deloitte ouvre.** 92% de factures traitées sans intervention, sur
   la porte 1, publié par un cabinet que le directeur financier connaît. C'est
   la carte qui fait le travail commercial.
3. **La ligne de DXC porte la thèse.** De 70% à 20% de dossiers exigeant un
   jugement humain. Elle dit ce que nous vendons, mesurée par quelqu'un d'autre.
4. **Chaque carte porte trois blocs séparés visuellement.** L'échelle du
   déploiement, ce qui a été mesuré là-bas, et ce qu'il faudrait pour que ça
   tienne chez le lecteur. Le troisième bloc est notre argumentaire et il ne se
   déguise jamais en résultat.
5. **Nos 14 cas modélisés restent**, en dessous, sous un autre titre et un autre
   niveau de preuve. Ce sont des chiffrages, pas des références.
6. **Aucun chiffre agrégateur, aucun chiffre non lu à la source.** 171% de
   retour, Klarna, JPMorgan, et pour l'instant McKinsey et BCG : bannis.

## À faire avant que ce fichier serve

- Lire à la main les quatre sources qui bloquent la lecture automatisée :
  OpenAI (Hebbia), BCG (quatre entreprises et transformation de coûts),
  McKinsey (mémos de crédit, opérations bancaires). Chacune peut ajouter une
  carte.
- Chercher un cas publié dans la bande 100 à 1 500 salariés. Aucun trouvé. Ce
  n'est pas bloquant, c'est une amélioration : un cas à la bonne taille
  vaudrait plus que les quatre autres réunis.
- Vérifier que chaque lien cité est encore en ligne avant chaque campagne. Une
  étude de cas retirée pendant qu'elle est affichée sur notre site est un
  incident.

## Sources

Toutes relevées le 1er septembre 2026.

| Cas | Lien | Éditeur qui publie |
|---|---|---|
| DXC | https://claude.com/customers/dxc | Anthropic |
| eSentire | https://claude.com/customers/esentire | Anthropic |
| Rocket Money | https://claude.com/customers/rocket-money | Anthropic |
| Index des cas Claude | https://claude.com/customers | Anthropic |
| Clients Mistral | https://mistral.ai/customers | Mistral |
| Factures fournisseurs, groupe de biens de consommation | https://www.deloitte.com/us/en/what-we-do/case-studies/hands-off-the-task-eyes-on-the-outcome.html | Deloitte |
| GL.ai, revue du grand livre | https://www.pwc.com/m1/en/events/socpa-2020/documents/gl-ai-brochure.pdf | PwC |
| Contrôle de facture AIP | documentation produit palantir.com/docs/foundry | Palantir |
