# Portfolio : les cas publiés par les laboratoires

**Relevé le 1er septembre 2026.** Ce que les éditeurs de modèles publient
eux-mêmes comme déploiements d'agents, avec chiffres, pour servir de référence
externe à notre portfolio.

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

**Presque aucun cas n'est dans notre bande de taille.** DXC compte 14 000
personnes sur son activité assurance. eSentire est un opérateur de sécurité
managée. Les résultats publiés viennent d'organisations qui ont une équipe de
plateforme, pas d'entreprises de 100 à 1 500 salariés. Une carte de portfolio
qui laisse croire l'inverse se retourne au premier appel.

**Les chiffres qui circulent le plus sont les moins solides.** 171% de retour
moyen, Klarna à 60 M$, JPMorgan à 360 000 heures d'avocat : tout ça vient de
blogs agrégateurs sans méthode consultable. Note C, à ne jamais afficher.

**openai.com refuse la lecture automatisée** (403 sur toutes les pages
`/index/`). Les cas OpenAI listés par la recherche, dont Hebbia sur
l'automatisation du travail financier et juridique, n'ont pas pu être lus à la
source et ne sont donc pas retenus ici. À reprendre à la main.

## Les cas retenus

Quatre critères de sélection, tous éliminatoires : l'entreprise est nommée,
l'éditeur publie lui-même, un acte réel est posé (pas seulement une suggestion),
et un chiffre est donné. Ce qui reste tient en peu de lignes.

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

Palantir mérite une note à part : la description de leur fonction de contrôle de
facture est **presque mot pour mot notre argumentaire**. Approuver dans la limite
d'une politique, signaler l'écart. La différence tient à ce qui reste après :
chez eux la politique et la trace vivent dans leur plateforme, chez nous la
trace est vérifiable par un tiers sans nous croire. C'est un concurrent, pas une
référence à citer.

## Ce que ce relevé change pour le site

1. **Le portfolio s'ouvre sur trois cartes, pas quinze.** DXC, eSentire, Rocket
   Money. Trois cas nommés, chiffrés, publiés par l'éditeur du modèle, chacun
   avec son lien.
2. **Chaque carte porte deux blocs séparés visuellement.** Ce qui a été mesuré
   là-bas, et ce qu'il faudrait pour que ça tienne ici. Le second bloc est notre
   argumentaire, et il ne se déguise pas en résultat.
3. **La ligne de DXC ouvre le portfolio.** De 70% à 20% de dossiers exigeant un
   jugement humain. C'est la meilleure phrase de vente disponible, elle est
   publiée par quelqu'un d'autre, et elle dit notre thèse.
4. **Nos 14 cas modélisés restent**, en dessous, sous un autre titre et un autre
   niveau de preuve. Ce sont des chiffrages, pas des références.
5. **Aucun chiffre agrégateur.** 171% de retour, Klarna, JPMorgan : bannis.

## À faire avant que ce fichier serve

- Lire les cas OpenAI à la main, openai.com bloquant la lecture automatisée.
  Hebbia en priorité.
- Chercher un cas publié dans la bande 100 à 1 500 salariés. Aucun trouvé à ce
  jour, et c'est le trou le plus gênant du portfolio.
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
| Contrôle de facture AIP | documentation produit palantir.com/docs/foundry | Palantir |
