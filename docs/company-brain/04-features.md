# 04. Les capacités et les connecteurs

Découle de [`03-produit.md`](03-produit.md). Ce fichier n'invente aucune
capacité : il classe ce qui existe, nomme ce qui manque, et fixe l'ordre dans
lequel on construit. Détail technique dans
[`../architecture/`](../architecture/tech-stack-overview.md) et
[`../integration/`](../integration/sdk-integration.md).

Étiquettes : **[vérifié]** démontrable dans le dépôt aujourd'hui,
**[direction]** décidé et en cours, **[hypothèse]** à prouver.

## Le noyau

Une seule chose doit rester meilleure chez nous que partout ailleurs : **la
contrainte appliquée en dehors du modèle, avec la preuve de ce qu'elle a laissé
passer et de ce qu'elle a refusé.**

Tout le reste est remplaçable et doit l'être : le modèle, le framework d'agents,
les connecteurs, l'interface, jusqu'à la façon dont l'agent est construit. Si
une capacité de cette page peut être obtenue ailleurs sans nous affaiblir, elle
n'est pas le noyau. Cette phrase sert à trancher chaque arbitrage de
construction.

## Les capacités, par ce qu'elles servent

### Enrôler un agent

| Capacité | Ce que ça donne au client | État |
|---|---|---|
| Clé propre par agent, liée à un propriétaire humain | personne ne peut agir au nom d'un agent, pas même l'opérateur | [vérifié] |
| Empreinte de la configuration (modèle, invite, outils) | changer la configuration invalide les appels suivants, donc un agent modifié en douce s'arrête | [vérifié] |
| Révocation immédiate | un agent suspect cesse d'agir tout de suite, sans redéploiement | [vérifié] |
| Délégation bornée en profondeur et en périmètre | un agent ne peut pas se donner un sous-traitant plus puissant que lui | [vérifié] |

### Borner ce qu'il peut faire

Vingt-huit contrôles évaluables, tous côté serveur, tous branchés au langage de
politique. **[vérifié]**

Une précision qui évite un malentendu vendable : le refus par défaut porte sur
l'appel, pas sur la règle. Un appel non signé, rejoué, altéré ou fait par un
agent révoqué est refusé sans qu'on ait rien écrit. En revanche une règle qu'on
n'a pas écrite n'interdit rien : ne pas déclarer de plafond ne crée pas un
plafond. C'est ce qui rend l'étape 6 du cycle de vie (écrire les règles avec le
client, après l'observation) non négociable.

| Famille | Contrôles |
|---|---|
| Outils et cibles | liste d'outils autorisés, liste d'outils interdits, domaines autorisés, domaines interdits |
| Argent | plafond global, plafond quotidien, plafond par action, devises autorisées, seuil déclenchant une exigence supplémentaire |
| Cadence | fréquence horaire, fréquence hebdomadaire, délai minimal entre deux actions, actions simultanées |
| Temps | fenêtre horaire, jours ouvrés, périodes de gel |
| Données | périmètre de données, sens de circulation autorisé, détection de données personnelles, taille de charge, type de contenu, langue, zone géographique, nombre de destinataires |
| Chaîne | profondeur de délégation, version d'agent épinglée |
| Humain | signatures M parmi N par rôle |
| Observation | mode à blanc, qui montre ce que la règle aurait refusé sans rien bloquer |

### Exécuter sans dépasser

| Capacité | Ce que ça donne au client | État |
|---|---|---|
| Capacité de sortie à usage unique | un appel externe est autorisé pour un hôte, une méthode, un chemin, un corps et une taille précis, et une seule fois | [vérifié] |
| Passerelle en coupure | l'agent ne parle à l'extérieur qu'à travers elle, avec refus des redirections et des adresses internes | [vérifié] |
| Paiement borné par l'intention déclarée | montant, devise et bénéficiaire sont contraints à l'enrôlement, pas au moment de payer | [vérifié] |

### Escalader vers un humain

| Capacité | Ce que ça donne au client | État |
|---|---|---|
| Co-signature M parmi N par rôle | une action sensible ne part qu'avec l'accord humain requis, et cet accord reste vérifiable après coup | [vérifié] |
| File d'escalade utilisable par un métier | voir les cas remontés, trancher, renvoyer à l'agent, sans passer par un ingénieur | [direction] |

### Prouver ce qui s'est passé

| Capacité | Ce que ça donne au client | État |
|---|---|---|
| Reçu chaîné par action | chaque acte laisse une trace qu'on ne peut pas réécrire sans casser la chaîne | [vérifié] |
| Journal d'audit inviolable des changements de règles et de droits | on sait quand une règle a changé et par quel accès | [vérifié] |
| Ancrage public des lots | même nous ne pouvons pas réécrire l'historique sans que ça se voie | [vérifié], mais le fournisseur d'ancrage est en simulation par défaut : un déploiement qui veut l'ancrage réel doit le configurer, et ça fait partie de la mise en production |
| Preuve calculée hors de nos machines sur les décisions de politique | une affirmation sur ce que l'agent a fait et sur ce que la règle a tranché se vérifie sans nous croire sur parole (guest `action-policy`, receipts RISC Zero) | [vérifié] |
| Export pour un audit ou un commissaire aux comptes | le jour du contrôle, la réponse tient dans un fichier | [vérifié] |

### Mesurer

| Capacité | Ce que ça donne au client | État |
|---|---|---|
| Registre de consommation en jetons et en euros, par agent | le coût d'un workflow est un chiffre, pas une estimation | [vérifié] |
| Liste des refus avec la règle qui a tranché | on voit où l'agent bute, donc où la règle est trop serrée ou l'agent trop bête | [vérifié] |
| Avant/après intégré au produit | le coût du processus mesuré au cadrage, rejoué contre le réalisé | [direction] |

## Les surfaces

Comment on se branche, aujourd'hui, **[vérifié]** : un binaire Rust exposant une
API HTTP ; des clients Python, TypeScript et Go ; un serveur MCP à sept outils
(état, enrôlement, autorisation de paiement, appel sortant, déclaration de
sortie, actions récentes, révocation) ; des adaptateurs pour LangChain, OpenAI,
Anthropic, CrewAI, AutoGen et LlamaIndex ; une console web ; des fichiers de
déploiement Docker, Helm et natif.

## Les connecteurs, en trois niveaux

Brancher un agent aux systèmes du client est le poste de travail le plus lourd
d'une livraison. Trois niveaux, du moins cher au plus cher, et la règle est de
toujours descendre au niveau le plus bas possible.

### Niveau 1 : les serveurs MCP existants

De plus en plus d'éditeurs publient un serveur MCP pour leur produit. Quand
c'est le cas, il n'y a rien à développer : on branche, et l'agent dispose des
outils du produit. La couverture augmente sans travail de notre part, portée par
l'écosystème.

C'est la voie par défaut. Elle transforme une question de développement en
question de configuration, et c'est ce qui rend une livraison rapide.

Aujourd'hui, l'inverse existe dans le dépôt : SauronID est un **serveur** MCP,
donc un client MCP comme Claude Desktop obtient nos actions gouvernées sans
intégrer le SDK. **[vérifié]** Ce qui manque est le sens utile pour une
livraison : SauronID en **client** MCP, en coupure devant les serveurs MCP du
client. **[direction]**

Et c'est là que ça devient plus qu'un raccourci d'intégration. La sortie d'un
outil MCP est une entrée non fiable : un agent branché à dix serveurs a dix
bouches par lesquelles on peut lui dicter sa conduite (problème 7 de 01). Chaque
serveur détient en plus ses propres jetons d'accès, ce qui recrée exactement le
contournement décrit dans
[`credential-broker.md`](../architecture/credential-broker.md). Se placer devant
eux, c'est appliquer la politique à chaque appel d'outil, délivrer une capacité
à usage unique, produire le reçu et compter le coût. On n'ajoute pas un
connecteur : on prend la place du tuyau.

Deux limites à connaître avant de le vendre :

1. **Le transport local.** Beaucoup de serveurs MCP tournent à côté de l'agent,
   sans passer par le réseau. La passerelle de sortie ne les voit pas :
   l'application doit se faire au niveau du transport MCP lui-même, sinon un
   agent peut appeler un outil local sans nous.
2. **La granularité des outils.** Un outil nommé `send_message` peut faire
   beaucoup de choses. Nos règles portent sur l'outil et ses arguments, donc on
   sait le borner, mais il faut déclarer par serveur quels outils sont des
   actions à effet réel. C'est du travail, sans commune mesure avec l'écriture
   d'un connecteur, mais pas nul.

### Niveau 2 : les API sans serveur MCP

La sortie générique bornée : n'importe quelle API HTTP est atteignable à travers
une capacité à usage unique, avec hôte, méthode, chemin, corps et taille
contraints. **[vérifié]** Il reste le travail de branchement, mais aucun
développement d'infrastructure.

### Niveau 3 : les outils internes du client

Le vrai sur mesure : l'application maison, le tableur qui fait foi, le logiciel
métier de 2011 sans API. C'est là que part le temps de livraison, et c'est ce
que mesure l'hypothèse 5 de 02.

Deux règles pour éviter le piège du catalogue infini :

1. **Un connecteur entre au catalogue quand une livraison payée le demande.**
   Jamais par anticipation, jamais pour remplir une grille comparative.
2. **Un connecteur qui ne servira qu'à un seul client est facturé à son coût
   complet**, en ligne séparée, ou refusé.

## Le plan de construction

Dans cet ordre, chacun avec son déclencheur. On ne démarre pas un chantier dont
le déclencheur n'est pas atteint.

| # | Chantier | Pourquoi lui | Déclencheur |
|---|---|---|---|
| 1 | Atelier de construction sur la plateforme : gabarits, connexion, règles et mise en service au même endroit | c'est nous qui y gagnons d'abord, chaque jour de livraison économisé | maintenant, construit au fil des livraisons |
| 2 | File d'escalade pour le métier | sans elle, l'agent en production crée un travail que personne ne fait | la première livraison qui produit des escalades |
| 3 | Lecture métier de la trace et avant/après intégré | c'est ce qui déclenche le renouvellement, étape 10 du cycle de vie | la première mesure à l'étape 8 |
| 4 | Passerelle MCP en coupure : SauronID comme client MCP devant les serveurs du client | une seule construction remplace N connecteurs, et place le contrôle là où l'injection arrive | la première livraison dont un système cible a un serveur MCP |
| 5 | Catalogue de connecteurs pour ce que MCP ne couvre pas | seulement quand la répétition est prouvée | le deuxième client qui demande le même branchement |
| 6 | Identité nominative derrière un changement de règle | aujourd'hui on trace l'accès, pas la personne | le premier client qui l'exige en audit |

## Ce qu'on ne construira pas

- **Du no-code grand public.** Un processus qui paie des factures se construit
  par quelqu'un qui sait ce qu'il fait.
- **De l'hébergement géré.** Décidé en 02, pour trois raisons qui n'ont pas
  changé.
- **Notre propre modèle.** On branche celui qui convient.
- **Un IAM pour les employés du client.** Il en a déjà un.
- **Une console d'observabilité générique.** Notre trace existe pour décider et
  prouver, pas pour concurrencer un outil de supervision.
- **Une place de marché d'agents.** Ça suppose un volume qu'on n'a pas et un
  contrôle qualité qu'on ne pourrait pas tenir.
