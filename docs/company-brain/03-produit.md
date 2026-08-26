# 03. Le produit

Ce qu'un client achète, concrètement, et ce qu'il vit du premier contact au
renouvellement. Découle de [`02-solution.md`](02-solution.md) et ne le
contredit pas. Le détail des capacités et le catalogue de connecteurs sont dans
04.

Étiquettes : **[vérifié]** démontrable dans le dépôt aujourd'hui,
**[direction]** décidé et en cours, **[hypothèse]** à prouver.

## Ce qu'il achète, en trois objets

1. **Un workflow qui tourne.** Un processus nommé, exécuté de bout en bout par
   un agent, sur son infrastructure, avec les cas difficiles escaladés à un
   humain. C'est le livrable, et c'est ce qui produit le gain.
2. **La plateforme qui le tient.** Identité de chaque agent et personnes qui en
   répondent, règles modifiables en direct, droits accordés et retirés, plafonds
   de dépense, trace exportable, refus consultables. C'est ce qui rend le
   workflow déployable, puis pilotable sans nous.
3. **La continuité.** Maintenir, améliorer, ajouter des workflows, surveiller
   les coûts et les comportements. C'est ce que paie l'abonnement.

Un client qui n'achèterait que le premier objet aurait un agent orphelin. Un
client qui n'achèterait que le deuxième aurait un outil sans usage. Les trois se
vendent ensemble, dans cet ordre.

## Le cycle de vie complet

Ce que vit le client, étape par étape. Chaque étape a une sortie observable :
si elle n'est pas atteinte, on ne passe pas à la suivante.

| # | Étape | Sortie observable |
|---|---|---|
| 1 | Il nous identifie sur un processus qu'il reconnaît comme le sien | il accepte un rendez-vous |
| 2 | Cadrage : quel processus, quel volume, quel coût actuel | volume, temps par unité, coût chargé, taux d'erreur et délai, écrits et validés par lui |
| 3 | Décision : périmètre, prix, délai, ce qui reste humain | contrat signé, avec le chiffre d'avant dedans |
| 4 | Installation sur son infrastructure | la plateforme tourne chez lui, sur son cloud, son hébergeur ou ses machines |
| 5 | Construction de l'agent, branchement à ses systèmes, passage en mode observation | sur des cas réels, l'agent montre ce qu'il ferait sans rien faire, et ce comportement est documenté |
| 6 | Écriture des règles avec lui, à partir de ce que l'observation a montré : outils, plafonds, droits, ce qui s'escalade | les règles sont lisibles par son métier, pas seulement par un ingénieur |
| 7 | Mise en production progressive | l'agent agit, les cas difficiles remontent, rien ne casse |
| 8 | Mesure : export de la trace à échéance convenue, croisée au retour des équipes | le volume traité sans intervention, le coût après, l'écart avec l'étape 2 |
| 9 | Extension : un deuxième workflow, par nous ou par lui | il choisit, et les deux nous conviennent |
| 10 | Renouvellement | l'abonnement continue parce qu'il voit ce qu'il paie |

L'étape 2 est la seule qu'on ne saute jamais. Sans le chiffre d'avant, l'étape 8
ne démontre rien, et sans l'étape 8 il n'y a pas d'étape 10. Elle est facturée
et déductible du projet, et s'offre quand c'est un levier pour emporter
l'affaire. Beaucoup de clients arrivent d'ailleurs avec leur processus en tête
et un besoin déjà chiffré : le cadrage confirme et borne, il ne part pas d'une
page blanche.

L'étape 5 mérite une phrase parce qu'elle est mal comprise ailleurs : l'agent
traite de vrais cas et montre ce qu'il ferait, sans rien envoyer, sans rien
écrire, sans rien payer. Ça coûte quelques minutes, ça se présente au client en
une demi-heure, et ça donne la matière de l'étape 6 : on écrit les règles en
ayant vu le comportement réel, au lieu de les deviner. Le mécanisme existe dans
le produit (`dry_run` sur une politique, plus un mode consultatif au niveau du
gateway). **[vérifié]**

## Qui voit quoi

Trois personnes différentes, trois attentes, une seule plateforme.

- **Celui qui paie** (direction générale ou financière) : ce que le processus
  coûtait, ce qu'il coûte, ce que l'agent a traité, ce qu'il a dépensé. Il n'a
  pas à ouvrir un terminal ni à lire du YAML.
- **Le métier qui vivait le processus** : ce qui a été fait, ce qui lui est
  remonté et pourquoi, comment il reprend la main sur un cas. L'agent lui retire
  la répétition, pas le jugement.
- **L'informatique et la sécurité** : où ça tourne, ce que l'agent a le droit
  d'appeler, comment on lui retire un droit, ce que dit la trace. Ce sont eux
  qui bloquent un déploiement, donc ils doivent trouver leurs réponses seuls.

## Le vocabulaire

Ces mots sont les mêmes dans le produit, le code, le site et un contrat. On n'en
invente pas d'autres.

| Mot | Ce qu'il désigne |
|---|---|
| workflow | le processus métier confié à un agent, de bout en bout |
| agent | l'exécutant, avec sa clé propre, sa configuration et son propriétaire humain |
| propriétaire | la personne qui répond de l'agent et dont l'accord le fait exister |
| politique | les règles qui bornent l'agent : outils, plafonds, horaires, domaines, validations |
| droit | ce que l'agent peut appeler, accordé et retiré à chaud |
| action | un acte à effet réel : un paiement, un envoi, une écriture, un accès accordé |
| reçu | la preuve chaînée qu'une action a eu lieu, avec son coût |
| refus | une action tentée et bloquée, avec la règle qui l'a bloquée |
| escalade | un cas que l'agent remonte à un humain au lieu de trancher seul |
| co-signature | l'accord humain exigé avant qu'une action parte, vérifiable après coup |
| observation | l'agent montre ce qu'il ferait sans le faire, avant la mise en service |
| connecteur | le branchement à un système du client |

## Ce qui existe aujourd'hui

**[vérifié]** dans le dépôt : le gateway (un binaire Rust) qui enrôle les
agents, évalue les politiques, borne les sorties réseau et produit les reçus ;
une console web qui liste les agents, montre l'activité et les refus, écrit et
valide une politique à partir de gabarits, expose les preuves et permet de
révoquer ; des clients Python, TypeScript et Go, plus un serveur MCP ; les
ancrages publics des lots de reçus ; un registre de consommation en jetons et
en euros ; les fichiers de déploiement (Docker, Helm, natif).

**Ce qui manque, et qui décide de la marche 2 de l'escalier :** l'agent se
construit aujourd'hui en code, à côté de la plateforme, avec les SDK. Un client
qui a une équipe technique peut donc déjà faire son deuxième workflow seul, et
c'est vrai dès maintenant. Ce qui n'existe pas, c'est de le construire **sur**
la plateforme : gabarits d'agents, branchement d'un connecteur, écriture des
règles et mise en service au même endroit, avec la trace et les droits déjà
câblés.

Le premier bénéficiaire n'est pas le client, c'est nous. Chaque jour gagné sur
une livraison est le rapport que l'hypothèse 5 de 02 mesure. Le client autonome
vient après, et par le même chemin. **[direction]**

Et c'est un atelier pour ingénieurs, pas du no-code. Confier un processus qui
paie des factures à un assemblage fait sans compétence technique déplacerait le
risque au lieu de le réduire, quelles que soient les règles autour. On donne la
possibilité de construire, on ne prétend pas qu'elle se passe de métier.

Manquent aussi : le catalogue de connecteurs (fichier 04) et une lecture de la
trace conçue pour le métier plutôt que pour un ingénieur.

## Ce que le produit n'est pas

- Ce n'est pas un modèle, ni un framework d'agents. On branche celui du client
  ou celui qui convient, propriétaire ou ouvert.
- Ce n'est pas une console d'observabilité, même si tout ce qu'on observerait y
  est : les actions menées, celles remontées à un humain, celles refusées avec
  la règle qui a tranché, le temps pris et le coût. La différence n'est pas la
  matière, c'est le pouvoir. Une console constate, le produit refuse.
- Ce n'est pas un IAM. Il gère l'identité des agents et ce qu'ils ont le droit
  de faire, pas les employés du client. Il enregistre en revanche l'origine de
  chaque changement de règle et de droit, dans la même chaîne inviolable que les
  actions : on ne répond pas d'une règle mal écrite, mais on peut toujours dire
  quand elle a changé et par quel accès. Nommer la personne derrière ce
  changement suppose que le client émette un identifiant par personne, ce qui
  n'est pas forcé aujourd'hui. **[direction]**
- Ce n'est pas un service hébergé. On ne fait pas tourner les agents à la place
  du client.
