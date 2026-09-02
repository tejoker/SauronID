# 20. Le modèle économique

Comment la valeur se capture. Premier fichier de la dizaine `2x`, il découle de
[`02-solution.md`](02-solution.md), qui pose les trois revenus et lui renvoie
explicitement la décision, de [`03-produit.md`](03-produit.md) pour les trois
objets vendus, et de [`10-segment-cible.md`](10-segment-cible.md) pour le
client. Il engage `21-pricing.md`, qui donne les niveaux, et
`22-unit-economics.md`, qui dit si ça tient.

Méthode : Business Model Canvas (Osterwalder et Pigneur) pour l'inventaire,
Design a Business Model, étape 15 des 24 Steps (Bill Aulet, MIT), pour la
question qui compte : parmi plusieurs modèles possibles, lequel capture le plus
de valeur pour le moins de friction à l'achat.

Étiquettes : **[vérifié]** démontrable dans le dépôt aujourd'hui,
**[direction]** décidé et en cours, **[hypothèse]** à prouver.

Ce fichier ne contient aucun prix. Les niveaux sont en 21, après mesure.

## Les trois revenus, et lequel est l'entreprise

02 les nomme : le projet de mise en production, l'abonnement à la couche de
contrôle, et le cas échéant l'action exécutée. Ils ne sont pas de même nature.

| Revenu | Ce qu'il paie | Rôle dans le modèle |
|---|---|---|
| **Projet** | le cadrage, l'agent, les connecteurs, les règles, la mise en service | il finance la livraison, il n'est pas la marge |
| **Abonnement** | la plateforme qui tient l'agent : identité, politiques, droits, plafonds, traces, reçus | **c'est l'entreprise** |
| **Volume** | l'action à effet réel, quand le processus s'y prête | expansion, pas socle |

La règle qui découle de 11 : **le projet ne doit jamais devenir la ligne
principale.** Une entreprise dont le chiffre vient du projet vend des jours,
donc est une agence, quel que soit le mot qu'elle emploie. L'abonnement est ce
qui distingue les deux, et il doit être vendu au premier contrat, pas proposé
après.

Le projet est facturé, pour trois raisons : un projet gratuit n'est pas défendu
en interne par celui qui l'a obtenu, il attire les clients qui ne déploieront
pas, et il fait de la livraison un coût d'acquisition non mesurable. L'étape 2
de 03, le cadrage, suit la même logique : facturée, déductible du projet,
offerte seulement quand c'est le levier qui emporte l'affaire.

## Le ratio qui décide de tout

02 pose la nuance sur le modèle de l'ingénieur déployé : ce qui doit tenir n'est
pas la taille du contrat, c'est **le rapport entre la charge de livraison et ce
qu'elle rapporte**, projet plus abonnement plus volume.

C'est la mesure centrale de ce fichier, et elle se prend dès la première
livraison :

- **Charge de livraison** : jours réellement passés du premier rendez-vous à la
  mise en production, cadrage inclus, incidents des six premières semaines
  inclus.
- **Ce qu'elle rapporte** : projet encaissé, plus douze mois d'abonnement
  contractés, plus le volume si le processus en produit.

Deux seuils, à trancher en 22 avec des chiffres réels : celui en dessous duquel
la livraison ne se rentabilise pas, et celui au-dessus duquel on est un cabinet
de conseil qui vend un logiciel en accessoire. **[hypothèse]**

La trajectoire visée est une charge de livraison qui baisse à chaque client
pendant que l'abonnement reste, parce que la méthode et les gabarits se
réutilisent alors que le processus, lui, change. Si la charge ne baisse pas
entre la livraison 1 et la livraison 5, le modèle est un cabinet de conseil et
il faut le dire à ce moment-là, pas deux ans plus tard.

## Ce qui rend la livraison répétable

Ce qui se répète d'un client à l'autre n'est pas le processus, c'est la méthode
(02) et le cycle de vie en dix étapes (03). Trois actifs la portent.

1. **La plateforme.** Elle est le seul élément imposé, et elle est agnostique
   par construction : rien dans le noyau n'est financier ni spécifique à un
   processus. C'est ce qui rend le deuxième workflow chez le même client
   rentable, et c'est la protection que 10 nomme — tant qu'on ne construit rien
   de spécifique à la facture, on n'est prisonnier de rien. **[vérifié]**
2. **La méthode et les gabarits de livraison.** Mesurer le coût actuel, cadrer,
   observer, écrire les règles, brancher, mettre en production, montrer l'écart.
   Les gabarits d'orchestration existants raccourcissent la construction, mais
   ils ne sont pas un catalogue de produits et une partie vient de tiers : leur
   licence et leur origine se vérifient avant tout usage chez un client, et rien
   qui porte les identifiants d'un client ne se réutilise chez un autre.
   **[direction]**
3. **L'atelier de construction sur la plateforme.** Gabarits d'agents,
   branchement d'un connecteur, écriture des règles et mise en service au même
   endroit. Il n'existe pas encore ; 03 rappelle que son premier bénéficiaire
   est nous, parce que chaque jour gagné sur une livraison entre directement
   dans le ratio ci-dessus. **[direction]**

## Ressources, partenaires, coûts

**Ressources clés.** Le gateway et la console, les SDK et le serveur MCP, la
méthode de livraison, et les gens capables de mener une livraison de bout en
bout. La ressource rare est la dernière, et c'est elle qui plafonne le nombre de
clients par trimestre.

**Partenaires.** Deux familles, aucune exclusive : ceux qui amènent le
processus (intégrateurs, experts-comptables, éditeurs métier déjà installés chez
le client) et ceux qui fournissent les briques (modèles, hébergeurs). Aucun
partenaire ne doit devenir le propriétaire de la relation client. **[direction]**

**Structure de coûts.** Dominée par le temps humain de livraison, pas par
l'infrastructure : la plateforme tourne chez le client, donc son exploitation
n'est pas notre coût. Ce qui reste à notre charge est le développement, la
maintenance de la cryptographie et des ancrages, le support, et l'acquisition.

## Ce que ce modèle exclut

Trois options écartées, chacune parce qu'elle contredit un fichier amont.

- **L'exploitation pour le compte du client.** 03 est explicite : ce n'est pas
  un service hébergé, on ne fait pas tourner les agents à la place du client. Un
  modèle dont le revenu viendrait de l'hébergement changerait le produit, la
  promesse « ça tourne chez vous » et la structure de coûts. Toute réflexion
  d'offre gérée est donc un autre modèle, pas une variante de celui-ci.
- **Le noyau ouvert avec fonctions de sécurité payantes.** La vérifiabilité sans
  nous faire confiance est l'argument ; la mettre derrière un paiement lui met
  un astérisque.
- **La vente de jours.** Voir 11. Un tarif journalier nous range dans la
  catégorie encombrée où le prospect compare des taux.

## La norme comme actif économique

Ajouté après la publication de la spécification du format de signature
([`../integration/agent-action-envelope.md`](../integration/agent-action-envelope.md),
Apache-2.0). Framework : 7 Powers (Hamilton Helmer), pour deux des sept
seulement — Network Economies et Switching Costs — parce que ce sont les deux
que la diffusion d'un format peut créer et qu'aucun autre revenu de ce fichier
ne crée.

La question n'est pas « faut-il donner le format ». Elle est tranchée : un
format qui se paie ne se diffuse pas, et un format qui ne se diffuse pas ne vaut
rien à monétiser. La question est **ce qui se vend à côté**.

### La règle

**Faire payer ce qui exige de la confiance, jamais ce qui exige de
l'ubiquité.** Le motif est constant dans les précédents : celui qui tient
l'ancre de confiance ou vend la marque de conformité est payé ; celui qui ne
possède que le format récolte des citations. Auth0 n'a jamais possédé JWT et a
monétisé le fait d'être l'émetteur. Docker a donné le format d'image et monétisé
le registre. Visa publie le Trusted Agent Protocol et garde le registre de clés.
OpenTelemetry est gratuit, les backends sont payants. FIDO, PCI et USB-IF
monétisent la certification, jamais la spécification. **[hypothèse]** — motif
observé, non chiffré ici ; à documenter dans [`research/`](research/README.md)
avant tout usage commercial.

### Les quatre positions payantes

| Position | Ce qui se vend | Compatible avec ce fichier ? |
|---|---|---|
| **La passerelle** | licence commerciale au-delà du seuil de revenu | **oui, déjà en place** : [`LICENSE`](../../LICENSE) rend l'usage en production gratuit sous 1 000 000 € de revenu annuel et payant au-dessus, et interdit l'offre à des tiers en service hébergé à toute taille. C'est le levier « les grandes entreprises paient », et il existe. **[vérifié]** |
| **La certification de conformité** | la marque « conforme SauronID », adossée à la suite de conformité publique que nous possédons | **oui, sans contradiction** : ne touche ni au produit, ni à la structure de coûts, et renforce la norme puisqu'un implémenteur veut la marque. C'est la seule des quatre qui sert directement l'objectif « être la norme ». **[direction]** |
| **L'ancre de confiance** | résolution de clés, émission d'identité, état de révocation — le chemin `.well-known` que la spécification déclare manquant | **non, contredit une décision prise** : voir ci-dessous |
| **L'archive de reçus** | rétention pluriannuelle, requête, portée d'exposition après divulgation d'une CVE | **non, contredit la même décision** |

### La contradiction, énoncée plutôt que contournée

Les deux dernières positions sont des services que **nous** exploitons. Or ce
fichier a déjà écarté l'exploitation pour le compte du client, et sa structure
de coûts repose sur le fait que « la plateforme tourne chez le client, donc son
exploitation n'est pas notre coût ». Une ancre de confiance hébergée casse les
deux : elle nous rend opérateur, elle crée une astreinte, et elle déplace le
coût dominant du temps humain de livraison vers l'infrastructure et la
disponibilité.

Trois issues possibles, à trancher ici et non ailleurs :

1. **On refuse.** La spécification définit le chemin `.well-known` et chaque
   client héberge le sien. La norme se diffuse, aucune économie de réseau ne
   nous revient, et le modèle reste celui décidé plus haut.
2. **On accepte pour cette seule brique.** Une ancre de confiance est
   qualitativement différente d'un agent exécuté : elle ne touche aucune donnée
   client, ne prend aucune décision d'autorisation, et sert un annuaire de clés
   publiques. L'exclusion viserait alors « faire tourner les agents », pas
   « faire tourner un annuaire ». Il faut le réécrire explicitement dans 03 et
   ici, pas l'assumer.
3. **On le confie à un tiers neutre.** Cohérent avec l'objectif de norme — une
   spécification dont l'ancre appartient à son auteur est un produit, pas une
   norme — et cela abandonne la position la plus rentable des quatre.

**Aucune n'est choisie.** C'est la décision la plus lourde ouverte par la
publication de la spécification, et elle appartient à ce fichier.

### Ce que la publication du format ne change pas

Elle ne remplace aucun des trois revenus ci-dessus. L'abonnement reste
l'entreprise. Un format libre augmente le nombre d'agents susceptibles de parler
à une passerelle ; il ne vend pas une passerelle. Le raisonnement inverse — « la
norme deviendra le produit » — est exactement l'erreur que 11 interdit :
confondre la notoriété et le chiffre.

## Ce que l'abonnement paie, et pourquoi il est récurrent

La question se pose dès qu'on vend l'agent d'abord : le client paie-t-il un
abonnement « pour utiliser SauronID » ? Formulé ainsi, non — et il ne faut pas le
vendre ainsi. Un acheteur à qui l'on présente un loyer d'intergiciel le compare à
`n8n`, qui est gratuit, et demande pourquoi payer. La comparaison est perdue
d'avance parce qu'elle porte sur le mauvais objet.

Ce que l'abonnement paie est l'objet 3 de [`03-produit.md`](03-produit.md), la
continuité : l'agent continue de tourner sous contrôle. Les règles restent
modifiables, les droits révocables, les plafonds opposables, les traces
produites et conservées. Le test est simple : **si l'agent n'a plus besoin de
cela, l'abonnement n'a plus de justification.** Ce n'est pas une rente, c'est un
service qui s'exerce en continu, parce qu'un mandat expire, une révocation doit
prendre effet, et une chaîne de reçus doit continuer d'être produite et retenue.

### Sa composition dépend de la taille du client, à cause de la licence

Point souvent manqué : [`LICENSE`](../../LICENSE) rend l'usage en production
**gratuit sous 1 000 000 € de revenu annuel**. Pour un client sous ce seuil,
l'abonnement ne peut donc pas être un droit d'usage — il n'y en a pas à vendre.
Il ne couvre que la continuité, le catalogue de connecteurs maintenu, et
l'archive de reçus. **[vérifié]**

| Client | Ce que l'abonnement contient |
|---|---|
| Sous le seuil de revenu | continuité, connecteurs maintenus, archive — pas de droit d'usage, il est déjà gratuit |
| Au-dessus du seuil | les mêmes, plus la licence commerciale de la passerelle |

Conséquence commerciale, contre-intuitive : c'est chez le petit client que
l'abonnement doit être justifié par le service, et chez le grand qu'il se
justifie aussi par la licence. Le discours n'est pas le même, et le confondre
fait perdre le petit client.

### La discipline de facturation, non négociable

**Deux lignes sur la première facture, jamais un prix unique.** Vendre l'agent
en premier rend la couche de contrôle invisible : le client achète un résultat,
et au renouvellement il coupe la ligne qu'il ne voit pas. C'est exactement
l'hypothèse 1 de ce fichier, et la stratégie « vendre l'agent d'abord » en
augmente le risque au lieu de le réduire. Un abonnement introduit à la deuxième
vente est le piège de l'agence.

## L'unité de facturation : la décision qui bloque 21

`21-pricing.md` ne peut pas s'écrire avant que l'unité comptée soit choisie. Ce
n'est pas choisir un prix — c'est choisir **ce qu'on compte**. Trois critères, et
chaque candidat en échoue au moins un :

1. **Elle croît avec l'adoption**, sinon le deuxième workflow chez le même client
   ne rapporte rien et l'hypothèse 3 n'a aucun effet économique.
2. **Elle ne paie pas le client pour mal se comporter.**
3. **La passerelle la compte elle-même**, sans déclaration du client.

| Unité | Croît ? | Incitation perverse | Comptable par nous ? |
|---|---|---|---|
| **Par action** | oui | **disqualifiante** : le client est payé pour faire passer moins d'actions par la passerelle, alors que le contournement est déjà la limite reconnue dans [`../../README.md`](../../README.md). Facturer à l'action, c'est financer le contournement du produit | oui |
| **Par workflow** | peu | aucune | **non** : « workflow » est une notion humaine, pas une ligne de base de données |
| **Par siège** | non | aucune | oui, et sans rapport : un agent n'est pas un siège |
| **Forfait par locataire** | **non** | aucune | oui |
| **Par identité d'agent enregistrée** | oui | à cadrer : incite à partager une identité entre plusieurs tâches, ce qui détruit l'attribution — donc l'intérêt du produit | oui, la table `agents` la compte |

**Recommandation : l'identité d'agent enregistrée.** C'est ce que SauronID émet
réellement, c'est ce que la table `agents` compte, et cela croît quand le client
ajoute un workflow sans consommer un jour de livraison de plus. **[direction]**

Deux points à trancher avec elle, sinon l'unité se retourne contre nous :

- **Une identité, pas un condensat.** Le condensat de configuration change à
  chaque modification du prompt système ou de la liste d'outils
  ([`../../core/src/agent_checksum.rs`](../../core/src/agent_checksum.rs)). Si
  l'unité facturée était le condensat, chaque redéploiement multiplierait la
  facture et le client apprendrait à ne plus mettre à jour sa configuration —
  c'est-à-dire à dégrader sa propre sécurité pour payer moins. On facture
  l'`agent_id`, la dérive de configuration met à jour la même identité.
- **Le partage d'identité doit coûter plus cher qu'il ne rapporte.** Une identité
  partagée entre deux tâches rend la chaîne de reçus inexploitable. La parade
  n'est pas tarifaire mais produit : c'est le plan déclaré par exécution
  (`run_id`, [`../integration/agent-action-envelope.md`](../integration/agent-action-envelope.md))
  qui rend une identité partagée inutilisable pour se justifier devant un
  auditeur. **[direction]**

Aucun niveau, aucun prix ici : ils appartiennent à 21, après mesure.

## Encaisser sans exploiter : la licence de déploiement

La contrainte est posée : on ne veut pas porter l'infrastructure d'un client
vendu il y a dix ans. C'est cohérent avec la structure de coûts de ce fichier —
la plateforme tourne chez le client — et avec 03, qui exclut de faire tourner
les agents à sa place.

Mais l'analogie avec un réseau de paiement s'arrête à un endroit précis, et il
faut le dire : **Visa n'exploite rien pour ses marchands parce que Visa *est*
l'infrastructure.** Le marchand se connecte au réseau, le réseau est dans le
chemin de chaque transaction, et le prélèvement se fait dans le flux. SauronID
est l'inverse : la passerelle tourne chez le client. On obtient ce qu'on
voulait — aucun serveur, aucune astreinte — et on perd les deux choses que Visa
possède : **la visibilité et le prélèvement.**

### Le mécanisme

Une **licence de déploiement signée** remplace le fait d'être dans le chemin.
Elle nomme le licencié, le locataire, un plafond d'identités d'agents
enregistrées et une date d'expiration. La passerelle la vérifie localement.
Aucun rappel, aucune télémétrie, fonctionne hors réseau, rien à exploiter de
notre côté. **[vérifié]** — [`../../core/src/licence.rs`](../../core/src/licence.rs),
émission par [`../../scripts/ops/issue-licence.py`](../../scripts/ops/issue-licence.py).

C'est ce qui répond à la question posée : **un prestataire tiers installe, le
client paie quand même.** Ce qui se paie n'est pas l'installation, c'est la
licence. La livraison devient délégable sans que la relation commerciale le
soit. [`LICENSE`](../../LICENSE) interdit déjà d'offrir la passerelle à des
tiers en service hébergé à toute taille, donc un intégrateur ne peut que monter
l'instance du client sous la licence du client : notre contrepartie reste le
client. **[vérifié]**

### La frontière qui ne bougera pas

Le plafond porte sur **l'enregistrement d'un nouvel agent**, jamais sur
l'autorisation des actions des agents existants. Couper un contrôle de sécurité
parce qu'une facture est en retard serait indéfendable, et un auditeur aurait
raison de le dire. Une licence expirée ramène le plafond au palier gratuit :
le déploiement cesse de croître, il ne cesse pas de fonctionner. **[vérifié]**,
c'est le test `expiry_falls_back_to_the_free_tier_rather_than_to_zero`.

Corollaire commercial : le levier de recouvrement est faible par construction.
Un client qui ne renouvelle pas garde un système qui marche. Ce qu'il perd est
l'extension, le support et les connecteurs maintenus — donc **la valeur du
renouvellement doit venir de là, pas de la menace d'un arrêt.** C'est plus
honnête et c'est plus fragile ; il faut le savoir avant de tarifer en 21.

### Ce que la licence n'est pas

Ce n'est pas un verrou technique. La source est publique et la clé d'émission
est surchargeable : qui veut tourner sans licence peut. **La BUSL est
l'instrument juridique**, la licence de déploiement est l'instrument comptable.
Elle rend le plafond explicite plutôt que caché dans un contrat que personne ne
relit, et elle rend la facturation vérifiable des deux côtés. Prétendre qu'elle
empêche quoi que ce soit serait faux et se retournerait contre nous.

### Le vrai coût d'un client de dix ans

Ce n'est pas l'infrastructure : l'auto-hébergement l'élimine entièrement. C'est
**le support** — des ingénieurs qui répondent sur une version livrée en 2027.
Aucune architecture ne règle cela ; seules des conditions contractuelles le
font, et elles doivent être écrites avant le premier contrat, pas au premier
incident :

1. **Une fenêtre de versions supportées** : la version courante et la
   précédente, rien de plus ancien.
2. **Le support est un palier facturé**, il n'est pas impliqué par la licence.
3. **La mise à jour est une condition du support**, pas une option.

Sans ces trois lignes, « on ne porte pas leur infrastructure » est vrai et sans
effet, parce que la charge arrive par courriel et non par une facture de cloud.
**[direction]**

## Les hypothèses de ce fichier

À tester, dans cet ordre, et à reprendre en 31.

1. **L'abonnement se vend au premier contrat**, sans être perçu comme un péage
   sur un projet déjà payé. C'est l'hypothèse qui porte tout le modèle : si
   l'abonnement ne passe qu'en seconde vente, le projet devient la ligne
   principale et on est une agence. **[hypothèse]**
2. **La charge de livraison baisse d'une livraison à la suivante.** Mesurée en
   jours, sur les cinq premières. **[hypothèse]**
3. **Le deuxième workflow arrive chez le même client**, dans une autre fonction
   que le premier, et il coûte moins cher à livrer que le premier. C'est ce qui
   sort de la niche d'entrée (10) et ce qui fait l'essentiel de la valeur d'un
   client. **[hypothèse]**
4. **Le volume est facturable là où le processus en produit**, sans que le
   client y voie une taxe sur son activité. À vérifier processus par processus ;
   pas un socle. **[hypothèse]**
5. **Le client qui continue seul paie quand même l'abonnement.** 02 l'affirme ;
   rien ne le prouve encore. **[hypothèse]**

6. **La marque de conformité se vend**, c'est-à-dire qu'un implémenteur du
   format préfère payer pour l'afficher plutôt que déclarer sa conformité
   lui-même. Sans cela, la certification est un coût de suite et non un revenu.
   **[hypothèse]**
7. **Un format libre augmente le nombre de passerelles vendues**, et non
   seulement le nombre de citations. C'est l'hypothèse qui justifie la licence
   Apache-2.0 de la spécification ; elle est aujourd'hui indémontrée.
   **[hypothèse]**
8. **Le seuil de revenu de la BUSL attrape effectivement les grandes
   entreprises** plutôt que de les pousser vers une réimplémentation du format,
   désormais qu'il est publié et librement implémentable. Publier la
   spécification rend cette hypothèse plus risquée qu'avant, et c'est le prix
   assumé de la diffusion. **[hypothèse]**

9. **La ligne d'abonnement survit à la négociation** quand l'agent est vendu en
   premier. Mesure : la part de la valeur du contrat que représente l'abonnement,
   sur les cinq premières livraisons. Si elle ne monte pas, on vend des agents
   avec une fonction d'audit ; si elle monte, SauronID est l'entreprise et les
   agents sont la distribution. Aucun seuil n'est fixé ici : il se déduit des
   cinq premières, pas d'une intuition. **[hypothèse]**

10. **Le renouvellement se vend sans levier d'arrêt.** La licence expirée ne
    casse rien : le client garde un système qui marche et perd l'extension, le
    support et les connecteurs maintenus. Si cela ne suffit pas à faire
    renouveler, le modèle n'a pas de mécanisme de recouvrement et il faut le
    découvrir au premier renouvellement, pas au dixième. **[hypothèse]**
11. **Un intégrateur tiers préfère livrer sur notre couche** plutôt que
    d'assembler des briques libres sans elle. Sa raison d'être doit être la
    marque de conformité ; sans elle, rien ne l'attache. **[hypothèse]**

Aucun chiffre n'entre ici avant d'être mesuré chez un client réel, avec sa note
de qualité, conformément aux règles de preuve de
[`research/`](research/README.md). L'exemple type de 02 — mille factures par
mois, trois personnes, environ 12 000 € de coût chargé mensuel — est une
illustration de raisonnement, pas une référence client, et ne sert pas de base
de calcul en 21.
