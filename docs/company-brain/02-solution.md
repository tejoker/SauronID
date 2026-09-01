# 02. La solution

Répond à [`01-problemes.md`](01-problemes.md) dans son ensemble, pas ligne à
ligne. Ce fichier dit ce qu'on fait et pourquoi ça tient. Il ne liste pas les
capacités (fichier 04), ne fixe pas le modèle de revenus (20) et ne décide pas
du discours (11).

Trois étiquettes obligatoires sur chaque affirmation de capacité :
**[vérifié]** démontrable dans le dépôt aujourd'hui, **[direction]** décidé et
en cours, **[hypothèse]** à prouver avant d'en parler à un client.

## En une phrase

**On remplace des processus manuels, ou assistés par un copilote, par des
agents qui tournent en production, et on facture une fraction de ce qu'ils font
gagner ou économiser.**

Attention à ne pas confondre deux choses. « Une fraction de ce que ça
économise » est **l'argument qui justifie le prix**, pas la structure de
facturation. Le modèle, lui, est un projet de mise en production, puis un
abonnement au logiciel, puis le cas échéant l'action exécutée. La valeur créée
dit combien on peut demander ; elle ne dit pas sur quoi on facture. Les deux se
tranchent en 20 et 21.

## Concrètement

Un service traite 1 000 factures fournisseurs par mois. Trois personnes, quatre
jours par semaine, environ 12 000 € de coût chargé mensuel. On livre l'agent qui
les traite : projet de mise en production, puis abonnement. Si l'écart n'est pas
lisible au bout de six semaines, c'est nous qui avons raté. (Exemple type, pas
une référence client.)

Trois choses, dans cet ordre :

1. **On livre en production, pas en pilote.** Cadrage, agent, connexion aux
   systèmes, règles, mise en service.
2. **L'agent ne peut faire que ce qui est écrit.** C'est ce qui fait signer le
   directeur financier et le RSSI, et ce qui nous fait gagner contre une agence
   qui n'a que des prompts à montrer.
3. **Ça tourne chez le client.** Son cloud, son hébergeur, ou ses machines. On
   n'exploite pas à sa place.

Trois revenus : le projet, l'abonnement à la couche de contrôle, et le cas
échéant l'action exécutée.

On ne vend pas de la sécurité. On ne vend pas de la gouvernance. On ne vend même
pas un outil. On vend un poste de coût qui baisse.

## Le marché existe, le budget aussi

On ne crée pas une ligne budgétaire, on en attaque une qui est déjà payée tous
les mois. Traiter les factures fournisseurs, relancer les clients qui ne paient
pas, ouvrir les accès demandés par ticket, vérifier un contrat d'achat : c'est
déjà fait, par des salariés ou des prestataires, et ça se chiffre en ETP. Le
client n'a pas à financer une catégorie nouvelle, il a à décider si cette
facture-là peut baisser.

Et la place est vide. L'usage d'agents à l'échelle est à un seul chiffre dans
presque toutes les fonctions, et même dans les deux plus avancées, informatique
et gestion des connaissances, deux tiers des organisations déclarent aucun usage
(AI Index 2026, note A). Hors du secteur technologique, quasiment personne n'a
réussi à mettre un agent en production. On n'arrive pas contre des concurrents
installés, on arrive là où tout le monde s'est arrêté au pilote.

### Le meilleur client a déjà acheté un copilote

Contre-intuitif et pourtant c'est le profil le plus facile. Une entreprise qui a
déployé des licences d'assistant a déjà fait trois choses pour nous : elle a
créé la ligne budgétaire, elle l'a fait valider, et elle a découvert son plafond
toute seule. L'assistant fait gagner du temps sur la partie du travail que la
personne continue de faire. Le reste du processus, lui, n'a pas bougé.

Cette entreprise n'a plus besoin d'être convaincue que l'IA sert à quelque
chose, elle a besoin qu'on lui explique pourquoi le gain s'est arrêté là. La
réponse est simple : un assistant accélère une personne, un agent retire la
tâche. Le passage de l'un à l'autre est une montée en gamme sur une ligne
existante, pas une vente nouvelle, et l'humain y garde le rôle qui compte,
traiter les cas que l'agent lui remonte.

Attention aux chiffres dans cette conversation : les gains d'assistant mesurés
par études contrôlées vont de +14% à +26% selon les métiers (note A), et les
taux de traitement de bout en bout annoncés pour les agents, de l'ordre de 70 à
90% du volume, viennent d'éditeurs et ne sont pas mesurés (note C). L'écart est
réel, sa taille exacte est à établir sur nos propres déploiements. C'est le
premier chiffre qu'on aura à publier.

### Notre métier, c'est le déploiement, pas un catalogue

On n'est pas un éditeur avec quatre produits. Notre métier est d'aller chez un
client, de comprendre un processus qui lui coûte cher, et de livrer l'agent qui
le fait. Quel que soit le processus. C'est le modèle de l'ingénieur déployé chez
le client, celui que Palantir a rendu célèbre : une équipe qui va sur place,
apprend le métier du client, construit dessus, et repart en laissant la
plateforme entre ses mains.

Ce que ça implique, et qu'il faut assumer :

- **Aucune restriction technique.** N'importe quel modèle, propriétaire ou
  ouvert, n'importe quelle brique open source, ce qui tourne chez le client ou
  ce qu'il a déjà payé. On ne vend pas un modèle, on ne vend pas un framework.
  La seule chose qu'on impose est la couche de contrôle, et elle est agnostique
  par construction.
- **Un playbook, pas un catalogue.** Ce qui se répète d'un client à l'autre,
  c'est la méthode : mesurer le coût actuel, cadrer le périmètre, écrire les
  règles, brancher, mettre en production, montrer l'écart. Le processus, lui,
  change à chaque fois. Une seule limite à ce « quel que soit le processus » :
  celui dont le coût actuel est inconnaissable, pour la raison expliquée plus
  bas.
- **Le client peut continuer sans nous.** Une fois le premier workflow livré, il
  a la plateforme, il connaît la méthode, il construit les suivants lui-même. On
  ne verrouille rien. Il nous rappelle quand il veut aller plus vite, et il paie
  l'abonnement dans les deux cas.

Une nuance sur le modèle de référence : Palantir rentabilise ses ingénieurs
déployés sur des contrats à sept chiffres. Ce n'est pas notre format. Chez une
PME ou une ETI, le contrat est plus petit, mais le périmètre et la charge le
sont aussi. Ce qui doit tenir n'est pas la taille du contrat, c'est le rapport
entre la charge de livraison et ce qu'elle rapporte, projet plus abonnement plus
volume traité. Ce rapport est mesuré dès la première livraison, et c'est lui qui
dit si le modèle passe à l'échelle ou reste un cabinet de conseil.

### Les portes d'entrée

On ne démarche pas « tout processus confondu » : un dirigeant reçoit déjà des
dizaines de messages par semaine sur l'implémentation d'IA, et un discours
généraliste est indistinguable du bruit. On entre donc par un processus nommé,
que l'interlocuteur reconnaît immédiatement comme le sien.

La liste n'est pas un catalogue et n'est pas fermée. Le critère de sélection est
constant : le coût actuel est chiffrable, la place est ouverte, et l'agent y
commet une action à effet réel, donc notre différence s'y démontre.

| Famille | Processus | L'action qui fait peur |
|---|---|---|
| Finance | factures fournisseurs, de la réception au paiement | un paiement part |
| Finance | recouvrement et relance client | un message part chez un client |
| Finance | notes de frais, contrôle et remboursement | un remboursement est émis |
| Finance | rapprochement bancaire et écritures de clôture | une écriture comptable est passée |
| Commerce | prospection et relance | un message part chez un prospect |
| Commerce | devis, grille de prix, remises | un engagement commercial est pris |
| Commerce | renouvellements et résiliations | un contrat bouge |
| Opérations | commandes, administration des ventes, exceptions logistiques | une commande est passée ou modifiée |
| Opérations | service client au-delà de la réponse : geste commercial, avoir, remboursement | de l'argent sort |
| Informatique | tickets, droits d'accès, provisionnement | un droit est accordé |
| Informatique | arrivée et départ d'un collaborateur | des comptes sont créés ou supprimés |
| Achats et juridique | revue de contrats, sélection de fournisseurs | un engagement est pris |
| Achats et juridique | contrôle documentaire et déclarations | un document part chez un tiers |

Cette peur est ce qui bloque le passage en production, et c'est exactement ce
que la couche de contrôle lève. Comment approcher ces entreprises sans
ressembler aux dizaines d'autres messages : fichier 30.

À l'inverse, on évite en amorçage les cas d'usage où on arriverait après tout le
monde (génération de code, chat de support de niveau 1 : les seuls endroits où
la valeur est prouvée par des études contrôlées, donc les plus encombrés) et
ceux sans action à effet réel (analyse de données, reporting), où notre
différence ne se paie pas. Classement et sources :
[`research/use-cases.md`](research/use-cases.md).

## Pourquoi nous, plutôt qu'une agence

Distinction à ne jamais perdre de vue : **ce qui déclenche l'achat, c'est le
gain. Ce qui fait signer, c'est le contrôle.** Ce sont deux moments différents
de la même conversation. On entre par un processus qui coûte cher et qu'on sait
faire baisser. Puis viennent les objections, toujours les mêmes : et s'il se
trompe, et si on me le reproche, et si je ne sais pas ce qu'il a fait, et si ça
part en dépense. Une agence répond qu'elle a testé. Nous, chaque objection a sa
réponse dans le produit, démontrable en réunion. C'est ce que 01 dit
autrement : la sécurité ne fait pas acheter, mais son absence fait reculer.

Une agence concurrente a le même modèle, les mêmes bibliothèques et souvent les
mêmes idées. Ce qu'elle n'a pas, c'est la réponse à la seule question qui bloque
la signature : « et s'il se trompe ». Elle répond qu'elle a testé. On répond en
montrant la règle qui l'en empêche, le refus horodaté quand l'agent a essayé, et
le reçu de tout ce qu'il a fait.

Et ce n'est pas qu'un argument de réunion. Ce qui suit se manipule après la
livraison, par le client, sans nous et sans redéployer l'agent : durcir ou
relâcher une règle, retirer un droit ou révoquer un agent immédiatement, poser
un plafond de dépense, exporter la trace complète pour un audit ou un
commissaire aux comptes, changer de modèle sans réécrire un seul garde-fou
puisqu'ils n'ont jamais vécu dans le prompt. Un directeur financier n'a pas
besoin d'un ingénieur pour lire ce que l'agent a fait et ce qu'il n'a pas eu le
droit de faire.

C'est ce qui nous fait sortir du lot sur un cas d'usage à conséquence, et c'est
précisément pour ça qu'on choisit ces cas d'usage là.

## Ce que l'abonnement achète

Question à laquelle il faut savoir répondre en une phrase, parce qu'un client la
posera : il paie quoi, une fois l'agent livré et tournant chez lui.

Il paie l'accès à la plateforme qui tient ses agents, quel que soit le
fournisseur de modèle derrière : l'identité de chaque agent et les personnes qui
en répondent, le système d'autorisation, les règles et leur modification en
direct, l'octroi et le retrait de droits, la trace exportable le jour où un
contrôle arrive, le suivi des coûts et des comportements, la liste de ce qui a
été refusé et pourquoi. C'est ce qui transforme un agent livré en agents qu'on
exploite : maintenus, améliorés, complétés par d'autres, et surveillés.

Il paie aussi ce qui arrive après : la plateforme est mise à jour, les
fonctionnalités qui sortent lui sont ouvertes sans supplément. Ce qu'on livre en
2027 à un client de 2026 fait partie de ce qu'il paie déjà.

Ce qu'on ne vend pas, c'est un dépôt de code livré à la porte. La continuité
fait partie de l'offre, et c'est elle qui justifie le récurrent.

C'est aussi la différence structurelle avec une agence, et elle se lit dans les
comptes : derrière la prestation il y a un vrai logiciel, donc un revenu qui
continue après la livraison. Une société de services facture des jours et
recommence à zéro ; nous facturons des jours **et** une plateforme qui reste.

Le partage de responsabilité doit être dit aussi clairement : **le client est
responsable des règles qu'il écrit, nous sommes responsables du fait qu'elles
soient tenues.** Une règle mal écrite laissera passer ce qu'elle autorise. Aucun
mécanisme ne rattrape une règle absurde, et personne ne devrait prétendre le
contraire.

Reste à trancher, et ça appartient aux fichiers 20 et 21 : l'abonnement au
nombre d'agents, au volume d'actions, ou les deux.

## Pourquoi c'est une meilleure entreprise

Une agence vend des jours : son chiffre d'affaires plafonne au nombre de
personnes qu'elle emploie, et il retombe à zéro à la fin de chaque projet. C'est
la raison pour laquelle on n'en est pas une, et les trois différences se lisent
dans les comptes.

1. **Ce qu'on laisse derrière se paie tous les mois.** Le projet finit,
   l'abonnement à la couche de contrôle continue, et le paiement à l'action suit
   le volume traité.
2. **Chaque livraison renforce le produit.** Un connecteur écrit pour un client
   sert au suivant, une règle type devient un modèle. Une agence classique
   recommence, nous capitalisons.
3. **Ça se vend sans nous.** Une agence tierce qui livre sur notre couche nous
   rapporte sans consommer nos jours. Notre capacité de livraison cesse alors de
   plafonner notre chiffre d'affaires, ce qu'aucune société de prestation pure
   ne peut dire. **[hypothèse]**

## L'unité de valeur

Un copilote rend du temps à quelqu'un qui reste payé pareil. Tant que l'heure
libérée n'est pas réaffectée, elle ne se lit nulle part dans les comptes : des
études contrôlées mesurent +14% à +26% de productivité individuelle pendant que
neuf dirigeants sur dix ne constatent aucun effet sur leur entreprise (note A).
Le plafond du copilote n'est pas le modèle, c'est l'attention de son
utilisateur.

Un agent ne rend pas du temps, il retire un coût de traitement. La seule unité
qui compte est donc celle-ci : **ce que coûte aujourd'hui de traiter un volume
donné, et ce que ça coûte une fois l'agent en place, tout compris.** Mille
factures, deux cents tickets, cinquante dossiers par semaine. Mesurable des deux
côtés, comparable, contractualisable.

Détail des mesures : [`research/copilot-vs-agent.md`](research/copilot-vs-agent.md).

## Ce qui rend le gain démontrable

Le chiffre qui manque à toute l'industrie est le coût du processus **avant**
l'agent. Personne ne le mesure, et c'est la vraie raison pour laquelle les
pilotes n'affichent aucun impact : sans point de départ, il n'y a rien à
comparer (problème 2 de 01).

D'où deux règles, qui sont des règles commerciales autant que méthodologiques :

1. **On mesure avant de construire.** Volume traité, temps par unité, coût
   chargé, taux d'erreur, délai. Si le client ne sait pas les donner, on les
   établit avec lui pendant le cadrage. C'est ce qui transforme une promesse en
   écart chiffré.
2. **On refuse un processus dont le coût actuel est inconnaissable.** Pas par
   pureté méthodologique : parce qu'un gain qu'on ne pourra pas montrer ne sera
   pas renouvelé, et parce qu'un client qui ne connaît pas son coût de
   traitement ne saura pas non plus reconnaître ce qu'on lui a fait gagner.

3. **Quand le coût unitaire est introuvable, on mesure une métrique de
   transition.** Le coût complet d'un traitement est souvent inconnu du client,
   et aucun processus d'entreprise n'a de coût de référence publié par une
   source sans intérêt commercial : tous les chiffres qui circulent viennent
   d'éditeurs qui vendent la chose mesurée (voir
   [`research/sources.md`](research/sources.md)). Un délai, lui, se lit dans les
   outils du client sans étude : combien de temps entre l'entrée d'un cas et sa
   résolution, combien de relances internes, quelle part du volume passe par le
   chemin dégradé. C'est sa donnée, donc elle vaut mieux qu'un benchmark
   d'éditeur, et elle bouge dans le même sens que le coût. On prend le coût
   quand il existe, le délai quand il n'existe pas, et on fixe lequel des deux
   fait foi au cadrage, pas à la fin.

Le côté « après » ne demande aucun effort supplémentaire : la couche de contrôle
enregistre chaque action, ce qu'elle a coûté en jetons et en euros, ce qui a été
refusé et pourquoi. On n'exploite pas l'agent, donc la mesure passe par un export
de la trace, demandé au client à échéance convenue : actions exécutées, actions
refusées, cas remontés à un humain. Croisé avec le retour des équipes, ça donne
le volume réellement traité sans intervention, qui est le seul chiffre dont
dépend la démonstration. C'est un usage détourné du mécanisme d'audit, et il faut
prévoir l'export dès le cadrage plutôt que de le demander après coup. Le tableau de bord du contrôle est aussi le tableau de bord
du retour. C'est le même mécanisme qui rend l'agent déployable et qui prouve
qu'il rapporte, et c'est la principale raison pour laquelle ces deux sujets ne
se vendent pas séparément.

## Prédiction et jugement

Cadre : *Prediction Machines*, Agrawal, Gans et Goldfarb (Harvard Business
School, 2018), et le AI Canvas qui en découle. Il sépare une décision en deux
composants dont les prix évoluent en sens inverse. La **prédiction** est ce
qu'un modèle produit : une sortie probable à partir de données. Le **jugement**
est ce qui reste humain : quelles conséquences on accepte, lesquelles on refuse,
et ce que coûte une erreur.

La thèse du livre est arithmétique. Quand le coût de la prédiction s'effondre,
la valeur du jugement monte, parce qu'il devient le facteur limitant. Un modèle
à 3 centimes l'appel rend la question « qui décide ce qu'on autorise » plus
chère que la question « qui sait prédire ».

Ce que ça dit de notre place. Le modèle est le moteur de prédiction : peu cher,
interchangeable, jamais fiable à cent pour cent. SauronID n'est pas un meilleur
moteur de prédiction, et n'a aucune raison de le devenir. C'est l'infrastructure
qui **exécute** le jugement de l'entreprise : plafonds, périmètres,
co-signatures, refus par défaut. Le jugement lui-même reste chez le client, chez
la personne qui écrit la règle. Nous garantissons seulement qu'un modèle ne peut
pas le contourner.

D'où une conséquence à tenir dans le discours : la séparation n'est pas un choix
d'architecture qu'on pourrait faire autrement, c'est la seule structure qui
suive l'économie du problème. Mettre le jugement dans le prompt, c'est le placer
du côté qui se déprécie et qui se négocie (problème 7 de 01). Le mettre côté
serveur, c'est le placer du côté qui prend de la valeur.

Et c'est ce qui désarme l'objection du dirigeant qui refuse de laisser une IA
toucher à l'argent : on ne lui demande pas de faire confiance au moteur de
prédiction. On lui demande d'écrire son jugement une fois, et on lui prouve
qu'il s'est appliqué.

**Ce que la trace prouve, et ce qu'elle ne prouve pas.** Un reçu atteste d'une
action : quel appel est parti, sous quelle règle, avec quelles signatures. Il
n'atteste pas du raisonnement du modèle, et la chaîne de reçus ne rend donc
aucun modèle explicable. Le problème de la boîte noire n'est pas résolu, il est
rendu sans conséquence : peu importe pourquoi le modèle a voulu payer quarante
mille euros, le plafond était à cinq mille et rien n'est parti. Confondre les
deux se paie devant un auditeur qui connaît le sujet.

## La thèse

Le contrôle n'est pas le produit, c'est ce qui rend le produit livrable. Sans
lui l'agent reste en pilote, et un agent en pilote ne rapporte rien.

Conséquence directe du fait d'ouverture de 01 : la sécurité ne déclenche pas
l'achat, elle bloque l'industrialisation. Une couche de gouvernance vendue seule
vise un budget qui n'existe pas. Un poste de coût qui baisse vise un budget qui
existe déjà.

## L'approche, trois choses indissociables

### 1. Un workflow livré en production, pas un outil livré à installer

Le livrable est un workflow qui tourne, pas une licence. C'est ce qui répond au
premier obstacle déclaré du marché, l'intégration au SI et l'état des données
(problème 4, classé hors périmètre en 01 parce qu'aucun contrôle d'exécution ne
le résout) : il ne se résout pas par du logiciel, il se résout par du travail,
et c'est précisément le travail que le client cherche à acheter. La méthode est
au-dessus, sous « notre métier, c'est le déploiement ».

### 2. Une couche de contrôle qui vit en dehors du modèle

Le mécanisme central : la contrainte n'est jamais dans le prompt. Un modèle ne
sait pas séparer une instruction d'une donnée (problème 7), donc tout ce qui
vit dans son contexte est négociable par une injection. Ce qui est appliqué
ailleurs ne l'est pas.

Cinq mécanismes, tous du même côté de la frontière :

- **Identité et périmètre à l'enrôlement.** L'agent reçoit une clé qui lui est
  propre, liée à un propriétaire humain et à sa configuration exacte. Changer le
  prompt ou la liste d'outils invalide les appels suivants. **[vérifié]**
- **Des règles évaluées côté serveur.** Outils autorisés et interdits, domaines
  autorisés et interdits, plafond de dépense global, quotidien et par action,
  fréquence par heure et par semaine, fenêtre horaire, concurrence maximale,
  périmètre de données, profondeur de délégation. **[vérifié]**
- **Une capacité de sortie à usage unique.** Un appel externe est autorisé pour
  un hôte, une méthode, un chemin, un corps et une taille précis, consommable
  une fois, avec refus des redirections et des adresses internes. **[vérifié]**
- **Une validation humaine sur les actions qui la méritent.** Exigence de
  signatures M parmi N par rôle, évaluée comme les autres règles. La différence
  avec un simple bouton d'approbation : la co-signature est vérifiable après
  coup. **[vérifié]**
- **Une trace non falsifiable.** Chaque action validée produit un reçu chaîné
  par empreinte, et les lots sont ancrés publiquement, ce qui rend une
  réécriture a posteriori détectable, y compris par nous. **[vérifié]**

Le refus est le comportement par défaut : ce qui n'est pas autorisé n'est pas
exécuté, et l'agent reçoit une erreur qui nomme la règle. Ce point sépare une
plateforme de gouvernance d'un tableau de bord (problème 6).

### 3. Ça tourne chez le client, on n'exploite pas

Déploiement sur son cloud, chez son hébergeur, ou en local sur ses machines. Il
exploite, il garde ses données, et la souveraineté devient sa décision et non
notre promesse : chez un hébergeur européen elle est réelle, chez un hyperscaler
américain elle ne l'est pas, et dans les deux cas le contrôle et les preuves
sont identiques.

On n'héberge pas et on n'exploite pas d'agent pour le client aujourd'hui.
C'est le bon choix pour trois raisons : l'exploitation demande une astreinte et
un engagement de disponibilité qui n'ont rien à voir avec le métier de
construire des agents, elle nous rendrait responsables d'incidents que nous ne
contrôlons pas, et elle retirerait au client la maîtrise du lieu
d'exécution, qui est l'une des rares choses qu'un acheteur européen ne peut
obtenir de personne d'autre. Son poids réel dans une décision d'achat n'est
mesuré nulle part (01), donc on le traite comme un atout, pas comme un
argument. Le seul cas qui justifierait d'y
revenir : un client prêt à payer mais sans aucune équipe pour exploiter. Ça se
traite alors par un partenaire d'infogérance, pas par nous. **[direction]**

## Ce que l'ensemble change

Quatre mécanismes, et le refus par défaut qui les rend opérants, couvrent les
cinq problèmes traités fortement en 01 et mordent partiellement sur quatre
autres.

**La contrainte hors modèle** neutralise l'injection comme voie d'escalade
(problème 7) et donne à chaque agent une identité et un périmètre à
l'enrôlement plutôt qu'en revue trimestrielle, au rythme où les identités non
humaines se multiplient (problème 9). C'est aussi la seule réponse honnête à
l'absence de contrôle d'accès mesurée chez 97% des organisations ayant subi un
incident (problème 8).

**Le plafond et le compteur** bornent ce qu'une chaîne d'appels peut dépenser
avant qu'un humain ne s'en aperçoive (problème 3). On ne touche pas au prix de
l'inférence, on supprime la surprise.

**La validation humaine et le refus par défaut** bornent la casse d'un agent
qui échoue une fois sur trois sur dix étapes (problème 5). On ne rend pas le
modèle fiable, on rend son échec sans conséquence.

**La trace** donne la matière que personne n'a pour mesurer un retour : ce qui a
été fait, ce qui a été refusé, ce que ça a coûté, par agent et par workflow
(problème 2). Elle ne fabrique pas la baseline métier, qui reste au client.
Elle rend aussi l'audit possible et peu coûteux le jour où il est demandé, sans
dépendre d'une échéance réglementaire qui vient de reculer de seize mois.

Reste le problème 1, la sortie de pilote. On en lève une cause sur plusieurs.
Le reste (valeur métier floue, conduite du changement, coût du projet) est
adressé par la prestation, pas par le logiciel.

## L'escalier de diffusion

Chaque euro de revenu nouveau coûte des jours d'ingénieur. Il n'existe que trois
sorties : livrer moins cher, faire livrer quelqu'un d'autre, faire livrer le
client. Elles consomment le même investissement produit, parce que ce qui rend
une livraison moins chère est exactement ce qui rend un partenaire capable de
livrer, qui est exactement ce qui rend un client capable de construire seul.

La vraie question n'est donc pas « self-serve ou pas », mais **qui livre sans
nous, dans quel ordre, et quel niveau de finition ça impose.**

| Marche | Qui livre | Ce que ça exige | Ce qui ouvre la marche |
|---|---|---|---|
| 1 | nous | l'outillage, la méthode écrite, les gabarits | en cours |
| 2 | le client chez qui on a livré | gabarits clonables, éditeur de règles lisible, lecture de la trace par un métier | le workflow N+1 chez le même client prend moins de 40% des jours du premier |
| 3 | une agence partenaire | documentation, formation, support, cadre contractuel et commercial | une livraison complète faite par quelqu'un hors de l'équipe fondatrice, avec la seule documentation écrite |
| 4 | un client froid | onboarding autonome, support à volume, acquisition | au moins trois clients de la marche 2 ont mis un workflow en production avec zéro heure de notre part |

La marche 2 est presque gratuite : le client a vu la méthode sur son propre
processus, son deuxième workflow est une variation du premier, et on sait quoi
polir puisqu'il l'a demandé pendant la livraison. La marche 3 coûte le même
investissement produit que la 4, sans la machine d'acquisition, ce qui en fait
la bonne deuxième dépense. La marche 4 est une entreprise différente, financée
par une marge de service qui est mince par nature. On la garde comme horizon,
pas comme plan.

### Trois niveaux de qualité, assumés

Les marches ne sont pas des étapes de remplacement, elles coexistent, et elles
forment une grille de prix et de qualité.

- **Nous.** Les experts du workflow et de l'agent. Le plus cher, le plus rapide,
  le plus abouti.
- **Une agence partenaire.** Experte de son domaine ou de son secteur, elle
  utilise la plateforme comme argument de vente chez ses propres clients.
- **Le client lui-même.** Moins abouti qu'un expert, et c'est normal : il paie en
  temps ce qu'il ne paie pas en prestation.

Aucun de ces trois niveaux n'est méprisable, et surtout aucun ne cannibalise les
autres : ils correspondent à trois arbitrages différents entre prix, délai et
qualité, chez des clients différents ou chez le même à des moments différents.

### La conséquence produit : l'autonomie doit être réelle et agréable

Deux exigences qui semblent s'opposer et qui tiennent ensemble.

L'autonomie doit être vraie. Le client doit pouvoir construire son prochain
workflow sans nous, sans se battre contre l'outil, et il doit le sentir dès la
démonstration. C'est ce qui rend crédible tout le reste : on ne verrouille pas,
on ne rend pas dépendant.

Et notre travail doit rester meilleur que ce qu'il ferait seul, au point qu'il
préfère nous rappeler. Ce n'est pas contradictoire : il choisit alors de payer,
au lieu de le subir.

Les deux issues nous conviennent, et c'est la propriété rare de ce modèle.
S'il revient, c'est une vente additionnelle entrante, sur un client déjà
convaincu, donc plus facile et mieux valorisée qu'une affaire nouvelle. S'il
construit seul, il consomme des actions et des licences sans nous coûter un
jour d'ingénieur. **À condition que l'action exécutée soit facturée**, son
autonomie devient notre meilleure marge plutôt qu'un revenu perdu. C'est la
contrainte principale que 02 impose au fichier 21 : sans facturation à l'usage,
la marche 2 nous appauvrit au lieu de nous enrichir.

D'où une règle de conception qui vaut pour tout ce qu'on construit, y compris
l'outillage qu'on croit interne : **il n'y a pas d'écran interne.** Ce qui sert à
livrer est ce que le client verra, puis utilisera, puis montrera à son
partenaire. L'expérience doit être finie partout, du premier jour, sans zone
qu'on aurait laissée moche en se disant qu'elle ne sortirait pas.

Et pour la marche 2 en particulier : les gabarits sont livrés serrés par défaut,
et un agent construit en autonomie passe une revue avant d'obtenir des droits à
effet réel. Notre promesse est qu'un agent ne peut pas déraper. Un client qui
écrit des règles molles produira un incident qui ressemblera à notre échec,
même si la règle était la sienne.

## Ce que l'approche ne fait pas

- Elle ne rend pas un modèle fiable. Elle borne les conséquences de son échec.
- Elle ne baisse pas le prix de l'inférence.
- Elle ne nettoie pas les données ni ne remplace un travail d'intégration.
- Elle ne remplace pas un IAM ni un outil d'observabilité. Elle décide et
  refuse là où ils constatent.
- Elle ne fournit pas d'hébergement géré.

## Ce qui doit être vrai

À tester, et suivi dans le fichier 31.

1. Sur un processus réel, l'écart entre le coût avant et le coût après dépasse
   ce qu'on facture, et se montre en euros au bout de quelques semaines. C'est
   l'hypothèse qui porte tout le reste : si le gain n'est pas démontrable, il
   n'y a ni renouvellement, ni référence, ni deuxième workflow.
2. Un acheteur nous choisit plutôt qu'une agence parce qu'on apporte un contrôle
   démontrable. Si le contrôle ne fait gagner aucune affaire, il redevient un
   coût de production et pas un argument.
3. Assez d'entreprises connaissent, ou acceptent d'établir, le coût actuel de
   leurs processus. Si presque personne ne sait le faire, la règle de
   qualification ci-dessus vide le pipeline.
4. Un client accepte un agent qui refuse des actions, et le vit comme une
   qualité et non comme une panne.
5. **La charge de livraison reste proportionnée à la taille du contrat.** C'est
   le point où un modèle d'ingénieurs déployés se transforme en cabinet de
   conseil : à mesurer dès la première livraison, en jours passés contre revenu
   total sur douze mois.
6. **Le client construit son deuxième workflow sans nous.** Toute la logique
   d'autonomie en dépend, et rendre la plateforme utilisable par quelqu'un qui
   n'est pas ingénieur est un investissement produit que la marge de service ne
   finance pas toute seule. C'est là que la plupart des sociétés de ce modèle
   s'arrêtent.
7. Une agence tierce accepte de dépendre d'une couche qu'elle ne contrôle pas.
8. Le récurrent survit à la fin du projet, parce que le client voit ce qu'il
   paie : la plateforme qui tient ses agents, pas une rente sur un livrable.

## Ce qu'on peut démontrer aujourd'hui

Tout ce qui porte **[vérifié]** ci-dessus tourne dans le dépôt et se montre :
identité par agent, empreinte de configuration, règles serveur, capacité de
sortie à usage unique, co-signature M parmi N, reçus chaînés et ancrage public,
plus un registre de consommation en jetons et en euros par agent. Les clients
existent en Python, TypeScript et Go, avec un serveur MCP.

Ce qui reste à construire pour tenir la thèse, et qui appartient au fichier 04 :
le catalogue de connecteurs, l'expérience de création d'un agent par quelqu'un
qui n'écrit pas de code, et la lecture des traces par un métier plutôt que par
un ingénieur.
