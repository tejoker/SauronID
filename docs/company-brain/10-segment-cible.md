# 10. Le segment cible

Par qui on commence. Premier fichier de la dizaine `1x`, il découle de
[`02-solution.md`](02-solution.md) et [`04-features.md`](04-features.md), et il
engage le discours (11), les concurrents à regarder (12) et le playbook (30).

Méthode : Market Segmentation, Beachhead Market et End User Profile des 24 Steps
(Bill Aulet, MIT), croisés avec Customer Development (Steve Blank, Stanford). Un
marché de tête n'est pas un marché prometteur : c'est le plus petit marché où on
peut gagner en entier, vite, et depuis lequel on peut aller ailleurs.

## Les sept critères

1. Le client a l'argent.
2. On peut l'atteindre.
3. Il a une raison impérieuse d'acheter maintenant.
4. On peut lui livrer un produit complet aujourd'hui.
5. Aucun concurrent installé ne tient la place.
6. Le gagner ouvre les segments voisins.
7. C'est cohérent avec ce que l'équipe sait et veut faire.

## Le segment retenu

**Les entreprises françaises de 100 à 1 500 salariés à fort volume de factures
fournisseurs, par la fonction finance.**

Trois précisions qui comptent plus que la catégorie juridique.

**La bande de taille.** En dessous de 100 salariés, le volume de factures paie
rarement un projet. Au-dessus de 1 500, le comportement d'achat bascule vers le
grand compte : achats centralisés, comité, DSI qui veut construire, exigences de
certification. Plus gros ne veut pas dire plus payeur, ça veut souvent dire plus
lent. La bande utile est donc à cheval sur les PME et le bas des ETI, et pas
alignée sur les catégories de l'INSEE.

**Le vrai critère est le volume, pas l'effectif.** Une entreprise de 150
personnes dans le négoce traite plus de factures fournisseurs qu'une ETI de 400
dans le service. Les secteurs à forte densité de fournisseurs passent en
premier : négoce et distribution, BTP, transport et logistique, industrie,
santé. L'effectif n'est qu'un filtre commode pour bâtir la liste.

**Les ordres de grandeur.** 7 031 ETI et 164 000 PME hors microentreprises en
France (INSEE, données 2023, note B, chiffre repris d'une synthèse et non lu
dans la publication). La cible réelle est un sous-ensemble des deux, à
construire par secteur et par taille. Un marché de tête doit se compter, se
lister et s'appeler.

## Pourquoi maintenant

**Le 1er septembre 2026, la facturation électronique devient obligatoire en
France.** Toutes les entreprises doivent recevoir leurs factures au format
électronique, et les grandes entreprises comme les ETI doivent les émettre et
transmettre les données de transaction et de paiement à l'administration. Les
PME et TPE suivent le 1er septembre 2027. Le passage par une plateforme agréée
est obligatoire. (impots.gouv.fr et economie.gouv.fr, note A)

Trois conséquences, et c'est la conjonction qui compte :

1. **Toute la cible touche à son flux de factures en ce moment.** L'obligation
   de réception vaut pour tout le monde dès septembre 2026, et le choix d'une
   plateforme agréée avec. Le haut de la bande (les ETI) a en plus l'obligation
   d'émettre et de déclarer dès cette date, le bas de la bande l'aura en
   septembre 2027. Dans les deux cas, le budget est voté et le chef de projet
   est nommé : on n'arrive pas pour créer un chantier, on arrive pendant un
   chantier.
2. **La donnée devient structurée.** Le problème 4 de 01, la donnée enfermée
   dans des PDF illisibles par un modèle, se règle tout seul pour ce
   processus-là : la facture arrive dans un format normalisé, par une plateforme
   agréée. Le principal obstacle technique à l'automatisation disparaît, sans
   qu'on ait à le résoudre.
3. **La date crée l'urgence que l'AI Act ne crée plus.** 01 établit qu'aucune
   échéance réglementaire ne force un achat de gouvernance avant fin 2027. Celle
   de la facturation électronique n'a rien à voir avec l'IA, et c'est
   précisément pour ça qu'elle marche : elle est réelle, datée, et elle tombe
   maintenant.

Le calendrier donne aussi le segment suivant, sans qu'on ait à le choisir : les
entreprises plus petites au 1er septembre 2027, avec un an d'avance sur ce qu'on
aura appris.

**Une règle absolue, sinon la réforme nous enferme : on ne vend jamais la
conformité.** Dire « on vous met en conformité avec la facture électronique »,
c'est entrer en concurrence frontale avec les plateformes agréées et les
éditeurs comptables, sur leur terrain, en dernier arrivé. Ce qu'on vend est le
coût du traitement de la comptabilité fournisseurs. La réforme n'est pas
l'argument, c'est la raison pour laquelle c'est maintenant et pour laquelle la
donnée est enfin exploitable.

De la même façon, l'entrée par les factures n'est pas l'identité de
l'entreprise. On est un éditeur de logiciel qui met ses agents en production
chez ses clients, pas une agence, et se déclarer spécialiste de la facturation
reviendrait à affronter sur leur terrain des éditeurs qui ont dix ans d'avance
sur ce sujet précis (voir [`11-positionnement.md`](11-positionnement.md)). La sortie de la niche se fait au deuxième workflow chez le même
client, pas au premier prospect, et elle est déjà protégée par 04 : tant qu'on
ne construit rien de spécifique à la facture, on n'est prisonnier de rien.

## Le plan d'attaque, et sa date de péremption

Un seul processus d'entrée, une population large, et une décision datée.

**Ce qu'on fait pendant six semaines.** On contacte la liste sur un seul sujet,
la comptabilité fournisseurs, avec trois messages différents et rien d'autre qui
change. On ne teste pas trois processus en parallèle : ce serait trois premières
fois pour toujours, et un résultat illisible, puisqu'on ne saurait pas si l'écart
vient du sujet, de la liste ou du message.

Les trois angles à tester :

1. **Le coût.** Votre compta fournisseurs occupe N personnes. Voilà ce que ça
   coûte, voilà ce que ça coûterait.
2. **Le calendrier.** Vous êtes en train de basculer en facture électronique. Le
   flux devient propre, c'est le moment où l'automatiser devient possible.
3. **L'erreur.** Un double paiement, une facture payée deux fois, un fournisseur
   payé trop tôt ou trop tard. Combien ça vous coûte par an, et qui s'en aperçoit.

**Le message est spécifique, l'offre ne l'est pas.** C'est la distinction qui
évite les deux erreurs symétriques.

Un message froid généraliste (« parlons de vos frictions, on peut construire
n'importe quel workflow ») demande au prospect de faire le travail de trouver le
cas d'usage, sonne comme les dizaines d'autres messages qu'il reçoit, et ne lui
donne rien à quoi réagir. C'est la manière la plus sûre d'être ignoré, et 02 le
dit déjà : un discours généraliste est indistinguable du bruit.

À l'inverse, se croire limité au processus par lequel on est entré serait
absurde : on sait livrer n'importe quel processus, c'est le métier.

Donc : **la porte est étroite, la maison est grande.** En prospection, un
processus nommé, un chiffre, une question fermée. En rendez-vous, dès qu'il
répond, on ouvre : « sur ce processus-là, combien ça vous coûte, et qu'est-ce
qui vous coûte plus cher encore ? » Si la vraie douleur est ailleurs, on prend
l'autre processus, et l'affaire est meilleure parce que c'est lui qui l'a
nommée.

**Ce qui décide, et ce qui ne décide pas.** Le taux de réponse est une mesure de
vanité : il dit si le message accroche, pas si le marché achète. Les deux
chiffres qui tranchent sont le nombre de rendez-vous obtenus et, surtout, le
nombre de cadrages payés. Un prospect poli accepte un rendez-vous ; un prospect
qui a un problème paie un cadrage.

**La règle de bascule, décidée maintenant pour ne pas être négociée plus tard.**
Si au bout de six semaines aucun cadrage n'est payé, on change de porte
d'entrée. La suivante est déjà nommée : le recouvrement, puis les tickets et les
droits d'accès. On change le sujet, pas la méthode, et pas la liste.

**Ce qu'on rapporte en plus des ventes.** Chaque conversation répond aux quatre
inconnues listées en bas de ce fichier. Six semaines d'appels valent plus que
six semaines de recherche documentaire, et c'est l'étape 2 du dossier
[`research/`](research/README.md) qui se fait en même temps que la prospection.

## Le segment contre les sept critères

| # | Critère | Verdict |
|---|---|---|
| 1 | L'argent | à partir de 100 salariés il y a un directeur financier, une dépense identifiable sur ce processus et un budget en cours sur la réforme. 30% des entreprises moyennes et 55% des grandes utilisent déjà l'IA (Eurostat 2025, note A), donc la ligne existe |
| 2 | L'accessibilité | la bande se liste nominativement par taille et par secteur, à partir des données d'entreprises publiques. C'est le critère le plus faible : savoir les atteindre sans ressembler aux dizaines de messages qu'elles reçoivent reste entièrement à démontrer (fichier 30) |
| 3 | La raison d'acheter maintenant | l'échéance du 1er septembre 2026, qui les oblige déjà à ouvrir le sujet |
| 4 | Le produit complet | oui pour le contrôle, l'exécution et la preuve. Non pour le confort : l'atelier de construction et la file d'escalade sont en chantier (04). On livre à la main ce qui manque, c'est le modèle |
| 5 | La concurrence | l'usage d'agents à l'échelle est à un seul chiffre dans presque toutes les fonctions (AI Index 2026, note A). Sur les factures il y a des éditeurs de dématérialisation, pas des agents qui exécutent |
| 6 | Les segments voisins | les autres processus finance chez le même client (recouvrement, notes de frais, rapprochement), puis les PME en 2027, puis les pays dont le calendrier de facturation électronique arrive après |
| 7 | La cohérence avec l'équipe | un processus à conséquence financière, où le contrôle décide de la mise en production. C'est exactement ce que le produit sait faire |

## Qui est en face

Trois personnes, trois questions différentes, et il faut les trois pour signer.

- **Le directeur financier.** Il paie et il décide. Sa question : combien ça
  coûte aujourd'hui, combien après, et qu'est-ce qui se passe si l'agent paie
  deux fois. Il ne veut ni terminal ni YAML.
- **Le responsable comptabilité fournisseurs.** Il vit le processus et il subit
  la réforme. Sa question : qu'est-ce que je continue de faire, comment je
  reprends la main sur un cas. C'est lui qui adopte ou qui enterre.
- **Le DSI ou le RSSI.** Il ne signe pas, mais il bloque. Sa question : où ça
  tourne, ce que l'agent a le droit d'appeler, comment on lui retire un droit.
  Il doit trouver ses réponses seul, et c'est là que le produit fait la
  différence.

## Ce qu'on exclut, et pourquoi

- **Les grandes entreprises** (312 en France). Cycle de vente long, achats
  centralisés, exigences de certification qu'on n'a pas encore, et une DSI qui
  construira en interne. On y va quand on aura des références, pas avant.
- **Les entreprises de moins de 100 salariés.** Le volume de factures paie
  rarement un projet, et il n'y a souvent personne à qui parler entre le
  dirigeant et le comptable. Elles redeviennent une cible en 2027, quand leur
  propre échéance tombe et quand l'atelier de construction aura baissé le coût
  de livraison.
- **Au-dessus de 1 500 salariés.** Le comportement d'achat bascule vers le grand
  compte, avec les délais et les exigences qui vont avec.
- **Le secteur technologique.** C'est le seul où les agents tournent déjà à
  l'échelle (24% en génie logiciel, note A). On y arriverait après tout le
  monde, face à des équipes qui construiront elles-mêmes.
- **Le secteur public.** Marchés publics, délais, références exigées. Plus tard.

## Ce qu'on ne sait pas encore

Aucune source publique ne répond, et le fichier 30 ne peut pas s'écrire sans.

1. Combien de factures par mois et combien de personnes, concrètement, dans une
   ETI de 400 personnes. L'ordre de grandeur décide si le gain paie un projet.
2. Qui pilote le chantier facturation électronique : la finance, la DSI, ou un
   prestataire déjà en place. C'est lui qu'il faut atteindre.
3. Ce que les plateformes agréées font déjà. Si l'une d'elles annonce un agent
   de traitement, le critère 5 change et il faut le savoir avant de construire
   le discours (fichier 12).
4. Ce qui se passe aujourd'hui quand une facture est payée en double, et ce que
   ça coûte. C'est la peur que le contrôle adresse, et personne ne l'a chiffrée.

Ces quatre réponses viennent d'entretiens, pas de recherche documentaire. C'est
l'étape 2 du dossier [`research/`](research/README.md).
