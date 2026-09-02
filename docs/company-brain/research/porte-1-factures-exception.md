# Porte 1 : les factures fournisseurs en exception

**Écrit le 31 août 2026. Périmé le 15 octobre 2026** si aucun cadrage n'est
payé, par la règle de bascule de
[`../10-segment-cible.md`](../10-segment-cible.md).

## Ce que ce fichier n'est pas

**Ce n'est pas le problème que SauronID résout.** C'est une porte d'entrée
commerciale, la première, choisie pour une fenêtre de calendrier. Le problème
que SauronID résout est horizontal et ne parle pas de comptabilité : un agent
qui exécute des actions réelles ne se déploie pas sans contrainte appliquée en
dehors du modèle. Il est formulé dans [`../01-problemes.md`](../01-problemes.md)
et n'a rien de financier.

`11-positionnement.md` le dit dans ces termes : la porte est étroite, la maison
est grande. Ce fichier décrit une porte. Trois conséquences à tenir.

1. **Rien ici ne monte dans le produit.** Aucune règle, aucun connecteur, aucun
   champ de schéma spécifique à un standard comptable. Le noyau reste agnostique
   (voir [`../04-features.md`](../04-features.md)).
2. **Rien ici ne monte sur le site.** Le site montre cinq fonctions et ne se
   déclare spécialiste d'aucune. Ce fichier sert la prospection sortante et
   seulement elle.
3. **La porte se remplace, la maison non.** À l'échéance ci-dessus, on passe au
   recouvrement, puis aux tickets et droits d'accès. Un fichier jumeau de
   celui-ci s'écrira alors, avec les mêmes six hypothèses réécrites pour ce
   processus. La méthode est réutilisable, les chiffres ne le sont pas.

## Ce que ce fichier est

L'instrument de terrain de l'étape 2 de [`README.md`](README.md), appliqué à un
seul processus. Il ne contient aucune preuve : des hypothèses écrites assez
précisément pour être fausses, et le guide d'entretien qui les tranche. Tout ce
qui est marqué **[hypothèse]** n'a été validé par personne.

## Ce qui contredit la thèse, d'abord

Trois raisons sérieuses pour lesquelles ce fichier peut se révéler sans objet.

1. **Les éditeurs de dématérialisation traitent peut-être déjà l'exception.**
   Yooz, Esker, Libeo et Cegid vendent tous du rapprochement automatique de bon
   de commande et du routage d'approbation avec seuils. Le pari de ce document
   est qu'ils automatisent le chemin nominal et laissent le cas d'exception à un
   humain. Ce pari n'a pas été vérifié en démonstration produit. S'il est faux,
   la porte d'entrée facture tombe.
2. **L'exception est peut-être trop peu volumique pour payer.** Un processus
   d'exception qui représente 3% des factures ne justifie pas un projet, même
   s'il coûte cher par unité. Le ratio exceptions sur volume total est le
   chiffre qui décide, et personne ne l'a mesuré chez un client réel.
3. **Le coût peut être invisible parce qu'il est absorbé.** Si le traitement des
   litiges est réparti sur douze personnes à raison de vingt minutes par jour,
   il n'existe dans aucun budget. Un coût que le client ne voit pas est un coût
   qu'il ne paiera pas pour supprimer. La règle 2 de la section « ce qui rend le
   gain démontrable » de [`../02-solution.md`](../02-solution.md) impose alors
   de refuser le processus.

## Le job à faire

Formulation Jobs to be Done, sans le vocabulaire produit. C'est le job d'un chef
comptable, pas la catégorie dans laquelle SauronID se range.

> Quand une facture fournisseur arrive et qu'elle ne correspond à rien
> d'attendu, je veux savoir vite qui doit trancher et obtenir sa décision, pour
> ne pas payer en retard, ne pas payer deux fois, et ne pas arriver à la clôture
> avec un écart que je ne sais pas expliquer.

Trois précisions qui changent le job.

**Le job n'est pas la saisie.** La lecture du document est un problème résolu,
et la réforme de septembre 2026 le résout une deuxième fois en livrant la donnée
structurée (voir [`../10-segment-cible.md`](../10-segment-cible.md)). Vendre de
la saisie en 2026, c'est arriver dix ans en retard.

**Le job n'est pas l'approbation nominale non plus.** Une facture qui
correspond à un bon de commande, dans les seuils, chez un fournisseur connu, se
route toute seule chez tous les éditeurs installés.

**Le job est la décision sous exception.** Facture sans bon de commande
préalable, écart de prix ou de quantité, fournisseur inconnu du référentiel,
double réception possible, service qui a commandé sans prévenir. C'est là que le
traitement redevient manuel, que le délai explose, et que le coût se cache.

## Qui le ressent

Trois personnes, trois douleurs différentes. **[hypothèse]** pour les trois.

| Qui | Ce qu'il ressent | Ce qui le ferait signer | Ce qui le ferait bloquer |
|---|---|---|---|
| Le directeur financier | le délai de paiement qui dérape, les pénalités, la trésorerie qu'il ne pilote pas parce qu'il ne sait pas ce qui est engagé | un délai d'exception qui baisse, un engagé fiable en fin de mois | l'idée qu'un système décide d'un paiement sans qu'il puisse dire qui a validé quoi |
| Le chef comptable | les relances internes, les gens qui ne répondent pas, la clôture avec des écarts à justifier | ne plus relancer à la main, arriver à la clôture sans dossier ouvert | un outil qui valide à tort et crée un écart de rapprochement qu'il devra démêler seul |
| Le responsable informatique | rien, ce n'est pas son sujet | rien, il ne signe pas | une intégration qui touche l'ERP comptable, ou des données financières qui sortent de son périmètre |

La personne à interroger en premier est le chef comptable, pas le directeur
financier. Il connaît le volume réel d'exceptions, il sait combien de fois il
relance, et il n'a aucune raison d'embellir. Le directeur financier connaît le
budget, pas le processus.

## Ce que ça coûte

**Inconnu.** C'est le point le plus important de ce fichier.

Aucune source indépendante ne donne le coût de traitement d'une facture en
France. Les chiffres qui circulent, 14 à 20 € par facture papier dont 5,40 € de
validation, viennent tous d'éditeurs de dématérialisation ou de leur association
professionnelle, et aucun n'a été lu à la source. Ils sont consignés en note C
dans [`sources.md`](sources.md), donc utilisables pour formuler une question,
jamais pour justifier un prix.

Deux conséquences pratiques.

1. **On n'annonce jamais un coût au prospect.** On lui demande le sien. Un
   chiffre d'éditeur concurrent servi à un chef comptable qui connaît son métier
   se retourne immédiatement.
2. **On mesure un délai à défaut d'un coût.** Le nombre de jours entre l'arrivée
   d'une facture en exception et sa résolution est dans ses outils, il est à
   lui, et il bouge dans le même sens que le coût. Voir la règle 3 de
   [`../02-solution.md`](../02-solution.md).

## Les six hypothèses à casser

Chacune est fausse ou vraie après huit à dix entretiens, pas avant.

| # | Hypothèse | Ce qui la casse |
|---|---|---|
| H1 | Entre 10% et 25% des factures fournisseurs partent en exception | un ratio sous 5% chez la majorité des interrogés |
| H2 | Une facture en exception met plus de cinq jours ouvrés à se résoudre | un délai médian sous deux jours |
| H3 | Le coût principal est la relance interne, pas la décision elle-même | les interrogés décrivent une décision longue et une relance rapide |
| H4 | Le chef comptable connaît son volume d'exceptions sans avoir à le chercher | personne ne sait répondre sans extraire un rapport |
| H5 | Les outils installés routent l'approbation mais ne décident pas sous exception | une démonstration produit concurrente qui décide sous exception |
| H6 | La réforme de septembre 2026 met le sujet sur le bureau du directeur financier maintenant | les interrogés déclarent avoir traité le sujet et être passés à autre chose |

H5 est la plus dangereuse : c'est la seule dont la réponse ne vient pas d'un
entretien client mais d'une démonstration concurrente. Elle se traite en
parallèle, pas après.

## Le guide d'entretien

Règles de Customer Development (Steve Blank) et du *Mom Test* (Rob Fitzpatrick),
qui tiennent en trois lignes : on parle du passé et jamais du futur, on ne
présente pas SauronID, et on ne mentionne pas l'IA. Une personne à qui on décrit
une solution devient polie, et une personne polie ne dit rien d'utile.

Quarante minutes. Le chef comptable d'abord.

**Cadrage, 5 minutes**
1. Décrivez-moi ce qui se passe entre le moment où une facture fournisseur
   arrive et le moment où elle est payée. Sans généraliser, la dernière que vous
   avez traitée.
2. Combien de factures fournisseurs passent chez vous par mois ? Qui les touche ?

**Le volume d'exception, H1 et H4, 10 minutes**
3. Sur cent factures, combien ne passent pas toutes seules ? Vous le savez de
   tête ou il faut le sortir d'un rapport ?
4. Quand une facture ne passe pas, c'est pour quelles raisons, dans l'ordre de
   fréquence ?
5. Racontez-moi la dernière qui a mal tourné. Qu'est-ce qui s'est passé
   exactement, jour par jour ?

**Le délai et le coût réel, H2 et H3, 12 minutes**
6. Cette facture-là, elle a mis combien de temps à se résoudre ? Et une facture
   normale ?
7. Pendant ce temps, qui a fait quoi ? Combien de fois avez-vous relancé
   quelqu'un, et par quel canal ?
8. Qui a fini par trancher ? Comment vous avez su qu'il avait tranché ?
9. Qu'est-ce que ça vous a coûté d'avoir mis ce temps-là ? Pénalité, escompte
   perdu, fournisseur qui bloque une livraison, autre chose ?
10. À la dernière clôture, combien de dossiers restaient ouverts pour cette
    raison ?

**L'existant, H5, 8 minutes**
11. Quels outils vous utilisez pour ça aujourd'hui ? Qu'est-ce qu'ils font tout
    seuls et qu'est-ce qu'ils vous laissent faire ?
12. Sur une facture sans bon de commande, votre outil fait quoi exactement ?
13. Qu'est-ce que vous avez essayé pour améliorer ça, et pourquoi ça n'a pas
    marché ?

**Le déclencheur, H6, 5 minutes**
14. La facturation électronique en septembre, ça change quoi chez vous ? Qui
    s'en occupe ?
15. Ce budget-là, il est voté ? Il couvre quoi ?

**La sortie**
16. Si je devais parler à une seule autre personne sur ce sujet, ce serait qui ?

**Ce qu'on ne demande jamais.** « Est-ce que vous seriez intéressé par », « est-ce
que vous paieriez pour », « et si un système pouvait ». Trois questions sur
l'avenir, trois réponses sans valeur.

## Ce qui sort de l'étape 2

Quatre livrables, et l'étape 3 ne démarre pas sans eux.

1. Un ratio d'exceptions observé, avec sa dispersion, sur au moins huit
   entreprises de la bande cible.
2. Un délai médian de résolution, mesuré et non déclaré quand c'est possible.
3. Le comité d'achat réel, observé : qui a signé le dernier outil comparable,
   qui a pu le bloquer.
4. Un coût de traitement établi chez au moins un client, en note A par
   construction puisque c'est sa donnée. C'est le chiffre qui débloque la
   tarification, aujourd'hui à l'arrêt faute de base mesurée.

Les transcripts sont conservés. Une synthèse sans transcript n'est pas une
preuve.
