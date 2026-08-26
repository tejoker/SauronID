# 01. Les problèmes

Premier fichier du company brain, et le seul qui ne parle pas de SauronID.
Il fixe ce qu'on cherche à résoudre et comment ça se mesure. Tout le reste
(solution, produit, features, positionnement, prix) en découle et ne peut pas
le contredire.

Les dix problèmes et leur numérotation viennent de
[`research/problem-landscape.md`](research/problem-landscape.md), sources et
notes dans [`research/sources.md`](research/sources.md). Même ordre, mêmes
numéros, pour que les deux fichiers se relisent ligne à ligne.
Note A : source primaire lue. Note B : enquête sérieuse, commanditaire connu.
Note C : à vérifier.

## Le fait qui commande tout le reste

La sécurité n'apparaît pas dans les obstacles déclarés à l'adoption. Interrogés
sur ce qui bloque leurs déploiements, plus de 500 responsables techniques citent
l'intégration au SI (46%), le coût (43%), la donnée (42%), la conduite du
changement (39%). Ni sécurité, ni gouvernance, ni auditabilité. (note B)

Chez McKinsey, la sécurité arrive au contraire en tête, citée par près de deux
tiers des répondants. Mais la question porte sur le passage à l'échelle d'un
système déjà en place, pas sur la décision d'en démarrer un. (note B)

Les deux enquêtes ne se contredisent pas : **la sécurité ne déclenche pas
l'achat, elle bloque l'industrialisation.** C'est le résultat le plus important
de la recherche, il commande l'ordre dans lequel les dix problèmes se posent, et
il demande à être vérifié en entretien.

## Les dix problèmes

### 1. Le pilote ne devient pas une production

85% des grands comptes expérimentent des agents, 5% en ont un en production
(Cisco, note B). Plus de 40% des projets agentiques seraient annulés d'ici fin
2027, sur 3 400 organisations interrogées, pour coûts qui dérapent, valeur floue
et contrôles insuffisants (Gartner, note B). Les usages à l'échelle restent à un
seul chiffre dans presque toutes les fonctions métier, maximum 24% en génie
logiciel (Stanford HAI, note A).

C'est le problème de sortie. Les neuf autres sont les raisons pour lesquelles il
se produit.

### 2. Personne ne sait mesurer le retour, faute de baseline

Deux mesures sérieuses disent l'inverse l'une de l'autre, et l'écart est le
problème. Neuf dirigeants sur dix déclarent aucun impact sur l'emploi ou la
productivité de leur entreprise sur trois ans, sur près de 6 000 dirigeants
interrogés par une équipe Bank of England, Fed d'Atlanta, Bundesbank, Stanford
et King's College (note A). En face, 80% des responsables techniques interrogés
par un fournisseur déclarent un retour économique mesurable (note B).

Trois lectures possibles, à départager en entretien. La plus probable : les
entreprises déclarent un ROI qu'elles n'ont jamais instrumenté, parce que le
pilote est parti sans baseline documentée.

Une asymétrie de mesure double le problème : les gains des copilotes sont
établis par des études contrôlées (+14% à +26% selon les métiers, jusqu'à +50%
sur de la production de contenu, 0% sur une tâche d'apprentissage, -19% chez des
développeurs expérimentés, recension AI Index 2026, note A), alors que les gains
des agents ne sont documentés que par des enquêtes déclaratives, souvent
commanditées par un fournisseur. Comparer les deux avec les données publiques,
c'est comparer une mesure et une déclaration. Détail dans
[`research/copilot-vs-agent.md`](research/copilot-vs-agent.md).

### 3. Les coûts dérapent et restent imprévisibles

73% des organisations dépassent leur budget IA, 20% seulement le prévoient à
±10% près, et l'inférence pèse 80 à 90% de la dépense (FinOps Foundation, près
de 1 200 praticiens responsables de plus de 83 Md$ de dépense cloud, note B). La
part d'organisations pilotant activement leur dépense IA est passée de 31% à 98%
en deux ans : le sujet est devenu un poste de gestion à part entière.

Deux choses à ne pas confondre : le prix unitaire de l'inférence, sur lequel
personne ne peut rien, et l'absence de plafond et de compteur par agent, qui est
un défaut d'outillage.

### 4. L'intégration au SI et l'état des données

Premier obstacle technique déclaré : 46% citent l'intégration aux systèmes
existants, 42% l'accès et la qualité des données (note B). Même chiffre chez
McKinsey, qui en conclut que l'intelligence des modèles n'est plus le goulot
d'étranglement pour mettre un workflow agentique en production (note B).

Le problème n'est pas la disponibilité de la donnée mais son accessibilité :
elle existe, enfermée dans des PDF, des tableurs et des CRM anciens qu'un modèle
ne lit pas directement. (note C, à requalifier en entretien)

### 5. La fiabilité s'effondre sur les chaînes multi-étapes

Le seul problème de la liste qui soit une propriété arithmétique. Une tâche de n
étapes réussit avec p puissance n.

| Fiabilité par étape | 5 étapes | 10 étapes | 20 étapes |
|---|---|---|---|
| 99% | 95% | 90% | 82% |
| 95% | 77% | 60% | 36% |
| 90% | 59% | 35% | 12% |

Un agent fiable à 95% par étape échoue une fois sur trois sur dix étapes, quel
que soit le modèle. C'est ce qui sépare la démo du processus qu'on laisse
tourner. Les organisations qui réussissent ont défini une validation humaine
dans la boucle, 65% contre 23% pour les autres (McKinsey, note B).

### 6. L'évaluation et l'observabilité ne suivent pas

Les outils capturent traces et métriques au niveau du modèle, sans le contexte
métier qui expliquerait pourquoi l'agent a fait ça. D'ici 2030, la moitié des
échecs de déploiement d'agents viendraient de l'insuffisance de l'application
des contrôles à l'exécution par la plateforme de gouvernance (Gartner, note B).
La même note avertit qu'appliquer une gouvernance uniforme à tous les agents,
quel que soit leur niveau d'autonomie, mène à l'échec.

C'est la frontière entre observer et empêcher.

### 7. L'injection de prompt reste non résolue

Défaut d'architecture, pas bug corrigeable : un modèle n'a aucun moyen natif de
séparer les instructions de confiance des données non fiables, les deux arrivant
dans le même flux de tokens. 73% des déploiements IA en production audités
présentent une faiblesse d'injection (Cisco, note B), et c'est le risque numéro
1 du classement OWASP pour les applications LLM (note A).

Corollaire direct : la contrainte ne peut pas vivre dans le prompt de l'agent,
elle doit être appliquée en dehors du modèle.

### 8. L'absence de contrôle d'accès, et le shadow AI

Parmi les organisations ayant subi un incident de sécurité lié à l'IA, 97%
n'avaient aucun contrôle d'accès sur les outils concernés (IBM, 600
organisations étudiées, note B). 63% n'ont aucune politique de gouvernance IA.
43% ont subi un incident impliquant un outil IA non approuvé, contre 20% l'année
précédente. Une brèche impliquant du shadow AI coûte 5,39 M$ en moyenne, jusqu'à
670 k$ de plus qu'une brèche ordinaire.

Le 97% est le chiffre le plus solide du dossier : une mesure d'absence de
contrôle sur une population déjà victime, pas une projection.

### 9. La prolifération des identités non humaines

109 identités machine pour une identité humaine, contre 82 pour 1 un an plus
tôt, dont 79 sur 109 sont des agents IA, et 97% portent des privilèges excessifs
(Palo Alto Networks, note B). Une mesure indépendante donne 80 pour 1 (KPMG,
note B) : l'ordre de grandeur tient, la précision non.

La gouvernance d'identité classique repose sur un enrôlement manuel et des
revues périodiques, un rythme incompatible avec une population qui double en un
an. À surveiller : Auth0, Google Cloud et Microsoft Entra Agent ID ont tous
publié une offre d'identité d'agent en 2026, la couche d'identité de base est en
train d'être absorbée par les fournisseurs d'IAM.

### 10. La dépendance à un fournisseur de modèle

Le dossier le plus faible : tout est en note C, aucune enquête primaire
consultée. 81% de dirigeants se déclarent préoccupés par leur dépendance à un
fournisseur IA, 6% estiment pouvoir en changer sans perturbation matérielle
(Zapier, note C). 37% des DSI feraient tourner cinq modèles ou plus en
production, contre 29% un an plus tôt (note C).

Ce qui est certain sans enquête : la dépendance n'est pas au niveau de la
plateforme, elle est au niveau de l'optimisation. Une couche de contrôle
indépendante du modèle laisse brancher n'importe lequel et s'applique
identiquement à tous. Ce qui reste attaché à un modèle donné, c'est le prompt et
le réglage des outils, optimisés pour lui et à réajuster quand on en change.
C'est une contrainte réelle, et elle est d'un autre ordre de grandeur qu'une
réécriture de la couche d'exécution.

## Périmètre visé

Provisoire. `02-solution.md` tranche définitivement, problème par problème, avec
la démonstration en face. Répondre fortement à cinq problèmes sur dix est déjà
beaucoup : mieux vaut cinq réponses démontrables que dix revendiquées.

| # | Problème | Ambition | Pourquoi ce niveau |
|---|---|---|---|
| 8 | Absence de contrôle d'accès | forte | c'est la définition même d'un contrôle à l'exécution |
| 9 | Identités non humaines | forte | l'agent reçoit une identité et un périmètre à l'enrôlement, pas en revue trimestrielle |
| 7 | Injection de prompt | forte | la contrainte vit hors du modèle, donc l'injection ne l'atteint pas |
| 6 | Observer ne suffit pas | forte | empêcher est une décision, pas un tableau de bord |
| 5 | Fiabilité multi-étapes | forte | plafonds, validation humaine et arrêt sur écart bornent la casse, sans rendre le modèle fiable |
| 1 | Pilote qui ne passe pas en production | partielle | on lève un blocage sur plusieurs, et pas celui que les acheteurs citent en premier |
| 3 | Dérapage des coûts | partielle | plafond et compteur par agent, aucune prise sur le prix unitaire de l'inférence |
| 10 | Dépendance au modèle | partielle | agnostique par construction : n'importe quel modèle se branche et les règles s'appliquent à l'identique. Reste le prompt et le réglage des outils, optimisés pour un modèle et à réajuster au changement |
| 2 | Mesure du retour | partielle | on fournit la matière (ce qui a été fait, refusé, dépensé), pas la baseline métier |
| 4 | Intégration au SI et données | hors périmètre | sujet de connecteurs et de tuyauterie, pas de contrôle d'exécution. Reste le prix d'entrée pour être déployable |

## Le cadre réglementaire

Les faits, sans conclusion commerciale, qui appartient au fichier 11.

L'AI Omnibus est entré en vigueur le 27 juillet 2026 et repousse les obligations
sur les systèmes à haut risque du 2 août 2026 au 2 décembre 2027, et au 2 août
2028 pour l'IA intégrée à des produits déjà couverts par la législation produit
(note A). Motif officiel : les normes techniques n'étaient pas prêtes. Les
sanctions maximales sont inchangées, jusqu'à 35 M€ ou 7% du chiffre d'affaires
mondial. Les obligations de transparence de l'article 50 et les pratiques
interdites de l'article 5 s'appliquent, elles, depuis le 2 août 2026.

Ce que ça implique : entre aujourd'hui et fin 2027, aucune échéance nouvelle ne
force une entreprise européenne à budgéter une couche de gouvernance. La
conformité reste une exigence interne chez beaucoup d'acheteurs, mais elle n'est
plus datée.

Note pour 02 : une trace d'exécution complète et non falsifiable ne dépend
d'aucune échéance. Elle rend l'audit possible et peu coûteux le jour où il est
demandé, et elle installe une responsabilisation interne (qui a autorisé quoi, à
quel agent) avant que la loi ne l'exige.

**La souveraineté est un sujet distinct de la réglementation.** Où tournent le
modèle et les données relève du choix de déploiement du client, pas de l'AI Act.
Un hébergeur européen et un hyperscaler américain ne donnent pas la même
réponse, et cette réponse appartient au client. Aucune source chiffrée du
dossier ne mesure ce que ça pèse dans une décision d'achat : à qualifier en
entretien avant d'en faire un argument.

## Les questions à poser en entretien

Aucune source publique n'y répond, et la stratégie commerciale en dépend.

1. Combien coûte réellement la mise en production d'un premier agent utile, dans
   une entreprise de 50 à 500 personnes.
2. Qui signe : direction générale, métier, DSI ou sécurité, et sur quelle ligne.
3. L'écart entre 80% de ROI déclaré et neuf dirigeants sur dix ne constatant
   aucun impact vient-il de la mesure ou de la réalité.
4. Que fait l'entreprise aujourd'hui quand un agent se trompe, et combien ça
   coûte. Aucune donnée trouvée hors contexte de brèche.
5. Le frein sécurité apparaît-il avant ou après la première mise en production.
6. Le lieu d'hébergement du modèle et des données est-il un critère éliminatoire,
   un critère de préférence, ou un non-sujet. Et pour qui dans l'organisation.
