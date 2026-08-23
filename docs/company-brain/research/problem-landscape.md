# Les dix problèmes durs de l'IA en entreprise

**Étape 0, recherche documentaire. 24 août 2026.**
**Objet :** établir ce qui est réellement mesuré avant de formuler un problème.
**Ce document ne propose rien.** Aucune solution, aucun positionnement, aucune
mention de ce que SauronID sait faire. La formulation du problème vient après,
en étape 1.

Notes de qualité A, B, C définies dans [`README.md`](README.md). Détail des
sources dans [`sources.md`](sources.md).

---

## Ce qui contredit la thèse SauronID, d'abord

Trois résultats de cette recherche vont contre le positionnement sécurité, et
expliquent mieux le refus d'Agicap que n'importe quelle hypothèse interne.

**1. La sécurité n'apparaît pas dans les obstacles déclarés à l'adoption.**
Interrogés sur ce qui bloque leurs déploiements d'agents, plus de 500
responsables techniques citent l'intégration au SI (46%), le coût
d'implémentation (43%), la qualité et l'accès aux données (42%) et la conduite
du changement (39%). Ni la sécurité, ni la gouvernance, ni l'auditabilité ne
figurent dans cette liste. (Anthropic et Material, fin 2025, note B)

**2. L'échéance réglementaire qui aurait pu forcer l'achat a sauté.** L'AI
Omnibus est entré en vigueur le 27 juillet 2026 et repousse les obligations sur
les systèmes à haut risque du 2 août 2026 au 2 décembre 2027, et au 2 août 2028
pour l'IA intégrée à des produits déjà couverts par la législation produit.
(Commission européenne, note A) Un acheteur qui n'avait pas de budget
gouvernance en juillet 2026 vient de gagner seize mois pour ne pas en créer.

**3. Là où la sécurité apparaît en tête, la question posée est différente.**
McKinsey trouve près de deux tiers de répondants citant la sécurité et le risque
comme premier frein, mais la question porte sur le passage à l'échelle d'un
système agentique déjà en place, pas sur la décision d'en démarrer un. (note B)
L'écart entre les deux enquêtes n'est pas une contradiction : la sécurité ne
déclenche pas l'achat, elle bloque l'industrialisation. C'est le résultat le plus
important de cette recherche et il demande à être vérifié en entretien.

---

## 1. Le pilote ne devient pas une production

Le problème le mieux documenté, et celui sur lequel toutes les sources
convergent malgré des méthodes très différentes.

| Mesure | Chiffre | Source | Note |
|---|---|---|---|
| Preuves de concept IA n'atteignant pas le déploiement large | 88%, soit 4 sur 33 | IDC avec Lenovo | C |
| Entreprises expérimentant des agents contre celles en production | 85% contre 5% | Cisco, clients grands comptes | B |
| Usage d'agents à l'échelle par fonction métier | chiffres à un seul chiffre dans presque toutes les fonctions | Stanford HAI, AI Index 2026, ch. 4 | A |
| Fonctions où deux tiers ou plus déclarent aucun usage d'agent | y compris IT et gestion des connaissances, les plus avancées | Stanford HAI, AI Index 2026 | A |
| Meilleur taux sectoriel d'usage agentique à l'échelle | 24% en génie logiciel, dans le secteur tech uniquement | Stanford HAI, AI Index 2026 | A |
| Projets agentiques annulés d'ici fin 2027 | plus de 40%, sondage sur 3 400+ organisations | Gartner, juin 2025 | B |

Les causes avancées par Gartner : coûts qui dérapent, valeur métier floue,
contrôles de risque insuffisants. Gartner ajoute que sur les milliers de
fournisseurs se réclamant de l'agentique, environ 130 le sont réellement, le
reste relevant du réétiquetage de chatbots et de RPA.

Le chiffre le plus cité du marché, les 95% de pilotes GenAI sans retour du MIT
NANDA, est volontairement classé **C**. Le rapport repose sur 52 entretiens de
dirigeants, 153 réponses de responsables et 300 déploiements publics, il est
préliminaire et non relu par les pairs, et il mesure l'absence d'impact P&L
mesurable, pas l'échec technique. Cette absence de mesure tient largement au
fait que les pilotes n'ont pas de baseline documentée avant déploiement, ce qui
en fait davantage un symptôme du problème 2 qu'une preuve du problème 1.

## 2. Personne ne sait mesurer le retour, faute de baseline

Deux mesures sérieuses disent l'inverse l'une de l'autre. L'écart est le
problème.

**Côté dirigeants, sans intérêt commercial.** Enquête auprès de près de 6 000
dirigeants d'entreprises américaines, britanniques, allemandes et australiennes,
menée par une équipe réunissant Bank of England, Fed d'Atlanta, Bundesbank,
Stanford et King's College. 69% des entreprises utilisent activement l'IA. Plus
des deux tiers des dirigeants s'en servent eux-mêmes, mais 1,5 heure par semaine
en moyenne. **Neuf sur dix déclarent aucun impact sur l'emploi ou la
productivité de leur propre entreprise sur les trois dernières années.** Les
mêmes prévoient sur les trois prochaines années +1,4% de productivité, +0,8% de
production et -0,7% d'emploi. (NBER WP 34836, février 2026 révisé mars 2026,
note A)

**Côté fournisseur.** 80% des responsables techniques interrogés déclarent que
leurs agents produisent déjà un retour économique mesurable, présenté comme du
ROI réel et non projeté. (Anthropic et Material, plus de 500 responsables
techniques américains, fin 2025, note B)

**Côté observateur neutre.** Le nombre de répondants estimant que l'IA a
amélioré tel indicateur organisationnel est souvent proche du nombre estimant
qu'elle n'a eu aucun effet. Les effets négatifs restent rares, au plus 7% sur
les indicateurs de coût. (Stanford HAI, AI Index 2026, note A)

Trois lectures possibles, à départager en entretien : l'échantillon Anthropic
est composé de responsables techniques déjà engagés et interrogés par leur
fournisseur ; les gains existent au niveau du cas d'usage sans remonter au P&L ;
ou les entreprises déclarent un ROI qu'elles n'ont jamais instrumenté. La
troisième est la plus probable et c'est un problème vendable en soi.

## 3. Les coûts dérapent et restent imprévisibles

| Mesure | Chiffre | Source | Note |
|---|---|---|---|
| Organisations ayant dépassé leur budget IA | 73% | FinOps Foundation, State of FinOps 2026 | B |
| Organisations prévoyant leur dépense à ±10% près | 20% | FinOps Foundation, State of FinOps 2026 | B |
| Part de l'inférence dans la dépense IA | 80 à 90% | FinOps Foundation, State of FinOps 2026 | B |
| Organisations pilotant activement leur dépense IA | 98%, contre 31% deux ans plus tôt | FinOps Foundation, State of FinOps 2026 | B |
| Dépense logicielle en agents IA | 86,4 Md$ en 2025, 206,5 Md$ prévus en 2026 | Gartner | B |

L'enquête FinOps repose sur près de 1 200 praticiens responsables de plus de
83 Md$ de dépense cloud annuelle. La bascule de 31% à 98% d'organisations
pilotant leur dépense IA en deux ans est le signal le plus net du dossier : le
sujet coût est devenu un poste de gestion à part entière.

Le mécanisme du dérapage, décrit de façon convergente mais sans source primaire
consultée : le volume de tokens sous-estimé quand l'usage passe à l'échelle, les
tokens de raisonnement absents des modèles de coût initiaux, et la
multiplication des appels dans les chaînes agentiques, où une tâche déclenchée
par un humain peut provoquer dix à vingt appels au modèle. (note C, à vérifier)

## 4. L'intégration au SI et l'état des données

Premier obstacle technique déclaré, et le seul point sur lequel une enquête
fournisseur et une enquête cabinet tombent exactement d'accord.

- 46% citent l'intégration aux systèmes existants comme obstacle principal,
  43% le coût d'implémentation, 42% l'accès et la qualité des données, 39% la
  conduite du changement. Les PME se distinguent sur le facteur humain, 51%
  citant la résistance des employés et le besoin de formation. (Anthropic et
  Material, note B)
- 46% citent l'intégration système comme premier frein, ce qui conduit McKinsey
  à conclure que l'intelligence des modèles n'est plus le goulot d'étranglement
  pour mettre un workflow agentique en production. (McKinsey, note B)

Formulation à retenir pour l'étape 1 : le problème n'est pas la disponibilité
de la donnée mais son accessibilité. La donnée existe, elle est enfermée dans
des PDF, des tableurs et des CRM anciens qu'un modèle ne lit pas directement.
(note C, à requalifier en entretien)

## 5. La fiabilité s'effondre sur les chaînes multi-étapes

Le seul problème de cette liste qui soit une propriété arithmétique et non un
résultat d'enquête. Si chaque étape réussit indépendamment avec une probabilité
p, une tâche de n étapes réussit avec p puissance n.

| Fiabilité par étape | 5 étapes | 10 étapes | 20 étapes |
|---|---|---|---|
| 99% | 95% | 90% | 82% |
| 95% | 77% | 60% | 36% |
| 90% | 59% | 35% | 12% |
| 85% | 44% | 20% | 4% |

Un agent fiable à 95% par étape échoue donc une fois sur trois sur dix étapes.
C'est ce qui sépare une démonstration réussie d'un système qu'on laisse tourner
sur un processus réel, et c'est indépendant du modèle utilisé.

Conséquence observée dans les organisations qui réussissent : la validation
humaine cesse d'être une option. Les organisations les plus performantes sont
bien plus susceptibles d'avoir défini des processus de validation humaine dans
la boucle, 65% contre 23%. (McKinsey, note B)

## 6. L'évaluation et l'observabilité ne suivent pas

Les entreprises mettent en production des agents qu'elles ne savent pas évaluer.
Les benchmarks disponibles optimisent le taux de complétion de tâche, alors
qu'une mise en production demande d'arbitrer aussi le coût, la fiabilité, la
sécurité et les contraintes d'exploitation. Les outils d'instrumentation
capturent traces, métriques et évaluations au niveau du modèle et de l'agent,
mais pas le contexte métier, de lignage et de gouvernance qui permettrait
d'expliquer pourquoi l'agent s'est comporté ainsi. (note C, littérature
convergente, aucune enquête primaire consultée)

Une prédiction chiffrée mérite d'être suivie, parce qu'elle décrit exactement la
frontière entre observer et empêcher : **d'ici 2030, la moitié des échecs de
déploiement d'agents seraient dus à l'insuffisance de l'application des
capacités à l'exécution par la plateforme de gouvernance, et au manque
d'interopérabilité multi-système.** (Gartner, mai 2026, note B)

Gartner chiffre aussi le marché naissant des agents de surveillance : 10 à 15%
du marché agentique d'ici 2030, avec 50% des répondants en phase de recherche ou
d'expérimentation et 17% prévoyant un déploiement d'ici fin 2026. (note B)
Gartner avertit en parallèle qu'appliquer une gouvernance uniforme à tous les
agents, quel que soit leur niveau d'autonomie et leur périmètre, conduit à
l'échec.

## 7. L'injection de prompt reste non résolue

Défaut d'architecture, pas de bug corrigeable : un modèle de langage ne dispose
d'aucun moyen natif de séparer les instructions de confiance des données non
fiables, les deux arrivant dans le même flux de tokens.

| Mesure | Chiffre | Source | Note |
|---|---|---|---|
| Déploiements IA en production audités présentant une faiblesse d'injection | 73% | Cisco, State of AI Security 2026 | B |
| Rang de l'injection de prompt dans le classement des risques LLM | 1er | OWASP Top 10 for LLM Applications | A |
| Incidents de sécurité IA investigués liés à une injection indirecte avec exposition de secrets ou de données de paiement | 18% | Unit 42 | C |

Le rapport Cisco couvre aussi la fragilité de la chaîne d'approvisionnement IA
(jeux de données, modèles open source, outils) et la surface de risque
introduite par MCP. Les incidents nominatifs qui circulent en 2026, dont un cas
de virements frauduleux d'environ 250 000 dollars déclenchés par injection, sont
en note C tant qu'ils n'ont pas été retrouvés dans un rapport d'incident
primaire.

## 8. L'absence de contrôle d'accès, et le shadow AI

Le dossier chiffré le plus solide sur le coût réel de l'absence de gouvernance,
et le seul où le coût est libellé en euros par incident.

| Mesure | Chiffre | Source | Note |
|---|---|---|---|
| Organisations sans aucune politique de gouvernance IA | 63% sur 600 étudiées | IBM, Cost of a Data Breach 2026 | B |
| Organisations ayant subi un incident lié à l'IA et déclarant ne pas avoir de contrôles d'accès IA | 97% | IBM, Cost of a Data Breach 2026 | B |
| Organisations touchées par un incident impliquant des outils IA non approuvés | 43%, contre 20% l'année précédente | IBM, Cost of a Data Breach 2026 | B |
| Coût moyen d'une brèche impliquant du shadow AI | 5,39 M$ | IBM, Cost of a Data Breach 2026 | B |
| Surcoût attribuable au shadow AI | jusqu'à 670 k$ | IBM, Cost of a Data Breach 2026 | B |
| Part des brèches malveillantes assistées par IA | 1 sur 4, en hausse de 56% sur un an | IBM, juillet 2026 | B |
| Coût moyen d'une brèche assistée par IA | 6 M$, contre 4,99 M$ de moyenne mondiale | IBM, juillet 2026 | B |

Le 97% est le chiffre le plus exploitable de tout le dossier : parmi les
organisations qui ont subi un incident de sécurité lié à l'IA, la quasi-totalité
n'avait aucun contrôle d'accès sur les outils concernés. C'est une mesure
d'absence de contrôle, sur une population déjà victime, pas une projection.

## 9. La prolifération des identités non humaines

| Mesure | Chiffre | Source | Note |
|---|---|---|---|
| Identités machine par identité humaine | 109 pour 1, contre 82 pour 1 un an plus tôt | Palo Alto Networks, Identity Security Landscape 2026 | B |
| Part d'agents IA dans ces identités machine | 79 sur 109 | Palo Alto Networks, 2026 | B |
| Identités machine portant des privilèges excessifs | 97% | Palo Alto Networks, 2026 | B |
| Organisations ayant subi au moins deux brèches centrées sur l'identité en douze mois | 83% | Palo Alto Networks, 2026 | B |
| Ratio identités non humaines sur humaines | 80 pour 1 | KPMG, 2026 | B |

Deux mesures indépendantes donnent 109:1 et 80:1. L'ordre de grandeur tient, la
précision non. Ce qui importe : la gouvernance d'identité traditionnelle repose
sur un enrôlement manuel et des revues périodiques, un rythme incompatible avec
une population qui double en un an.

Point à surveiller pour SauronID : Auth0, Google Cloud et Microsoft Entra Agent
ID ont tous publié en 2026 une offre d'identité d'agent. La couche d'identité
technique de base est en train d'être absorbée par les fournisseurs d'IAM.

## 10. La dépendance à un fournisseur de modèle

| Mesure | Chiffre | Source | Note |
|---|---|---|---|
| Dirigeants américains préoccupés par leur dépendance à un fournisseur IA | 81% | Zapier, enquête 2026 | C |
| Ceux qui pourraient en changer sans perturbation matérielle | 6% | Zapier, enquête 2026 | C |
| Entreprises déclarant que le verrouillage a déjà freiné l'adoption d'un meilleur outil | 45% | non retrouvé à la source | C |
| DSI faisant tourner cinq modèles ou plus en production | 37%, contre 29% l'année précédente | enquête 100 DSI, 2026 | C |

Le dossier le plus faible de la liste en qualité de sources : tout est en note C,
aucune enquête primaire n'a pu être consultée. L'écart entre 81% de préoccupation
et 6% de capacité effective à changer est l'affirmation la plus intéressante et
la moins vérifiée. À traiter comme une hypothèse d'entretien, pas comme un fait.

---

## Le cadre réglementaire, et pourquoi il n'aide pas en 2026

| Échéance | Ce qui s'applique | Source |
|---|---|---|
| 2 août 2025 | Obligations des fournisseurs de modèles à usage général (GPAI) | Commission européenne, note A |
| 2 août 2026 | Transparence de l'article 50, étiquetage des contenus IA, pratiques interdites de l'article 5 | Commission européenne, note A |
| 2 décembre 2027 | Systèmes à haut risque autonomes, annexe III, **repoussé** du 2 août 2026 | Commission européenne, note A |
| 2 août 2028 | IA intégrée à des produits déjà couverts par la législation produit, annexe I, **repoussé** | Commission européenne, note A |

L'AI Omnibus a été proposé le 19 novembre 2025, accord politique le 7 mai 2026,
entré en vigueur le 27 juillet 2026. Motif officiel du report : les normes
techniques n'étaient pas disponibles à temps. Sanctions maximales inchangées,
jusqu'à 35 M€ ou 7% du chiffre d'affaires mondial.

Conclusion opérationnelle : entre août 2026 et décembre 2027, aucune contrainte
réglementaire nouvelle ne force une entreprise européenne à acheter une couche
de gouvernance pour ses agents. Vendre sur l'échéance réglementaire en 2026,
c'est vendre sur une date qui vient de reculer de seize mois.

---

## Ce qui reste inconnu

Les questions auxquelles cette recherche documentaire ne répond pas, et qui
demandent des entretiens.

1. Combien de temps et d'argent coûte réellement la mise en production d'un
   premier agent utile, chez une entreprise de 50 à 500 personnes. Aucune source
   consultée ne donne un chiffre crédible et non commercial.
2. Qui signe. Direction générale, direction métier, DSI ou sécurité, et sur
   quelle ligne budgétaire.
3. Si l'écart entre 80% de ROI déclaré et neuf dirigeants sur dix ne constatant
   aucun impact vient de la mesure ou de la réalité.
4. Ce que les entreprises font aujourd'hui quand un agent se trompe, et ce que
   ça leur coûte. Aucune donnée trouvée sur le coût d'un incident agentique hors
   contexte de brèche de sécurité.
5. Si le frein sécurité apparaît avant ou après la première mise en production.
   Toute la stratégie commerciale dépend de cette réponse et aucune enquête
   publique ne la pose dans ces termes.
