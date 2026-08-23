# Copilote et agent : ce que la valeur ajoutée a de mesuré

**Étape 0, recherche documentaire. 24 août 2026.**
**Question posée :** la différence de valeur entre un outil qui assiste un
humain et un système qui exécute une tâche de bout en bout est-elle mesurée, et
par qui.

**Réponse courte : non, pas symétriquement.** Les gains des copilotes sont
mesurés par des études contrôlées, publiées, parfois négatives. Les gains des
agents autonomes ne sont documentés que par des enquêtes déclaratives, souvent
commanditées par un fournisseur. Comparer les deux avec les données publiques
de 2026, c'est comparer une mesure et une déclaration.

---

## Ce qui est mesuré côté copilote

Sept études recensées par le AI Index 2026 de Stanford HAI, chapitre Économie.
Elles portent toutes sur un assistant utilisé par un humain, jamais sur un
système autonome. (note A pour la recension, la qualité de chaque étude primaire
variant)

| Étude | Métier | Outil | Effet mesuré |
|---|---|---|---|
| Reimers et Waldfogel, 2026 | auteurs | LLM pour le contenu | +200% de volume produit, sorties triplées |
| Choi et Xie, 2025 | comptables | comptabilité assistée | +55% de débit, support client hebdomadaire |
| Ju et Aral, 2025 | marketing | création publicitaire multimodale | +50% de production par personne |
| Cui et al., 2025 | développeurs | GitHub Copilot | +26% de pull requests complétées |
| Brynjolfsson et al., 2025 | support client | assistant conversationnel | +14 à 15% de tickets résolus par heure |
| Shen et Tamkin, 2025 | ingénieurs logiciels | apprentissage de nouvelles bibliothèques | 0%, variation non significative |
| Becker et al., 2025, METR | développeurs open source expérimentés | outils IA | **-19% de vitesse** |

Trois enseignements qui tiennent quel que soit le camp qu'on défend.

**Le gain va aux moins expérimentés.** Les agents de support les moins qualifiés
gagnent 30 à 35%, contre 14 à 15% en moyenne. Même constat chez les développeurs
juniors. L'IA assistante comble un écart de compétence, elle ne multiplie pas
l'expert.

**Le gain devient nul ou négatif quand la tâche demande du jugement.** Les
développeurs open source expérimentés de l'étude METR sont 19% plus lents avec
l'IA, et l'écart entre l'aide qu'ils croient recevoir et leur performance réelle
est le résultat le plus dérangeant de la littérature. À noter honnêtement :
METR n'a pas réussi à répliquer ce résultat dans une étude ultérieure, en partie
parce que les développeurs refusaient de travailler sans IA et parce que les
modèles de fin 2025 les accéléraient probablement.

**Les gains se concentrent sur le travail découpable.** Formulation du AI Index :
les gains sont les plus forts quand le travail se divise en tâches répétables et
bien définies, avec un contrôle qualité clair.

Au niveau macro, une étude de 12 000 entreprises européennes trouve +4% de
productivité du travail liée à l'adoption de l'IA, renforcée par la formation
(Aldasoro et al., 2026). La productivité américaine a atteint 2,7% de croissance
en 2025 contre 1,4% de moyenne sur la décennie précédente, ce que Brynjolfsson
lit comme le début possible d'une courbe en J. (note A)

## Ce qui est déclaré côté agent

Aucune étude contrôlée équivalente. La source la plus complète est une enquête
menée par Anthropic avec le cabinet Material auprès de plus de 500 responsables
techniques américains, fin 2025. (note B, le commanditaire vend les modèles qui
font tourner les agents)

| Mesure | Chiffre |
|---|---|
| Organisations déployant des agents sur des workflows multi-étapes | 57% |
| Dont processus transverses à plusieurs équipes | 16% |
| Organisations utilisant l'IA pour assister le code | plus de 9 sur 10 |
| Déployant des agents de code sur du code de production | 86%, dont 91% en grande entreprise et 83% en PME |
| Faisant confiance à l'agent pour mener le développement, avec supervision humaine | 42% |
| Déclarant un retour économique mesurable déjà réalisé | 80% |
| Prévoyant des cas d'usage plus complexes en 2026 | 81% |
| Gains de temps déclarés sur le cycle de développement | 59% génération de code, 59% recherche et documentation, 59% revue et tests, 58% planification |
| Cas d'usage les plus impactants hors code | 60% analyse de données et reporting, 48% automatisation de processus internes |
| Attendant une exécution plus rapide des tâches sur 12 mois | 44% |

Deux réserves de méthode. Le verbe utilisé est *believe* : 8 dirigeants sur 10
**estiment** que les agents ont livré un ROI mesurable. Et la population
interrogée est composée de responsables techniques déjà engagés dans
l'agentique, interrogés par leur fournisseur de modèles.

Mis en regard des 6 000 dirigeants du papier NBER dont neuf sur dix ne
constatent aucun impact sur la productivité de leur entreprise, l'écart ne se
résout pas dans les données publiques. Voir
[`problem-landscape.md`](problem-landscape.md), problème 2.

## La différence structurelle, indépendamment des chiffres

Ce que les deux modes ont de réellement différent, et qui explique pourquoi ils
ne se mesurent pas pareil.

| | Copilote | Agent |
|---|---|---|
| Qui décide | l'humain, à chaque étape | le système, entre deux points de contrôle |
| Où va le gain | temps par tâche, pour la personne qui l'utilise | tâche entière retirée du flux humain |
| Comment le mesurer | avant/après sur un individu, comparable | avant/après sur un processus, demande une baseline |
| Ce qui casse quand ça rate | un humain corrige, coût nul | une action a été commise dans un système réel |
| Plafond | l'attention disponible de l'utilisateur | la fiabilité de la chaîne, p puissance n |
| Adoption réelle | 20 à 30% de sièges actifs par semaine selon des enquêtes indépendantes sur Microsoft 365 Copilot (note C) | 57% déclarent du multi-étapes, 16% du transverse (note B) |

Le point que la littérature établit sans ambiguïté : le copilote a un plafond
qui est l'attention de son utilisateur. 1,5 heure d'usage hebdomadaire moyen
chez les dirigeants qui déclarent se servir de l'IA (NBER, note A), 20 à 30% de
sièges Copilot actifs par semaine dans les enquêtes indépendantes. Un gain de
26% sur une tâche que personne ne fait plus que trois heures par semaine ne
remonte pas au P&L, ce qui réconcilie les études micro positives et l'absence
d'effet macro déclarée par les dirigeants.

L'agent n'a pas ce plafond, il a l'autre : la fiabilité composée. À 95% par
étape, une tâche de dix étapes réussit six fois sur dix.

## Ce qu'il faut mesurer nous-mêmes

Les cinq chiffres qui manquent à la littérature publique et qu'aucune source
consultée ne fournit. Ils ne s'obtiennent que sur un déploiement réel.

1. Le coût complet, en jours-homme, d'un premier agent mis en production.
2. Le taux de réussite de bout en bout sur un processus réel, mesuré sur au
   moins un mois, pas sur une démonstration.
3. Le nombre de points de validation humaine nécessaires pour tenir ce taux, et
   ce que chacun coûte en délai.
4. Le coût de traitement du processus avant l'agent, mesuré avant de le
   déployer. Sans cette mesure, aucun ROI n'est démontrable, et c'est
   exactement pourquoi 95% des pilotes n'affichent aucun impact P&L.
5. Ce qui se passe et ce que ça coûte quand l'agent se trompe.

Le point 4 est le plus important et le moins fait dans l'industrie.
