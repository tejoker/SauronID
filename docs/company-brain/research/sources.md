# Journal des sources

**Établi le 24 août 2026.** Toute source citée dans ce dossier figure ici avec
sa note, son commanditaire et ce qui a réellement été consulté. Une source lue
en entier ne vaut pas la même chose qu'un chiffre repris d'un article.

Notes A, B, C définies dans [`README.md`](README.md).

## A, sources primaires sans intérêt commercial

| Source | Ce qui a été consulté | Méthode | Usage |
|---|---|---|---|
| NBER Working Paper 34836, *Firm Data on AI*, Yotzov, Barrero, Bloom, Bunn, Davis, Foster, Jalca, Meyer, Mizen, Navarrete, Smietanka, Thwaites, Wang. Février 2026, révisé mars 2026 | PDF téléchargé, résumé lu intégralement | près de 6 000 dirigeants, US, UK, Allemagne, Australie. Auteurs Bank of England, Fed d'Atlanta, Bundesbank, Stanford, King's College, Macquarie | problème 2 |
| Stanford HAI, *AI Index Report 2026*, chapitre 4 Économie | PDF de 6,2 Mo téléchargé, texte extrait, sections adoption, agents, productivité lues | enquête d'adoption corporate, plus recension de 7 études micro et de travaux macro | problèmes 1, 2, copilote/agent |
| Commission européenne, AI Omnibus et calendrier de l'AI Act | pages officielles digital-strategy.ec.europa.eu | texte réglementaire | section réglementaire |
| OWASP, Top 10 for LLM Applications | classement, rang de l'injection de prompt | consensus de projet ouvert | problème 7 |
| Eurostat, *Use of artificial intelligence in enterprises*, données 2025 | page Statistics Explained lue à la source | enquête officielle, entreprises de 10 salariés ou plus dans l'UE | cas d'usage, segment cible |
| DGFiP et economie.gouv.fr, réforme de la facturation électronique | pages officielles et guide pratique, calendrier et obligations | texte réglementaire et documentation administrative | segment cible, raison d'acheter maintenant |
| Stanford HAI, *AI Index 2026*, chapitre 4, sections 4.3.4 à 4.3.8 | texte extrait du PDF, passages adoption par fonction et agents lus | enquête McKinsey reprise et commentée par le AI Index | cas d'usage |

Études recensées par le AI Index et citées nommément : Reimers et Waldfogel
2026, Shen et Tamkin 2025, Becker et al. 2025 (METR), Brynjolfsson et al. 2025,
Cui et al. 2025, Ju et Aral 2025, Choi et Xie 2025, Aldasoro et al. 2026. Aucune
n'a été lue à la source, seulement la recension. Elles héritent donc du A du AI
Index, pas d'un A propre.

## B, sources primaires avec intérêt commercial

| Source | Ce qui a été consulté | Méthode | Biais à connaître |
|---|---|---|---|
| Anthropic et Material, *The 2026 State of AI Agents Report* | PDF de 2,3 Mo téléchargé, texte extrait, parties I à III lues | plus de 500 responsables techniques américains, fin 2025 | le commanditaire vend les modèles qui font tourner les agents mesurés. Le verbe des questions ROI est *believe* |
| IBM, *Cost of a Data Breach Report 2026* | communiqué du 29 juillet 2026 et pages d'analyse | 600 organisations étudiées | IBM vend de la sécurité et de la gouvernance de données |
| Gartner, communiqués de presse 2025 et 2026 | titres et extraits des communiqués publics. Le site refuse la lecture automatisée, contenu non vérifié dans le corps du texte | sondage 3 400+ organisations pour la prédiction d'annulation | modèle économique fondé sur la prédiction |
| Cisco, *State of AI Security 2026* | page produit et billet de blog | audits de déploiements en production | Cisco vend AI Defense |
| Palo Alto Networks, *Identity Security Landscape 2026* | page de rapport | non consultée en détail | vend de la sécurité d'identité |
| FinOps Foundation, *State of FinOps 2026* | chiffres repris, rapport non consulté en direct | près de 1 200 praticiens, plus de 83 Md$ de dépense cloud annuelle | fondation d'éditeurs de FinOps |
| McKinsey, *State of AI trust in 2026* | page consultée, lecture bloquée par timeout, chiffres repris de synthèses | non vérifiée | vend du conseil en transformation IA |
| KPMG, rapport cybersécurité 2026 | chiffre du ratio d'identités non humaines uniquement | non consultée | vend du conseil |

## C, chiffres de seconde main, non vérifiés à la source

À ne jamais utiliser dans un document client ni dans un deck. Listés pour
mémoire, et pour être vérifiés ou abandonnés.

| Chiffre | Origine annoncée | Statut |
|---|---|---|
| 95% des pilotes GenAI sans retour mesurable | MIT NANDA, *The GenAI Divide: State of AI in Business 2025* | rapport préliminaire, non relu par les pairs. 52 entretiens, 153 réponses, 300 déploiements. Mesure l'absence d'impact P&L, pas l'échec technique |
| 88% des POC n'atteignent pas le déploiement large, 4 sur 33 | IDC avec Lenovo | repris via CIO.com, rapport non consulté |
| 73% des déploiements IA audités présentant une faiblesse d'injection | Cisco 2026 | cohérent avec le rapport mais non retrouvé verbatim |
| 18% des incidents IA investigués liés à une injection indirecte | Unit 42 | non retrouvé à la source |
| Virements frauduleux d'environ 250 k$ par injection, secteur financier | presse spécialisée | aucun rapport d'incident primaire trouvé |
| 81% de dirigeants préoccupés par la dépendance fournisseur, 6% capables de changer | Zapier, 2026 | enquête non consultée |
| 45% déclarant que le verrouillage a freiné l'adoption d'un meilleur outil | non identifiée | à abandonner si non retrouvée |
| 37% de DSI faisant tourner cinq modèles ou plus | enquête 100 DSI, 2026 | échantillon trop petit et non identifié |
| 20 à 30% de sièges Microsoft 365 Copilot actifs par semaine | enquêtes indépendantes | plusieurs reprises concordantes, aucune source primaire |
| 116% de ROI Copilot, 14 à 26 minutes gagnées par jour | Forrester Total Economic Impact | étude commanditée par Microsoft, non consultée |
| Mécanique du dérapage de coûts : 10 à 20 appels modèle par tâche, 5 à 30 fois plus de tokens qu'un chatbot | attribué à Gartner, mars 2026 | non vérifié |
| Données trouvées en PDF, tableurs et CRM anciens illisibles par les modèles | littérature de conseil | affirmation plausible, aucune mesure |
| 70 à 90% de réduction du temps de traitement d'une facture | éditeurs de solutions d'automatisation | argument de vente, aucun rapport primaire |
| 70% des demandes de support de niveau 1 traitées de bout en bout | éditeurs de CRM | argument de vente |
| Retour sur investissement en 3 à 6 mois sur les cas à fort volume | éditeurs et blogs sectoriels | aucune méthode publiée |
| 131 agences d'implémentation IA recensées, segment services à +46% par an | annuaire privé et cabinets d'études | ne mesure pas une population, à ne pas citer comme taille de marché |
| 14 à 20 € de coût de traitement d'une facture fournisseur papier, dont 1,40 € de saisie et 5,40 € de validation, 6,60 € une fois dématérialisée | APECA, Quadient, DIMO Demat, et une étude Arthur D. Little commanditée par Deskom | tous éditeurs de dématérialisation ou association d'éditeurs, aucune étude consultée à la source. La décomposition ne se recoupe pas : si 1,40 € vaut 10%, la base est 14 €, et 5,40 € en fait 39% et non « près d'un tiers ». Utilisable pour cadrer un entretien, jamais dans un document client |
| 7 031 ETI, 164 000 PME, 312 grandes entreprises en France (données 2023) | INSEE, Focus n° 372 | chiffres repris d'une synthèse, publication non lue à la source. À revérifier avant tout usage externe |

## Littérature de méthode, à relire à la source

Ces références ne portent pas de chiffre. Elles portent un cadre de
raisonnement, et c'est pour ça qu'elles ne prennent pas de note A, B ou C : la
notation qualifie une mesure, pas une méthode. Elles ont été restituées par une
synthèse NotebookLM le 31 août 2026 et **aucune n'a été lue à la source**. Un
cadre peut servir à structurer un discours interne dans cet état. Il ne part
pas dans un document client avant relecture du texte original.

| Référence | Ce qu'on en tire | Où c'est utilisé | État |
|---|---|---|---|
| Agrawal, Gans, Goldfarb, *Prediction Machines*, Harvard Business School Press, 2018, et le AI Canvas | la baisse du coût de la prédiction augmente la valeur du jugement, qui devient le facteur limitant | 02, section prédiction et jugement | à relire, cadre central, priorité haute |
| Chip Huyen, *Designing Machine Learning Systems*, O'Reilly, 2022 | le déploiement fantôme comme méthode de mise en production sans impact opérationnel, et l'échec par optimisation de métriques ML déconnectées du métier | 02, mode observation et unité de valeur | à relire |
| Enholm, Papagiannidis, Mikalef, Krogstie, *Artificial Intelligence and Business Value: a Literature Review*, Information Systems Frontiers, 2021 | aucune étude n'établit l'impact financier long terme de l'IA, faute de point de départ mesuré | 02, ce qui rend le gain démontrable | à relire, revue par les pairs, devrait passer en A une fois lue |
| Raisch et Krakowski, 2021, cas Symrise, cité par Enholm et al. | deux ans de validation humaine de chaque suggestion avant bascule en automatisation | 02, mode observation | à relire, et vérifier le cas à la source et non via la revue |
| Lee et Shin, *Machine Learning for Enterprises*, Business Horizons, 2020 | la pénurie de compétences comme frein d'adoption propre aux entreprises de taille intermédiaire | 11, modèle éditeur plus déploiement | à relire |
| Anderson et Coveyduc, *Artificial Intelligence for Business*, Wiley, 2020 | permissions et sécurité écartées du prototype, redevenant le point de friction au passage en production | 02, la thèse | à relire |
| Andrew Ng, recommandations publiques sur les projets pilotes | commencer par des tâches discrètes plutôt que par des rôles entiers | 10 et 30, ciblage outbound | à relire, et identifier la publication exacte plutôt que la citation de seconde main |

Une remarque qui compte plus que la liste. Ces sept références **valident** le
raisonnement écrit dans 02, 10 et 11, elles ne l'ont pas produit. Le
positionnement a été écrit avant de les rencontrer. C'est une bonne nouvelle
pour la solidité du raisonnement, et une raison de plus de ne pas les citer
comme si elles étaient à l'origine de nos choix.

## Sources cherchées et non trouvées

Ce que la recherche n'a pas pu établir, malgré des requêtes ciblées.

- Aucune étude contrôlée mesurant le gain de productivité d'un agent autonome,
  comparable aux sept études micro sur les assistants. Toute la valeur agentique
  publiée en 2026 est déclarative.
- Aucun chiffre non commercial sur le coût et la durée réels d'une mise en
  production d'agent chez une PME ou une ETI.
- Aucune donnée sur le coût d'un incident causé par un agent en dehors du cadre
  d'une brèche de sécurité.
- Aucune enquête posant la question de la sécurité avant la première mise en
  production plutôt qu'au moment du passage à l'échelle.

## Méthode de collecte

Recherche web du 24 août 2026, puis téléchargement et extraction de texte des
PDF primaires quand ils étaient accessibles. Trois sites ont refusé la lecture
automatisée : Gartner, IBM et OWASP renvoient un 403, McKinsey un timeout. Les
chiffres issus de ces quatre sources sont donc en note B ou C selon qu'un
communiqué officiel a pu être lu ou non.
