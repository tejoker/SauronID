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
