# SauronID Agent Action Envelope

**Version 2** (call signature, owner mandate) — *vérifié dans le dépôt*.
**Version 3 fields** (mandate binding, run scope, dependency set) — *direction produit*, specified here, not implemented.

Ce document est une **spécification**, pas une page produit. Il définit ce qu'une
signature d'action d'agent *dit*, en octets, de manière qu'un tiers puisse écrire
un vérificateur sans lire notre code.

## Licence de cette spécification

Une spécification sous BUSL-1.1 est morte à la naissance : personne n'implémente
un format qu'il ne peut pas livrer. L'intention est donc :

| Artefact | Licence visée |
|---|---|
| Ce document, `schemas/agent-action-envelope-vectors.json` | CC-BY-4.0 ou Apache-2.0 avec octroi de brevet explicite |
| Un vérificateur de référence (à extraire) | Apache-2.0 |
| La passerelle qui applique la spécification | BUSL-1.1, inchangé |

**Décision en attente.** [`LICENSE`](../../LICENSE) place aujourd'hui `docs/` en
« supporting material », traité comme Apache-2.0 ou BUSL-1.1 selon ce qu'il
accompagne — ce qui est ambigu pour un texte que l'on veut voir implémenté par
des tiers. L'amendement doit être un commit séparé et signé par le propriétaire.
`visa/trusted-agent-protocol` est le contre-exemple utile : la spécification est
lisible, le code de référence est sous conditions Visa Developer Center, et notre
propre audit de licences l'a classé inutilisable.

## Ce que cette spécification revendique, et ce qu'elle ne revendique pas

Le transport est un problème résolu. **HTTP Message Signatures (RFC 9421)** est
la forme sur laquelle Visa (Trusted Agent Protocol) et Cloudflare (web-bot-auth)
ont convergé en 2026. Se battre à cette couche, c'est demander à un implémenteur
de choisir entre nous et une base qu'il livre déjà.

La couche non revendiquée est **la sémantique** : ce que la signature affirme.
Aucun registre, aucun protocole d'agent ne normalise aujourd'hui le lien entre
une action et (a) le mandat qui l'autorise, (b) le plan déclaré avant exécution,
(c) l'ensemble de dépendances présent au moment de l'acte. C'est l'objet de ce
document.

## 1. Encodage canonique

Aucune signature ne porte sur du JSON sérialisé : l'ordre des clés,
l'échappement, les espaces et le format des nombres diffèrent selon les
langages. Chaque valeur est encodée en champ UTF-8 préfixé par sa longueur, dans
un ordre fixe, **le nom du champ faisant partie des octets signés** — ajouter,
retirer ou réordonner un champ est donc un changement de protocole et non une
analyse ambiguë.

```
canonical(domain, fields) :=
    u32be(len(domain))  || domain
    for (name, value) in fields:        # ordre fixe, imposé par le protocole
        u32be(len(name))  || name
        u32be(len(value)) || value
```

`u32be` est un entier non signé 32 bits gros-boutiste. Toutes les chaînes sont
en UTF-8. Aucun séparateur, aucun remplissage, aucune longueur totale en
préfixe. Référence : [`crypto_protocol::canonical_fields`](../../core/src/crypto_protocol.rs).

Deux propriétés en découlent, et ce sont les seules qui comptent :

1. **Non-ambiguïté.** `[("a","x|y"),("b","z")]` et `[("a","x"),("b","y|z")]`
   produisent des octets différents. Un encodage par concaténation avec
   séparateur ne le garantit pas.
2. **Séparation de domaine.** Le domaine est le premier champ signé, donc une
   signature d'un protocole ne peut pas être rejouée comme signature d'un autre.

### Domaines enregistrés

| Domaine | Rôle | Version |
|---|---|---|
| `sauron.call.v2` | signature par appel | 2 |
| `sauron.owner-mandate.v1` | mandat signé par le propriétaire humain | 1 |
| `sauron.attestation-challenge.v1` | défi d'attestation | 1 |
| `sauron.user-auth-challenge.v1` | défi d'authentification utilisateur | 1 |

Un nouveau domaine se termine toujours par `.vN`. Changer les octets d'un
domaine existant sans incrémenter `N` est interdit.

## 2. Signature par appel — champs v2

Algorithme : **Ed25519**. Signature encodée en base64url sans remplissage.

| # | Champ | Contenu |
|---|---|---|
| 1 | `version` | `"2"` |
| 2 | `agent_id` | identifiant de l'agent dont la clé PoP signe |
| 3 | `tenant_id` | locataire ; lie la signature à une frontière d'isolation |
| 4 | `audience` | audience du service configurée — empêche le rejeu vers un autre déploiement |
| 5 | `method` | méthode HTTP en majuscules |
| 6 | `target_uri` | chemin **et** chaîne de requête |
| 7 | `content_type` | type de contenu de la requête |
| 8 | `body_sha256` | SHA-256 du corps, en hexadécimal minuscule |
| 9 | `config_digest` | condensat de la configuration déclarée de l'agent (§4) |
| 10 | `timestamp_ms` | millisecondes Unix, décimal ASCII |
| 11 | `nonce` | ≤ 128 caractères, **usage unique** |

Référence : [`crypto_protocol::call_signature_payload`](../../core/src/crypto_protocol.rs),
vérification dans [`agent/call_sig.rs`](../../core/src/agent/call_sig.rs).

### Liaison de transport

**Native.** Sept en-têtes : `x-sauron-agent-id`, `x-sauron-tenant-id`,
`x-sauron-call-ts`, `x-sauron-call-nonce`, `x-sauron-call-sig`,
`x-sauron-call-audience`, `x-sauron-protocol-version`,
`x-sauron-agent-config-digest`.

**RFC 9421** — *direction produit*. La même charge signée est publiable dans
`Signature` / `Signature-Input` avec `tag="sauron-agent-action"`,
`keyid` = `agent_id`, `created` = `timestamp_ms / 1000`, `nonce` = `nonce`,
`alg="ed25519"`. Les composants `@method`, `@authority` et `@path` de 9421
recouvrent nos champs 5, 4 et 6 ; les champs 3, 8, 9 et ceux de la v3 n'ont pas
d'équivalent 9421 et voyagent comme composants dérivés d'en-têtes. Un
vérificateur 9421 générique accepte alors l'enveloppe ; la sémantique reste
celle de ce document.

Deux différences avec le jeu minimal de Visa, assumées :

- Nous lions **davantage** : `tenant_id`, `body_sha256` et `config_digest` n'ont
  pas de contrepartie.
- Il nous manque `expires` et `alg`. Le signataire ne borne pas la durée de vie
  de sa propre signature : une fenêtre serveur `±SAURON_CALL_SIG_SKEW_MS`
  (60 s par défaut) le fait à sa place, et l'algorithme est fixé plutôt que
  déclaré. **`expires` doit entrer en v3** ; c'est le signataire qui devrait
  décider combien de temps sa propre affirmation vaut.

## 3. Algorithme de vérification

Dans cet ordre. Chaque étape échoue en refusant, jamais en avertissant.

1. Version de protocole présente et reconnue, sinon rejet.
2. `agent_id` résolu : agent connu, non révoqué, **non expiré**, du locataire
   annoncé. Un bail expiré ne signe plus.
3. `timestamp_ms` dans la fenêtre de dérive acceptée.
4. `config_digest` de l'en-tête égal au condensat stocké côté serveur (§4).
5. Charge canonique recalculée à partir de la requête reçue — jamais à partir de
   valeurs fournies par le client — puis signature Ed25519 vérifiée avec la clé
   PoP enregistrée.
6. `nonce` consommé **atomiquement** ; un nonce déjà vu est un rejeu et la
   requête est refusée.
7. *(v3)* `mandate_digest` cité résolu, non révoqué, non expiré, et couvrant
   l'action demandée.
8. *(v3)* action appartenant au plan déclaré du `run_id`, compteurs sous
   plafond.

L'étape 5 est la seule qui empêche la classe d'attaques « A-JWT capturé rejoué
vers un autre point d'entrée ou avec un corps modifié ». L'étape 6 est la seule
qui empêche le rejeu exact.

## 4. Condensat de configuration

L'agent ne fournit pas un condensat pré-calculé. Il soumet un objet
`checksum_inputs` structuré dont les champs requis dépendent de son type ; le
serveur canonicalise, calcule SHA-256, et stocke les entrées **et** le
condensat. Chaque appel protégé doit porter le condensat ; une dérive rejette
l'appel.

| `agent_type` | Champs requis |
|---|---|
| `llm` | `model_id`, `system_prompt`, `tools` |
| `mcp_server` | `manifest_json`, `tool_signatures` |
| `browser` | `script_sha`, `lockfile_sha` |
| `framework` | `code_sha`, `lockfile_sha` |
| `openai_assistant` | `assistant_id`, `instructions`, `tools`, `model` |
| `rule_bot` | `image_sha` |
| `custom` | définis par l'opérateur |

Référence : [`agent_checksum.rs`](../../core/src/agent_checksum.rs).

**Limite, écrite dans le code lui-même :** l'hypothèse d'honnêteté est que le
runtime calcule correctement son propre condensat. Un hôte compromis peut
mentir. Une signature sur « j'ai utilisé X » prouve que l'agent l'a *affirmé*,
de manière non répudiable — ce n'est pas une preuve d'usage. Toute page produit
qui présente ceci comme une preuve est fausse.

## 5. Champs v3 — *direction produit*

Ce sont les champs qui rendent la spécification utile à quelqu'un d'autre que
nous, et aucun n'est implémenté.

| Champ | Contenu | Ce qu'il rend possible |
|---|---|---|
| `mandate_digest` | SHA-256 de la charge `sauron.owner-mandate.v1` | Chaque action **cite l'autorité qui l'a permise**. Aujourd'hui la signature d'appel ne référence pas le mandat : les deux existent sans lien signé |
| `run_id` | identifiant d'exécution | Le champ existe déjà comme revendication `workflow_id` de l'A-JWT ; le promouvoir en champ signé donne une portée qui **survit à un point de reprise** |
| `plan_digest` | SHA-256 du plan déclaré et canonicalisé | Le plan est fixé *avant* que l'agent ne lise un contenu hostile. Une instruction injectée produit une action hors plan, donc refusée |
| `sbom_digest` | SHA-256 d'un document CycloneDX | Réponse exacte à « lesquelles de mes actions signées ont tourné avec cette bibliothèque » après divulgation d'une CVE |
| `expires` | millisecondes Unix | Le signataire borne sa propre affirmation, comme l'exige RFC 9421 |

Le plan **ne doit pas être du texte libre**. Un plan en langue naturelle impose
un juge LLM, donc une décision d'application non déterministe, non
reproductible, et contournable par un plan vague. Le plan est un ensemble de
n-uplets `(outil, hôte cible, méthode, plafond de montant, plafond de nombre)` :
l'appartenance se décide par appartenance ensembliste et arithmétique de
compteurs.

## 6. Registre de champs et règle d'extension

L'encodage à ordre fixe implique qu'ajouter un champ change les octets signés.
La règle est donc explicite :

1. Tout champ nouveau **incrémente la version du domaine** (`sauron.call.v2` →
   `.v3`). Deux versions peuvent être acceptées simultanément pendant une
   fenêtre de migration ; une signature ne mélange jamais les deux.
2. Les noms de champs sont enregistrés dans le tableau §2 ou §5 de ce document.
   Un nom non enregistré est un rejet, pas une extension silencieuse.
3. Les extensions propres à un déploiement utilisent le préfixe `x-` et ne sont
   jamais requises par un vérificateur conforme.
4. Retirer un champ est un changement de version au même titre qu'en ajouter un.

## 7. Vecteurs de test

[`schemas/agent-action-envelope-vectors.json`](../../schemas/agent-action-envelope-vectors.json)
publie, pour une clé de test dont la graine est publiée : les champs d'entrée,
les octets canoniques en hexadécimal, leur longueur, leur SHA-256, et la
signature attendue.

```
domaine            sauron.call.v2
octets canoniques  473
SHA-256 canonique  d44097382062b34b490e7624afd6520a476709f7fb84f2917454b063151df366
signature          AmS164osrYaN83efRmgd8xPMxZvJQoDn9puS8lkU7SJiYMw4gLey1lBoiBq1z4jaziiTGieqV2CfyK6Z4EGGAA
clé publique       A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
```

Ces octets sont produits **indépendamment** par deux implémentations : la
référence Rust, où le test `published_test_vector_call_signature_v2_001` les
épingle, et un encodeur écrit à partir du texte de cette spécification seule. Si
ce test doit changer, le format de fil a changé et la constante de version doit
changer avec lui.

Un implémenteur qui reproduit `canonical_bytes_hex` a un encodeur correct. C'est
l'artefact qui permet d'écrire un vérificateur en Go, en Java ou en Python sans
lire notre Rust — et c'est, après la licence, ce qui décide de l'adoption.

## 8. Codes d'erreur

Un vérificateur conforme renvoie un code stable, jamais seulement un statut
HTTP. Les codes existants sont émis par `agent/call_sig.rs` avec un indice de
remédiation ; `call_sig_nonce_reused` en est l'exemple. **À enregistrer
formellement dans ce document** : la taxonomie est aujourd'hui dans le code et
non dans la spécification, ce qui est exactement le genre d'écart qui rend deux
implémentations incompatibles sans que personne ne s'en aperçoive.

## 9. Découverte — *direction produit*

Rien de tout ceci n'est interopérable sans un endroit où chercher les clés. Visa
publie les siennes sur un chemin `/.well-known/jwks`. Il manque ici :

- un chemin `.well-known` publiant les clés de vérification et les versions de
  protocole acceptées,
- un type de média enregistré pour le document de vecteurs,
- un état de révocation interrogeable sans authentification préalable.

## 10. Ce qu'il reste avant que ce soit une norme

Dans l'ordre où le manquement tue le projet :

1. **La licence** — décision propriétaire, un commit.
2. **Les vecteurs publiés** — fait, §7.
3. **La règle d'extension et le registre de champs** — fait, §6.
4. **Une seconde implémentation écrite par quelqu'un d'autre**, à partir de ce
   texte seul. C'est la barre historique qui sépare « une norme » de « le format
   d'un produit ».
5. **Une suite de conformité publique.** `redteam/` contient 51 scénarios : les
   attaques restent privées, la conformité devient publique pour qu'un
   implémenteur puisse prouver et citer sa conformité.
6. **La découverte et les identifiants stables** — §9.
7. **Un foyer qui ne soit pas nous.** Une spécification détenue par une seule
   entreprise est un produit ; une spécification dotée d'un processus de
   changement auquel d'autres peuvent participer est une norme.
   `draft-klrc-aiagent-auth` est déjà à l'IETF : c'est la salle où cela se
   décide, et on y entre avec du code qui tourne, des vecteurs multi-langages et
   une suite de conformité.
