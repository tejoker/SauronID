# Company brain

The reference point. Brand Kit v2.0, August 2026, imported from the kit that
used to live outside the repository. When a claim about the product, the
positioning or the visual identity changes, it changes here first and the code
follows. A value that lives only in a component is not a decision.

| Fichier | Ce qu'il gouverne |
|---|---|
| [`product-truth.md`](product-truth.md) | ce que le produit est, les trois labels de vérité, la discipline de claim |
| [`brand-system.md`](brand-system.md) | identité, voix, système visuel, logo, palette canonique |
| [`design-system.md`](design-system.md) | l'implémentation du système visuel dans le site vitrine (grammaire rail/path/checkpoint) |
| [`market-positioning-fr.md`](market-positioning-fr.md) | positionnement marché, concurrence, adoption |
| [`website-brief.md`](website-brief.md) | brief de refonte du site et architecture d'information |
| [`brand/tokens.css`](brand/tokens.css), [`brand/tokens.json`](brand/tokens.json) | tokens canoniques, préfixe `--sid-` |
| [`brand/brand-book.pdf`](brand/brand-book.pdf) | brand book v2, généré par [`brand/build-brand-book.js`](brand/build-brand-book.js) |
| [`brand/logo.svg`](brand/logo.svg) | le mark vectoriel |

## Positionnement courant

Master line : **Build agents you can actually let act.**
Descriptor : **The agent platform with boundaries built in.**
Grammaire produit : Intent, Capabilities, Boundaries, Run, Proof.

La palette est light-first : `--sid-canvas` sur `cloud-50 #f7faff`, `signal-600
#0054f3` pour la seule chose actionnable, `midnight-950 #000d35` uniquement là
où le produit prouve quelque chose.

## Écarts connus

`dashboard/app/globals.css` tourne encore sur l'identité v1 de mai 2026
(`--bg: #06090f`, canvas sombre, Satoshi). Ce n'est pas le système ci-dessus, et
la console est à réaligner. Le site vitrine (`site/`), lui, suit bien
`design-system.md`.

Les déclinaisons raster du logo vivent avec le code qui les sert
(`site/public/sauronid-logo.png`, `dashboard/public/logo.svg`), pas ici.

## Règle

Un claim produit ne se formule pas dans un composant. Une couleur ne se choisit
pas dans une feuille de style. Les deux se décident ici, puis se propagent.
Aucune capacité future ne se présente comme disponible : les labels de
`product-truth.md` sont obligatoires.
