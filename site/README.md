# Le site public n'est plus ici

`www.sauronid.eu` a été extrait le 2026-08-27 vers son propre dépôt, avec son
historique. Ce dossier ne contient que le pointeur.

| | |
|---|---|
| Dépôt | `clement-sporrer/SauronID-Landing` (privé) |
| Clone local | `~/code/sauronid-site` |
| Stack | Next.js 16.3.0, React 19.2.3, export statique (`output: "export"`) |
| Déploiement | Vercel, sur push vers `main` |
| Contenu | 10 pages, bilingue EN à la racine et FR sous `/fr`, formulaire early access |

Pourquoi dehors : ce dépôt est public et le code marketing ne l'est pas, Vercel
exige un accès propriétaire sur ce qu'il construit, et le site se déploie à
chaque push alors que la passerelle ne doit pas partager ce déclencheur.

## Travailler sur les deux dans une seule session

Cloner une fois :

```bash
git clone git@github.com:clement-sporrer/SauronID-Landing.git ~/code/sauronid-site
```

Puis, depuis une session ouverte ici :

```
/add-dir ~/code/sauronid-site
```

La session lit la vérité produit ici et écrit le site là-bas, dans le même tour.
Rien ne se recopie à la main. Sur cette machine le dossier est déjà déclaré dans
`.claude/settings.local.json`, la commande n'est pas nécessaire.

## Ce qui reste vrai de l'autre côté de la frontière

- Un claim sur le site doit être vrai ici d'abord, et autorisé par
  `docs/company-brain/`. Le company brain décide, le site exécute.
- Les trois labels de disponibilité (vérifié dans le dépôt, direction produit,
  hypothèse) s'appliquent au site comme au reste.
- Design et voix : `docs/design/design-system.md` et
  `docs/company-brain/brand/`.
- Les identifiants sont des variables d'environnement Vercel, jamais dans un
  dépôt.

Ne pas reconstruire de page marketing dans cet arbre. Il n'y a qu'une copie
vivante du site, elle est dans l'autre dépôt.
