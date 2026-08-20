# SauronID website

Bilingual (EN at `/`, FR at `/fr`) marketing site. Next.js 16 App Router,
static export (`output: "export"`), no server required: `next build` emits a
plain `out/` folder deployable on any static host.

## Develop

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # static export in out/
```

## Structure

```
app/          routes only: metadata + render a view (EN at root, FR under app/fr)
components/
  layout/     Header (nav, language menu, scroll reset), Footer
  interactive/ BoundaryDemo, RingSeal, Checkpoint, EarlyAccessForm
  ui/         shared building blocks
  views/      one folder per page: the view component + copy.ts (EN/FR dictionaries)
lib/          i18n helpers, early-access signup client
styles/       design system split by concern, imported by app/globals.css
supabase/     SQL to provision the early-access signups table (insert-only RLS)
```

Conventions: all visible copy lives in `copy.ts` dictionaries keyed by locale;
internal links go through `localeHref(locale, path)`; strings inside
`evidence` / mono blocks are product artifacts and stay in English; claim
wording follows `../PRODUCT.md` (never "certified/compliant", availability is
always labeled).

## Early-access form — modes

- **No configuration**: falls back to a pre-filled email (always works).
- **Supabase configured**: signups are stored in `early_access_signups`.
- **Launcher URL configured**: a stored signup immediately starts the real
  download; before that, users are told their cohort will email the link.

Setup (5 minutes): create a Supabase project → run
`supabase/early_access.sql` in its SQL editor → copy `env.example` to
`.env.local` and fill `NEXT_PUBLIC_SUPABASE_URL` +
`NEXT_PUBLIC_SUPABASE_ANON_KEY` (public by design; the table is insert-only
for the anon role). The day the Launcher binary exists, host it anywhere and
set `NEXT_PUBLIC_LAUNCHER_URL`.

## Next steps before public launch

1. **Supabase**: create the production project, run the SQL, set the two env
   vars in the deploy environment.
2. **Launcher binary**: build, sign, host it; set `NEXT_PUBLIC_LAUNCHER_URL`.
   Until then the form honestly queues people for their cohort.
3. **Deploy**: any static host (Vercel/Netlify/nginx/S3). Root domain
   required (links are root-absolute). Wire `www` + apex, HTTPS.
4. **Domains in metadata**: set `metadataBase` in `app/layout.tsx` once the
   final domain is known, so hreflang/OG URLs are absolute.
5. **Analytics/consent**: nothing is installed by choice; add a
   privacy-respecting analytics only with a consent story consistent with the
   compliance page.
6. **Legal pages**: privacy policy + imprint before collecting real signups
   (GDPR: the form stores personal data once Supabase is live).
7. **Verify claims at launch**: supported OS/model list published with the
   Launcher; keep availability labels in sync with reality (see PRODUCT.md
   claim discipline).
