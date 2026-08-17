-- Early-access signups table for the SauronID website form.
-- Run this in the Supabase SQL editor of the project you connect.

create table if not exists public.early_access_signups (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) <= 200),
  email text not null check (char_length(email) <= 320),
  role_company text check (char_length(role_company) <= 300),
  os text not null check (os in ('macOS', 'Windows', 'Linux')),
  workflow text not null check (char_length(workflow) <= 4000),
  tools text check (char_length(tools) <= 1000),
  model_provider text check (char_length(model_provider) <= 300),
  feedback_call text check (char_length(feedback_call) <= 20),
  locale text check (char_length(locale) <= 10)
);

alter table public.early_access_signups enable row level security;

-- The public site may only insert. Nobody can read, update, or delete
-- through the anon key; review signups in the Supabase dashboard or with
-- the service-role key.
drop policy if exists "public can sign up" on public.early_access_signups;
create policy "public can sign up"
  on public.early_access_signups
  for insert
  to anon
  with check (true);
