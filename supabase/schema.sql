-- Scrapeer: run once in Supabase → SQL Editor → New query → Run.
-- Row Level Security is ON with NO policies: browsers (anon/authenticated keys) can never read or write these
-- tables. Only the Scrapeer server (service_role key, kept in Vercel env) can, after checking who is signed in.

create table if not exists public.scrapeer_accounts (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  label      text not null,
  provider   text not null check (provider in ('resend', 'brevo', 'mailjet', 'smtp')),
  cap        int  not null default 100,
  public     jsonb not null default '{}'::jsonb,  -- from / reply_to / from_name / domain (no secrets)
  secret     text not null,                       -- AES-256-GCM encrypted account incl. API key / password
  created_at timestamptz not null default now(),
  unique (user_id, label)
);
create index if not exists scrapeer_accounts_user on public.scrapeer_accounts (user_id, created_at);

create table if not exists public.scrapeer_state (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,  -- sent log, already-emailed, do-not-email, drafts, read replies
  updated_at timestamptz not null default now()
);

alter table public.scrapeer_accounts enable row level security;
alter table public.scrapeer_state    enable row level security;
revoke all on public.scrapeer_accounts, public.scrapeer_state from anon, authenticated;
