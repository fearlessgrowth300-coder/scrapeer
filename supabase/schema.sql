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

-- Live events from Resend webhooks (opened / delivered / clicked / bounced / complained / received)
create table if not exists public.scrapeer_events (
  id         bigserial primary key,
  event_id   text unique,
  user_id    uuid not null references auth.users (id) on delete cascade,
  account_id uuid references public.scrapeer_accounts (id) on delete cascade,
  type       text not null,
  email_id   text,
  contact    text,
  subject    text,
  at         timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index if not exists scrapeer_events_user on public.scrapeer_events (user_id, created_at desc);
alter table public.scrapeer_events enable row level security;
revoke all on public.scrapeer_events from anon, authenticated;

-- Phones/browsers that get a notification when a reply arrives (Web Push subscriptions)
create table if not exists public.scrapeer_push (
  endpoint   text primary key,
  user_id    uuid not null references auth.users (id) on delete cascade,
  keys       jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists scrapeer_push_user on public.scrapeer_push (user_id);
alter table public.scrapeer_push enable row level security;
revoke all on public.scrapeer_push from anon, authenticated;

-- Background searches and sending (run on the VPS, keep going when the app is closed)
create table if not exists public.scrapeer_jobs (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  kind       text not null,
  status     text not null default 'running',
  input      jsonb not null default '{}',
  progress   jsonb not null default '{}',
  result     jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists scrapeer_jobs_user on public.scrapeer_jobs (user_id, kind, created_at desc);
alter table public.scrapeer_jobs enable row level security;
revoke all on public.scrapeer_jobs from anon, authenticated;
