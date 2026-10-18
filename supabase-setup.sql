-- Bwjspace: run this once in Supabase → SQL Editor → New query → Run.
-- No email or password. Your data is locked with a "sync key" that only your devices know.
-- The database never stores the key itself, only a fingerprint (hash) of it.

create extension if not exists pgcrypto with schema extensions;

-- Clean up the earlier email-login version if it was set up before (it had no data yet).
drop function if exists public.push_items(jsonb);
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'items' and column_name = 'user_id') then
    drop table public.items;
  end if;
end $$;

-- one "vault" = one person's data
create table if not exists public.vaults (
  id         uuid primary key default gen_random_uuid(),
  key_hash   text not null unique,
  created_at timestamptz not null default now()
);

-- every page, to-do, repeat rule etc. is its own row
create table if not exists public.items (
  vault_id   uuid        not null references public.vaults(id) on delete cascade,
  id         text        not null,
  kind       text        not null,
  data       jsonb,
  updated    bigint      not null,          -- when YOU last changed it (milliseconds)
  deleted    boolean     not null default false,
  synced_at  timestamptz not null default now(),
  primary key (vault_id, id)
);
create index if not exists items_vault_synced on public.items (vault_id, synced_at);

-- Nobody can read or write the tables directly. Everything goes through the functions below,
-- and every function first checks the sync key.
alter table public.vaults enable row level security;
alter table public.items  enable row level security;
revoke all on public.vaults, public.items from anon, authenticated;

create or replace function public.bwj_vault(p_key text)
returns uuid language sql stable security definer set search_path = public, extensions as $$
  select id from public.vaults where key_hash = encode(extensions.digest(p_key, 'sha256'), 'hex');
$$;

-- first device: create the vault for a new key
create or replace function public.create_vault(p_key text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare v uuid;
begin
  if p_key is null or length(p_key) < 24 then raise exception 'key too short'; end if;
  insert into public.vaults (key_hash) values (encode(extensions.digest(p_key, 'sha256'), 'hex')) returning id into v;
  return v;
end $$;

-- another device: check that a key is right
create or replace function public.check_key(p_key text)
returns uuid language plpgsql stable security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  return v;
end $$;

-- download changes since the last sync
create or replace function public.pull_items(p_key text, p_since timestamptz, p_offset integer, p_limit integer)
returns setof public.items language plpgsql stable security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  return query
    select * from public.items i
    where i.vault_id = v and (p_since is null or i.synced_at > p_since)
    order by i.synced_at, i.id
    offset greatest(p_offset, 0) limit least(greatest(p_limit, 1), 500);
end $$;

-- upload changes. A change is only accepted if the cloud copy has not been changed by
-- another device since this device last saw it ("base"). Old devices and old browser tabs
-- are refused instead of overwriting newer work. Returns the ids that were refused.
create or replace function public.push_items(p_key text, p_rows jsonb)
returns text[] language plpgsql security definer set search_path = public, extensions as $$
declare
  v uuid := public.bwj_vault(p_key);
  r jsonb;
  n integer;
  refused text[] := '{}';
begin
  if v is null then raise exception 'bad key'; end if;
  for r in select * from jsonb_array_elements(p_rows) loop
    insert into public.items as it (vault_id, id, kind, data, updated, deleted, synced_at)
    values (v, r->>'id', r->>'kind', r->'data', (r->>'updated')::bigint,
            coalesce((r->>'deleted')::boolean, false), clock_timestamp())
    on conflict (vault_id, id) do update
      set kind = excluded.kind,
          data = excluded.data,
          updated = greatest(excluded.updated, it.updated + 1),
          deleted = excluded.deleted,
          synced_at = clock_timestamp()
      where it.updated <= coalesce((r->>'base')::bigint, 0);
    get diagnostics n = row_count;
    if n = 0 then refused := refused || (r->>'id'); end if;
  end loop;
  return refused;
end $$;

-- replace the key; the old key stops working right away, the data stays
create or replace function public.change_key(p_old text, p_new text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_old);
begin
  if v is null then raise exception 'bad key'; end if;
  if p_new is null or length(p_new) < 24 then raise exception 'key too short'; end if;
  update public.vaults set key_hash = encode(extensions.digest(p_new, 'sha256'), 'hex') where id = v;
  return v;
end $$;

revoke all on function public.bwj_vault(text) from public, anon, authenticated;
revoke all on function public.create_vault(text), public.check_key(text),
  public.pull_items(text, timestamptz, integer, integer), public.push_items(text, jsonb),
  public.change_key(text, text) from public;
grant execute on function public.create_vault(text), public.check_key(text),
  public.pull_items(text, timestamptz, integer, integer), public.push_items(text, jsonb),
  public.change_key(text, text) to anon, authenticated;
