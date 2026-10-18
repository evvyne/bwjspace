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

-- ============================================================
-- Sharing one page with a link (added later; safe to run again)
-- ============================================================
create or replace function public.bwj_hash(p text)
returns text language sql immutable set search_path = public, extensions as $$
  select encode(extensions.digest(coalesce(p, ''), 'sha256'), 'hex');
$$;

create table if not exists public.shares (
  token_hash   text primary key,
  vault_id     uuid not null references public.vaults(id) on delete cascade,
  page_id      text not null,
  perm         text not null check (perm in ('view', 'edit')),
  include_subs boolean not null default true,
  created_at   timestamptz not null default now()
);
create unique index if not exists shares_vault_page on public.shares (vault_id, page_id);
alter table public.shares enable row level security;
revoke all on public.shares from anon, authenticated;

-- which pages a link can reach: the shared page, plus its sub-pages if allowed
create or replace function public.bwj_share_ids(p_vault uuid, p_root text, p_subs boolean)
returns setof text language sql stable security definer set search_path = public as $$
  with recursive tree(pid) as (
    select p_root
    union
    select substring(i.id from 3)
    from public.items i
    join tree t on p_subs
      and (i.data->>'parent' = t.pid or i.data->>'dbId' = t.pid)
    where i.vault_id = p_vault and i.kind = 'page' and not i.deleted
  )
  select 'p:' || pid from tree;
$$;

-- owner: turn sharing on or change who can do what (needs the sync key)
create or replace function public.share_set(p_key text, p_page text, p_token text, p_perm text, p_subs boolean)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  if p_perm not in ('view', 'edit') then raise exception 'bad permission'; end if;
  if p_token is null or length(p_token) < 24 then raise exception 'link too short'; end if;
  delete from public.shares where vault_id = v and page_id = p_page and token_hash <> public.bwj_hash(p_token);
  insert into public.shares (token_hash, vault_id, page_id, perm, include_subs)
  values (public.bwj_hash(p_token), v, p_page, p_perm, coalesce(p_subs, true))
  on conflict (token_hash) do update set perm = excluded.perm, include_subs = excluded.include_subs
  where public.shares.vault_id = v;
  return true;
end $$;

-- owner: turn the link off
create or replace function public.share_stop(p_key text, p_page text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  delete from public.shares where vault_id = v and page_id = p_page;
  return true;
end $$;

-- anyone with the link: read the shared page(s) only
create or replace function public.shared_pull(p_token text)
returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare s public.shares; res jsonb;
begin
  select * into s from public.shares where token_hash = public.bwj_hash(p_token);
  if not found then raise exception 'link off'; end if;
  select coalesce(jsonb_agg(jsonb_build_object('id', i.id, 'data', i.data - 'share', 'updated', i.updated) order by i.id), '[]'::jsonb)
  into res
  from public.items i
  where i.vault_id = s.vault_id
    and i.id in (select public.bwj_share_ids(s.vault_id, s.page_id, s.include_subs))
    and not i.deleted
    and coalesce(i.data->>'trashed', 'false') <> 'true';
  return jsonb_build_object('perm', s.perm, 'root', s.page_id, 'items', res);
end $$;

-- people with an "edit" link: change the shared page(s).
-- They can not delete or move pages, create new pages, or touch anything else.
create or replace function public.shared_push(p_token text, p_rows jsonb)
returns text[] language plpgsql security definer set search_path = public, extensions as $$
declare
  s public.shares;
  r jsonb;
  old public.items;
  n integer;
  allowed text[];
  refused text[] := '{}';
begin
  select * into s from public.shares where token_hash = public.bwj_hash(p_token);
  if not found then raise exception 'link off'; end if;
  if s.perm <> 'edit' then raise exception 'view only'; end if;
  allowed := array(select public.bwj_share_ids(s.vault_id, s.page_id, s.include_subs));
  for r in select * from jsonb_array_elements(p_rows) loop
    select * into old from public.items where vault_id = s.vault_id and id = r->>'id';
    if not found or not ((r->>'id') = any(allowed)) or old.deleted
       or coalesce((r->>'deleted')::boolean, false) or jsonb_typeof(r->'data') <> 'object' then
      refused := refused || (r->>'id');
      continue;
    end if;
    update public.items
    set data = ((r->'data') - 'share') || jsonb_build_object(
                 'id', old.data->'id', 'parent', old.data->'parent', 'space', old.data->'space',
                 'dbId', old.data->'dbId', 'kind', old.data->'kind', 'trashed', old.data->'trashed',
                 'share', old.data->'share'),
        updated = greatest((r->>'updated')::bigint, old.updated + 1),
        synced_at = clock_timestamp()
    where vault_id = s.vault_id and id = r->>'id' and updated <= coalesce((r->>'base')::bigint, 0);
    get diagnostics n = row_count;
    if n = 0 then refused := refused || (r->>'id'); end if;
  end loop;
  return refused;
end $$;

revoke all on function public.bwj_hash(text), public.bwj_share_ids(uuid, text, boolean) from public, anon, authenticated;
revoke all on function public.share_set(text, text, text, text, boolean), public.share_stop(text, text),
  public.shared_pull(text), public.shared_push(text, jsonb) from public;
grant execute on function public.share_set(text, text, text, text, boolean), public.share_stop(text, text),
  public.shared_pull(text), public.shared_push(text, jsonb) to anon, authenticated;
