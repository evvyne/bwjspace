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
    perform set_config('bwj.author', left(coalesce(r->>'author', ''), 60), true);
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
  perm         text not null,
  include_subs boolean not null default true,
  created_at   timestamptz not null default now()
);
create unique index if not exists shares_vault_page on public.shares (vault_id, page_id);
alter table public.shares enable row level security;
revoke all on public.shares from anon, authenticated;
-- which pages inside the shared page / space: only_ids = just these; skip_ids = everything except these
alter table public.shares add column if not exists only_ids text[];
alter table public.shares add column if not exists skip_ids text[];

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


-- which pages a link can open. p_root is a page id, or 'space:<id>' for a whole space.
-- Cards inside a shared database (like prompts) come with it.
create or replace function public.bwj_share_allowed(p_vault uuid, p_root text, p_subs boolean, p_only text[], p_skip text[])
returns setof text language sql stable security definer set search_path = public as $$
  with recursive tree(pid, db) as (
    select substring(i.id from 3), coalesce(i.data->>'dbId', '')
    from public.items i
    where i.vault_id = p_vault and i.kind = 'page' and not i.deleted
      and coalesce(i.data->>'kind', '') <> 'journal'
      and ((p_root like 'space:%' and i.data->>'space' = substring(p_root from 7)
             and coalesce(i.data->>'parent', '') = '' and coalesce(i.data->>'dbId', '') = '')
        or (p_root not like 'space:%' and i.id = 'p:' || p_root))
    union
    select substring(i.id from 3), coalesce(i.data->>'dbId', '')
    from public.items i
    join tree t on (p_subs or p_root like 'space:%' or i.data->>'dbId' = t.pid)
      and (i.data->>'parent' = t.pid or i.data->>'dbId' = t.pid)
    where i.vault_id = p_vault and i.kind = 'page' and not i.deleted
  )
  select 'p:' || t.pid from tree t
  where (p_only is null or t.pid = any(p_only) or t.db = any(p_only))
    and (p_skip is null or not (t.pid = any(p_skip) or t.db = any(p_skip)));
$$;

-- owner: turn sharing on or change who can do what (needs the sync key)
create or replace function public.share_set(p_key text, p_page text, p_token text, p_perm text, p_subs boolean)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  if p_perm not in ('view', 'comment', 'edit') then raise exception 'bad permission'; end if;
  if p_token is null or length(p_token) < 24 then raise exception 'link too short'; end if;
  delete from public.shares where vault_id = v and page_id = p_page and token_hash <> public.bwj_hash(p_token);
  insert into public.shares (token_hash, vault_id, page_id, perm, include_subs)
  values (public.bwj_hash(p_token), v, p_page, p_perm, coalesce(p_subs, true))
  on conflict (token_hash) do update set perm = excluded.perm, include_subs = excluded.include_subs
  where public.shares.vault_id = v;
  return true;
end $$;

-- owner: same as above, plus which pages inside (only these / all except these)
create or replace function public.share_set(p_key text, p_page text, p_token text, p_perm text, p_subs boolean, p_only text[], p_skip text[])
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  perform public.share_set(p_key, p_page, p_token, p_perm, p_subs);
  update public.shares set only_ids = p_only, skip_ids = p_skip
  where token_hash = public.bwj_hash(p_token) and vault_id = v;
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
    and i.id in (select public.bwj_share_allowed(s.vault_id, s.page_id, s.include_subs, s.only_ids, s.skip_ids))
    and not i.deleted
    and coalesce(i.data->>'trashed', 'false') <> 'true';
  return jsonb_build_object('perm', s.perm, 'root', s.page_id, 'items', res,
    'space', case when s.page_id like 'space:%' then (
      select e from public.items sp, jsonb_array_elements(case when jsonb_typeof(sp.data) = 'array' then sp.data else '[]'::jsonb end) e
      where sp.vault_id = s.vault_id and sp.id = 'spaces' and e->>'id' = substring(s.page_id from 7) limit 1) end);
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
  allowed := array(select public.bwj_share_allowed(s.vault_id, s.page_id, s.include_subs, s.only_ids, s.skip_ids));
  for r in select * from jsonb_array_elements(p_rows) loop
    perform set_config('bwj.author', left(coalesce(r->>'author', ''), 60), true);
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

revoke all on function public.bwj_hash(text), public.bwj_share_ids(uuid, text, boolean), public.bwj_share_allowed(uuid, text, boolean, text[], text[]) from public, anon, authenticated;
revoke all on function public.share_set(text, text, text, text, boolean, text[], text[]) from public;
grant execute on function public.share_set(text, text, text, text, boolean, text[], text[]) to anon, authenticated;
revoke all on function public.share_set(text, text, text, text, boolean), public.share_stop(text, text),
  public.shared_pull(text), public.shared_push(text, jsonb) from public;
grant execute on function public.share_set(text, text, text, text, boolean), public.share_stop(text, text),
  public.shared_pull(text), public.shared_push(text, jsonb) to anon, authenticated;

-- ============================================================
-- Comment links and comments (added later; safe to run again)
-- ============================================================
alter table public.shares drop constraint if exists shares_perm_check;
alter table public.shares add constraint shares_perm_check check (perm in ('view', 'comment', 'edit'));

create table if not exists public.comments (
  id         text primary key,
  vault_id   uuid not null references public.vaults(id) on delete cascade,
  page_id    text not null,
  block_id   text,                      -- the line it is about (empty = the whole page)
  quote      text,                      -- a few words of that line, in case it is deleted later
  author     text not null,
  body       text not null,
  by_owner   boolean not null default false,
  resolved   boolean not null default false,
  created    timestamptz not null default now()
);
create index if not exists comments_vault_page on public.comments (vault_id, page_id);
alter table public.comments enable row level security;
revoke all on public.comments from anon, authenticated;

-- you (needs the sync key): read the comments of one page
create or replace function public.comments_owner(p_key text, p_page text)
returns setof public.comments language plpgsql stable security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  return query select * from public.comments c where c.vault_id = v and c.page_id = p_page order by c.created;
end $$;

-- you: how many open comments each page has (for the sidebar)
create or replace function public.comments_summary(p_key text)
returns table(page_id text, open_count integer) language plpgsql stable security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  return query select c.page_id, count(*)::integer from public.comments c where c.vault_id = v and not c.resolved group by c.page_id;
end $$;

-- you: add a comment or reply
create or replace function public.comment_add_owner(p_key text, p_id text, p_page text, p_block text, p_quote text, p_author text, p_body text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  if length(coalesce(p_body, '')) = 0 or length(p_body) > 4000 then raise exception 'bad comment'; end if;
  insert into public.comments (id, vault_id, page_id, block_id, quote, author, body, by_owner)
  values (p_id, v, p_page, nullif(p_block, ''), left(p_quote, 120), left(coalesce(nullif(p_author, ''), 'Owner'), 60), p_body, true)
  on conflict (id) do nothing;
  return true;
end $$;

-- you: mark the comments on one line (or the whole page) as done
create or replace function public.comment_resolve(p_key text, p_page text, p_block text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  update public.comments set resolved = true
  where vault_id = v and page_id = p_page and block_id is not distinct from nullif(p_block, '') and not resolved;
  return true;
end $$;

-- you: delete one comment
create or replace function public.comment_delete(p_key text, p_id text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  delete from public.comments where vault_id = v and id = p_id;
  return true;
end $$;

-- people with a comment or edit link: read the comments on the shared page(s)
create or replace function public.shared_comments(p_token text)
returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare s public.shares; res jsonb;
begin
  select * into s from public.shares where token_hash = public.bwj_hash(p_token);
  if not found then raise exception 'link off'; end if;
  if s.perm = 'view' then return '[]'::jsonb; end if;
  select coalesce(jsonb_agg(jsonb_build_object('id', c.id, 'page_id', c.page_id, 'block_id', c.block_id, 'quote', c.quote,
           'author', c.author, 'body', c.body, 'by_owner', c.by_owner, 'resolved', c.resolved, 'created', c.created) order by c.created), '[]'::jsonb)
  into res
  from public.comments c
  where c.vault_id = s.vault_id
    and ('p:' || c.page_id) in (select public.bwj_share_allowed(s.vault_id, s.page_id, s.include_subs, s.only_ids, s.skip_ids));
  return res;
end $$;

-- people with a comment or edit link: add a comment or reply
create or replace function public.shared_comment_add(p_token text, p_id text, p_page text, p_block text, p_quote text, p_author text, p_body text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare s public.shares;
begin
  select * into s from public.shares where token_hash = public.bwj_hash(p_token);
  if not found then raise exception 'link off'; end if;
  if s.perm not in ('comment', 'edit') then raise exception 'view only'; end if;
  if not (('p:' || p_page) in (select public.bwj_share_allowed(s.vault_id, s.page_id, s.include_subs, s.only_ids, s.skip_ids))) then raise exception 'not shared'; end if;
  if length(coalesce(p_body, '')) = 0 or length(p_body) > 4000 or length(coalesce(p_id, '')) < 8 then raise exception 'bad comment'; end if;
  insert into public.comments (id, vault_id, page_id, block_id, quote, author, body, by_owner)
  values (p_id, s.vault_id, p_page, nullif(p_block, ''), left(p_quote, 120), left(coalesce(nullif(trim(p_author), ''), 'Guest'), 60), p_body, false)
  on conflict (id) do nothing;
  return true;
end $$;

revoke all on function public.comments_owner(text, text), public.comments_summary(text),
  public.comment_add_owner(text, text, text, text, text, text, text), public.comment_resolve(text, text, text),
  public.comment_delete(text, text), public.shared_comments(text),
  public.shared_comment_add(text, text, text, text, text, text, text) from public;
grant execute on function public.comments_owner(text, text), public.comments_summary(text),
  public.comment_add_owner(text, text, text, text, text, text, text), public.comment_resolve(text, text, text),
  public.comment_delete(text, text), public.shared_comments(text),
  public.shared_comment_add(text, text, text, text, text, text, text) to anon, authenticated;

-- ============================================================
-- Page history (last 10 days) and photos in Storage (added later; safe to run again)
-- ============================================================
create table if not exists public.page_versions (
  id        bigserial primary key,
  vault_id  uuid not null references public.vaults(id) on delete cascade,
  page_id   text not null,
  author    text not null default '',
  data      jsonb,
  created   timestamptz not null default now(),
  updated   timestamptz not null default now()
);
create index if not exists page_versions_page on public.page_versions (vault_id, page_id, updated desc);
alter table public.page_versions enable row level security;
revoke all on public.page_versions from anon, authenticated;

-- every time a page is saved, keep a copy. Changes by the same person within 10 minutes share one copy.
create or replace function public.bwj_keep_version()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  a text := coalesce(current_setting('bwj.author', true), '');
  pid text := substring(new.id from 3);
  last_id bigint; last_author text; last_upd timestamptz;
begin
  if new.kind <> 'page' or new.deleted or new.data is null then return new; end if;
  if tg_op = 'UPDATE' and old.data is not distinct from new.data then return new; end if;
  select id, author, updated into last_id, last_author, last_upd
  from public.page_versions where vault_id = new.vault_id and page_id = pid order by updated desc limit 1;
  if last_id is null and tg_op = 'UPDATE' and old.data is not null and not old.deleted then
    insert into public.page_versions (vault_id, page_id, author, data, created, updated)
    values (new.vault_id, pid, '', old.data, to_timestamp(old.updated / 1000.0), to_timestamp(old.updated / 1000.0));
  end if;
  if last_id is not null and last_author = a and last_upd > now() - interval '10 minutes' then
    update public.page_versions set data = new.data, updated = now() where id = last_id;
  else
    insert into public.page_versions (vault_id, page_id, author, data) values (new.vault_id, pid, a, new.data);
  end if;
  -- keep 10 days, plus the last copy from before that (so the page before an edit can always come back)
  delete from public.page_versions v
  where v.vault_id = new.vault_id and v.page_id = pid and v.updated < now() - interval '10 days'
    and v.id <> (select x.id from public.page_versions x where x.vault_id = new.vault_id and x.page_id = pid
                 and x.updated < now() - interval '10 days' order by x.updated desc limit 1);
  return new;
end $$;
drop trigger if exists bwj_items_versions on public.items;
create trigger bwj_items_versions after insert or update on public.items
  for each row execute function public.bwj_keep_version();

-- you: the saved copies of one page, newest first
create or replace function public.page_history(p_key text, p_page text)
returns table(id bigint, author text, created timestamptz, updated timestamptz, data jsonb)
language plpgsql stable security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key);
begin
  if v is null then raise exception 'bad key'; end if;
  return query select pv.id, pv.author, pv.created, pv.updated, pv.data from public.page_versions pv
    where pv.vault_id = v and pv.page_id = p_page order by pv.updated desc limit 200;
end $$;

-- photos: a private folder name per vault, only your devices know it
alter table public.vaults add column if not exists img_folder text;
create or replace function public.img_folder(p_key text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := public.bwj_vault(p_key); f text;
begin
  if v is null then raise exception 'bad key'; end if;
  select img_folder into f from public.vaults where id = v;
  if f is null then
    f := encode(extensions.gen_random_bytes(16), 'hex');
    update public.vaults set img_folder = f where id = v;
  end if;
  return f;
end $$;
create or replace function public.bwj_img_folder_ok(p text)
returns boolean language sql stable security definer set search_path = public as $$
  select p is not null and length(p) = 32 and exists (select 1 from public.vaults where img_folder = p);
$$;

revoke all on function public.page_history(text, text), public.img_folder(text), public.bwj_img_folder_ok(text) from public;
grant execute on function public.page_history(text, text), public.img_folder(text), public.bwj_img_folder_ok(text) to anon, authenticated;
revoke all on function public.bwj_keep_version() from public, anon, authenticated;

-- the photo bucket: anyone with the exact photo address can see a photo (addresses are long and random);
-- only images up to 5 MB, and only into your private folder
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('bwj-images', 'bwj-images', true, 5242880, array['image/jpeg', 'image/png', 'image/webp', 'image/gif'])
on conflict (id) do update set public = true, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;
drop policy if exists "bwj upload images" on storage.objects;
create policy "bwj upload images" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'bwj-images' and public.bwj_img_folder_ok((storage.foldername(name))[1]));
-- uploading also reads the new file back, so allow reading inside your private folder
drop policy if exists "bwj read images" on storage.objects;
create policy "bwj read images" on storage.objects for select to anon, authenticated
  using (bucket_id = 'bwj-images' and public.bwj_img_folder_ok((storage.foldername(name))[1]));
