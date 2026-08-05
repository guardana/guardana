-- The tenant is the project; an organization is what a project belongs to.
--
-- A database that already holds data is **adopted**, not refused. Refusing is the
-- most faithful to "a decision, never a default", but it stops an upgrade half-way,
-- and that is exactly the pressure that produces workarounds. Adoption creates no
-- leak: every pre-tenancy row and every pre-tenancy key lands in ONE project,
-- which is where they already were together.

create table organizations (
    id          bigserial    primary key,
    slug        text         not null unique,
    name        text         not null,
    -- A historical fact, not a name: "this is where migration 0003 put the rows
    -- that predate tenancy". Recognising it by its slug would stop working the
    -- moment somebody runs `org rename` — and `org rename` exists precisely so a
    -- name the migration invented is not permanent.
    adopted     boolean      not null default false,
    created_at  timestamptz  not null default now()
);

create table projects (
    id               bigserial    primary key,
    organization_id  bigint       not null references organizations (id) on delete restrict,
    slug             text         not null,
    name             text         not null,
    created_at       timestamptz  not null default now(),
    unique (organization_id, slug)
);

alter table submissions add column project_id bigint references projects (id) on delete restrict;
alter table api_keys    add column project_id bigint references projects (id) on delete restrict;

-- The organization is created only when there is something to adopt, so a fresh
-- install does not get a tenant it never asked for. The condition covers keys as
-- well as submissions, because a collector that has issued credentials and
-- received no runs is a real state — and `api_keys.project_id` becomes `not null`
-- too.
do $$
declare
    adopted_organization bigint;
    adopted_project      bigint;
begin
    if exists (select 1 from submissions) or exists (select 1 from api_keys) then
        insert into organizations (slug, name, adopted)
        values ('adopted', 'adopted', true)
        returning id into adopted_organization;

        insert into projects (organization_id, slug, name)
        values (adopted_organization, 'adopted', 'adopted')
        returning id into adopted_project;

        update submissions set project_id = adopted_project;
        update api_keys    set project_id = adopted_project;
    end if;
end $$;

-- After adoption: no row can exist without a tenant, so a scoped query cannot
-- silently fail to return something that belongs to the caller.
alter table submissions alter column project_id set not null;
alter table api_keys    alter column project_id set not null;

-- Indexes are replaced rather than added. Every read now filters on `project_id`
-- first, which makes the two single-column indexes dead weight paid for on every
-- insert. The composite one is also what keeps `trend()`'s join driven from the
-- submission side.
drop index submissions_received_at_idx;
drop index submissions_source_idx;
create index submissions_project_received_idx on submissions (project_id, received_at desc);
create index submissions_project_source_idx   on submissions (project_id, source);
create index api_keys_project_idx on api_keys (project_id);
