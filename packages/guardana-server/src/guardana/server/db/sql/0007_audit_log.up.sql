-- Who did what, and by which route.
--
-- A collector holds a team's security evidence and its credentials and could not
-- say who created a key, who waived a finding, or who rolled the schema back at
-- three in the morning. `api_keys.created_by` has existed since 0.8 with nothing
-- filling it — a column nobody writes is a promise the code does not keep.
--
-- State changes only. A read log on a dashboard refresh is volume without an
-- answer, and volume is how a log stops being read.

create table audit_events (
    id               bigserial    primary key,
    occurred_at      timestamptz  not null default now(),
    -- Both nullable: a schema migration belongs to no tenant, and an organization
    -- action belongs to no project. A row that had to invent one would be a row
    -- that lies about scope.
    organization_id  bigint       references organizations (id) on delete cascade,
    project_id       bigint       references projects (id) on delete cascade,
    -- 'key' — the credential was presented and matched, so this is verified.
    -- 'cli' — an operator with database access said so, which is asserted and not
    -- proof of anything. The distinction is a column rather than a convention
    -- because calling an assertion authentication is the false green this project
    -- refuses everywhere else.
    actor_kind       text         not null,
    actor            text         not null,
    action           text         not null,
    subject          text,
    detail           jsonb        not null default '{}'
);

create index audit_events_occurred_idx on audit_events (occurred_at desc);
create index audit_events_project_idx on audit_events (project_id, occurred_at desc);

-- Which credential wrote a submission: the open question from the tenancy design.
-- Nullable, because a submission that arrived on an unauthenticated evaluation
-- collector has no key, and inventing one would be worse than the null.
alter table submissions add column api_key_id bigint references api_keys (id) on delete set null;

-- Retention is per project, because the tenant is the project everywhere else here
-- and a policy at a different granularity is one that eventually deletes somebody
-- else's evidence. Null means "keep everything", which is what a collector that
-- was never told does.
alter table projects add column retention_days integer;

alter table projects
    add constraint projects_retention_is_positive
    check (retention_days is null or retention_days > 0);
