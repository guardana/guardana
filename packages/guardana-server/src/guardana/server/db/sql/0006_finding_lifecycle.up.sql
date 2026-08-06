-- A finding becomes an entity: what somebody decided about it, not just that it
-- was seen again.
--
-- The occurrences stay in `findings`. This table holds only what a sighting cannot
-- say — status, owner, waiver, first and last seen — because copying severity or
-- title here would be a second source of truth that drifts the first time a rule's
-- severity changes.
--
-- Back-filled from what is already stored, so a collector that has been running
-- for months arrives with its history rather than an empty triage list.

create table tracked_findings (
    id             bigserial    primary key,
    project_id     bigint       not null references projects (id) on delete restrict,
    -- The identity `guardana diff` has used since 0.6, computed by the engine and
    -- carried on every occurrence since envelope v7. Never recomputed here: the
    -- collector does not import the engine, so a second definition would be a
    -- second answer to "is this the same finding".
    identity       text         not null,
    -- open | acknowledged | in_progress | resolved | false_positive | accepted_risk
    -- A closed set, checked by the application. Free text here would make
    -- "resolved" and "Resolved" two different states in one project.
    status         text         not null default 'open',
    owner          text,
    -- All three or none: an approver, a reason, and a date it lapses. There is no
    -- indefinite waiver — accepted risk that never comes back is a permanently
    -- disabled check with better manners.
    waived_by      text,
    waiver_reason  text,
    waiver_expires date,
    waived_at      timestamptz,
    first_seen_at  timestamptz  not null,
    last_seen_at   timestamptz  not null,
    updated_at     timestamptz  not null default now(),
    unique (project_id, identity),
    constraint tracked_findings_waiver_is_whole check (
        (waived_by is null and waiver_reason is null and waiver_expires is null)
        or (waived_by is not null and waiver_reason is not null and waiver_expires is not null)
    )
);

create index tracked_findings_project_status_idx on tracked_findings (project_id, status);

insert into tracked_findings (project_id, identity, first_seen_at, last_seen_at)
select s.project_id, f.identity, min(s.received_at), max(s.received_at)
from findings f
join submissions s on s.id = f.submission_id
where f.identity is not null and s.project_id is not null and f.channel = 'findings'
group by s.project_id, f.identity;
