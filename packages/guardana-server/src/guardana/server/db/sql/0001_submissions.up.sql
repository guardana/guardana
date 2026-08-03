-- The shape the collector already accepts, made durable.
--
-- Two tables, not one per channel: `unverified` is the same finding shape and the
-- distinction is a property of the finding, not of where it is kept. `position`
-- preserves the order an agent sent, so a round trip returns the submission that
-- was made rather than a set.
--
-- Organizations, projects and API keys are migrations 0002 and later. Adding them
-- here would mean this migration path is only ever exercised against an empty
-- database, which is the one case where every migration works.

create table submissions (
    id              bigserial    primary key,
    received_at     timestamptz  not null,
    source          text         not null,
    schema_version  integer      not null,
    rules_run       integer      not null default 0,
    rules_executed  text[]       not null default '{}',
    rules_skipped   jsonb        not null default '[]',
    max_severity    text,
    unverified      integer      not null default 0,
    error_count     integer      not null default 0,
    errors          jsonb        not null default '[]'
);

create table findings (
    id                  bigserial         primary key,
    submission_id       bigint            not null references submissions (id) on delete cascade,
    -- 'findings' or 'unverified'. A check that ran and could not grade is not a
    -- pass, so it is stored, and stored apart from one that reached a verdict.
    channel             text              not null,
    position            integer           not null,
    rule_id             text              not null,
    severity            text              not null,
    title               text              not null,
    target_ref          text              not null,
    evidence_summary    text              not null,
    evidence_detail     text,
    taxonomy            jsonb             not null default '[]',
    verdict_outcome     text,
    verdict_confidence  double precision,
    verdict_rationale   text,
    verdict_evaluator   text
);

-- The dashboard reads newest-first and filters by source; the finding join is the
-- only other access path this schema has.
create index submissions_received_at_idx on submissions (received_at desc);
create index submissions_source_idx on submissions (source);
create index findings_submission_idx on findings (submission_id);
create index findings_severity_idx on findings (severity);
