-- What the run itself was, and what links a finding to the same finding next week.
--
-- A submission said which rules ran and what they found, and nothing about the run:
-- whether it passed its gate, when it actually ran, what it cost, or which build
-- produced it. So "is production failing" had no answer here — a collector holding
-- findings and no verdicts cannot tell a failing run from one whose findings a
-- baseline waived.

alter table submissions
    add column run_id             text,
    add column started_at         timestamptz,
    add column completed_at       timestamptz,
    add column tool_version       text,
    -- 'pass' | 'fail' | 'indeterminate', or null for "the agent did not say".
    -- Null is never folded into passing: a fleet with one old agent must not read
    -- as green because the old agent could not speak.
    add column gate               text,
    add column evidence_mode      text,
    add column requests           integer,
    add column input_tokens       integer,
    add column output_tokens      integer,
    add column wall_time_seconds  double precision;

-- What links this sighting to the same finding in another run. Computed by the
-- engine (`guardana.core.diff.finding_identity`), never here: the collector does
-- not depend on guardana-core, so recomputing it would put a second definition of
-- "the same finding" in a package that cannot import the first.
alter table findings add column identity text;

-- A retried pipeline job re-sends its run. Without this that is two runs in the
-- history and twice the findings, and "production got worse" answers from a
-- duplicate. Partial, because a pre-v7 agent sends no run id and nothing
-- identifies those runs — storing each of them is the honest behaviour.
create unique index submissions_project_run_idx
    on submissions (project_id, run_id) where run_id is not null;

create index findings_identity_idx on findings (identity) where identity is not null;
