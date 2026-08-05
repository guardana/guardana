-- Dropping the run's own facts loses information and merges no tenants, so this
-- rollback needs no refusal — but the submissions and their findings stay, minus
-- what they said about themselves.
drop index if exists submissions_project_run_idx;
drop index if exists findings_identity_idx;

alter table submissions
    drop column run_id,
    drop column started_at,
    drop column completed_at,
    drop column tool_version,
    drop column gate,
    drop column evidence_mode,
    drop column requests,
    drop column input_tokens,
    drop column output_tokens,
    drop column wall_time_seconds;

alter table findings drop column identity;
