-- Rolling this back destroys the audit log itself, which is the one table whose
-- loss cannot be reconstructed from anything else the collector holds: the
-- submissions and findings stay, and no record of who touched them survives.
--
-- It also drops each project's retention policy, so a collector that was pruning
-- silently stops — and drops the link from a submission to the key that wrote it.
--
-- Take a backup first (`docs/deployment.md`), and if the reason for rolling back
-- is a bad deployment rather than a bad schema, roll the *image* back instead.
drop index if exists audit_events_project_idx;
drop index if exists audit_events_occurred_idx;
drop table if exists audit_events;

alter table projects drop constraint if exists projects_retention_is_positive;
alter table projects drop column if exists retention_days;
alter table submissions drop column if exists api_key_id;
