-- This rollback loses every triage decision: statuses, owners, and every waiver
-- with its approver, reason and expiry date. The occurrences are untouched, so
-- nothing about what was *found* is lost, and re-applying 0006 rebuilds the table
-- from them — as `open`, because the decisions themselves are only here.
--
-- Said plainly because an operator should meet that cost before running the
-- command rather than after it. Take a backup first: `docs/deployment.md`.
drop index if exists tracked_findings_project_status_idx;
drop table if exists tracked_findings;
