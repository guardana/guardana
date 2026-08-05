-- Dropping a label loses information and merges no tenants, so unlike 0003 this
-- rollback needs no refusal. It must still not take the evidence with it: the
-- submissions stay, they simply stop saying what they verified and where.
--
-- The index goes with the column it leads on, so it is dropped explicitly rather
-- than left to cascade — this file says what it means.
drop index if exists submissions_project_environment_idx;

alter table submissions
    drop column ai_system,
    drop column environment,
    drop column deployment_ref,
    drop column commit_sha,
    drop column image_digest,
    drop column model_digest,
    drop column model_name,
    drop column model_revision;

alter table api_keys drop column environment;
