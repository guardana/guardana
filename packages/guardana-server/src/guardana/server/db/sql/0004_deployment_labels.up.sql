-- What a run verified, where it runs, and which version of it.
--
-- Labels on a submission rather than three new tables. Today a run declares a
-- *slug* and nothing else, so an `ai_systems` row would hold that slug and a name
-- column nothing sets, and an `environments` row would hold a slug and nothing at
-- all — a row whose only column is the name it was created from is a table
-- pretending to be an entity. They become entities when they gain an owner, a
-- policy and a lifecycle, and the migration that promotes these labels then has
-- real data to build them from.

alter table submissions
    -- Which AI system this run verified. Declared, never guessed: a repository name
    -- is not an AI system (a monorepo has several) and a branch is not an
    -- environment.
    add column ai_system       text,
    add column environment     text,
    -- The run's own deployment identifier, or its commit when it gave no other. A
    -- run with neither identifies no deployment, and a surrogate would invent one
    -- "deployment" per run.
    add column deployment_ref  text,
    add column commit_sha      text,
    add column image_digest    text,
    add column model_digest    text,
    add column model_name      text,
    add column model_revision  text;

-- An optional pin. A pinned key writes and reads only this environment; an
-- unpinned one gets the whole project, as every key does today. Text rather than a
-- foreign key because it is an assertion by a credential, true whether or not any
-- run has yet reported against that environment — a foreign key would mean
-- creating a row to hold a name nobody has used.
alter table api_keys add column environment text;

-- Every column above is nullable, and null means "the run did not say" — never
-- "applies to everything". So nothing needs adopting: every submission already
-- stored *is* a run that did not say, which is exactly what null records.

-- The unpinned read stays the common one, and `(project_id, received_at desc)`
-- from 0003 still serves it: a composite led by (project_id, environment) cannot
-- order by received_at for a query that constrains only the project. Two indexes,
-- each for a shape of read that actually happens.
create index submissions_project_environment_idx
    on submissions (project_id, environment, received_at desc);
