-- Credentials for the agents that write into this collector.
--
-- `secret_hash` is a digest, never the key. A collector database is a list of
-- every security finding an organisation has; a stolen backup must not also be a
-- set of working credentials for the thing that produced them.
--
-- `prefix` is stored in the clear on purpose. It is the part of the key printed
-- in `key list` and safe to put in a log line, so a key can be named, audited and
-- revoked without anybody ever needing to see the secret again.

create table api_keys (
    id            bigserial    primary key,
    -- What a person calls it: "github-actions", "nightly-monitor".
    name          text         not null,
    prefix        text         not null unique,
    secret_hash   text         not null,
    -- 'ingest' writes runs; 'read' browses them. Two, because a CI job needs to
    -- write and never to browse, and one scope covering both would make every
    -- pipeline credential a full read of the finding history.
    scopes        text[]       not null,
    created_at    timestamptz  not null default now(),
    created_by    text,
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    expires_at    timestamptz
);

create index api_keys_prefix_idx on api_keys (prefix);
