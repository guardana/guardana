-- What a stored run holds, as a digest, so a retry that carries other content under
-- the same run id is refused instead of answered as a duplicate. Null for a run stored
-- before this column: a retry of it is answered as a duplicate whose content was not
-- compared.
alter table submissions add column content_digest text;
