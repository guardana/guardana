-- Retries of every run are answered as duplicates again, whatever they carry.
alter table submissions drop column if exists content_digest;
