-- Undoing this removes every credential. That is the correct behaviour and it is
-- worth saying out loud: rolling back past authentication leaves a collector with
-- no keys, which the application reads as "refuse everything" rather than as
-- "allow everything".
drop table if exists api_keys;
