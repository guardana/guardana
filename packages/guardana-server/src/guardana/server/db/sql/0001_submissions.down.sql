-- `findings` first: it references `submissions`, and dropping in the other order
-- would depend on cascade behaviour rather than on this file saying what it means.
drop table if exists findings;
drop table if exists submissions;
