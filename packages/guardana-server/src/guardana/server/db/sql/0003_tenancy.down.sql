-- A fourth thing the migration runner refuses, and the only one tied to a single
-- migration — because only this one can destroy an isolation boundary.
--
-- Counted over the union of both tables rather than per table: one project in the
-- submissions and another in the keys is still two tenants, and a per-table count
-- would see "one and one" and let the merge through.
do $$
declare
    tenants integer;
begin
    select count(*) into tenants from (
        select project_id from submissions
        union
        select project_id from api_keys
    ) as distinct_tenants;
    if tenants > 1 then
        raise exception 'refusing to roll back tenancy: this database holds data for more '
                        'than one project, and dropping the tenant column would merge them '
                        'into one undifferentiated pile';
    end if;
end $$;

-- The columns go first: they hold the foreign keys, and the composite indexes the
-- forward migration created go with them.
alter table submissions drop column project_id;
alter table api_keys    drop column project_id;

drop table projects;
drop table organizations;

-- Restored, because the forward migration dropped them. A rollback that leaves the
-- database missing what the previous migration created only half went backwards.
create index submissions_received_at_idx on submissions (received_at desc);
create index submissions_source_idx on submissions (source);
