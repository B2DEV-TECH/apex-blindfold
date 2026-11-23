-- APEX Blindfold: removes everything create_schema.sql created.
-- Run as a DBA inside the PDB. Define BF_SCHEMA, BF_DBA and BF_WORKSPACE first.

declare
  v_exists pls_integer;
begin
  select count(*)
    into v_exists
    from apex_workspaces
   where workspace = upper('&&BF_WORKSPACE');

  if v_exists > 0 then
    apex_instance_admin.remove_workspace(
      p_workspace        => upper('&&BF_WORKSPACE'),
      p_drop_users       => 'N',
      p_drop_tablespaces => 'N');
    commit;
  end if;
end;
/

drop user if exists &&BF_SCHEMA cascade;
drop user if exists &&BF_DBA cascade;
