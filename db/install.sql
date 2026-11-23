-- APEX Blindfold: installs the database objects into the current schema.
-- Run with SQLcl or SQL*Plus, connected as the application owner:
--
--   SQL> @db/install.sql
--
-- The schema needs: CREATE SESSION, CREATE TABLE, CREATE SEQUENCE,
-- CREATE PROCEDURE and a quota on its tablespace (see db/admin/create_schema.sql).

whenever sqlerror exit failure rollback
set define off

prompt == tables
@@01_tables.sql

prompt == blind tally (Java stored procedure)
@@02_blind_tally_java.sql

prompt == package bf_election
@@03_bf_election.sql

prompt == package bf_web (APEX Ajax callbacks)
@@04_bf_web.sql

prompt == checking for invalid objects
declare
  v_invalid pls_integer;
begin
  select count(*) into v_invalid from user_objects where status <> 'VALID';
  if v_invalid > 0 then
    for r_error in (
      select name, type, line, text
        from user_errors
       order by name, type, sequence
    ) loop
      dbms_output.put_line(r_error.type || ' ' || r_error.name || ' line ' || r_error.line || ': ' || r_error.text);
    end loop;
    raise_application_error(-20000, v_invalid || ' invalid object(s) after installation.');
  end if;
end;
/

prompt == APEX Blindfold database objects installed
