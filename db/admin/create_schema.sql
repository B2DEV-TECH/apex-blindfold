-- APEX Blindfold: one-time prerequisites. Run as a DBA inside the PDB.
--
-- Creates
--   1. the application owner (parsing schema), with the smallest set of
--      privileges the lab needs;
--   2. a separate "curious DBA" account that the audits use when they try to
--      read votes they should not be able to read;
--   3. an APEX workspace on the owner schema, plus one developer account.
--      The application itself has no login: every page is public.
--
-- The caller defines these substitution variables before running the script:
--   BF_SCHEMA, BF_SCHEMA_PW, BF_DBA, BF_DBA_PW,
--   BF_WORKSPACE, BF_WS_ADMIN, BF_WS_ADMIN_PW
--
-- Privileges for MLE JavaScript (verified in evidence/00-environment):
--   CREATE MLE             to create the MLE module
--   CREATE PROCEDURE       to create the PL/SQL call specification
--   EXECUTE ON JAVASCRIPT  to run JavaScript at all

create user &&BF_SCHEMA identified by "&&BF_SCHEMA_PW"
  default tablespace users quota 2G on users;

grant create session, create table, create sequence, create procedure, create mle
  to &&BF_SCHEMA;
grant execute on javascript to &&BF_SCHEMA;

-- The auditor persona: full DBA rights, no knowledge of any private key.
create user &&BF_DBA identified by "&&BF_DBA_PW";
grant dba to &&BF_DBA;
-- JAVASCRIPT is a SYS-owned MLE language, so the DBA role alone cannot grant it.
-- The Step 0 privilege probe needs to hand it to a throwaway user.
grant execute on javascript to &&BF_DBA with grant option;

begin
  apex_instance_admin.add_workspace(
    p_workspace      => '&&BF_WORKSPACE',
    p_primary_schema => '&&BF_SCHEMA');
  apex_util.set_security_group_id(apex_util.find_security_group_id('&&BF_WORKSPACE'));
  apex_util.create_user(
    p_user_name                    => '&&BF_WS_ADMIN',
    p_email_address                => 'blindfold@example.invalid',
    p_web_password                 => '&&BF_WS_ADMIN_PW',
    p_developer_privs              => 'ADMIN:CREATE:DATA_LOADER:EDIT:HELP:MONITOR:SQL',
    p_change_password_on_first_use => 'N');
  commit;
end;
/
