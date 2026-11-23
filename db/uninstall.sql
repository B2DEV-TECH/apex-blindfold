-- APEX Blindfold: removes every database object of the lab from the current
-- schema. Safe to run on a schema where nothing is installed yet.

whenever sqlerror exit failure rollback
set define off

declare
  -- Objects created by install.sql and by the tests, in drop order.
  type t_statements is table of varchar2(200);
  v_statements t_statements := t_statements(
    'drop package if exists bf_web',
    'drop package if exists bf_election',
    'drop function if exists bf_blind_tally',
    'drop function if exists bf_square_hex',
    'drop table if exists blind_ballots purge',
    'drop table if exists voter_roll purge',
    'drop table if exists candidates purge',
    'drop table if exists election_key purge',
    'drop table if exists plain_ballots purge',
    'drop sequence if exists blind_ballots_seq'
  );
  v_java pls_integer;
begin
  for i in 1 .. v_statements.count loop
    execute immediate v_statements(i);
  end loop;

  -- DROP JAVA SOURCE has no IF EXISTS clause.
  select count(*)
    into v_java
    from user_objects
   where object_type = 'JAVA SOURCE'
     and object_name = 'BlindfoldTally';
  if v_java > 0 then
    execute immediate 'drop java source "BlindfoldTally"';
  end if;
end;
/

prompt == APEX Blindfold database objects removed
