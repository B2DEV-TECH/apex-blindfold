-- APEX Blindfold: election API.
-- Every server-side action of the lab goes through this package: the APEX
-- Ajax callbacks call it, and so do the automated tests.

create or replace package bf_election authid definer as

  c_err_no_key        constant pls_integer := -20001;
  c_err_bad_key       constant pls_integer := -20002;
  c_err_unknown_voter constant pls_integer := -20003;
  c_err_already_voted constant pls_integer := -20004;
  c_err_malformed     constant pls_integer := -20005;

  e_no_key        exception;
  e_bad_key       exception;
  e_unknown_voter exception;
  e_already_voted exception;
  e_malformed     exception;

  pragma exception_init(e_no_key,        -20001);
  pragma exception_init(e_bad_key,       -20002);
  pragma exception_init(e_unknown_voter, -20003);
  pragma exception_init(e_already_voted, -20004);
  pragma exception_init(e_malformed,     -20005);

  -- Publishes the election public key (the Paillier modulus n, lower-case
  -- hexadecimal) and starts a new election: every ballot is removed and the
  -- voter roll is rebuilt with p_voter_count codes (VOTER-0001, VOTER-0002, ...).
  -- Uses TRUNCATE, so it commits.
  procedure open_election (
    p_n_hex       in varchar2,
    p_voter_count in pls_integer default 20
  );

  -- The published modulus n, or null when no election is open.
  function public_key return varchar2;

  -- Stores one ballot: one ciphertext per candidate, in candidate order.
  -- Marks the voter as having voted. Returns the new ballot id.
  -- The caller commits.
  function cast_ballot (
    p_voter_id in varchar2,
    p_enc_1    in varchar2,
    p_enc_2    in varchar2,
    p_enc_3    in varchar2
  ) return number;

  -- Homomorphic tally. Returns JSON with one encrypted total per candidate:
  -- {"ballot_rows": N, "totals": [{"candidate_id": 1, "total_enc": "..."}, ...]}
  function encrypted_tally return varchar2;

end bf_election;
/

create or replace package body bf_election as

  c_hex_digits constant varchar2(16) := '0123456789abcdef';

  -- n^2 in hexadecimal for the current key, cached for the session.
  g_cached_n_hex  election_key.n_hex%type;
  g_cached_n2_hex varchar2(1024);

  function is_lower_hex (p_text in varchar2) return boolean is
  begin
    return p_text is not null and ltrim(p_text, c_hex_digits) is null;
  end is_lower_hex;

  function public_key return varchar2 is
    v_n_hex election_key.n_hex%type;
  begin
    select max(n_hex) into v_n_hex from election_key;
    return v_n_hex;
  end public_key;

  -- Upper bound for a ciphertext: n^2, at the fixed ciphertext width.
  function n_squared_hex return varchar2 is
    v_n_hex election_key.n_hex%type := public_key;
  begin
    if v_n_hex is null then
      raise_application_error(c_err_no_key, 'No election is open: no public key has been published.');
    end if;
    if g_cached_n_hex is null or g_cached_n_hex <> v_n_hex then
      g_cached_n2_hex := bf_square_hex(v_n_hex);
      g_cached_n_hex  := v_n_hex;
    end if;
    return g_cached_n2_hex;
  end n_squared_hex;

  -- The server can check the shape of a ciphertext: hexadecimal, fixed width,
  -- 0 < c < n^2. It cannot check what the ciphertext encrypts.
  procedure assert_well_formed (
    p_enc    in varchar2,
    p_n2_hex in varchar2
  ) is
  begin
    if p_enc is null
       or length(p_enc) <> length(p_n2_hex)
       or not is_lower_hex(p_enc)
       or p_enc >= p_n2_hex
       or ltrim(p_enc, '0') is null
    then
      raise_application_error(c_err_malformed,
        'Malformed ciphertext: expected ' || length(p_n2_hex) || ' lower-case hexadecimal characters, with 0 < c < n^2.');
    end if;
  end assert_well_formed;

  procedure open_election (
    p_n_hex       in varchar2,
    p_voter_count in pls_integer default 20
  ) is
  begin
    -- A modulus between 256 and 2048 bits, in whole bytes, with an odd value.
    if not is_lower_hex(p_n_hex)
       or length(p_n_hex) not between 64 and 512
       or mod(length(p_n_hex), 2) <> 0
       or substr(p_n_hex, 1, 1) = '0'
       or substr(p_n_hex, -1) not in ('1', '3', '5', '7', '9', 'b', 'd', 'f')
    then
      raise_application_error(c_err_bad_key,
        'Bad public key: expected an odd modulus of 256 to 2048 bits in lower-case hexadecimal.');
    end if;
    if p_voter_count is null or p_voter_count not between 1 and 100000 then
      raise_application_error(c_err_bad_key, 'The number of voters must be between 1 and 100000.');
    end if;

    execute immediate 'truncate table blind_ballots';
    execute immediate 'truncate table voter_roll';
    execute immediate 'alter sequence blind_ballots_seq restart start with 1';

    delete from election_key;
    insert into election_key (n_hex) values (p_n_hex);

    -- VOTER-0001, VOTER-0002, ... at least four digits, and as many as the
    -- number needs: a fixed format mask would turn voter 10000 into '#####'.
    insert into voter_roll (voter_id)
    select 'VOTER-' || lpad(to_char(level), greatest(4, length(to_char(level))), '0')
      from dual
   connect by level <= p_voter_count;

    commit;
  end open_election;

  function cast_ballot (
    p_voter_id in varchar2,
    p_enc_1    in varchar2,
    p_enc_2    in varchar2,
    p_enc_3    in varchar2
  ) return number is
    v_n2_hex     varchar2(1024) := n_squared_hex;
    v_voter_id   voter_roll.voter_id%type := upper(trim(substr(p_voter_id, 1, 30)));
    v_known      pls_integer;
    v_ballot_id  blind_ballots.ballot_id%type;
    v_candidates sys.odcinumberlist   := sys.odcinumberlist(1, 2, 3);
    v_encrypted  sys.odcivarchar2list := sys.odcivarchar2list(p_enc_1, p_enc_2, p_enc_3);
  begin
    for i in 1 .. v_encrypted.count loop
      assert_well_formed(v_encrypted(i), v_n2_hex);
    end loop;

    -- One ballot per registered voter.
    update voter_roll
       set voted_at = systimestamp
     where voter_id = v_voter_id
       and voted_at is null;

    if sql%rowcount = 0 then
      select count(*) into v_known from voter_roll where voter_id = v_voter_id;
      if v_known = 0 then
        raise_application_error(c_err_unknown_voter, 'Unknown voter code.');
      end if;
      raise_application_error(c_err_already_voted, 'This voter code has already been used.');
    end if;

    v_ballot_id := blind_ballots_seq.nextval;

    forall i in 1 .. v_encrypted.count
      insert into blind_ballots (ballot_id, candidate_id, vote_enc)
      values (v_ballot_id, v_candidates(i), v_encrypted(i));

    return v_ballot_id;
  end cast_ballot;

  function encrypted_tally return varchar2 is
  begin
    if public_key is null then
      raise_application_error(c_err_no_key, 'No election is open: no public key has been published.');
    end if;
    return bf_blind_tally;
  end encrypted_tally;

end bf_election;
/
