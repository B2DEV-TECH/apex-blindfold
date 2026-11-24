-- APEX Blindfold: election API.
-- Every server-side action of the lab goes through this package: the APEX
-- Ajax callbacks call it, and so do the automated tests.

create or replace package bf_election authid definer as

  c_err_no_key        constant pls_integer := -20001;
  c_err_bad_key       constant pls_integer := -20002;
  c_err_unknown_voter constant pls_integer := -20003;
  c_err_already_voted constant pls_integer := -20004;
  c_err_malformed     constant pls_integer := -20005;
  c_err_invalid_proof constant pls_integer := -20006;
  c_err_bad_signature constant pls_integer := -20007;
  c_err_registration  constant pls_integer := -20008;
  c_err_broken_chain  constant pls_integer := -20009;

  e_no_key        exception;
  e_bad_key       exception;
  e_unknown_voter exception;
  e_already_voted exception;
  e_malformed     exception;
  e_invalid_proof exception;
  e_bad_signature exception;
  e_registration  exception;
  e_broken_chain  exception;

  pragma exception_init(e_no_key,        -20001);
  pragma exception_init(e_bad_key,       -20002);
  pragma exception_init(e_unknown_voter, -20003);
  pragma exception_init(e_already_voted, -20004);
  pragma exception_init(e_malformed,     -20005);
  pragma exception_init(e_invalid_proof, -20006);
  pragma exception_init(e_bad_signature, -20007);
  pragma exception_init(e_registration,  -20008);
  pragma exception_init(e_broken_chain,  -20009);

  -- Publishes the election public key (the Paillier modulus n, lower-case
  -- hexadecimal, 512 to 2048 bits) and starts a new election with a new number.
  -- The voter roll is rebuilt with p_voter_count codes (VOTER-0001, VOTER-0002, ...).
  -- The ballots of earlier elections stay where they are: the ballot tables are
  -- blockchain tables and nothing can be removed from them. Uses TRUNCATE on the
  -- roll, so it commits.
  procedure open_election (
    p_n_hex       in varchar2,
    p_voter_count in pls_integer default 20
  );

  -- The published modulus n, or null when no election is open.
  function public_key return varchar2;

  -- The number of the current election, or null when none is open.
  function election_id return number;

  -- Registers the public key of a voter (ECDSA P-256, SubjectPublicKeyInfo in
  -- lower-case hexadecimal) and reserves a ballot number for that voter. The
  -- proofs and the signature are bound to that number, so the browser needs it
  -- before it can build the ballot. A voter code takes one key, once: asking
  -- again with the same key returns the same number, with another key it fails.
  -- The caller commits.
  function register_voter (
    p_voter_id   in varchar2,
    p_public_key in varchar2
  ) return number;

  -- Stores one ballot: one ciphertext and one bit proof per candidate, in
  -- candidate order, the sum proof and the voter signature. Before anything is
  -- stored, the proofs and the signature are verified; a ballot that fails is
  -- rejected with the reason. Marks the voter as having voted. Returns the
  -- ballot number. The caller commits.
  function cast_ballot (
    p_voter_id  in varchar2,
    p_ballot_id in number,
    p_enc_1     in varchar2,
    p_enc_2     in varchar2,
    p_enc_3     in varchar2,
    p_proof_1   in varchar2,
    p_proof_2   in varchar2,
    p_proof_3   in varchar2,
    p_proof_sum in varchar2,
    p_signature in varchar2
  ) return number;

  -- Verifies the hash chains of the two ballot tables. Returns JSON with the
  -- number of rows verified in each: {"blind_ballots": N, "ballot_seals": M}.
  -- Raises c_err_broken_chain when the database reports a broken chain.
  function verify_chains return varchar2;

  -- Homomorphic tally of the current election. First the chains are verified.
  -- Then every ballot has its proofs and signature verified again, and only
  -- those that pass are multiplied in. Returns JSON:
  -- {"chain": {...}, "election_id": E, "ballot_rows": N, "ballots_counted": C,
  --  "ballots_rejected": R, "rejected": [{"ballot_id", "voter_id", "reason"}],
  --  "totals": [{"candidate_id": 1, "total_enc": "..."}, ...]}
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

  function election_id return number is
    v_election_id election_key.election_id%type;
  begin
    select max(election_id) into v_election_id from election_key;
    return v_election_id;
  end election_id;

  function public_key return varchar2 is
    v_n_hex election_key.n_hex%type;
  begin
    select max(n_hex) keep (dense_rank last order by election_id) into v_n_hex from election_key;
    return v_n_hex;
  end public_key;

  procedure assert_open (p_n_hex in varchar2) is
  begin
    if p_n_hex is null then
      raise_application_error(c_err_no_key, 'No election is open: no public key has been published.');
    end if;
  end assert_open;

  -- Upper bound for a ciphertext: n^2, at the fixed ciphertext width.
  function n_squared_hex (p_n_hex in varchar2) return varchar2 is
  begin
    assert_open(p_n_hex);
    if g_cached_n_hex is null or g_cached_n_hex <> p_n_hex then
      g_cached_n2_hex := bf_square_hex(p_n_hex);
      g_cached_n_hex  := p_n_hex;
    end if;
    return g_cached_n2_hex;
  end n_squared_hex;

  -- The shape of a ciphertext: hexadecimal, fixed width, 0 < c < n^2.
  -- What it encrypts is the business of the proofs.
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

  function clean_voter_id (p_voter_id in varchar2) return varchar2 is
  begin
    return upper(trim(substr(p_voter_id, 1, 30)));
  end clean_voter_id;

  procedure open_election (
    p_n_hex       in varchar2,
    p_voter_count in pls_integer default 20
  ) is
  begin
    -- A modulus between 512 and 2048 bits, in whole bytes, with an odd value.
    -- The validity proofs use a 128-bit challenge, which must be smaller than
    -- both primes of the modulus: 512 bits is the floor.
    if not is_lower_hex(p_n_hex)
       or length(p_n_hex) not between 128 and 512
       or mod(length(p_n_hex), 2) <> 0
       or substr(p_n_hex, 1, 1) = '0'
       or substr(p_n_hex, -1) not in ('1', '3', '5', '7', '9', 'b', 'd', 'f')
    then
      raise_application_error(c_err_bad_key,
        'Bad public key: expected an odd modulus of 512 to 2048 bits in lower-case hexadecimal.');
    end if;
    if p_voter_count is null or p_voter_count not between 1 and 100000 then
      raise_application_error(c_err_bad_key, 'The number of voters must be between 1 and 100000.');
    end if;

    execute immediate 'truncate table voter_roll';
    execute immediate 'alter sequence blind_ballots_seq restart start with 1';

    insert into election_key (election_id, n_hex) values (election_seq.nextval, p_n_hex);

    -- VOTER-0001, VOTER-0002, ... at least four digits, and as many as the
    -- number needs: a fixed format mask would turn voter 10000 into '#####'.
    insert into voter_roll (voter_id)
    select 'VOTER-' || lpad(to_char(level), greatest(4, length(to_char(level))), '0')
      from dual
   connect by level <= p_voter_count;

    commit;
  end open_election;

  function register_voter (
    p_voter_id   in varchar2,
    p_public_key in varchar2
  ) return number is
    v_voter_id voter_roll.voter_id%type := clean_voter_id(p_voter_id);
    v_roll     voter_roll%rowtype;
    v_verdict  varchar2(400);
  begin
    assert_open(public_key);

    begin
      select * into v_roll from voter_roll where voter_id = v_voter_id for update;
    exception
      when no_data_found then
        raise_application_error(c_err_unknown_voter, 'Unknown voter code.');
    end;

    if v_roll.voted_at is not null then
      raise_application_error(c_err_already_voted, 'This voter code has already been used.');
    end if;

    if v_roll.public_key is not null then
      if v_roll.public_key = p_public_key then
        return v_roll.ballot_id; -- the same browser asking again
      end if;
      raise_application_error(c_err_registration,
        'This voter code already has a key, registered by another browser tab. A voter code takes one key, once.');
    end if;

    if p_public_key is null or length(p_public_key) > 256 then
      raise_application_error(c_err_registration, 'Malformed voter public key.');
    end if;
    v_verdict := bf_v2_check_public_key(p_public_key);
    if v_verdict <> 'OK' then
      raise_application_error(c_err_registration, 'Voter public key refused: ' || substr(v_verdict, 6) || '.');
    end if;

    update voter_roll
       set public_key    = p_public_key,
           ballot_id     = blind_ballots_seq.nextval,
           registered_at = systimestamp
     where voter_id = v_voter_id
    returning ballot_id into v_roll.ballot_id;

    return v_roll.ballot_id;
  end register_voter;

  function cast_ballot (
    p_voter_id  in varchar2,
    p_ballot_id in number,
    p_enc_1     in varchar2,
    p_enc_2     in varchar2,
    p_enc_3     in varchar2,
    p_proof_1   in varchar2,
    p_proof_2   in varchar2,
    p_proof_3   in varchar2,
    p_proof_sum in varchar2,
    p_signature in varchar2
  ) return number is
    v_n_hex       election_key.n_hex%type := public_key;
    v_n2_hex      varchar2(1024) := n_squared_hex(v_n_hex);
    v_election_id election_key.election_id%type := election_id;
    v_voter_id    voter_roll.voter_id%type := clean_voter_id(p_voter_id);
    v_roll        voter_roll%rowtype;
    v_verdict     varchar2(400);
    v_candidates  sys.odcinumberlist   := sys.odcinumberlist(1, 2, 3);
    v_encrypted   sys.odcivarchar2list := sys.odcivarchar2list(p_enc_1, p_enc_2, p_enc_3);
    v_proofs      sys.odcivarchar2list := sys.odcivarchar2list(p_proof_1, p_proof_2, p_proof_3);
  begin
    for i in 1 .. v_encrypted.count loop
      assert_well_formed(v_encrypted(i), v_n2_hex);
    end loop;

    -- One ballot per registered voter, under the number reserved for that voter.
    begin
      select * into v_roll from voter_roll where voter_id = v_voter_id for update;
    exception
      when no_data_found then
        raise_application_error(c_err_unknown_voter, 'Unknown voter code.');
    end;
    if v_roll.voted_at is not null then
      raise_application_error(c_err_already_voted, 'This voter code has already been used.');
    end if;
    if v_roll.public_key is null then
      raise_application_error(c_err_bad_signature, 'Unsigned ballot: this voter code has no registered key.');
    end if;
    if p_ballot_id is null or v_roll.ballot_id <> p_ballot_id then
      raise_application_error(c_err_invalid_proof, 'Ballot rejected: this is not the ballot number reserved for this voter code.');
    end if;

    -- The proofs: every ciphertext encrypts 0 or 1, and together they encrypt 1.
    v_verdict := bf_v2_verify_ballot(v_n_hex, v_election_id, p_ballot_id,
                                     p_enc_1, p_enc_2, p_enc_3, p_proof_1, p_proof_2, p_proof_3, p_proof_sum);
    if v_verdict <> 'OK' then
      raise_application_error(c_err_invalid_proof, 'Ballot rejected, invalid proof: ' || substr(v_verdict, 6) || '.');
    end if;

    -- The signature: the whole ballot, signed with the key this voter registered.
    if p_signature is null then
      raise_application_error(c_err_bad_signature, 'Unsigned ballot.');
    end if;
    v_verdict := bf_v2_verify_signature(v_roll.public_key, p_signature, v_n_hex, v_election_id, p_ballot_id, v_voter_id,
                                        p_enc_1, p_enc_2, p_enc_3, p_proof_1, p_proof_2, p_proof_3, p_proof_sum);
    if v_verdict <> 'OK' then
      raise_application_error(c_err_bad_signature, 'Ballot rejected, signature: ' || substr(v_verdict, 6) || '.');
    end if;

    update voter_roll set voted_at = systimestamp where voter_id = v_voter_id;

    forall i in 1 .. v_encrypted.count
      insert into blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof)
      values (v_election_id, p_ballot_id, v_candidates(i), v_encrypted(i), v_proofs(i));

    insert into ballot_seals (election_id, ballot_id, voter_id, sum_proof, signature)
    values (v_election_id, p_ballot_id, v_voter_id, p_proof_sum, p_signature);

    return p_ballot_id;
  end cast_ballot;

  function verify_chains return varchar2 is
    v_schema  varchar2(128) := sys_context('userenv', 'current_schema');
    v_ballots number;
    v_seals   number;
  begin
    begin
      dbms_blockchain_table.verify_rows(
        schema_name             => v_schema,
        table_name              => 'BLIND_BALLOTS',
        number_of_rows_verified => v_ballots,
        verify_signature        => false);
      dbms_blockchain_table.verify_rows(
        schema_name             => v_schema,
        table_name              => 'BALLOT_SEALS',
        number_of_rows_verified => v_seals,
        verify_signature        => false);
    exception
      when others then
        -- Whatever the database reports here means the chain cannot be trusted:
        -- the tally stops and the caller sees the original error.
        raise_application_error(c_err_broken_chain,
          'The chain of the ballot tables could not be verified: ' || sqlerrm, true);
    end;
    return '{"blind_ballots":' || v_ballots || ',"ballot_seals":' || v_seals || '}';
  end verify_chains;

  function encrypted_tally return varchar2 is
    v_chain varchar2(200);
  begin
    assert_open(public_key);
    v_chain := verify_chains;
    -- The tally is JSON that starts with "{": the chain report goes in front.
    return '{"chain":' || v_chain || ',' || substr(bf_blind_tally, 2);
  end encrypted_tally;

end bf_election;
/
