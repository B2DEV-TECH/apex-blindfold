-- APEX Blindfold: Ajax callbacks of the APEX application.
-- Each procedure reads the request from APEX_APPLICATION and prints one JSON
-- document. The pages contain no logic of their own: they call this package.

create or replace package bf_web authid definer as

  -- Public. The published key, the candidates and the public counters.
  procedure election_info;

  -- Public. x01 = voter code, x02 = the voter's public key.
  -- Answers with the election number and the ballot number reserved for the voter.
  procedure register_voter;

  -- Public. x01 = voter code, x02 = ballot number, x03 = sum proof, x04 = signature,
  -- f01 = three ciphertexts and f02 = three bit proofs, in candidate order.
  -- The voter's choice is not a parameter: the server never receives it.
  procedure cast_ballot;

  -- Authority only. x01 = modulus n (hexadecimal), x02 = number of voters.
  procedure open_election;

  -- Authority only. One encrypted total per candidate.
  procedure encrypted_tally;

end bf_web;
/

create or replace package body bf_web as

  procedure print_error (
    p_code    in pls_integer,
    p_message in varchar2
  ) is
  begin
    apex_json.open_object;
    apex_json.write('ok', false);
    apex_json.write('code', p_code);
    -- "ORA-20003: Unknown voter code." becomes "Unknown voter code."
    apex_json.write('message', regexp_replace(p_message, '^ORA-[0-9]+: '));
    apex_json.close_object;
  end print_error;

  procedure write_counters is
    v_registered pls_integer;
    v_turnout    pls_integer;
    v_rows       pls_integer;
  begin
    select count(*), count(voted_at)
      into v_registered, v_turnout
      from voter_roll;

    select count(*) into v_rows from blind_ballots where election_id = bf_election.election_id;

    apex_json.write('registered', v_registered);
    apex_json.write('turnout', v_turnout);
    apex_json.write('ballot_rows', v_rows);
  end write_counters;

  procedure election_info is
  begin
    apex_json.open_object;
    apex_json.write('ok', true);
    apex_json.write('n_hex', bf_election.public_key, true);
    apex_json.write('election_id', bf_election.election_id, true);
    apex_json.open_array('candidates');
    for r_candidate in (
      select candidate_id, label, tag
        from candidates
       order by candidate_id
    ) loop
      apex_json.open_object;
      apex_json.write('id', r_candidate.candidate_id);
      apex_json.write('label', r_candidate.label);
      apex_json.write('tag', r_candidate.tag);
      apex_json.close_object;
    end loop;
    apex_json.close_array;
    write_counters;
    apex_json.close_object;
  end election_info;

  procedure register_voter is
    v_ballot_id blind_ballots.ballot_id%type;
  begin
    v_ballot_id := bf_election.register_voter(
      p_voter_id   => apex_application.g_x01,
      p_public_key => apex_application.g_x02);
    -- The reservation must outlive this request: the ballot arrives in the next one.
    commit;

    apex_json.open_object;
    apex_json.write('ok', true);
    apex_json.write('election_id', bf_election.election_id);
    apex_json.write('ballot_id', v_ballot_id);
    apex_json.close_object;
  exception
    when bf_election.e_no_key
      or bf_election.e_unknown_voter
      or bf_election.e_already_voted
      or bf_election.e_registration
    then
      print_error(sqlcode, sqlerrm);
  end register_voter;

  procedure cast_ballot is
    v_ballot_id blind_ballots.ballot_id%type;
  begin
    if apex_application.g_f01.count <> 3 or apex_application.g_f02.count <> 3 then
      print_error(bf_election.c_err_malformed, 'A ballot must carry exactly three ciphertexts and three bit proofs.');
      return;
    end if;

    v_ballot_id := bf_election.cast_ballot(
      p_voter_id  => apex_application.g_x01,
      p_ballot_id => to_number(apex_application.g_x02 default null on conversion error),
      p_enc_1     => apex_application.g_f01(1),
      p_enc_2     => apex_application.g_f01(2),
      p_enc_3     => apex_application.g_f01(3),
      p_proof_1   => apex_application.g_f02(1),
      p_proof_2   => apex_application.g_f02(2),
      p_proof_3   => apex_application.g_f02(3),
      p_proof_sum => apex_application.g_x03,
      p_signature => apex_application.g_x04);

    apex_json.open_object;
    apex_json.write('ok', true);
    apex_json.write('ballot_id', v_ballot_id);
    apex_json.close_object;
  exception
    when bf_election.e_no_key
      or bf_election.e_unknown_voter
      or bf_election.e_already_voted
      or bf_election.e_malformed
      or bf_election.e_invalid_proof
      or bf_election.e_bad_signature
    then
      print_error(sqlcode, sqlerrm);
  end cast_ballot;

  procedure open_election is
    v_voter_count pls_integer;
  begin
    v_voter_count := to_number(apex_application.g_x02 default null on conversion error);

    bf_election.open_election(
      p_n_hex       => apex_application.g_x01,
      p_voter_count => v_voter_count);

    apex_json.open_object;
    apex_json.write('ok', true);
    write_counters;
    apex_json.close_object;
  exception
    when bf_election.e_bad_key then
      print_error(sqlcode, sqlerrm);
  end open_election;

  procedure encrypted_tally is
    v_tally varchar2(32767);
  begin
    v_tally := bf_election.encrypted_tally;

    apex_json.open_object;
    apex_json.write('ok', true);
    write_counters;
    -- The tally is already JSON: embed it as is.
    apex_json.write_raw('tally', v_tally);
    apex_json.close_object;
  exception
    when bf_election.e_no_key
      or bf_election.e_broken_chain
    then
      print_error(sqlcode, sqlerrm);
  end encrypted_tally;

end bf_web;
/
