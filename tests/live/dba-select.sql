-- APEX Blindfold, live session, step 4: look for your own vote, as a DBA.
--
-- Run these as any account that can read the lab schema: SYSTEM, the lab's
-- DBA account, or SQL Workshop > SQL Commands in the lab's APEX workspace
-- (one statement at a time there). BLINDFOLD is the default schema name of
-- the lab; replace it if you installed under another one.

-- 1. Every stored ballot is three rows. Which row holds your vote?
select ballot_id, candidate_id, vote_enc
  from blindfold.blind_ballots
 order by ballot_id, candidate_id;

-- 2. What a GROUP BY tells about the result: nothing, every option has one row per ballot.
select candidate_id,
       count(*)                 as ciphertexts,
       count(distinct vote_enc) as distinct_values,
       min(length(vote_enc))    as shortest,
       max(length(vote_enc))    as longest
  from blindfold.blind_ballots
 group by candidate_id
 order by candidate_id;

-- 3. The turnout table: who voted, and when. No ballot id and no choice.
select voter_id, voted_at
  from blindfold.voter_roll
 order by voted_at nulls last, voter_id;

-- 4. The only key the database has is the public one.
select n_hex
  from blindfold.election_key;

-- 5. Is there anything else? Every column of every table the application owns.
select table_name, column_name, data_type, data_length
  from all_tab_columns
 where owner = 'BLINDFOLD'
 order by table_name, column_id;
