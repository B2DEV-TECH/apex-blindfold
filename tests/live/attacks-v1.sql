-- APEX Blindfold, live session of Layer 2, part A: the attacks of the DBA by hand, on tag v1-layer1.
--
-- Run each section in its own shot, as the lab's DBA account, in a SQL tool that was connected
-- BEFORE the recording started (the connection shows an account name and a host).
-- BLINDFOLD is the default schema of the lab (scripts/db.example.json). If yours has another name,
-- change it here before the session, not on camera.
--
-- Layer 1 tables: BLIND_BALLOTS (ballot_id, candidate_id, vote_enc), VOTER_ROLL (voter_id, voted_at).
-- The ballot numbers below assume six honest ballots, 1 to 6, in a freshly opened election.

-- Shot 13. Re-link voters to ballots: the order of VOTER_ROLL.voted_at against the order of the
-- ballot numbers. Read-only.
select r.voter_id, b.ballot_id
  from (select voter_id, row_number() over (order by voted_at) as position
          from blindfold.voter_roll
         where voted_at is not null) r
  join (select ballot_id, row_number() over (order by ballot_id) as position
          from (select distinct ballot_id from blindfold.blind_ballots)) b
    on b.position = r.position
 order by b.ballot_id;

-- Shot 14. Move a vote: ballot 1 trades its ciphertexts for A and B. One statement.
update blindfold.blind_ballots
   set candidate_id = case candidate_id when 1 then 2 when 2 then 1 end
 where ballot_id = 1
   and candidate_id in (1, 2);
commit;

-- Shot 15. Delete a ballot.
delete from blindfold.blind_ballots where ballot_id = 2;
commit;

-- Shot 16. Copy a stored ballot: ballot 3 again, as ballot 900, without a voter.
insert into blindfold.blind_ballots (ballot_id, candidate_id, vote_enc)
select 900, candidate_id, vote_enc
  from blindfold.blind_ballots
 where ballot_id = 3;
commit;

-- Shot 17. Disable the primary key, then store the three rows of ballot 4 a second time.
alter table blindfold.blind_ballots disable constraint blind_ballots_pk;
insert into blindfold.blind_ballots (ballot_id, candidate_id, vote_enc)
select ballot_id, candidate_id, vote_enc
  from blindfold.blind_ballots
 where ballot_id = 4;
commit;

-- Shot 18. Find voter codes that have not voted. One of them is used on the Vote page.
select voter_id from blindfold.voter_roll where voted_at is null order by voter_id;
