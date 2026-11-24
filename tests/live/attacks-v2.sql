-- APEX Blindfold, live session of Layer 2, part B: the attacks of the DBA by hand, on Layer 2.
--
-- Run each section in its own shot, as the lab's DBA account, in a SQL tool that was connected
-- BEFORE the recording started (the connection shows an account name and a host).
-- BLINDFOLD is the default schema of the lab (scripts/db.example.json). If yours has another name,
-- change it here before the session, not on camera.
--
-- Layer 2 tables: BLIND_BALLOTS and BALLOT_SEALS are blockchain tables, with an ELECTION_ID column.
-- The ballot numbers below assume six honest ballots, 1 to 6, in a freshly opened election: the
-- current election is the one with the highest number in ELECTION_KEY.

-- Shot 34. Re-link voters to ballots by the hidden insert time of the blockchain rows, without
-- reading BALLOT_SEALS. The last column is what the seal says, to compare. Read-only.
select r.voter_id as paired_voter, b.ballot_id, b.created,
       (select s.voter_id from blindfold.ballot_seals s
         where s.election_id = b.election_id and s.ballot_id = b.ballot_id) as seal_says
  from (select voter_id, row_number() over (order by voted_at) as position
          from blindfold.voter_roll
         where voted_at is not null) r
  join (select election_id, ballot_id, min(orabctab_creation_time$) as created,
               row_number() over (order by min(orabctab_creation_time$)) as position
          from blindfold.blind_ballots
         where election_id = (select max(election_id) from blindfold.election_key)
         group by election_id, ballot_id) b
    on b.position = r.position
 order by b.ballot_id;

-- Shot 35. Move a vote: the same statement as in part A, with the election.
update blindfold.blind_ballots
   set candidate_id = case candidate_id when 1 then 2 when 2 then 1 end
 where election_id = (select max(election_id) from blindfold.election_key)
   and ballot_id = 1
   and candidate_id in (1, 2);

-- Shot 36. Delete a ballot.
delete from blindfold.blind_ballots
 where election_id = (select max(election_id) from blindfold.election_key)
   and ballot_id = 2;

-- Shot 37. Copy a stored ballot: ballot 3 again, as ballot 900. First the ciphertexts and their
-- proofs, then the seal with the voter code and the signature.
insert into blindfold.blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof)
select election_id, 900, candidate_id, vote_enc, bit_proof
  from blindfold.blind_ballots
 where election_id = (select max(election_id) from blindfold.election_key)
   and ballot_id = 3;
insert into blindfold.ballot_seals (election_id, ballot_id, voter_id, sum_proof, signature)
select election_id, 900, voter_id, sum_proof, signature
  from blindfold.ballot_seals
 where election_id = (select max(election_id) from blindfold.election_key)
   and ballot_id = 3;
commit;

-- Shot 39. Take over a voter code that registered a key in another browser and did not vote.
update blindfold.voter_roll
   set public_key = null,
       ballot_id = null,
       registered_at = null
 where voter_id = 'VOTER-0007'
   and voted_at is null;
commit;

-- Shot 40. Drop both ballot tables, rebuild them and copy back every ballot but ballot 1.
create table blindfold.bf_copy_ballots as
select election_id, ballot_id, candidate_id, vote_enc, bit_proof
  from blindfold.blind_ballots
 where not (election_id = (select max(election_id) from blindfold.election_key) and ballot_id = 1);
create table blindfold.bf_copy_seals as
select election_id, ballot_id, voter_id, sum_proof, signature
  from blindfold.ballot_seals
 where not (election_id = (select max(election_id) from blindfold.election_key) and ballot_id = 1);

drop table blindfold.ballot_seals purge;
drop table blindfold.blind_ballots purge;

create blockchain table blindfold.blind_ballots (
  election_id  number         not null,
  ballot_id    number         not null,
  candidate_id number(1)      not null,
  vote_enc     varchar2(1024) not null,
  bit_proof    varchar2(1088) not null,
  constraint blind_ballots_pk primary key (election_id, ballot_id, candidate_id),
  constraint blind_ballots_candidate_fk foreign key (candidate_id) references blindfold.candidates (candidate_id)
)
no drop until 0 days idle
no delete until 16 days after insert
hashing using "SHA2_512" version "v2";

create blockchain table blindfold.ballot_seals (
  election_id number        not null,
  ballot_id   number        not null,
  voter_id    varchar2(30)  not null,
  sum_proof   varchar2(544) not null,
  signature   varchar2(128) not null,
  constraint ballot_seals_pk primary key (election_id, ballot_id),
  constraint ballot_seals_voter_uk unique (election_id, voter_id)
)
no drop until 0 days idle
no delete until 16 days after insert
hashing using "SHA2_512" version "v2";

insert into blindfold.blind_ballots select * from blindfold.bf_copy_ballots;
insert into blindfold.ballot_seals select * from blindfold.bf_copy_seals;
commit;
drop table blindfold.bf_copy_ballots purge;
drop table blindfold.bf_copy_seals purge;

-- Shot 41. Disable the primary key and drop the foreign key, then store the three rows of
-- ballot 4 a second time.
alter table blindfold.blind_ballots disable constraint blind_ballots_pk;
alter table blindfold.blind_ballots drop constraint blind_ballots_candidate_fk;
insert into blindfold.blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof)
select election_id, ballot_id, candidate_id, vote_enc, bit_proof
  from blindfold.blind_ballots
 where election_id = (select max(election_id) from blindfold.election_key)
   and ballot_id = 4;
commit;
