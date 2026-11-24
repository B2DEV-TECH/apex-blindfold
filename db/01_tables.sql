-- APEX Blindfold: data model.
-- Nothing in this schema can hold a vote in the clear or a private key.
--
-- Layer 2 changes, each one a recorded decision (docs/decisions-layer2.md):
--   the two ballot tables are blockchain tables, so a stored row cannot be changed or removed;
--   ballots of every election stay in them, told apart by ELECTION_ID, because TRUNCATE is refused;
--   a ballot carries its validity proofs, the voter code and the voter signature.

-- One row per election: its number and its public key, the Paillier modulus n in hexadecimal.
-- The current election is the one with the highest number. The private key is generated in the
-- authority's browser and stays there.
create table election_key (
  election_id number        not null,
  n_hex       varchar2(512) not null,
  opened_at   timestamp with time zone default systimestamp not null,
  constraint election_key_pk primary key (election_id)
);

create sequence election_seq;

-- The three options of the fictional election.
create table candidates (
  candidate_id number(1)     not null,
  label        varchar2(100) not null,
  tag          varchar2(30)  not null,
  constraint candidates_pk primary key (candidate_id),
  constraint candidates_id_ck check (candidate_id between 1 and 3)
);

-- One ciphertext per candidate per ballot: Enc(1) for the choice, Enc(0) for the others, each
-- with the proof that it encrypts 0 or 1.
-- A ciphertext is a number modulo n^2: 4096 bits = 1024 hexadecimal characters.
-- A bit proof is e0 | e1 | z0 | z1: 32 + 32 + 512 + 512 hexadecimal characters.
--
-- A blockchain table: every row is chained to the one before it by a hash, and UPDATE, DELETE,
-- TRUNCATE and MERGE are refused, for the owner and for a DBA alike.
--   NO DROP UNTIL 0 DAYS IDLE    the table can be dropped at any time, so that the lab can be
--                                reinstalled. A DBA can therefore drop it and build another one.
--   NO DELETE UNTIL 16 DAYS ...  16 days is the shortest retention the database accepts.
-- The database adds hidden columns to every row, among them the time of the insert
-- (ORABCTAB_CREATION_TIME$) and the database user who made it.
create blockchain table blind_ballots (
  election_id  number         not null,
  ballot_id    number         not null,
  candidate_id number(1)      not null,
  vote_enc     varchar2(1024) not null,
  bit_proof    varchar2(1088) not null,
  constraint blind_ballots_pk primary key (election_id, ballot_id, candidate_id),
  constraint blind_ballots_candidate_fk foreign key (candidate_id) references candidates (candidate_id)
)
no drop until 0 days idle
no delete until 16 days after insert
hashing using "SHA2_512" version "v2";

-- One row per ballot: who cast it, the proof that its three plaintexts add up to 1, and the
-- voter signature over the whole ballot. This is what links a ballot to a voter, in writing.
-- A sum proof is e | z: 32 + 512 hexadecimal characters. A signature is r | s: 128.
create blockchain table ballot_seals (
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

create sequence blind_ballots_seq;

-- The roll of the current election: who is registered, the public key the voter registered
-- (ECDSA P-256, SubjectPublicKeyInfo in hexadecimal), the ballot number reserved for that voter,
-- and when they voted. An ordinary table: whoever can write to it can replace a public key.
create table voter_roll (
  voter_id      varchar2(30) not null,
  public_key    varchar2(256),
  ballot_id     number,
  registered_at timestamp with time zone,
  voted_at      timestamp with time zone,
  constraint voter_roll_pk primary key (voter_id),
  constraint voter_roll_ballot_uk unique (ballot_id)
);

insert into candidates (candidate_id, label, tag)
values (1, 'File-Level Import with APEXlang', 'APEXlang');
insert into candidates (candidate_id, label, tag)
values (2, 'Computed Columns with Natural Language in Interactive Reports', 'AI');
insert into candidates (candidate_id, label, tag)
values (3, 'Deep Data Security Integration', 'Security');
commit;
