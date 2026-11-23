-- APEX Blindfold: data model.
-- Nothing in this schema can hold a vote in the clear or a private key.

-- The election's public key: the Paillier modulus n, in hexadecimal.
-- The private key is generated in the authority's browser and stays there.
create table election_key (
  n_hex varchar2(512) not null,
  constraint election_key_pk primary key (n_hex)
);

-- The three options of the fictional election.
create table candidates (
  candidate_id number(1)     not null,
  label        varchar2(100) not null,
  tag          varchar2(30)  not null,
  constraint candidates_pk primary key (candidate_id),
  constraint candidates_id_ck check (candidate_id between 1 and 3)
);

-- One ciphertext per candidate per ballot: Enc(1) for the choice, Enc(0) for
-- the others. No voter identifier and no timestamp, on purpose.
-- A ciphertext is a number modulo n^2: 4096 bits = 1024 hexadecimal characters.
create table blind_ballots (
  ballot_id    number         not null,
  candidate_id number(1)      not null,
  vote_enc     varchar2(1024) not null,
  constraint blind_ballots_pk primary key (ballot_id, candidate_id),
  constraint blind_ballots_candidate_fk foreign key (candidate_id) references candidates (candidate_id)
);

create sequence blind_ballots_seq;

-- Turnout only: who is registered and when they voted. Kept apart from the
-- ballots. VOTED_AT stays null until the voter casts a ballot.
create table voter_roll (
  voter_id varchar2(30) not null,
  voted_at timestamp with time zone,
  constraint voter_roll_pk primary key (voter_id)
);

insert into candidates (candidate_id, label, tag)
values (1, 'File-Level Import with APEXlang', 'APEXlang');
insert into candidates (candidate_id, label, tag)
values (2, 'Computed Columns with Natural Language in Interactive Reports', 'AI');
insert into candidates (candidate_id, label, tag)
values (3, 'Deep Data Security Integration', 'Security');
commit;
