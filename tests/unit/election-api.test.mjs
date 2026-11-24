// Contract tests for the PL/SQL election API (db/03_bf_election.sql): what the
// database accepts, what it refuses, and with which error. They need the lab
// schema installed and they open elections. Since Layer 2 an election cannot
// erase the ballots of the one before: the ballot tables are blockchain tables.
// Run with: node --test tests/unit/election-api.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../lib/config.mjs';
import { connect } from '../lib/db.mjs';
import * as P from '../lib/paillier.mjs';
import * as V from '../lib/validity.mjs';
import { prepareBallot, castBallot, tryCastBallot, registerVoter, encryptedTally, decryptTally, honest, currentElectionId } from '../lib/election.mjs';

let conn;
let pair; // a small key keeps these tests fast; the size is not what they test
let key;

const open = (nHex, voters) => conn.execute('begin bf_election.open_election(p_n_hex => :n, p_voter_count => :voters); end;', { n: nHex, voters });
const raises = (code) => (error) => String(error.message).startsWith(`ORA-${code}`);
const scalar = async (sql, binds = {}) => Object.values((await conn.execute(sql, binds)).rows[0])[0];
const flip = (hexText, at) => `${hexText.slice(0, at)}${hexText[at] === '0' ? '1' : '0'}${hexText.slice(at + 1)}`;
const fresh = async (voters = 6) => {
  await open(P.toHex(key.n), voters);
  return currentElectionId(conn);
};
const ballotsOf = (election) => scalar('select count(*) from blind_ballots where election_id = :e', { e: election });

before(async () => {
  conn = await connect(loadConfig(), 'schema');
  pair = await P.generateKeyPair(512);
  key = pair.publicKey;
});

after(async () => {
  await conn.rollback();
  await conn.close();
});

test('open_election creates one distinct code per voter, up to the limit of 100000', async () => {
  await open(P.toHex(key.n), 100000);
  assert.equal(await scalar('select count(*) from voter_roll'), 100000);
  assert.equal(await scalar('select count(distinct voter_id) from voter_roll'), 100000);
  assert.equal(await scalar("select count(*) from voter_roll where voter_id in ('VOTER-0001', 'VOTER-9999', 'VOTER-10000', 'VOTER-100000')"), 4);
  assert.equal(await scalar("select count(*) from voter_roll where not regexp_like(voter_id, '^VOTER-[0-9]{4,6}$')"), 0);
});

test('open_election starts a new election with an empty ballot box and ballot 1, and keeps the old ballots', async () => {
  const first = await fresh(3);
  await castBallot(conn, await prepareBallot(conn, key, 'VOTER-0001', honest(0)));
  await conn.commit();
  const second = await fresh(3);
  assert.equal(second > first, true);
  assert.equal(await ballotsOf(second), 0);
  assert.equal(await ballotsOf(first), 3, 'the ballot of the earlier election is still stored');
  assert.equal(await scalar('select count(voted_at) from voter_roll'), 0);
  const id = await castBallot(conn, await prepareBallot(conn, key, 'VOTER-0001', honest(0)));
  assert.equal(id, 1);
  assert.equal(await ballotsOf(second), 3);
  await conn.rollback();
});

test('open_election refuses a modulus that is not an odd lower-case hexadecimal number of 512 to 2048 bits', async () => {
  const n = P.toHex(key.n);
  const small = P.toHex((await P.generateKeyPair(256)).publicKey.n);
  for (const bad of [n.toUpperCase(), `${n.slice(0, -1)}0`, n.slice(0, 126), small, `0${n.slice(1)}`, `${n}zz`, '']) {
    await assert.rejects(open(bad, 3), raises(20002), `accepted "${bad.slice(0, 16)}..."`);
  }
});

test('open_election refuses a voter count outside 1..100000', async () => {
  for (const bad of [0, -1, 100001]) await assert.rejects(open(P.toHex(key.n), bad), raises(20002), `accepted ${bad}`);
});

test('register_voter takes one key per voter code, once', async () => {
  await fresh();
  const a = await V.generateVoterKey();
  const b = await V.generateVoterKey();
  const id = await registerVoter(conn, 'VOTER-0001', a.publicKeyHex);
  assert.equal(await registerVoter(conn, '  voter-0001 ', a.publicKeyHex), id, 'the same key asks again and gets the same number');
  await assert.rejects(registerVoter(conn, 'VOTER-0001', b.publicKeyHex), raises(20008));
  await assert.rejects(registerVoter(conn, 'VOTER-0099', a.publicKeyHex), raises(20003));
  await assert.rejects(registerVoter(conn, 'VOTER-0002', 'not a key'), raises(20008));
  await assert.rejects(registerVoter(conn, 'VOTER-0002', a.publicKeyHex.slice(0, -4)), raises(20008));
  assert.notEqual(await registerVoter(conn, 'VOTER-0002', b.publicKeyHex), id);
  await conn.rollback();
});

test('cast_ballot accepts one honest ballot per registered voter', async () => {
  await fresh();
  const ballot = await prepareBallot(conn, key, 'VOTER-0001', honest(1));
  assert.equal(await castBallot(conn, ballot), ballot.ballotId);
  assert.equal((await tryCastBallot(conn, ballot)).code, 20004);
  assert.equal(await scalar('select count(voted_at) from voter_roll'), 1);
  assert.equal(await scalar('select count(*) from ballot_seals where election_id = bf_election.election_id'), 1);
  await conn.rollback();
});

test('cast_ballot rejects a ballot whose proofs do not hold, before anything is stored', async () => {
  const election = await fresh(8);
  const cheats = {
    'a thousand votes': [[1000, 0, 0], [1, 0, 0]],
    'three for A, minus two for B': [[3, -2, 0], [1, 0, 0]],
    'minus one': [[-1, 1, 1], [1, 1, 1]],
    'two options set to 1': [[1, 1, 0], null],
    'blank': [[0, 0, 0], null],
  };
  let voter = 1;
  for (const [name, [plaintexts, claims]] of Object.entries(cheats)) {
    const answer = await tryCastBallot(conn, await prepareBallot(conn, key, `VOTER-000${voter++}`, plaintexts, { claims }));
    assert.equal(answer.code, 20006, `${name}: ${answer.error ?? 'accepted'}`);
  }
  assert.equal(await ballotsOf(election), 0);
  assert.equal(await scalar('select count(voted_at) from voter_roll'), 0);
  await conn.rollback();
});

test('cast_ballot rejects a proof replayed under another ballot number or another voter', async () => {
  await fresh();
  const mine = await prepareBallot(conn, key, 'VOTER-0001', honest(2));
  const theirs = await prepareBallot(conn, key, 'VOTER-0002', honest(0));
  // The ciphertexts and proofs of voter 1, presented by voter 2 under voter 2's number and signature.
  const copied = { ...mine, voter: theirs.voter, ballotId: theirs.ballotId };
  copied.signature = await V.signBallot(theirs.voterKey.privateKey, key, theirs.context, theirs.voter, mine);
  assert.equal((await tryCastBallot(conn, copied)).code, 20006);
  // Voter 2 claiming the number reserved for voter 1.
  assert.equal((await tryCastBallot(conn, { ...theirs, ballotId: mine.ballotId })).code, 20006);
  assert.equal(await castBallot(conn, mine), mine.ballotId);
  await conn.rollback();
});

test('cast_ballot rejects an unsigned or forged ballot', async () => {
  await fresh();
  const good = await prepareBallot(conn, key, 'VOTER-0001', honest(0));
  const other = await V.generateVoterKey();
  const forged = await V.signBallot(other.privateKey, key, good.context, good.voter, good);
  assert.equal((await tryCastBallot(conn, { ...good, signature: flip(good.signature, 10) })).code, 20007);
  assert.equal((await tryCastBallot(conn, { ...good, signature: forged })).code, 20007);
  assert.equal((await tryCastBallot(conn, { ...good, signature: null })).code, 20007);
  // A voter code that never registered a key.
  assert.equal((await tryCastBallot(conn, { ...good, voter: 'VOTER-0003' })).code, 20007);
  assert.equal(await castBallot(conn, good), good.ballotId);
  await conn.rollback();
});

test('cast_ballot still checks the shape of a ciphertext', async () => {
  await fresh();
  const good = await prepareBallot(conn, key, 'VOTER-0001', honest(0));
  const c = good.ciphertexts[0];
  for (const bad of [c.slice(1), `0${c}`, c.toUpperCase(), '0'.repeat(c.length), 'f'.repeat(c.length)]) {
    assert.equal((await tryCastBallot(conn, { ...good, ciphertexts: [bad, good.ciphertexts[1], good.ciphertexts[2]] })).code, 20005);
  }
  await conn.rollback();
});

test('the ballot tables refuse UPDATE and DELETE, and the chain verifies', async () => {
  await fresh();
  await castBallot(conn, await prepareBallot(conn, key, 'VOTER-0001', honest(0)));
  await conn.commit();
  await assert.rejects(conn.execute('update blind_ballots set vote_enc = vote_enc where election_id = bf_election.election_id'), raises('05715'));
  await assert.rejects(conn.execute('delete from ballot_seals where election_id = bf_election.election_id'), raises('05715'));
  const chain = JSON.parse(await scalar('select bf_election.verify_chains from dual'));
  assert.equal(chain.blind_ballots >= 3 && chain.ballot_seals >= 1, true);
});

test('encrypted_tally verifies again, counts the honest ballots and leaves out a row inserted behind the API', async () => {
  const election = await fresh();
  const choices = [0, 1, 1, 2];
  for (let i = 0; i < choices.length; i++) await castBallot(conn, await prepareBallot(conn, key, `VOTER-000${i + 1}`, honest(choices[i])));
  // What a DBA can do to a blockchain table: add rows. Enc(5) for option A, signed by nobody.
  const stuffed = P.ciphertextToHex(key, P.encrypt(key, 5n));
  await conn.execute('insert into blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:e, 900, 1, :c, :p)', { e: election, c: stuffed, p: '0'.repeat(64 + 4 * V.modulusBytes(key)) });
  await conn.commit();
  const tally = await encryptedTally(conn);
  assert.equal(tally.ballots_counted, 4);
  assert.equal(tally.ballots_rejected, 1);
  assert.equal(tally.rejected[0].ballot_id, 900);
  assert.deepEqual(decryptTally(key, pair.privateKey, tally).map(Number), [1, 2, 1]);
});
