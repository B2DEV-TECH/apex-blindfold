// Contract tests for the PL/SQL election API (db/03_bf_election.sql): what the
// database accepts, what it refuses, and with which error. They need the lab
// schema installed and they open elections, so they erase stored ballots.
// Run with: node --test tests/unit/election-api.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../lib/config.mjs';
import { connect } from '../lib/db.mjs';
import * as P from '../lib/paillier.mjs';

let conn;
let key; // a small key keeps these tests fast; the size is not what they test
let goodBallot;

const open = (nHex, voters) => conn.execute('begin bf_election.open_election(p_n_hex => :n, p_voter_count => :voters); end;', { n: nHex, voters });
const cast = (voter, ballot) => conn.execute('declare v number; begin v := bf_election.cast_ballot(:voter, :c1, :c2, :c3); end;', { voter, c1: ballot[0], c2: ballot[1], c3: ballot[2] });
const raises = (code) => (error) => String(error.message).startsWith(`ORA-${code}`);
const scalar = async (sql) => Object.values((await conn.execute(sql)).rows[0])[0];

before(async () => {
  conn = await connect(loadConfig(), 'schema');
  key = (await P.generateKeyPair(512)).publicKey;
  goodBallot = P.encryptBallot(key, 0, 3);
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

test('open_election starts from an empty ballot box and ballot 1', async () => {
  await open(P.toHex(key.n), 3);
  await cast('VOTER-0001', goodBallot);
  await conn.commit();
  await open(P.toHex(key.n), 3);
  assert.equal(await scalar('select count(*) from blind_ballots'), 0);
  assert.equal(await scalar('select count(voted_at) from voter_roll'), 0);
  await cast('VOTER-0001', goodBallot);
  assert.equal(await scalar('select min(ballot_id) from blind_ballots'), 1);
  assert.equal(await scalar('select count(*) from blind_ballots'), 3);
  await conn.rollback();
});

test('open_election refuses a modulus that is not an odd lower-case hexadecimal number of 256 to 2048 bits', async () => {
  const n = P.toHex(key.n);
  for (const bad of [n.toUpperCase(), `${n.slice(0, -1)}0`, n.slice(0, 62), `0${n.slice(1)}`, `${n}zz`, '']) {
    await assert.rejects(open(bad, 3), raises(20002), `accepted "${bad.slice(0, 16)}..."`);
  }
});

test('open_election refuses a voter count outside 1..100000', async () => {
  for (const bad of [0, -1, 100001]) await assert.rejects(open(P.toHex(key.n), bad), raises(20002), `accepted ${bad}`);
});

test('cast_ballot accepts one ballot per registered voter', async () => {
  await open(P.toHex(key.n), 3);
  await cast('VOTER-0001', goodBallot);
  await assert.rejects(cast('VOTER-0001', goodBallot), raises(20004));
  await assert.rejects(cast('VOTER-0004', goodBallot), raises(20003));
  await assert.rejects(cast('SOMEONE', goodBallot), raises(20003));
  // The code is trimmed and upper-cased before the lookup.
  await cast('  voter-0002 ', goodBallot);
  assert.equal(await scalar('select count(voted_at) from voter_roll'), 2);
  await conn.rollback();
});

test('cast_ballot checks the shape of a ciphertext, and only the shape', async () => {
  await open(P.toHex(key.n), 3);
  const width = key.hexLength;
  const malformed = {
    'too short': goodBallot[0].slice(1),
    'too long': `0${goodBallot[0]}`,
    'upper case': goodBallot[0].toUpperCase().replace(/^[0-9]+$/, 'A'.repeat(width)),
    'not hexadecimal': `${goodBallot[0].slice(0, -1)}g`,
    zero: '0'.repeat(width),
    'n squared': P.toHex(key.nSquared, width),
    'above n squared': 'f'.repeat(width),
  };
  for (const [name, value] of Object.entries(malformed)) {
    await assert.rejects(cast('VOTER-0001', [value, goodBallot[1], goodBallot[2]]), raises(20005), `accepted a ciphertext that is ${name}`);
    await assert.rejects(cast('VOTER-0001', [goodBallot[0], goodBallot[1], value]), raises(20005), `accepted a third ciphertext that is ${name}`);
  }
  assert.equal(await scalar('select count(voted_at) from voter_roll'), 0, 'a refused ballot must not mark the voter');
  // A well-formed ciphertext is accepted whatever it encrypts: this is hypothesis H4.
  const thousand = P.ciphertextToHex(key, P.encrypt(key, 1000n));
  await cast('VOTER-0001', [thousand, goodBallot[1], goodBallot[2]]);
  await conn.rollback();
});

test('encrypted_tally needs an open election', async () => {
  await open(P.toHex(key.n), 3);
  await conn.execute('delete from election_key');
  await assert.rejects(conn.execute('select bf_election.encrypted_tally from dual'), raises(20001));
  await assert.rejects(cast('VOTER-0001', goodBallot), raises(20001));
  await conn.rollback();
  assert.equal(await scalar('select count(*) from election_key'), 1);
});
