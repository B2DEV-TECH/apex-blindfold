// Election helpers used by the hypothesis tests. Every call goes through the
// same PL/SQL package (bf_election) that the APEX Ajax callbacks use.
import * as P from './paillier.mjs';
import * as V from './validity.mjs';
import { oracledb } from './db.mjs';

export const OPTIONS = 3;

export const voterCode = (index) => `VOTER-${String(index + 1).padStart(4, '0')}`;

export async function openElection(conn, publicKey, voterCount) {
  await conn.execute('begin bf_election.open_election(p_n_hex => :n, p_voter_count => :voters); end;', {
    n: P.toHex(publicKey.n),
    voters: voterCount,
  });
}

// ---- Layer 2: a ballot carries proofs and a signature, bound to a reserved ballot number

export async function currentElectionId(conn) {
  return (await conn.execute('select bf_election.election_id as id from dual')).rows[0].ID;
}

// Registers the voter key and returns the ballot number reserved for the voter. Does not commit.
export async function registerVoter(conn, voter, publicKeyHex) {
  const result = await conn.execute(
    'begin :id := bf_election.register_voter(:voter, :key); end;',
    { id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, voter, key: publicKeyHex },
  );
  return result.outBinds.id;
}

// What a browser does before it sends a ballot: generate the voter key, register it, receive the
// ballot number, encrypt, prove and sign. `plaintexts` is what the three ciphertexts hold; an
// honest ballot has a single 1. `claims` is what a cheater pretends they hold (see validity.js).
// Returns everything cast_ballot takes. Does not commit.
export async function prepareBallot(conn, publicKey, voter, plaintexts, { claims = null, electionId = null, voterKey = null, random = undefined } = {}) {
  const key = voterKey ?? await V.generateVoterKey();
  const ballotId = await registerVoter(conn, voter, key.publicKeyHex);
  const context = { electionId: electionId ?? await currentElectionId(conn), ballotId };
  const ballot = await V.proveBallot(publicKey, context, plaintexts, { claims, ...(random ? { random } : {}) });
  const wire = { ciphertexts: ballot.ciphertexts, bitProofs: ballot.bitProofs, sumProof: ballot.sumProof };
  const signature = await V.signBallot(key.privateKey, publicKey, context, voter, wire);
  return { voter, ballotId, context, ...wire, signature, voterKey: key };
}

export const honest = (choice) => Array.from({ length: OPTIONS }, (_, option) => (option === choice ? 1 : 0));

const CAST = 'begin :id := bf_election.cast_ballot(:voter, :ballot, :c1, :c2, :c3, :p1, :p2, :p3, :psum, :signature); end;';
const castBinds = (b) => ({
  voter: b.voter, ballot: b.ballotId,
  c1: b.ciphertexts[0], c2: b.ciphertexts[1], c3: b.ciphertexts[2],
  p1: b.bitProofs[0], p2: b.bitProofs[1], p3: b.bitProofs[2],
  psum: b.sumProof, signature: b.signature,
});

// Casts one prepared ballot and returns its number. Does not commit.
export async function castBallot(conn, prepared) {
  const result = await conn.execute(CAST, { id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, ...castBinds(prepared) });
  return result.outBinds.id;
}

// Like castBallot, for ballots that may be refused: { ok, ballotId } or { ok: false, code, error }.
export async function tryCastBallot(conn, prepared) {
  try {
    return { ok: true, ballotId: await castBallot(conn, prepared) };
  } catch (error) {
    const message = String(error.message).split('\n')[0];
    return { ok: false, code: Number((message.match(/^ORA-(\d+)/) ?? [])[1] ?? 0), error: message };
  }
}

// Honest ballots for voters firstVoter, firstVoter + 1, ...: choices[i] is the zero-based option
// of ballot i. Commits once at the end, like one long polling day.
export async function castChoices(conn, publicKey, choices, { firstVoter = 0 } = {}) {
  const electionId = await currentElectionId(conn);
  const ids = [];
  for (let i = 0; i < choices.length; i++) {
    const prepared = await prepareBallot(conn, publicKey, voterCode(firstVoter + i), honest(choices[i]), { electionId });
    ids.push(await castBallot(conn, prepared));
  }
  await conn.commit();
  return ids;
}

// The homomorphic tally as the database computes it: encrypted totals.
export async function encryptedTally(conn) {
  const result = await conn.execute('select bf_election.encrypted_tally as tally from dual');
  return JSON.parse(result.rows[0].TALLY);
}

// What only the key holder can do: turn encrypted totals into numbers.
export function decryptTally(publicKey, privateKey, tally) {
  return tally.totals.map((t) => P.decrypt(publicKey, privateKey, P.ciphertextFromHex(publicKey, t.total_enc)));
}

export function countChoices(choices) {
  const counts = new Array(OPTIONS).fill(0);
  for (const choice of choices) counts[choice] += 1;
  return counts;
}

// Small seeded generator (mulberry32) so that a run can be replayed with --seed.
export function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
