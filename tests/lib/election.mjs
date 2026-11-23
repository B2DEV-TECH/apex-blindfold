// Election helpers used by the hypothesis tests. Every call goes through the
// same PL/SQL package (bf_election) that the APEX Ajax callbacks use.
import * as P from './paillier.mjs';
import { oracledb } from './db.mjs';

export const OPTIONS = 3;

export const voterCode = (index) => `VOTER-${String(index + 1).padStart(4, '0')}`;

export async function openElection(conn, publicKey, voterCount) {
  await conn.execute('begin bf_election.open_election(p_n_hex => :n, p_voter_count => :voters); end;', {
    n: P.toHex(publicKey.n),
    voters: voterCount,
  });
}

// ballots: [[c1, c2, c3], ...]; ballot i is cast by voter firstVoter + i.
// Commits once at the end, like one long polling day.
export async function castBallots(conn, ballots, { firstVoter = 0 } = {}) {
  const BATCH = 500;
  for (let start = 0; start < ballots.length; start += BATCH) {
    const rows = ballots.slice(start, start + BATCH).map((enc, i) => ({
      voter: voterCode(firstVoter + start + i),
      c1: enc[0],
      c2: enc[1],
      c3: enc[2],
    }));
    await conn.executeMany(
      'declare v_ballot_id number; begin v_ballot_id := bf_election.cast_ballot(:voter, :c1, :c2, :c3); end;',
      rows,
      {
        bindDefs: {
          voter: { type: oracledb.STRING, maxSize: 30 },
          c1: { type: oracledb.STRING, maxSize: 1024 },
          c2: { type: oracledb.STRING, maxSize: 1024 },
          c3: { type: oracledb.STRING, maxSize: 1024 },
        },
      },
    );
  }
  await conn.commit();
}

// Casts one ballot and returns its id. Does not commit.
export async function castBallot(conn, voter, enc) {
  const result = await conn.execute(
    'begin :id := bf_election.cast_ballot(:voter, :c1, :c2, :c3); end;',
    { id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, voter, c1: enc[0], c2: enc[1], c3: enc[2] },
  );
  return result.outBinds.id;
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
