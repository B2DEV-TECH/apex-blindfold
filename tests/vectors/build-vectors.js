// Builds the Layer 2 test vectors: fixed ballots with their proofs and challenge hashes.
//
// This file runs twice, unchanged: in a real browser, which exports the vectors, and in Node, which
// must arrive at the same proofs. Everything is drawn from a seeded generator, so the same seed
// gives the same key, the same ciphertexts and the same proofs on any machine. The only part that
// cannot be replayed is the ECDSA signature: WebCrypto draws its own randomness.
//
// The seeded generator is for vectors only. It is not a source of secrets.

/** mulberry32, one byte per step. */
export function seededBytes(seed) {
  let state = seed >>> 0;
  return (length) => {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      bytes[i] = ((t ^ (t >>> 14)) >>> 0) & 0xff;
    }
    return bytes;
  };
}

const ELECTION = 7;

// name, ballot number, voter, what the ciphertexts hold, what the prover claims they hold,
// and the context the ballot is presented under when that differs from the one it was made for.
const CASES = [
  { name: 'honest ballot for A', ballot: 1, voter: 'VOTER-0001', plaintexts: [1, 0, 0], valid: true },
  { name: 'honest ballot for B', ballot: 2, voter: 'VOTER-0002', plaintexts: [0, 1, 0], valid: true },
  { name: 'honest ballot for C', ballot: 3, voter: 'VOTER-0003', plaintexts: [0, 0, 1], valid: true },
  { name: 'stuffed: a thousand votes for A', ballot: 4, voter: 'VOTER-0004', plaintexts: [1000, 0, 0], claims: [1, 0, 0], valid: false },
  { name: 'balanced: three for A, minus two for B', ballot: 5, voter: 'VOTER-0005', plaintexts: [3, -2, 0], claims: [1, 0, 0], valid: false },
  { name: 'two options set to 1', ballot: 6, voter: 'VOTER-0006', plaintexts: [1, 1, 0], valid: false },
  { name: 'blank ballot', ballot: 7, voter: 'VOTER-0007', plaintexts: [0, 0, 0], valid: false },
  { name: 'replay: an honest ballot presented under another ballot number', ballot: 8, presentedBallot: 9, voter: 'VOTER-0008', plaintexts: [0, 1, 0], valid: false },
  { name: 'replay: an honest ballot presented in another election', ballot: 10, presentedElection: 8, voter: 'VOTER-0010', plaintexts: [0, 0, 1], valid: false },
];

/**
 * P and V are the modules paillier.js and validity.js. Returns the vectors of one key size.
 * With `sign`, every ballot is also signed by a fresh voter key (browser export only).
 */
export async function buildVectors(P, V, { seed, bits, sign = false }) {
  const random = seededBytes(seed);
  const { publicKey } = await P.generateKeyPair(bits, { random });
  const samples = [];
  for (const item of CASES) {
    const made = { electionId: ELECTION, ballotId: item.ballot };
    const presented = { electionId: item.presentedElection ?? ELECTION, ballotId: item.presentedBallot ?? item.ballot };
    const ballot = await V.proveBallot(publicKey, made, item.plaintexts, { random, claims: item.claims ?? null });
    const wire = { ciphertexts: ballot.ciphertexts, bitProofs: ballot.bitProofs, sumProof: ballot.sumProof };
    const verdict = await V.verifyBallot(publicKey, presented, wire);
    const sample = {
      name: item.name,
      plaintexts: item.plaintexts,
      made_for: { election_id: made.electionId, ballot_id: made.ballotId },
      presented_as: { election_id: presented.electionId, ballot_id: presented.ballotId },
      voter_id: item.voter,
      ciphertexts: wire.ciphertexts,
      bit_proofs: wire.bitProofs,
      sum_proof: wire.sumProof,
      // What the prover hashed, for the context the ballot was made for.
      prover: {
        bits: ballot.trace.bits,
        sum: ballot.trace.sum,
      },
      // What a verifier arrives at, for the context the ballot is presented under.
      verifier: {
        valid: verdict.ok,
        reason: verdict.reason,
        bit_valid: verdict.bits.map((b) => b.ok),
        bit_challenge_hashes: verdict.bits.map((b) => (b.digest ? V.bytesToHex(b.digest) : null)),
        sum_valid: verdict.sum.ok,
        sum_challenge_hash: verdict.sum.digest ? V.bytesToHex(verdict.sum.digest) : null,
      },
      expected_valid: item.valid,
      signed_bytes_sha256: V.bytesToHex(await V.sha256(V.ballotBytes(publicKey, presented, item.voter, wire))),
    };
    if (sign) {
      const voterKey = await V.generateVoterKey();
      sample.voter_public_key = voterKey.publicKeyHex;
      sample.signature = await V.signBallot(voterKey.privateKey, publicKey, presented, item.voter, wire);
      sample.signature_verifies_in_the_browser = await V.verifyBallotSignature(voterKey.publicKeyHex, sample.signature, publicKey, presented, item.voter, wire);
    }
    samples.push(sample);
  }
  return { seed, modulus_bits: publicKey.bits, n_hex: P.toHex(publicKey.n), samples };
}

/** The parts of a vector set that any implementation must reproduce from the seed alone. */
export function replayable(set) {
  return {
    ...set,
    samples: set.samples.map(({ voter_public_key, signature, signature_verifies_in_the_browser, ...rest }) => rest),
  };
}
