/**
 * Ballot validity proofs for Paillier ciphertexts, on JavaScript BigInt.
 *
 * A ballot is three ciphertexts. Without opening any of them, the proofs show that
 *   - every ciphertext encrypts 0 or 1                      (one "bit proof" per option)
 *   - the three plaintexts add up to 1                      (one "sum proof" per ballot)
 *
 * Both rest on one fact. With g = n + 1, a ciphertext is c = g^m * r^n mod n^2, so
 *
 *     u_k = c * g^-k = c * (1 - k*n) mod n^2
 *
 * is an n-th power (u_k = r^n) exactly when c encrypts k. Knowing an n-th root r of u is proven
 * with a three-move protocol:
 *
 *     commit     a = w^n mod n^2            w random in Z*_n
 *     challenge  e                          128 bits
 *     respond    z = w * r^e mod n
 *     check      z^n = a * u^e mod n^2
 *
 * Bit proof: the prover knows a root of u_0 or of u_1, not of both. It runs the real protocol for
 * the branch it knows and simulates the other one, picking that branch's e and z first and solving
 * the check for a. The two challenges must add up to the hash, so only one of them was free
 * (Cramer, Damgard and Schoenmakers, CRYPTO 1994; applied to Paillier by Damgard and Jurik).
 *
 * Sum proof: the product of the three ciphertexts encrypts the sum of the plaintexts, with
 * randomness r1*r2*r3. One protocol run shows that this product encrypts 1.
 *
 * Non-interactive (Fiat and Shamir): the challenge is the first 128 bits of a SHA-256 hash of n,
 * the election, the ballot, the option, the ciphertext and the commitments. A proof therefore
 * holds for one row only.
 *
 * Stored form, compact: challenges and responses. The verifier recomputes the commitments.
 *     bit proof   e0 | e1 | z0 | z1      (32 + 32 + W + W hexadecimal characters)
 *     sum proof   e | z                  (32 + W)
 * where W is the width of n in hexadecimal characters.
 *
 * EDUCATIONAL CODE. Not constant time, never audited. It must not protect real data.
 * The same file runs in the browser and in Node. SHA-256 comes from WebCrypto.
 */
import * as P from './paillier.js';

export const CHALLENGE_BITS = 128;
export const CHALLENGE_HEX = CHALLENGE_BITS / 4;
// Soundness needs a challenge smaller than both primes of n: a modulus of at least 512 bits.
export const MIN_MODULUS_BITS = 512;

const CHALLENGE_SPACE = 1n << BigInt(CHALLENGE_BITS);
const LABEL_BIT = 'apex-blindfold/v2/bit';
const LABEL_SUM = 'apex-blindfold/v2/sum';
const LABEL_BALLOT = 'apex-blindfold/v2/ballot';

// ------------------------------------------------------------------ encoding

const utf8 = new TextEncoder();

export function bytesToHex(bytes) {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) throw new TypeError('expected lower-case hexadecimal, whole bytes');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

/** A non-negative integer as exactly `width` bytes, most significant first. */
export function intToBytes(value, width) {
  const v = BigInt(value);
  if (v < 0n) throw new RangeError('negative value');
  const hex = v.toString(16);
  if (hex.length > width * 2) throw new RangeError('value does not fit the width');
  return hexToBytes(hex.padStart(width * 2, '0'));
}

/**
 * The one way bytes are put together before hashing or signing: every field is a 4-byte length,
 * most significant byte first, followed by its bytes. Text fields are UTF-8. Two different lists
 * of fields can never give the same bytes.
 */
export function frame(fields) {
  const parts = fields.map((field) => (typeof field === 'string' ? utf8.encode(field) : field));
  const out = new Uint8Array(parts.reduce((total, part) => total + 4 + part.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const part of parts) {
    view.setUint32(at, part.length);
    out.set(part, at + 4);
    at += 4 + part.length;
  }
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

/** Width of n in bytes. A number modulo n^2 takes twice as many. */
export const modulusBytes = (publicKey) => Math.ceil(publicKey.bits / 8);

// Identifiers travel as 8-byte integers.
const id = (value) => intToBytes(value, 8);

/** What a proof is bound to: { electionId, ballotId }. */
function contextFields(publicKey, context) {
  return [intToBytes(publicKey.n, modulusBytes(publicKey)), id(context.electionId), id(context.ballotId)];
}

/** The bytes hashed for the bit proof of one option (candidateId starts at 1). */
export function bitChallengeBytes(publicKey, context, candidateId, c, a0, a1) {
  const wide = 2 * modulusBytes(publicKey);
  return frame([LABEL_BIT, ...contextFields(publicKey, context), id(candidateId), intToBytes(c, wide), intToBytes(a0, wide), intToBytes(a1, wide)]);
}

/** The bytes hashed for the sum proof of one ballot. */
export function sumChallengeBytes(publicKey, context, ciphertexts, a) {
  const wide = 2 * modulusBytes(publicKey);
  return frame([LABEL_SUM, ...contextFields(publicKey, context), ...ciphertexts.map((c) => intToBytes(c, wide)), intToBytes(a, wide)]);
}

/** The challenge is the first 128 bits of the hash. */
export const challengeFromDigest = (digest) => P.bytesToBigInt(digest.subarray(0, CHALLENGE_BITS / 8));

// --------------------------------------------------------------- the protocol

/** u_k = c * (1 - k*n) mod n^2: an n-th power exactly when c encrypts k. */
export function shifted(publicKey, c, k) {
  const { n, nSquared } = publicKey;
  return (c * (((1n - BigInt(k) * n) % nSquared) + nSquared)) % nSquared;
}

/** The commitment that makes the check hold: a = z^n * u^-e mod n^2. */
function commitmentFor(publicKey, u, e, z) {
  const { n, nSquared } = publicKey;
  return (P.modPow(z, n, nSquared) * P.modPow(P.modInv(u, nSquared), e, nSquared)) % nSquared;
}

/** Encrypts and keeps the random r, which the proofs need as their secret. */
export function encryptWithWitness(publicKey, message, random = P.systemRandom) {
  const r = P.randomUnit(publicKey.n, random);
  const c = P.encryptWithRandomizer(publicKey, message, P.modPow(r, publicKey.n, publicKey.nSquared));
  return { c, r };
}

/**
 * Proves that c encrypts 0 or 1. `bit` is what it encrypts and `r` its randomness.
 * Returns { e0, e1, z0, z1, a0, a1, digest }: the last three are not stored.
 */
export async function proveBit(publicKey, context, candidateId, c, bit, r, random = P.systemRandom) {
  if (bit !== 0 && bit !== 1) throw new RangeError('a bit proof needs a plaintext of 0 or 1');
  const { n, nSquared } = publicKey;
  const real = bit;
  const fake = 1 - bit;
  const e = [0n, 0n];
  const z = [0n, 0n];
  const a = [0n, 0n];

  // The branch that is not true: choose its challenge and response, then solve for the commitment.
  e[fake] = P.randomBelow(CHALLENGE_SPACE, random);
  z[fake] = P.randomUnit(n, random);
  a[fake] = commitmentFor(publicKey, shifted(publicKey, c, fake), e[fake], z[fake]);

  // The branch that is true: commit first, answer after the hash is known.
  const w = P.randomUnit(n, random);
  a[real] = P.modPow(w, n, nSquared);

  const digest = await sha256(bitChallengeBytes(publicKey, context, candidateId, c, a[0], a[1]));
  e[real] = (((challengeFromDigest(digest) - e[fake]) % CHALLENGE_SPACE) + CHALLENGE_SPACE) % CHALLENGE_SPACE;
  z[real] = (w * P.modPow(r, e[real], n)) % n;
  return { e0: e[0], e1: e[1], z0: z[0], z1: z[1], a0: a[0], a1: a[1], digest };
}

/** Returns { ok, reason, digest }. The digest is the challenge hash the verifier computed. */
export async function verifyBit(publicKey, context, candidateId, c, proof) {
  const { n, nSquared } = publicKey;
  const e = [proof.e0, proof.e1];
  const z = [proof.z0, proof.z1];
  if (c <= 0n || c >= nSquared || P.gcd(c, n) !== 1n) return { ok: false, reason: 'ciphertext out of range', digest: null };
  const a = [];
  for (let k = 0; k < 2; k++) {
    if (e[k] < 0n || e[k] >= CHALLENGE_SPACE) return { ok: false, reason: 'challenge out of range', digest: null };
    if (z[k] <= 0n || z[k] >= n) return { ok: false, reason: 'response out of range', digest: null };
    a[k] = commitmentFor(publicKey, shifted(publicKey, c, k), e[k], z[k]);
  }
  const digest = await sha256(bitChallengeBytes(publicKey, context, candidateId, c, a[0], a[1]));
  const ok = (e[0] + e[1]) % CHALLENGE_SPACE === challengeFromDigest(digest);
  return { ok, reason: ok ? null : 'the challenges do not add up to the hash', digest };
}

/** Proves that the ciphertexts together encrypt 1. `rs` are their random numbers. */
export async function proveSum(publicKey, context, ciphertexts, rs, random = P.systemRandom) {
  const { n, nSquared } = publicKey;
  const product = rs.reduce((acc, r) => (acc * r) % n, 1n);
  const w = P.randomUnit(n, random);
  const a = P.modPow(w, n, nSquared);
  const digest = await sha256(sumChallengeBytes(publicKey, context, ciphertexts, a));
  const e = challengeFromDigest(digest);
  return { e, z: (w * P.modPow(product, e, n)) % n, a, digest };
}

export async function verifySum(publicKey, context, ciphertexts, proof) {
  const { n, nSquared } = publicKey;
  if (proof.e < 0n || proof.e >= CHALLENGE_SPACE) return { ok: false, reason: 'challenge out of range', digest: null };
  if (proof.z <= 0n || proof.z >= n) return { ok: false, reason: 'response out of range', digest: null };
  for (const c of ciphertexts) {
    if (c <= 0n || c >= nSquared || P.gcd(c, n) !== 1n) return { ok: false, reason: 'ciphertext out of range', digest: null };
  }
  const u = shifted(publicKey, P.add(publicKey, ...ciphertexts), 1);
  const a = commitmentFor(publicKey, u, proof.e, proof.z);
  const digest = await sha256(sumChallengeBytes(publicKey, context, ciphertexts, a));
  const ok = challengeFromDigest(digest) === proof.e;
  return { ok, reason: ok ? null : 'the challenge is not the hash', digest };
}

// ---------------------------------------------------------------- wire format

const challengeHex = (e) => P.toHex(e, CHALLENGE_HEX);
const responseHex = (publicKey, z) => P.toHex(z, 2 * modulusBytes(publicKey));

export function bitProofToHex(publicKey, proof) {
  return challengeHex(proof.e0) + challengeHex(proof.e1) + responseHex(publicKey, proof.z0) + responseHex(publicKey, proof.z1);
}

export function bitProofFromHex(publicKey, hex) {
  const w = 2 * modulusBytes(publicKey);
  if (typeof hex !== 'string' || hex.length !== 2 * CHALLENGE_HEX + 2 * w || !/^[0-9a-f]+$/.test(hex)) throw new RangeError('malformed bit proof');
  const part = (from, length) => BigInt(`0x${hex.slice(from, from + length)}`);
  return { e0: part(0, CHALLENGE_HEX), e1: part(CHALLENGE_HEX, CHALLENGE_HEX), z0: part(2 * CHALLENGE_HEX, w), z1: part(2 * CHALLENGE_HEX + w, w) };
}

export function sumProofToHex(publicKey, proof) {
  return challengeHex(proof.e) + responseHex(publicKey, proof.z);
}

export function sumProofFromHex(publicKey, hex) {
  const w = 2 * modulusBytes(publicKey);
  if (typeof hex !== 'string' || hex.length !== CHALLENGE_HEX + w || !/^[0-9a-f]+$/.test(hex)) throw new RangeError('malformed sum proof');
  return { e: BigInt(`0x${hex.slice(0, CHALLENGE_HEX)}`), z: BigInt(`0x${hex.slice(CHALLENGE_HEX)}`) };
}

// --------------------------------------------------------------------- ballots

/**
 * Encrypts the plaintexts and proves the ballot. An honest ballot is `plaintexts` with a single 1.
 * `claims`, used by the tests only, is what a cheater pretends each ciphertext holds: without the
 * secret of a true statement it can do no better than run the honest prover on a lie.
 *
 * Returns hexadecimal strings, in option order:
 *   { ciphertexts: [c1, c2, c3], bitProofs: [p1, p2, p3], sumProof, trace }
 * `trace` holds the commitments and the challenge hashes, for test vectors. It is never sent.
 */
export async function proveBallot(publicKey, context, plaintexts, { random = P.systemRandom, claims = null } = {}) {
  if (publicKey.bits < MIN_MODULUS_BITS) throw new RangeError(`the proofs need a modulus of at least ${MIN_MODULUS_BITS} bits`);
  const { n } = publicKey;
  const parts = plaintexts.map((m) => encryptWithWitness(publicKey, ((BigInt(m) % n) + n) % n, random));
  const cs = parts.map((part) => part.c);
  const rs = parts.map((part) => part.r);
  const bits = [];
  for (let i = 0; i < cs.length; i++) {
    bits.push(await proveBit(publicKey, context, i + 1, cs[i], claims ? claims[i] : Number(plaintexts[i]), rs[i], random));
  }
  const sum = await proveSum(publicKey, context, cs, rs, random);
  return {
    ciphertexts: cs.map((c) => P.ciphertextToHex(publicKey, c)),
    bitProofs: bits.map((proof) => bitProofToHex(publicKey, proof)),
    sumProof: sumProofToHex(publicKey, sum),
    trace: {
      bits: bits.map((proof) => ({
        a0: P.ciphertextToHex(publicKey, proof.a0),
        a1: P.ciphertextToHex(publicKey, proof.a1),
        challenge_hash: bytesToHex(proof.digest),
      })),
      sum: { a: P.ciphertextToHex(publicKey, sum.a), challenge_hash: bytesToHex(sum.digest) },
    },
  };
}

/** An honest ballot: Enc(1) for the chosen option (zero-based), Enc(0) for the others. */
export function proveChoice(publicKey, context, choice, optionCount, options = {}) {
  if (!Number.isInteger(choice) || choice < 0 || choice >= optionCount) throw new RangeError('choice out of range');
  return proveBallot(publicKey, context, Array.from({ length: optionCount }, (_, option) => (option === choice ? 1 : 0)), options);
}

/**
 * Checks every proof of a ballot given in wire format.
 * Returns { ok, reason, bits: [{ ok, reason, digest }], sum: { ok, reason, digest } }.
 */
export async function verifyBallot(publicKey, context, ballot) {
  let cs;
  let bitProofs;
  let sumProof;
  try {
    cs = ballot.ciphertexts.map((hex) => P.ciphertextFromHex(publicKey, hex));
    bitProofs = ballot.bitProofs.map((hex) => bitProofFromHex(publicKey, hex));
    sumProof = sumProofFromHex(publicKey, ballot.sumProof);
  } catch (error) {
    return { ok: false, reason: error.message, bits: [], sum: null };
  }
  const bits = [];
  for (let i = 0; i < cs.length; i++) bits.push(await verifyBit(publicKey, context, i + 1, cs[i], bitProofs[i]));
  const sum = await verifySum(publicKey, context, cs, sumProof);
  const failedBit = bits.findIndex((b) => !b.ok);
  const ok = failedBit < 0 && sum.ok;
  const reason = ok ? null : failedBit >= 0 ? `option ${failedBit + 1}: ${bits[failedBit].reason}` : `sum: ${sum.reason}`;
  return { ok, reason, bits, sum };
}

// ------------------------------------------------------------------ signatures

/**
 * The bytes a voter signs: the whole ballot. Election, ballot number, voter code, and every
 * ciphertext with its proof, then the sum proof.
 */
export function ballotBytes(publicKey, context, voterId, ballot) {
  const fields = [LABEL_BALLOT, ...contextFields(publicKey, context), String(voterId)];
  for (let i = 0; i < ballot.ciphertexts.length; i++) fields.push(hexToBytes(ballot.ciphertexts[i]), hexToBytes(ballot.bitProofs[i]));
  fields.push(hexToBytes(ballot.sumProof));
  return frame(fields);
}

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' };

/** A voter key pair. The private key cannot be exported from the object that holds it. */
export async function generateVoterKey() {
  const pair = await globalThis.crypto.subtle.generateKey(ECDSA, false, ['sign', 'verify']);
  const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicKeyHex: bytesToHex(spki) };
}

/** ECDSA P-256 over SHA-256. WebCrypto returns r and s side by side, 64 bytes, not DER. */
export async function signBallot(privateKey, publicKey, context, voterId, ballot) {
  const signature = await globalThis.crypto.subtle.sign(ECDSA_SHA256, privateKey, ballotBytes(publicKey, context, voterId, ballot));
  return bytesToHex(new Uint8Array(signature));
}

export async function verifyBallotSignature(voterPublicKeyHex, signatureHex, publicKey, context, voterId, ballot) {
  try {
    const key = await globalThis.crypto.subtle.importKey('spki', hexToBytes(voterPublicKeyHex), ECDSA, false, ['verify']);
    return await globalThis.crypto.subtle.verify(ECDSA_SHA256, key, hexToBytes(signatureHex), ballotBytes(publicKey, context, voterId, ballot));
  } catch {
    return false;
  }
}
