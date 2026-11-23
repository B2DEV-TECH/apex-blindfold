// Unit tests for the Paillier library that the browser runs
// (app/apexlang/shared-components/static-files/blindfold/paillier.js).
// Run with: node --test tests/unit/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as P from '../lib/paillier.mjs';

// A deterministic "random" source that replays fixed bytes, to force a chosen r.
const fixedRandom = (...values) => {
  let i = 0;
  return (length) => {
    const bytes = new Uint8Array(length);
    bytes[length - 1] = values[i++ % values.length];
    return bytes;
  };
};

test('modPow matches known answers', () => {
  assert.equal(P.modPow(4n, 13n, 497n), 445n);
  assert.equal(P.modPow(2n, 10n, 1000n), 24n);
  assert.equal(P.modPow(7n, 0n, 13n), 1n);
  assert.equal(P.modPow(5n, 3n, 1n), 0n);
  // Fermat: a^(p-1) = 1 mod p for the Mersenne prime 2^127 - 1
  const mersenne = (1n << 127n) - 1n;
  assert.equal(P.modPow(3n, mersenne - 1n, mersenne), 1n);
});

test('gcd, lcm and modInv', () => {
  assert.equal(P.gcd(48n, 18n), 6n);
  assert.equal(P.lcm(6n, 10n), 30n);
  assert.equal(P.modInv(30n, 77n), 18n);
  assert.equal((P.modInv(3n, 11n) * 3n) % 11n, 1n);
  assert.throws(() => P.modInv(6n, 9n), RangeError);
});

test('Miller-Rabin separates primes from composites', () => {
  const primes = [2n, 3n, 8191n, 8209n, 104729n, (1n << 61n) - 1n, (1n << 127n) - 1n];
  // 561, 1105 and 6601 are Carmichael numbers; the last two are products of large primes.
  const composites = [1n, 561n, 1105n, 6601n, 8192n, 104729n * 104723n, ((1n << 61n) - 1n) * ((1n << 31n) - 1n)];
  for (const p of primes) assert.equal(P.isProbablePrime(p), true, `${p} is prime`);
  for (const c of composites) assert.equal(P.isProbablePrime(c), false, `${c} is composite`);
});

test('textbook example with p = 7, q = 11', () => {
  const pub = P.publicKeyFromN(77n);
  const priv = P.privateKeyFromPrimes(7n, 11n);
  assert.equal(priv.lambda, 30n);
  assert.equal(priv.mu, 18n);
  // r is forced to 3, so the ciphertext can be checked by hand:
  // c = (1 + 5*77) * 3^77 mod 77^2
  const c = P.encrypt(pub, 5n, fixedRandom(3));
  assert.equal(c, (386n * P.modPow(3n, 77n, 5929n)) % 5929n);
  assert.equal(P.decrypt(pub, priv, c), 5n);
});

test('round trip, addition and scalar multiplication on a 512-bit key', async () => {
  const { publicKey, privateKey } = await P.generateKeyPair(512);
  assert.equal(publicKey.bits, 512);
  assert.equal(publicKey.hexLength, 256);
  for (const m of [0n, 1n, 2n, 1000n, publicKey.n - 1n]) {
    assert.equal(P.decrypt(publicKey, privateKey, P.encrypt(publicKey, m)), m);
  }
  const a = P.encrypt(publicKey, 17n);
  const b = P.encrypt(publicKey, 25n);
  assert.equal(P.decrypt(publicKey, privateKey, P.add(publicKey, a, b)), 42n);
  assert.equal(P.decrypt(publicKey, privateKey, P.scalarMultiply(publicKey, a, 3n)), 51n);
  // The empty sum is an encryption of zero.
  assert.equal(P.decrypt(publicKey, privateKey, P.add(publicKey)), 0n);
  // Sums wrap around modulo n.
  const big = P.encrypt(publicKey, publicKey.n - 1n);
  assert.equal(P.decrypt(publicKey, privateKey, P.add(publicKey, big, b)), 24n);
});

test('the same plaintext never encrypts to the same ciphertext', async () => {
  const { publicKey } = await P.generateKeyPair(512);
  const seen = new Set();
  for (let i = 0; i < 50; i++) seen.add(P.encrypt(publicKey, 1n));
  assert.equal(seen.size, 50);
});

test('a ballot is Enc(1) for the choice and Enc(0) for the rest', async () => {
  const { publicKey, privateKey } = await P.generateKeyPair(512);
  for (let choice = 0; choice < 3; choice++) {
    const ballot = P.encryptBallot(publicKey, choice, 3);
    assert.equal(ballot.length, 3);
    ballot.forEach((hex, option) => {
      assert.equal(hex.length, publicKey.hexLength, 'fixed width');
      assert.match(hex, /^[0-9a-f]+$/);
      const m = P.decrypt(publicKey, privateKey, P.ciphertextFromHex(publicKey, hex));
      assert.equal(m, option === choice ? 1n : 0n);
    });
  }
  assert.throws(() => P.encryptBallot(publicKey, 3, 3), RangeError);
});

test('range checks reject bad input', async () => {
  const { publicKey, privateKey } = await P.generateKeyPair(512);
  assert.throws(() => P.encrypt(publicKey, -1n), RangeError);
  assert.throws(() => P.encrypt(publicKey, publicKey.n), RangeError);
  assert.throws(() => P.decrypt(publicKey, privateKey, 0n), RangeError);
  assert.throws(() => P.decrypt(publicKey, privateKey, publicKey.nSquared), RangeError);
  assert.throws(() => P.fromHex('xyz'), TypeError);
});

test('a 2048-bit key has the documented shape', async () => {
  const { publicKey, privateKey } = await P.generateKeyPair(2048);
  assert.equal(publicKey.bits, 2048);
  assert.equal(P.bitLength(privateKey.p), 1024);
  assert.equal(P.bitLength(privateKey.q), 1024);
  assert.equal(privateKey.p * privateKey.q, publicKey.n);
  assert.equal(publicKey.hexLength, 1024, 'a ciphertext is 1024 hex characters: it fits VARCHAR2(1024)');
  assert.equal((privateKey.lambda * privateKey.mu) % publicKey.n, 1n);
  const c = P.encrypt(publicKey, 1n);
  assert.equal(P.ciphertextToHex(publicKey, c).length, 1024);
  assert.equal(P.decrypt(publicKey, privateKey, c), 1n);
});
