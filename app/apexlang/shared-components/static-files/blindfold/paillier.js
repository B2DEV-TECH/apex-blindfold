/**
 * Paillier additively homomorphic encryption on JavaScript BigInt.
 *
 * Written from the definition in P. Paillier, "Public-Key Cryptosystems Based
 * on Composite Degree Residuosity Classes" (EUROCRYPT 1999), using the common
 * simplification g = n + 1.
 *
 *   key       n = p*q,  lambda = lcm(p-1, q-1),  mu = lambda^-1 mod n
 *   encrypt   c = (1 + m*n) * r^n mod n^2        with r random in Z*_n
 *   decrypt   m = L(c^lambda mod n^2) * mu mod n  with L(x) = (x - 1) / n
 *   add       Enc(a) * Enc(b) mod n^2 = Enc(a + b)
 *   scalar    Enc(a)^k mod n^2        = Enc(k * a)
 *
 * EDUCATIONAL CODE. It is not constant time, it was never audited, and it must
 * not protect real data. The same file runs in the browser and in Node.
 */

// Small primes for trial division, built once with a sieve.
const SMALL_PRIMES = (() => {
  const limit = 8192;
  const composite = new Uint8Array(limit + 1);
  const primes = [];
  for (let i = 2; i <= limit; i++) {
    if (composite[i]) continue;
    primes.push(BigInt(i));
    for (let j = i * i; j <= limit; j += i) composite[j] = 1;
  }
  return primes;
})();

/** Default random source: the platform CSPRNG. Returns `length` random bytes. */
export function systemRandom(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

// ---------------------------------------------------------------- conversions

export function bytesToBigInt(bytes) {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

/** Lower-case hexadecimal, left-padded with zeros to `width` characters. */
export function toHex(value, width = 0) {
  return value.toString(16).padStart(width, '0');
}

export function fromHex(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]+$/.test(hex)) throw new TypeError('expected a hexadecimal string');
  return BigInt(`0x${hex}`);
}

export function bitLength(value) {
  return value === 0n ? 0 : value.toString(2).length;
}

// ----------------------------------------------------------------- arithmetic

/** base^exponent mod modulus, by left-to-right square-and-multiply. */
export function modPow(base, exponent, modulus) {
  if (modulus <= 0n) throw new RangeError('modulus must be positive');
  if (exponent < 0n) throw new RangeError('exponent must not be negative');
  if (modulus === 1n) return 0n;
  let b = base % modulus;
  if (b < 0n) b += modulus;
  let acc = 1n;
  const bits = exponent.toString(2);
  for (let i = 0; i < bits.length; i++) {
    acc = (acc * acc) % modulus;
    if (bits.charCodeAt(i) === 49 /* '1' */) acc = (acc * b) % modulus;
  }
  return acc;
}

export function gcd(a, b) {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

export function lcm(a, b) {
  return (a / gcd(a, b)) * b;
}

/** Modular inverse by the extended Euclidean algorithm. */
export function modInv(value, modulus) {
  let [r0, r1] = [((value % modulus) + modulus) % modulus, modulus];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const quotient = r0 / r1;
    [r0, r1] = [r1, r0 - quotient * r1];
    [s0, s1] = [s1, s0 - quotient * s1];
  }
  if (r0 !== 1n) throw new RangeError('value has no inverse for this modulus');
  return ((s0 % modulus) + modulus) % modulus;
}

// ------------------------------------------------------------------ randomness

/** Uniform random integer in [0, limit), by rejection sampling. */
export function randomBelow(limit, random = systemRandom) {
  if (limit <= 0n) throw new RangeError('limit must be positive');
  const bits = bitLength(limit - 1n);
  if (bits === 0) return 0n;
  const byteCount = Math.ceil(bits / 8);
  const topMask = 0xff >> (byteCount * 8 - bits);
  for (;;) {
    const bytes = random(byteCount);
    bytes[0] &= topMask;
    const candidate = bytesToBigInt(bytes);
    if (candidate < limit) return candidate;
  }
}

/** Uniform random element of Z*_n: 0 < r < n and gcd(r, n) = 1. */
export function randomUnit(n, random = systemRandom) {
  for (;;) {
    const r = randomBelow(n, random);
    if (r > 0n && gcd(r, n) === 1n) return r;
  }
}

// ---------------------------------------------------------------------- primes

/**
 * Miller-Rabin primality test with random bases, after trial division.
 * A composite passes `rounds` rounds with probability at most 4^-rounds.
 */
export function isProbablePrime(candidate, rounds = 40, random = systemRandom) {
  if (candidate < 2n) return false;
  for (const prime of SMALL_PRIMES) {
    if (candidate === prime) return true;
    if (candidate % prime === 0n) return false;
  }
  // candidate - 1 = d * 2^s with d odd
  let d = candidate - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1;
  }
  nextRound: for (let round = 0; round < rounds; round++) {
    const base = 2n + randomBelow(candidate - 3n, random); // in [2, candidate - 2]
    let x = modPow(base, d, candidate);
    if (x === 1n || x === candidate - 1n) continue;
    for (let i = 1; i < s; i++) {
      x = (x * x) % candidate;
      if (x === candidate - 1n) continue nextRound;
    }
    return false;
  }
  return true;
}

/**
 * Random prime with exactly `bits` bits. The two top bits are set, so the
 * product of two such primes always has exactly 2 * bits bits.
 * `pause`, when given, is awaited between candidates so a browser can repaint.
 */
export async function generatePrime(bits, { random = systemRandom, rounds = 40, pause = null, onCandidate = null } = {}) {
  if (bits < 16 || bits % 8 !== 0) throw new RangeError('prime size must be a multiple of 8, at least 16 bits');
  for (let tried = 1; ; tried++) {
    const bytes = random(bits / 8);
    bytes[0] |= 0xc0;
    bytes[bytes.length - 1] |= 0x01;
    const candidate = bytesToBigInt(bytes);
    if (onCandidate) onCandidate(tried);
    if (isProbablePrime(candidate, rounds, random)) return candidate;
    if (pause && tried % 8 === 0) await pause();
  }
}

// ------------------------------------------------------------------------ keys

/** Everything a voter or the database needs: the modulus n. */
export function publicKeyFromN(n) {
  const nSquared = n * n;
  return {
    n,
    nSquared,
    bits: bitLength(n),
    // Fixed width of a ciphertext in hexadecimal characters.
    hexLength: Math.ceil(bitLength(nSquared) / 4),
  };
}

export function privateKeyFromPrimes(p, q) {
  const n = p * q;
  const lambda = lcm(p - 1n, q - 1n);
  const mu = modInv(lambda, n);
  return { p, q, lambda, mu };
}

/** Generates a key pair with a modulus of `bits` bits (2048 by default). */
export async function generateKeyPair(bits = 2048, options = {}) {
  if (bits % 16 !== 0) throw new RangeError('key size must be a multiple of 16 bits');
  for (;;) {
    const p = await generatePrime(bits / 2, options);
    const q = await generatePrime(bits / 2, options);
    if (p === q) continue;
    const n = p * q;
    // Needed for g = n + 1 to be valid. Always true for primes of equal length.
    if (gcd(n, (p - 1n) * (q - 1n)) !== 1n) continue;
    return { publicKey: publicKeyFromN(n), privateKey: privateKeyFromPrimes(p, q) };
  }
}

// ------------------------------------------------------------------ operations

/**
 * c = (1 + m*n) * randomizer mod n^2, where randomizer = r^n mod n^2.
 * Split from `encrypt` so that a caller can compute r^n elsewhere.
 */
export function encryptWithRandomizer(publicKey, message, randomizer) {
  const { n, nSquared } = publicKey;
  const m = BigInt(message);
  if (m < 0n || m >= n) throw new RangeError('message must be in [0, n)');
  return (((1n + m * n) % nSquared) * randomizer) % nSquared;
}

/** c = (1 + m*n) * r^n mod n^2. A fresh random r makes every ciphertext different. */
export function encrypt(publicKey, message, random = systemRandom) {
  const { n, nSquared } = publicKey;
  const r = randomUnit(n, random);
  return encryptWithRandomizer(publicKey, message, modPow(r, n, nSquared));
}

/** m = L(c^lambda mod n^2) * mu mod n, with L(x) = (x - 1) / n. */
export function decrypt(publicKey, privateKey, ciphertext) {
  const { n, nSquared } = publicKey;
  if (ciphertext <= 0n || ciphertext >= nSquared) throw new RangeError('ciphertext must be in (0, n^2)');
  const x = modPow(ciphertext, privateKey.lambda, nSquared);
  return (((x - 1n) / n) * privateKey.mu) % n;
}

/** Homomorphic addition: the product of ciphertexts encrypts the sum of plaintexts. */
export function add(publicKey, ...ciphertexts) {
  let acc = 1n; // 1 is a (trivial) encryption of zero
  for (const c of ciphertexts) acc = (acc * c) % publicKey.nSquared;
  return acc;
}

/** Homomorphic scalar multiplication: Enc(m)^k encrypts k * m. */
export function scalarMultiply(publicKey, ciphertext, k) {
  return modPow(ciphertext, BigInt(k), publicKey.nSquared);
}

// ---------------------------------------------------------------- wire format

export function ciphertextToHex(publicKey, ciphertext) {
  return toHex(ciphertext, publicKey.hexLength);
}

export function ciphertextFromHex(publicKey, hex) {
  const c = fromHex(hex);
  if (c <= 0n || c >= publicKey.nSquared) throw new RangeError('ciphertext out of range');
  return c;
}

/**
 * A ballot is one ciphertext per option: Enc(1) for the chosen option and
 * Enc(0) for every other one. `choice` is the zero-based index of the option.
 * Returns hexadecimal strings in option order.
 */
export function encryptBallot(publicKey, choice, optionCount, random = systemRandom) {
  if (!Number.isInteger(choice) || choice < 0 || choice >= optionCount) throw new RangeError('choice out of range');
  const ballot = [];
  for (let option = 0; option < optionCount; option++) {
    ballot.push(ciphertextToHex(publicKey, encrypt(publicKey, option === choice ? 1n : 0n, random)));
  }
  return ballot;
}

/** Short label for a public key, for display only. It is not a secure fingerprint. */
export function keyLabel(publicKey) {
  const hex = toHex(publicKey.n);
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}
