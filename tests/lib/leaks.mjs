// Leak scanner: looks for secret numbers inside any text the server side holds.
//
// Two independent detectors:
//
//   windows     every 20-character window of every secret, in several
//               encodings (hex, little-endian hex, decimal, base64 at the
//               three byte alignments, base64url). A leak of a fragment as
//               short as 20 characters is found.
//
//   structure   every long number found in the text is tested against the
//               public key: does it share a factor with n, is it a multiple
//               of lambda, is it an n-th root that opens a stored ciphertext?
//               This finds secrets in forms the window detector does not
//               know, as long as they are written as one hexadecimal or
//               decimal number.
//
// What counts as a secret needs care, because parts of the private key are
// public. phi(n) = n - (p + q) + 1, so the upper half of phi(n) is the upper
// half of n, and lambda = phi(n) / gcd(p-1, q-1) inherits it. The scanner
// therefore drops every window that also occurs in a public number (n, n^2,
// n / gcd): finding one of those would prove nothing.
//
// For the same reason r^n is not on the list of secrets, although it opens a
// vote: for an encryption of zero the ciphertext IS r^n. The secret is r.
import * as P from './paillier.mjs';

const WINDOW = 20;
const TOKEN_CHAR = /[0-9A-Za-z+/_-]/;

function bytesOf(value) {
  const hex = value.toString(16);
  return Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
}

// Every textual form of one number that the window detector looks for.
export function secretEncodings(value) {
  const bytes = bytesOf(value);
  const forms = [
    { encoding: 'hex', text: value.toString(16), caseInsensitive: true },
    { encoding: 'hex of little-endian bytes', text: Buffer.from(bytes).reverse().toString('hex'), caseInsensitive: true },
    { encoding: 'decimal', text: value.toString(10), caseInsensitive: false },
  ];
  for (let offset = 0; offset < 3; offset++) {
    // Base64 text depends on where the bytes start inside a larger message.
    const core = Buffer.concat([Buffer.alloc(offset), bytes]).toString('base64').replace(/=+$/, '').slice(4, -4);
    forms.push({ encoding: `base64 (byte offset ${offset})`, text: core, caseInsensitive: false });
    const urlSafe = core.replace(/\+/g, '-').replace(/\//g, '_');
    if (urlSafe !== core) forms.push({ encoding: `base64url (byte offset ${offset})`, text: urlSafe, caseInsensitive: false });
  }
  return forms;
}

function* windowsOf(value) {
  for (const form of secretEncodings(value)) {
    const text = form.caseInsensitive ? form.text.toLowerCase() : form.text;
    for (let i = 0; i + WINDOW <= text.length; i++) yield { window: text.substr(i, WINDOW), form };
  }
}

// The private key and everything equivalent to it.
export function privateKeySecrets({ p, q, lambda, mu }) {
  return [
    { name: 'p', value: p },
    { name: 'q', value: q },
    { name: 'lambda', value: lambda },
    { name: 'mu', value: mu },
    { name: 'p-1', value: p - 1n },
    { name: 'q-1', value: q - 1n },
    { name: 'phi(n)', value: (p - 1n) * (q - 1n) },
    { name: 'p+q', value: p + q },
  ];
}

export class LeakScanner {
  // secrets:     [{ name, value: BigInt }]
  // publicKey:   enables the structural detector
  // privateKey:  enables the "multiple of lambda" and "inverse of lambda" tests,
  //              and tells which windows of the secrets are in fact public
  // ciphertexts: [BigInt] enables the "n-th root that opens a ciphertext" test
  constructor(secrets, { publicKey = null, privateKey = null, ciphertexts = [] } = {}) {
    this.secrets = secrets;
    this.publicKey = publicKey;
    this.lambda = privateKey?.lambda ?? null;
    this.insensitive = new Map();
    this.sensitive = new Map();
    this.sources = [];
    this.structureCache = new Map();

    const publicValues = [];
    if (publicKey) publicValues.push(publicKey.n, publicKey.nSquared);
    if (publicKey && privateKey) publicValues.push(publicKey.n / P.gcd(privateKey.p - 1n, privateKey.q - 1n));
    const publicWindows = new Set();
    for (const value of publicValues) for (const { window } of windowsOf(value)) publicWindows.add(window);
    this.publicWindowsDropped = 0;

    for (const secret of secrets) {
      for (const { window, form } of windowsOf(secret.value)) {
        if (publicWindows.has(window)) {
          this.publicWindowsDropped += 1;
          continue;
        }
        const target = form.caseInsensitive ? this.insensitive : this.sensitive;
        if (!target.has(window)) target.set(window, `${secret.name} as ${form.encoding}`);
      }
    }

    // For each stored ciphertext c: r^n is c if it encrypts 0, c / (1 + n) if it encrypts 1.
    this.openings = new Set();
    if (publicKey) {
      const unshift = P.modInv(1n + publicKey.n, publicKey.nSquared);
      for (const c of ciphertexts) {
        this.openings.add(c);
        this.openings.add((c * unshift) % publicKey.nSquared);
      }
    }
  }

  get windowCount() {
    return this.insensitive.size + this.sensitive.size;
  }

  // Structural test of one number against the public key.
  structure(value) {
    if (!this.publicKey || value <= 1n) return null;
    const { n, nSquared } = this.publicKey;
    const common = P.gcd(value, n);
    if (common !== 1n && common !== n) return 'shares a prime factor with n';
    if (value % n === 0n) return null;
    // A multiple of lambda maps every unit to 1. Two bases: no false alarms.
    if (P.modPow(2n, value, n) === 1n && P.modPow(3n, value, n) === 1n) return 'is a multiple of lambda';
    if (this.lambda && (value * this.lambda) % n === 1n) return 'is the inverse of lambda modulo n (mu)';
    if (this.openings.size > 0 && value < nSquared && this.openings.has(P.modPow(value, n, nSquared))) return 'is an n-th root that opens a stored ciphertext (a randomizer r)';
    return null;
  }

  // Scans one text. Returns the findings and records a line for the report.
  scan(label, text) {
    const source = { label, chars: text.length, windowHits: [], structureHits: [], numbers: 0, numbersTested: 0 };
    const lower = text.toLowerCase();
    const seen = new Set();
    let run = 0;
    for (let i = 0; i < text.length; i++) {
      run = TOKEN_CHAR.test(text[i]) ? run + 1 : 0;
      if (run < WINDOW) continue;
      const start = i - WINDOW + 1;
      const hit = this.sensitive.get(text.substr(start, WINDOW)) ?? this.insensitive.get(lower.substr(start, WINDOW));
      if (hit && !seen.has(hit)) {
        seen.add(hit);
        source.windowHits.push({ what: hit, offset: start, excerpt: text.substr(Math.max(0, start - 12), WINDOW + 24) });
      }
    }

    if (this.publicKey) {
      const numbers = new Map();
      for (const match of lower.matchAll(/[0-9a-f]{48,}/g)) numbers.set(`x${match[0]}`, { radix: 16, text: match[0] });
      for (const match of lower.matchAll(/(?<![0-9a-f])[0-9]{60,}(?![0-9a-f])/g)) numbers.set(`d${match[0]}`, { radix: 10, text: match[0] });
      source.numbers = numbers.size;
      for (const [key, number] of numbers) {
        if (number.text.length > 1300) continue; // longer than any value derived from a 2048-bit key
        if (!this.structureCache.has(key)) {
          const value = number.radix === 16 ? BigInt(`0x${number.text}`) : BigInt(number.text);
          this.structureCache.set(key, this.structure(value));
        }
        source.numbersTested += 1;
        const verdict = this.structureCache.get(key);
        if (verdict) source.structureHits.push({ what: verdict, excerpt: `${number.text.slice(0, 24)}… (${number.text.length} chars)` });
      }
    }
    this.sources.push(source);
    return source;
  }

  get findings() {
    return this.sources.flatMap((s) => [
      ...s.windowHits.map((h) => ({ source: s.label, detector: 'window', ...h })),
      ...s.structureHits.map((h) => ({ source: s.label, detector: 'structure', ...h })),
    ]);
  }

  // Text table for the evidence file.
  reportLines() {
    const width = Math.max(6, ...this.sources.map((s) => s.label.length));
    const lines = [`${'source'.padEnd(width)}  characters  long numbers  tested  findings`];
    lines.push('-'.repeat(lines[0].length));
    for (const s of this.sources) {
      lines.push(`${s.label.padEnd(width)}  ${String(s.chars).padStart(10)}  ${String(s.numbers).padStart(12)}  ${String(s.numbersTested).padStart(6)}  ${String(s.windowHits.length + s.structureHits.length).padStart(8)}`);
    }
    return lines;
  }
}

// Positive controls: the scanner must find secrets that we plant on purpose,
// in whole and in fragments, and must stay silent on public and random data.
//
// opening: optional { r, ciphertext } - a randomizer and the ciphertext it opens.
export function selfTest(publicKey, privateKey, randomHex, opening = null) {
  const secrets = privateKeySecrets(privateKey);
  const { p, q, lambda, mu } = privateKey;
  const phi = (p - 1n) * (q - 1n);
  const b64 = (value, offset) => Buffer.concat([Buffer.alloc(offset, 0x41), bytesOf(value)]).toString('base64');
  const options = { publicKey, privateKey, ciphertexts: opening ? [opening.ciphertext] : [] };
  const all = opening ? [...secrets, { name: 'randomizer r', value: opening.r }] : secrets;

  const plants = [
    { name: 'lambda, full hex inside JSON', text: `{"debug":"key=${lambda.toString(16)}"}` },
    { name: 'p, upper-case hex', text: `P=${p.toString(16).toUpperCase()};` },
    { name: 'q, decimal', text: `q is ${q.toString(10)} today` },
    { name: 'mu, base64 at byte offset 1', text: `blob:${b64(mu, 1)}` },
    { name: 'phi(n), full hex', text: `phi=${phi.toString(16)}` },
    { name: 'lambda, 24 characters of its lower half', text: `...${lambda.toString(16).slice(-124, -100)}...` },
    { name: 'phi(n), 30 decimal digits of its lower half', text: `x=${phi.toString(10).slice(-80, -50)}` },
    { name: '3 * lambda as hex (structure detector only)', text: `value ${(3n * lambda).toString(16)} end` },
    { name: '7 * p as decimal (structure detector only)', text: `value ${(7n * p).toString(10)} end` },
  ];
  if (opening) {
    plants.push({ name: 'randomizer r of one ciphertext, hex', text: `r=${opening.r.toString(16)}` });
    plants.push({ name: 'r + 5n as decimal (structure detector only)', text: `value ${(opening.r + 5n * publicKey.n).toString(10)} end` });
  }
  const silent = [
    { name: 'control: n, n^2 and random hex', text: `n=${publicKey.n.toString(16)} n2=${publicKey.nSquared.toString(10)} noise=${randomHex}` },
    { name: 'control: upper half of phi(n), which equals the upper half of n', text: `top=${phi.toString(16).slice(0, 200)}` },
  ];
  if (opening) silent.push({ name: 'control: the ciphertext itself', text: `c=${opening.ciphertext.toString(16)}` });

  const run = (plant, expectDetected) => {
    const source = new LeakScanner(all, options).scan(plant.name, plant.text);
    const by = [...source.windowHits.map(() => 'window'), ...source.structureHits.map(() => 'structure')].filter((v, i, a) => a.indexOf(v) === i).join('+');
    return { name: plant.name, expectDetected, detected: source.windowHits.length + source.structureHits.length > 0, by };
  };
  return [...plants.map((plant) => run(plant, true)), ...silent.map((plant) => run(plant, false))];
}
