// Exports the Layer 2 test vectors from a real browser.
//
// The browser loads the very files the APEX application serves (paillier.js and validity.js) from
// a local web server, builds the vectors and signs every ballot with WebCrypto. Node then builds
// the same vectors from the same seed with the same files, and the two must be equal before
// anything is written. The result, tests/vectors/layer2-vectors.json, is committed: the Java
// verifier in the database is tested against that fixed file (tests/g1-vectors.mjs).
//
//   node tests/vectors/export-vectors.mjs            writes the file
//   node tests/vectors/export-vectors.mjs --check    fails if the proofs in the file can no longer be reproduced
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as P from '../lib/paillier.mjs';
import * as V from '../lib/validity.mjs';
import { buildVectors, replayable } from './build-vectors.js';
import { loadConfig, ROOT } from '../lib/config.mjs';
import { launchBrowser } from '../lib/browser.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const STATIC = join(ROOT, 'app', 'apexlang', 'shared-components', 'static-files', 'blindfold');
const OUT = join(HERE, 'layer2-vectors.json');
const SEED = 20261124;
const SIZES = [512, 2048];
const check = process.argv.includes('--check');

// Serves the application's static files and the vector builder, and nothing else.
const FILES = {
  '/': ['text/html', '<!doctype html><meta charset="utf-8"><title>APEX Blindfold vectors</title>'],
  '/blindfold/paillier.js': ['text/javascript', readFileSync(join(STATIC, 'paillier.js'))],
  '/blindfold/validity.js': ['text/javascript', readFileSync(join(STATIC, 'validity.js'))],
  '/build-vectors.js': ['text/javascript', readFileSync(join(HERE, 'build-vectors.js'))],
};
const server = createServer((request, response) => {
  const file = FILES[request.url];
  if (!file) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'content-type': file[0] }).end(file[1]);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

const browser = await launchBrowser(loadConfig());
let fromBrowser;
try {
  const page = await browser.newPage();
  page.on('pageerror', (error) => console.error(`[browser] ${error.message}`));
  await page.goto(`${origin}/`);
  fromBrowser = await page.evaluate(async ({ seed, sizes }) => {
    const P = await import('/blindfold/paillier.js');
    const V = await import('/blindfold/validity.js');
    const { buildVectors } = await import('/build-vectors.js');
    const sets = [];
    for (const bits of sizes) sets.push(await buildVectors(P, V, { seed, bits, sign: true }));
    return sets;
  }, { seed: SEED, sizes: SIZES });
} finally {
  const version = browser.version();
  const channel = browser.bfChannel;
  await browser.close();
  server.close();
  fromBrowser = { browser: `${channel} ${version}`, sets: fromBrowser };
}

// ---- Node builds the same vectors from the same seed
const fromNode = [];
for (const bits of SIZES) fromNode.push(await buildVectors(P, V, { seed: SEED, bits }));

const same = JSON.stringify(fromBrowser.sets.map(replayable)) === JSON.stringify(fromNode.map(replayable));
const samples = fromBrowser.sets.flatMap((set) => set.samples);
const asExpected = samples.every((s) => s.verifier.valid === s.expected_valid);
const signed = samples.every((s) => s.signature_verifies_in_the_browser === true && s.signature.length === 128);
console.log(`browser: ${fromBrowser.browser}; node: ${process.version}`);
console.log(`${samples.length} samples in ${SIZES.length} key sizes (${SIZES.join(', ')} bits), seed ${SEED}`);
console.log(`browser and Node built the same ciphertexts, proofs and challenge hashes: ${same ? 'yes' : 'NO'}`);
console.log(`every sample is accepted or rejected as expected by the JavaScript verifier: ${asExpected ? 'yes' : 'NO'}`);
console.log(`every sample carries a 64-byte signature that the browser itself verifies: ${signed ? 'yes' : 'NO'}`);
if (!same || !asExpected || !signed) {
  process.exitCode = 1;
} else if (check) {
  if (!existsSync(OUT)) {
    console.log('No vector file to check.');
    process.exitCode = 1;
  } else {
    const stored = JSON.parse(readFileSync(OUT, 'utf8'));
    const unchanged = JSON.stringify(stored.sets.map(replayable)) === JSON.stringify(fromNode.map(replayable));
    console.log(`the proofs in ${OUT.slice(ROOT.length + 1).replace(/\\/g, '/')} are reproduced from the seed: ${unchanged ? 'yes' : 'NO'}`);
    if (!unchanged) process.exitCode = 1;
  }
} else {
  const document = {
    description: 'APEX Blindfold, Layer 2 test vectors: fixed ballots with their validity proofs, challenge hashes and voter signatures. Exported by a browser; every implementation must reproduce the challenge hashes byte for byte.',
    exported_by: fromBrowser.browser,
    reproduced_by: `node ${process.version}`,
    encoding: {
      framing: 'every field is a 4-byte big-endian length followed by its bytes; text is UTF-8',
      bit_challenge: ['"apex-blindfold/v2/bit"', 'n (width of n)', 'election_id (8 bytes)', 'ballot_id (8 bytes)', 'candidate_id (8 bytes)', 'c (twice the width of n)', 'a0', 'a1'],
      sum_challenge: ['"apex-blindfold/v2/sum"', 'n', 'election_id', 'ballot_id', 'c1', 'c2', 'c3', 'a'],
      signed_bytes: ['"apex-blindfold/v2/ballot"', 'n', 'election_id', 'ballot_id', 'voter_id (text)', 'c1', 'bit proof 1', 'c2', 'bit proof 2', 'c3', 'bit proof 3', 'sum proof'],
      challenge: 'the first 128 bits of the SHA-256 of those bytes',
      bit_proof: 'e0 | e1 | z0 | z1 in hexadecimal: 32 + 32 + W + W characters, W = hexadecimal width of n',
      sum_proof: 'e | z in hexadecimal: 32 + W characters',
      signature: 'ECDSA P-256 over SHA-256, r | s (IEEE P1363), 64 bytes; public key as SubjectPublicKeyInfo',
    },
    sets: fromBrowser.sets,
  };
  writeFileSync(OUT, `${JSON.stringify(document, null, 1)}\n`);
  console.log(`written: ${OUT.slice(ROOT.length + 1).replace(/\\/g, '/')}`);
}
