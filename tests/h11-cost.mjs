// H11 - Cost.
//
//   "What Layer 2 costs against Layer 1: proof size, proving time in the browser, verification
//    time per ballot in the database, and the tally of 10,000 voters."
//
// The Layer 1 numbers are read from evidence/h6-cost/result.json, the run on tag v1-layer1,
// same machine. Every raw Layer 2 measurement goes to evidence/h11-cost/timings.json.
//
// How the 10,000 ballots are made: in Node worker threads, with the same library the browser
// loads (validity.js), one voter key per voter, then inserted by the owner of the tables with
// the voter roll updated as cast_ballot would. They skip the verification at arrival, which
// would cost the same time again (about two hours at 10,000), and which is measured on its own
// below. The tally verifies every one of them again, and that is what is timed.
//
//   node tests/h11-cost.mjs [--quick] [--seed N]
import os from 'node:os';
import { Worker } from 'node:worker_threads';
import * as P from './lib/paillier.mjs';
import * as V from './lib/validity.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect, oracledb } from './lib/db.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser } from './lib/app.mjs';
import { openElection, prepareBallot, encryptedTally, decryptTally, countChoices, seededRandom, voterCode, currentElectionId, OPTIONS } from './lib/election.mjs';
import { writeText, writeJson, header, stats, EVIDENCE } from './lib/evidence.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h11-cost';
const now = () => Number(process.hrtime.bigint()) / 1e6;
const round = (x) => Math.round(x * 1000) / 1000;
const BITS = 2048; // the key size of the application, in both modes

// ---- part 1: what a voter pays, measured inside the browser
async function browserCost(cfg, args) {
  const casts = args.quick ? 3 : 20;
  const rounds = args.quick ? 3 : 20;
  const browser = await launchBrowser(cfg);
  try {
    const authority = await (await browser.newContext()).newPage();
    watch(authority, 'authority');
    await openElectionInBrowser(authority, cfg, casts + 2);

    const voter = await (await browser.newContext()).newPage();
    watch(voter, 'voter');
    const castBytes = [];
    const registerBytes = [];
    voter.on('request', (request) => {
      const body = request.postData() ?? '';
      if (body.includes('CAST_BALLOT')) castBytes.push(Buffer.byteLength(body));
      if (body.includes('REGISTER_VOTER')) registerBytes.push(Buffer.byteLength(body));
    });
    await voter.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
    await voter.waitForSelector('.bf-option');

    // From the click to the receipt: key, registration, encryption, proofs, signature, the
    // request, the verification in the database and the insert, as the voter experiences it.
    const castUi = [];
    for (let i = 0; i < casts; i++) {
      await voter.fill('#bf-voter', voterCode(i));
      await voter.locator('.bf-option').nth(i % OPTIONS).click();
      castUi.push(await voter.evaluate(() => new Promise((resolve) => {
        const receipt = document.querySelector('#bf-receipt');
        const started = performance.now();
        const observer = new MutationObserver(() => {
          if (receipt.hidden) return;
          observer.disconnect();
          resolve(performance.now() - started);
        });
        observer.observe(receipt, { attributes: true, attributeFilter: ['hidden'] });
        document.querySelector('#bf-cast').click();
      })));
      await voter.click('#bf-next');
    }

    // The library alone, loaded from the application's own static files.
    const micro = await voter.evaluate(async ({ rounds }) => {
      const base = document.querySelector('script[src*="blindfold/boot.js"]').src.replace(/boot\.js.*$/, '');
      const P = await import(`${base}paillier.js`);
      const V = await import(`${base}validity.js`);
      const info = await new Promise((resolve, reject) => apex.server.process('ELECTION_INFO', {}, { dataType: 'json', success: resolve, error: reject }));
      const key = P.publicKeyFromN(P.fromHex(info.n_hex));
      const context = { electionId: info.election_id, ballotId: 999999 };
      const time = async (fn) => { const started = performance.now(); const value = await fn(); return [performance.now() - started, value]; };
      const encryptOnly = [];
      const prove = [];
      const keygen = [];
      const sign = [];
      let last = null;
      for (let i = 0; i < rounds; i++) {
        encryptOnly.push((await time(() => P.encryptBallot(key, i % 3, 3)))[0]);
        const [ms, ballot] = await time(() => V.proveChoice(key, context, i % 3, 3));
        prove.push(ms);
        const [kms, voterKey] = await time(() => V.generateVoterKey());
        keygen.push(kms);
        sign.push((await time(() => V.signBallot(voterKey.privateKey, key, context, 'VOTER-0001', ballot)))[0]);
        last = ballot;
      }
      return {
        encryptOnly, prove, keygen, sign,
        sizes: { ciphertexts: last.ciphertexts.join('').length, bitProofs: last.bitProofs.join('').length, sumProof: last.sumProof.length },
        userAgent: navigator.userAgent, logicalCores: navigator.hardwareConcurrency,
      };
    }, { rounds });
    return {
      browser: `${browser.bfChannel} ${browser.version()} (headless)`,
      logical_cores: micro.logicalCores,
      cast_ballot_ui_ms: castUi.map(round),
      cast_ballot_request_bytes: castBytes,
      register_request_bytes: registerBytes,
      encrypt_only_ms: micro.encryptOnly.map(round),
      encrypt_and_prove_ms: micro.prove.map(round),
      voter_keygen_ms: micro.keygen.map(round),
      sign_ms: micro.sign.map(round),
      hex_sizes: micro.sizes,
    };
  } finally {
    await browser.close();
  }
}

// ---- part 2: verification of one ballot in the database, as cast_ballot does it
async function verificationCost(conn, args) {
  const samples = args.quick ? 3 : 20;
  const pair = await P.generateKeyPair(BITS);
  const key = pair.publicKey;
  await openElection(conn, key, samples);
  const e = await currentElectionId(conn);
  const proofs = [];
  const signatures = [];
  const casts = [];
  for (let i = 0; i < samples; i++) {
    const b = await prepareBallot(conn, key, voterCode(i), [i % 3 === 0 ? 1 : 0, i % 3 === 1 ? 1 : 0, i % 3 === 2 ? 1 : 0], { electionId: e });
    const common = { n: P.toHex(key.n), e, b: b.ballotId, c1: b.ciphertexts[0], c2: b.ciphertexts[1], c3: b.ciphertexts[2], p1: b.bitProofs[0], p2: b.bitProofs[1], p3: b.bitProofs[2], ps: b.sumProof };
    let t = now();
    const ok = (await conn.execute('select bf_v2_verify_ballot(:n, :e, :b, :c1, :c2, :c3, :p1, :p2, :p3, :ps) as v from dual', common)).rows[0].V;
    proofs.push(now() - t);
    t = now();
    const signed = (await conn.execute('select bf_v2_verify_signature(:k, :g, :n, :e, :b, :voter, :c1, :c2, :c3, :p1, :p2, :p3, :ps) as v from dual',
      { ...common, k: b.voterKey.publicKeyHex, g: b.signature, voter: b.voter })).rows[0].V;
    signatures.push(now() - t);
    if (ok !== 'OK' || signed !== 'OK') throw new Error(`An honest ballot did not verify: ${ok} / ${signed}`);
    t = now();
    await conn.execute('begin :id := bf_election.cast_ballot(:voter, :b, :c1, :c2, :c3, :p1, :p2, :p3, :ps, :g); end;',
      { id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, voter: b.voter, b: b.ballotId, c1: b.ciphertexts[0], c2: b.ciphertexts[1], c3: b.ciphertexts[2], p1: b.bitProofs[0], p2: b.bitProofs[1], p3: b.bitProofs[2], ps: b.sumProof, g: b.signature });
    casts.push(now() - t);
  }
  await conn.commit();
  // The first call of a session also starts the Java virtual machine: reported apart.
  return { proofs_ms: proofs.map(round), signature_ms: signatures.map(round), cast_ballot_ms: casts.map(round) };
}

// ---- part 3: proven ballots in worker threads
async function buildBallots(nHex, electionId, jobs) {
  const threads = Math.max(1, Math.min(os.cpus().length - 1, 8));
  const slices = Array.from({ length: threads }, (_, t) => jobs.filter((_, i) => i % threads === t));
  let made = 0;
  const started = now();
  const results = await Promise.all(slices.map((slice) => new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./lib/prove-worker.mjs', import.meta.url), { workerData: { nHex, electionId, jobs: slice } });
    worker.on('message', (message) => {
      if (message.progress) {
        made += message.progress;
        if (made % 1000 === 0) console.log(`  ... ${made}/${jobs.length} ballots proven and signed, ${Math.round((now() - started) / 1000)} s`);
      }
      if (message.done) resolve(message.done);
    });
    worker.on('error', reject);
    worker.on('exit', (code) => { if (code !== 0) reject(new Error(`worker exit ${code}`)); });
  })));
  return { ballots: results.flat().sort((a, b) => a.ballotId - b.ballotId), threads, ms: now() - started };
}

async function insertBallots(conn, electionId, ballots) {
  await conn.executeMany('insert into blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:1, :2, :3, :4, :5)',
    ballots.flatMap((b) => [0, 1, 2].map((i) => [electionId, b.ballotId, i + 1, b.ciphertexts[i], b.bitProofs[i]])));
  await conn.executeMany('insert into ballot_seals (election_id, ballot_id, voter_id, sum_proof, signature) values (:1, :2, :3, :4, :5)',
    ballots.map((b) => [electionId, b.ballotId, b.voter, b.sumProof, b.signature]));
  await conn.executeMany('update voter_roll set public_key = :1, ballot_id = :2, registered_at = systimestamp, voted_at = systimestamp where voter_id = :3',
    ballots.map((b) => [b.publicKeyHex, b.ballotId, b.voter]));
  await conn.commit();
}

async function tallyCost(conn, args) {
  const sizes = args.quick ? [10, 50] : [100, 1000, 10000];
  const largest = sizes.at(-1);
  const random = seededRandom(args.seed);
  const pair = await P.generateKeyPair(BITS);
  const key = pair.publicKey;
  await openElection(conn, key, largest);
  const e = await currentElectionId(conn);
  const choices = Array.from({ length: largest }, () => Math.floor(random() * OPTIONS));
  const jobs = choices.map((choice, i) => ({ voter: voterCode(i), ballotId: i + 1, choice }));
  const built = await buildBallots(P.toHex(key.n), e, jobs);
  console.log(`  ${built.ballots.length} ballots proven and signed in ${Math.round(built.ms / 1000)} s on ${built.threads} threads`);

  const out = [];
  let inserted = 0;
  for (const size of sizes) {
    await insertBallots(conn, e, built.ballots.slice(inserted, size));
    inserted = size;
    const repeats = size <= 100 ? 3 : 1;
    const runs = [];
    let tally = null;
    for (let r = 0; r < repeats; r++) {
      const t = now();
      tally = await encryptedTally(conn);
      runs.push(now() - t);
    }
    const decrypted = decryptTally(key, pair.privateKey, tally).map(Number);
    const truth = countChoices(choices.slice(0, size));
    const storage = (await conn.execute(
      `select (select sum(vsize(election_id) + vsize(ballot_id) + vsize(candidate_id) + vsize(vote_enc) + vsize(bit_proof)) from blind_ballots where election_id = :e) as ballots,
              (select sum(vsize(election_id) + vsize(ballot_id) + vsize(voter_id) + vsize(sum_proof) + vsize(signature)) from ballot_seals where election_id = :e) as seals from dual`, { e })).rows[0];
    out.push({
      voters: size, tally_ms: runs.map(round), counted: tally.ballots_counted, rejected: tally.ballots_rejected, chain: tally.chain,
      correct: decrypted.join() === truth.join(), truth, decrypted,
      column_bytes_per_ballot: round((storage.BALLOTS + storage.SEALS) / size),
    });
    console.log(`  tally of ${size}: ${runs.map((ms) => `${(ms / 1000).toFixed(1)} s`).join(', ')}; counted ${tally.ballots_counted}, rejected ${tally.ballots_rejected}, ${decrypted.join() === truth.join() ? 'correct' : 'WRONG'}`);
  }
  return { key_bits: BITS, build: { ballots: built.ballots.length, threads: built.threads, ms: round(built.ms) }, sizes: out };
}

export async function run(cfg, args) {
  const report = new Report('H11', 'Cost: proof size, proving time in the browser, verification time per ballot and the tally of 10,000 voters, against Layer 1', DIR);
  const layer1File = join(EVIDENCE, 'h6-cost', 'result.json');
  const layer1 = existsSync(layer1File) ? JSON.parse(readFileSync(layer1File, 'utf8')).numbers : null;
  const conn = await connect(cfg, 'schema');
  try {
    const browser = await browserCost(cfg, args);
    const verify = await verificationCost(conn, args);
    const tally = await tallyCost(conn, args);
    const machine = { cpu: os.cpus()[0].model.trim(), logical_cores: os.cpus().length, memory_gb: Math.round(os.totalmem() / 2 ** 30) };
    const timings = { generated: new Date().toISOString(), mode: args.quick ? 'quick' : 'full', seed: args.seed, machine, browser, verify, tally, layer1_reference: layer1 ? 'evidence/h6-cost/result.json (tag v1-layer1)' : null };
    writeJson(cfg, report.file(`${DIR}/timings.json`), timings);

    const s = (values) => stats(values);
    const cast = s(browser.cast_ballot_ui_ms);
    const prove = s(browser.encrypt_and_prove_ms);
    const proofsDb = s(verify.proofs_ms);
    const sigDb = s(verify.signature_ms);
    const big = tally.sizes.at(-1);
    const bigMs = s(big.tally_ms).median;
    const l1Big = layer1?.tally.find((t) => t.voters === big.voters);
    const proofHex = browser.hex_sizes.bitProofs + browser.hex_sizes.sumProof;

    report.check('casting a ballot was measured in a real browser', browser.cast_ballot_ui_ms.length > 0 && browser.cast_ballot_request_bytes.length === browser.cast_ballot_ui_ms.length, `${cast.n} ballots, median ${Math.round(cast.median)} ms`);
    report.check('proving was measured in the browser, with the library of the application', prove.n > 0, `median ${Math.round(prove.median)} ms per ballot`);
    report.check('verification at arrival was measured in the database', proofsDb.n > 0 && sigDb.n > 0, `proofs ${Math.round(proofsDb.median)} ms, signature ${Math.round(sigDb.median)} ms`);
    report.check(`the tally of ${big.voters} voters verified and counted every ballot, and decrypted to the true result`, tally.sizes.every((t) => t.correct && t.counted === t.voters && t.rejected === 0),
      tally.sizes.map((t) => `${t.voters}: ${t.counted} counted, ${t.rejected} rejected, ${t.correct ? 'correct' : 'WRONG'}`).join('; '));
    if (!layer1) report.note('no Layer 1 reference found in evidence/h6-cost/result.json');

    const line = (name, values, unit = 'ms') => {
      const x = s(values);
      return `  ${name.padEnd(54)} median ${String(x.median).padStart(10)} ${unit}   min ${x.min}  max ${x.max}  n=${x.n}`;
    };
    const vs = (l2, l1, unit) => (l1 ? `${l2} ${unit} against ${l1} ${unit} in Layer 1 (${(l2 / l1).toFixed(1)}x)` : `${l2} ${unit}`);
    writeText(cfg, report.file(`${DIR}/summary.txt`), [
      header('H11: cost of Layer 2', [
        `${BITS}-bit election key. Machine: ${machine.cpu}, ${machine.logical_cores} logical cores. Browser: ${browser.browser}.`,
        'Layer 1 reference: evidence/h6-cost/result.json, the run of tag v1-layer1 on the same machine.',
        `The ${big.voters} ballots of the tally were proven in ${tally.build.threads} Node worker threads and inserted by the owner; the tally verified each one again.`,
      ]),
      'Size of one ballot (hexadecimal characters)',
      `  three ciphertexts:   ${browser.hex_sizes.ciphertexts}`,
      `  three bit proofs:    ${browser.hex_sizes.bitProofs}`,
      `  sum proof:           ${browser.hex_sizes.sumProof}`,
      `  signature:           128`,
      `  request body of CAST_BALLOT: ${vs(s(browser.cast_ballot_request_bytes).median, layer1?.request_bytes, 'bytes')}`,
      `  request body of REGISTER_VOTER: ${s(browser.register_request_bytes).median} bytes (Layer 1 had no such request)`,
      '',
      'In the browser',
      line('encrypt one ballot (three ciphertexts), no proofs', browser.encrypt_only_ms),
      line('encrypt and prove one ballot', browser.encrypt_and_prove_ms),
      line('generate the voter key (ECDSA P-256)', browser.voter_keygen_ms),
      line('sign the ballot', browser.sign_ms),
      line('cast one ballot, from the click to the receipt', browser.cast_ballot_ui_ms),
      layer1 ? `  Layer 1: encrypt ${layer1.encrypt_ballot_ms.median} ms, cast from the click to the receipt ${layer1.cast_ballot_ui_ms.median} ms` : '',
      '',
      'In the database, per ballot',
      line('verify the four proofs (bf_v2_verify_ballot)', verify.proofs_ms),
      line('verify the signature (bf_v2_verify_signature)', verify.signature_ms),
      line('bf_election.cast_ballot, everything included', verify.cast_ballot_ms),
      '',
      'Tally (chain verification, proofs and signatures of every ballot again, then the products)',
      ...tally.sizes.map((t) => {
        const l1 = layer1?.tally.find((x) => x.voters === t.voters);
        return `  ${String(t.voters).padStart(6)} voters: ${t.tally_ms.map((ms) => `${(ms / 1000).toFixed(1)} s`).join(', ').padEnd(28)} ${l1 ? `Layer 1: ${(l1.warm_ms / 1000).toFixed(2)} s (${(s(t.tally_ms).median / l1.warm_ms).toFixed(0)}x)` : ''}   stored ${Math.round(t.column_bytes_per_ballot)} bytes per ballot${l1 ? ` (Layer 1: ${Math.round(l1.bytes_per_ballot)})` : ''}`;
      }),
      `  building the ${tally.build.ballots} ballots in Node: ${Math.round(tally.build.ms / 1000)} s on ${tally.build.threads} threads`,
      '  One tally per size from 1,000 voters up; three at 100. Times seen from the client, same machine.',
      '',
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'PARTIAL',
      statement: ok
        ? `Measured: proofs add ${proofHex} hexadecimal characters to a ballot; encrypting and proving takes a median ${Math.round(prove.median)} ms in the browser and casting ${Math.round(cast.median)} ms from the click to the receipt${layer1 ? ` (Layer 1: ${Math.round(layer1.cast_ballot_ui_ms.median)} ms)` : ''}; the database verifies one ballot in ${Math.round(proofsDb.median + sigDb.median)} ms; the tally of ${big.voters} voters takes ${(bigMs / 60000).toFixed(1)} min${l1Big ? ` against ${(l1Big.warm_ms / 1000).toFixed(1)} s in Layer 1` : ''}.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: {
        key_bits: BITS,
        hex_sizes: browser.hex_sizes,
        request_bytes: s(browser.cast_ballot_request_bytes).median,
        register_request_bytes: s(browser.register_request_bytes).median,
        encrypt_only_ms: s(browser.encrypt_only_ms),
        encrypt_and_prove_ms: prove,
        voter_keygen_ms: s(browser.voter_keygen_ms),
        sign_ms: s(browser.sign_ms),
        cast_ballot_ui_ms: cast,
        verify_proofs_ms: proofsDb,
        verify_signature_ms: sigDb,
        cast_ballot_db_ms: s(verify.cast_ballot_ms),
        tally: tally.sizes.map((t) => ({ voters: t.voters, ms: s(t.tally_ms).median, runs: t.tally_ms.length, bytes_per_ballot: t.column_bytes_per_ballot, correct: t.correct })),
        build: tally.build,
        layer1: layer1 ? { request_bytes: layer1.request_bytes, encrypt_ballot_ms: layer1.encrypt_ballot_ms.median, cast_ballot_ui_ms: layer1.cast_ballot_ui_ms.median, tally: layer1.tally.map((t) => ({ voters: t.voters, ms: t.warm_ms, bytes_per_ballot: t.bytes_per_ballot })) } : null,
      },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await conn.rollback();
    await conn.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
