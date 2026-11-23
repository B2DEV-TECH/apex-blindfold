// H1 - Correctness.
//
//   "The decrypted tally equals the true tally in 100 randomized elections,
//    10 to 5,000 voters. Also cross-check Paillier against an independent
//    implementation in another language."
//
// Three implementations take part, in three languages, sharing no code:
//   JavaScript (BigInt)        encrypts ballots and decrypts totals, as the browser does
//   Java (BigInteger)          multiplies ciphertexts inside the database
//   Python (built-in int)      independent reference, tests/crosscheck/paillier_ref.py
//
//   node tests/h1-correctness.mjs [--quick] [--seed <n>]
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect } from './lib/db.mjs';
import { BallotFactory } from './lib/ballot-factory.mjs';
import { OPTIONS, openElection, castBallots, encryptedTally, decryptTally, countChoices, seededRandom } from './lib/election.mjs';
import { pythonRef, pythonVersion } from './lib/python.mjs';
import { writeText, header } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h1-correctness';
const hex = (value) => value.toString(16);

// Election sizes: log-uniform between the two bounds, so that small and large
// elections are equally represented, with both bounds always present.
function electionSizes(random, count, low, high) {
  const sizes = [low, high];
  while (sizes.length < count) {
    sizes.push(Math.round(Math.exp(Math.log(low) + random() * (Math.log(high) - Math.log(low)))));
  }
  return sizes;
}

// Each election gets its own random preference for the three options.
function drawChoices(random, voters) {
  const weights = Array.from({ length: OPTIONS }, () => -Math.log(1 - random()));
  const total = weights.reduce((a, b) => a + b, 0);
  const choices = [];
  for (let i = 0; i < voters; i++) {
    let x = random() * total;
    let option = 0;
    while (option < OPTIONS - 1 && x >= weights[option]) {
      x -= weights[option];
      option += 1;
    }
    choices.push(option);
  }
  return choices;
}

// ---- part 1: JavaScript against the Python reference, no database involved
async function crossCheck(report, random, lines) {
  const { publicKey, privateKey } = await P.generateKeyPair(2048);
  const { n } = publicKey;
  const key = { n: hex(n), p: hex(privateKey.p), q: hex(privateKey.q) };

  const derived = await pythonRef({ op: 'derive', p: key.p, q: key.q });
  report.check('key derivation agrees (n, lambda, mu)',
    derived.n === hex(n) && derived.lambda === hex(privateKey.lambda) && derived.mu === hex(privateKey.mu),
    'Python derives the same n, lambda and mu from p and q');

  // Messages: the edges of the plaintext space and random values in between.
  const messages = [0n, 1n, 2n, 1000n, n - 1n, n - 2n, n / 2n];
  while (messages.length < 60) messages.push(P.randomBelow(n));

  const jsCipher = messages.map((m) => P.encrypt(publicKey, m));
  const pyPlain = await pythonRef({ op: 'decrypt', p: key.p, q: key.q, c: jsCipher.map(hex) });
  const jsToPy = messages.every((m, i) => BigInt(pyPlain.m[i]) === m);
  report.check('JavaScript encrypts, Python decrypts', jsToPy, `${messages.length} messages, including 0, 1, n-1 and random values`);

  const pyCipher = await pythonRef({ op: 'encrypt', n: key.n, m: messages.map((m) => m.toString()) });
  const pyToJs = messages.every((m, i) => P.decrypt(publicKey, privateKey, BigInt(`0x${pyCipher.c[i]}`)) === m);
  report.check('Python encrypts, JavaScript decrypts', pyToJs, `${messages.length} messages`);

  // Homomorphic addition: product of ciphertexts, computed by each side.
  const jsSum = P.add(publicKey, ...jsCipher);
  const pySum = await pythonRef({ op: 'add', n: key.n, c: jsCipher.map(hex) });
  const expectedSum = messages.reduce((a, b) => (a + b) % n, 0n);
  report.check('homomorphic sum agrees bit for bit', pySum.result === hex(jsSum) && P.decrypt(publicKey, privateKey, jsSum) === expectedSum,
    `product of ${messages.length} ciphertexts: same ${hex(jsSum).length}-digit number in both languages, decrypts to the sum modulo n`);

  // Scalar multiplication: Enc(m)^k = Enc(k * m).
  const k = BigInt(1 + Math.floor(random() * 1_000_000));
  const jsScaled = P.scalarMultiply(publicKey, jsCipher[3], k);
  const pyScaled = await pythonRef({ op: 'scalar', n: key.n, c: hex(jsCipher[3]), k: k.toString() });
  report.check('scalar multiplication agrees bit for bit', pyScaled.result === hex(jsScaled) && P.decrypt(publicKey, privateKey, jsScaled) === (1000n * k) % n,
    `Enc(1000)^${k} decrypts to ${1000n * k}`);

  lines.push('Part 1. JavaScript (BigInt) against Python (built-in int), 2048-bit key', `  public key n = ${hex(n).slice(0, 32)}...${hex(n).slice(-16)} (${publicKey.bits} bits)`);
  for (const check of report.checks) lines.push(`  ${check.pass ? 'ok  ' : 'FAIL'} ${check.name}: ${check.detail}`);
  lines.push('');
}

export async function run(cfg, args) {
  const report = new Report('H1', 'Correctness: the decrypted tally equals the true tally', DIR);
  const random = seededRandom(args.seed);
  const count = args.quick ? 12 : 100;
  const high = args.quick ? 300 : 5000;
  const sizes = electionSizes(random, count, 10, high);
  const python = await pythonVersion();

  const crossLines = [];
  await crossCheck(report, random, crossLines);
  const crossChecks = report.checks.length;

  // ---- part 2: randomized elections through the database
  const conn = await connect(cfg, 'schema');
  const factory = new BallotFactory();
  const rows = [];
  let mismatches = 0;
  let pythonMismatches = 0;
  let productMismatches = 0;
  let productChecked = 0;
  let totalBallots = 0;
  const encryption = { pure: 0, accelerated: 0, verified: 0 };
  const started = Date.now();

  try {
    for (let e = 0; e < sizes.length; e++) {
      const voters = sizes[e];
      const choices = drawChoices(random, voters);
      const truth = countChoices(choices);
      const { publicKey, privateKey } = await P.generateKeyPair(2048);

      await openElection(conn, publicKey, voters);
      const t0 = Date.now();
      const { ballots, stats } = await factory.encrypt(hex(publicKey.n), choices, { pureCount: 10 });
      const t1 = Date.now();
      await castBallots(conn, ballots);
      const t2 = Date.now();
      const tally = await encryptedTally(conn);
      const t3 = Date.now();
      const decrypted = decryptTally(publicKey, privateKey, tally).map(Number);
      for (const k of Object.keys(encryption)) encryption[k] += stats[k];
      totalBallots += voters;

      const match = decrypted.every((v, i) => v === truth[i]) && tally.ballot_rows === voters * OPTIONS;
      if (!match) mismatches += 1;

      // Python decrypts the same three encrypted totals, from p and q alone.
      const py = await pythonRef({ op: 'decrypt', p: hex(privateKey.p), q: hex(privateKey.q), c: tally.totals.map((t) => t.total_enc) });
      const pythonMatch = py.m.every((v, i) => Number(v) === truth[i]);
      if (!pythonMatch) pythonMismatches += 1;

      // For the smaller elections Python also recomputes the homomorphic
      // product from the stored ciphertexts: the database must return the
      // very same number.
      let product = '-';
      if (voters <= 400) {
        const requests = [];
        for (let option = 0; option < OPTIONS; option++) {
          requests.push({ op: 'add', n: hex(publicKey.n), c: ballots.map((b) => b[option]) });
        }
        const products = await pythonRef(requests);
        const same = products.every((r, option) => BigInt(`0x${r.result}`) === BigInt(`0x${tally.totals[option].total_enc}`));
        productChecked += 1;
        if (!same) productMismatches += 1;
        product = same ? 'same' : 'DIFF';
      }

      rows.push({ election: e + 1, voters, truth: truth.join('/'), decrypted: decrypted.join('/'), match: match ? 'yes' : 'NO', python: pythonMatch ? 'yes' : 'NO', product, key: `${hex(publicKey.n).slice(0, 12)}...`, encryptMs: t1 - t0, castMs: t2 - t1, tallyMs: t3 - t2 });
      if ((e + 1) % 10 === 0 || e + 1 === sizes.length) console.log(`  ${e + 1}/${sizes.length} elections, ${totalBallots} ballots, ${Math.round((Date.now() - started) / 1000)} s`);
    }
  } finally {
    await factory.close();
    await conn.close();
  }

  report.check(`decrypted tally equals true tally in ${sizes.length} randomized elections`, mismatches === 0,
    `${sizes.length - mismatches}/${sizes.length} elections match, ${Math.min(...sizes)} to ${Math.max(...sizes)} voters, ${totalBallots} ballots in total`);
  report.check('Python decrypts the same encrypted totals to the true tally', pythonMismatches === 0,
    `${sizes.length - pythonMismatches}/${sizes.length} elections`);
  report.check('database product equals the product Python computes from the stored ciphertexts', productMismatches === 0 && productChecked > 0,
    `${productChecked - productMismatches}/${productChecked} elections of up to 400 voters, compared bit for bit`);
  report.check('accelerated test ciphertexts equal pure BigInt ciphertexts', encryption.verified > 0,
    `${encryption.verified} sampled ciphertexts recomputed with the browser code path, all identical (a difference aborts the run)`);

  // ---- evidence
  const table = [
    '  #  voters  true tally (A/B/C)   decrypted (A/B/C)    match  python  product  public key       encrypt ms  cast ms  tally ms',
    '---  ------  -------------------  -------------------  -----  ------  -------  ---------------  ----------  -------  --------',
    ...rows.map((r) => `${String(r.election).padStart(3)}  ${String(r.voters).padStart(6)}  ${r.truth.padEnd(19)}  ${r.decrypted.padEnd(19)}  ${r.match.padEnd(5)}  ${r.python.padEnd(6)}  ${r.product.padEnd(7)}  ${r.key}  ${String(r.encryptMs).padStart(10)}  ${String(r.castMs).padStart(7)}  ${String(r.tallyMs).padStart(8)}`),
  ];
  writeText(cfg, report.file(`${DIR}/elections.txt`), [
    header('H1: randomized elections', [
      `seed ${args.seed}${args.quick ? ' (quick mode: fewer and smaller elections)' : ''}`,
      `${sizes.length} elections, sizes log-uniform between ${Math.min(...sizes)} and ${Math.max(...sizes)} voters, both bounds included`,
      'every election: fresh 2048-bit key, random preferences, ballots cast through bf_election.cast_ballot,',
      'encrypted totals computed in the database (Java), decrypted by JavaScript and, independently, by Python',
      'column "python": Python decrypts the database totals from p and q and gets the true tally',
      'column "product": Python multiplies the stored ciphertexts itself; "same" = identical to the database result',
      `ballot encryption for bulk: ${encryption.pure} ciphertexts on the pure BigInt path (first 10 ballots of each election),`,
      `${encryption.accelerated} with r^n computed by OpenSSL, of which ${encryption.verified} were recomputed on the pure path and compared`,
    ]),
    ...table,
    '',
    `elections: ${sizes.length}   matching: ${sizes.length - mismatches}   mismatching: ${mismatches}`,
    `ballots: ${totalBallots}   ciphertexts multiplied by the database: ${totalBallots * OPTIONS}`,
    '',
  ].join('\n'));

  writeText(cfg, report.file(`${DIR}/crosscheck.txt`), [
    header('H1: cross-check against an independent implementation', [
      `reference: tests/crosscheck/paillier_ref.py, ${python}, standard library only`,
      'the reference shares no code with the JavaScript library: other language, other big-number arithmetic, other random source',
    ]),
    ...crossLines,
    'Part 2. The database (Java BigInteger) against Python, on real elections',
    `  ${sizes.length - pythonMismatches}/${sizes.length} elections: Python decrypts the encrypted totals returned by the database to the true tally`,
    `  ${productChecked - productMismatches}/${productChecked} elections: Python multiplies the stored ciphertexts and obtains the same totals, bit for bit`,
    '',
  ].join('\n'));

  const ok = report.failed.length === 0;
  return report.close(cfg, {
    verdict: ok ? 'CONFIRMED' : 'REFUTED',
    statement: ok
      ? `The decrypted tally equals the true tally in ${sizes.length}/${sizes.length} randomized elections (${Math.min(...sizes)} to ${Math.max(...sizes)} voters, ${totalBallots} ballots), and JavaScript, Java and Python agree on every value compared.`
      : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
    numbers: { elections: sizes.length, matching: sizes.length - mismatches, min_voters: Math.min(...sizes), max_voters: Math.max(...sizes), ballots: totalBallots, ciphertexts: totalBallots * OPTIONS, cross_checks: crossChecks, python },
    mode: { quick: args.quick, seed: args.seed },
  });
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
