// H3 - Indistinguishability.
//
//   "Two identical votes produce different ciphertexts; a DBA cannot tell
//    Enc(0) from Enc(1)."
//
// Part (a) is a fact that a test can settle: count the distinct ciphertexts.
// Part (b) cannot be proved by a test. Its foundation is the decisional
// composite residuosity assumption (Paillier, 1999). What a test can do is
// play the DBA: take every stored ciphertext, with labels only the harness
// knows, and run a battery of distinguishers. Two deliberately broken
// variants of the scheme show that the battery can detect a leak.
//
//   node tests/h3-indistinguishability.mjs [--quick] [--seed <n>]
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect, asTable } from './lib/db.mjs';
import { BallotFactory } from './lib/ballot-factory.mjs';
import { openElection, castBallots, seededRandom } from './lib/election.mjs';
import { chiSquareTwoSample, meanDifference, kolmogorovSmirnov, normalP, wilson } from './lib/stats.mjs';
import { writeText, header } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h3-indistinguishability';
const FAMILY_ALPHA = 0.01; // family-wise error rate for the whole battery
const BITS = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

function jacobi(a, n) {
  let x = a % n;
  let y = n;
  let result = 1;
  while (x !== 0n) {
    while ((x & 1n) === 0n) {
      x >>= 1n;
      const r = y & 7n;
      if (r === 3n || r === 5n) result = -result;
    }
    [x, y] = [y, x];
    if ((x & 3n) === 3n && (y & 3n) === 3n) result = -result;
    x %= y;
  }
  return y === 1n ? result : 0;
}

const histogram = (values, size) => {
  const counts = new Array(size).fill(0);
  for (const v of values) counts[v] += 1;
  return counts;
};

function shuffle(items, random) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Bits the classifier looks at: the 128 highest and the 128 lowest of a ciphertext.
function bitFeatures(hexText) {
  const features = [];
  for (const part of [hexText.slice(0, 32), hexText.slice(-32)]) {
    for (const ch of part) {
      const v = parseInt(ch, 16);
      features.push(v & 8 ? 1 : -1, v & 4 ? 1 : -1, v & 2 ? 1 : -1, v & 1 ? 1 : -1);
    }
  }
  return features;
}

// Logistic regression trained by gradient descent. Returns held-out accuracy.
function classifier(zeros, ones, random) {
  const data = shuffle([...zeros.map((h) => ({ x: bitFeatures(h), y: 0 })), ...ones.map((h) => ({ x: bitFeatures(h), y: 1 }))], random);
  const half = Math.floor(data.length / 2);
  const train = data.slice(0, half);
  const test = data.slice(half);
  const w = new Array(train[0].x.length + 1).fill(0);
  const predict = (x) => {
    let z = w[w.length - 1];
    for (let i = 0; i < x.length; i++) z += w[i] * x[i];
    return 1 / (1 + Math.exp(-z));
  };
  for (let epoch = 0; epoch < 150; epoch++) {
    const grad = new Array(w.length).fill(0);
    for (const { x, y } of train) {
      const error = predict(x) - y;
      for (let i = 0; i < x.length; i++) grad[i] += error * x[i];
      grad[grad.length - 1] += error;
    }
    for (let i = 0; i < w.length; i++) w[i] -= (0.5 * grad[i]) / train.length;
  }
  const correct = test.filter(({ x, y }) => (predict(x) >= 0.5 ? 1 : 0) === y).length;
  const z = (correct - test.length / 2) / Math.sqrt(test.length / 4);
  return { correct, total: test.length, accuracy: correct / test.length, p: normalP(z), interval: wilson(correct, test.length) };
}

// The battery. zeros / ones: arrays of fixed-width hexadecimal ciphertexts.
// Returns one row per distinguisher: { name, statistic, p } (p = null when the
// test has no p-value).
function battery(zeros, ones, publicKey, random, { jacobiSample = 400 } = {}) {
  const { n, nSquared } = publicKey;
  const big = (h) => BigInt(`0x${h}`);
  const rows = [];
  const add = (name, result, note = '') => rows.push({ name, statistic: result.statistic, p: result.p, note });

  const lengths = new Set([...zeros, ...ones].map((h) => h.length));
  rows.push({ name: 'length in hex characters', statistic: lengths.size, p: null, note: lengths.size === 1 ? `constant (${[...lengths][0]}): carries no information` : `${lengths.size} different lengths` });

  const all = [...zeros, ...ones];
  const distinct = new Set(all).size;
  rows.push({ name: 'repeated ciphertexts', statistic: all.length - distinct, p: null, note: `${distinct} distinct values among ${all.length}` });

  add('highest hex digit', chiSquareTwoSample(histogram(zeros.map((h) => parseInt(h[0], 16)), 16), histogram(ones.map((h) => parseInt(h[0], 16)), 16)));
  add('lowest hex digit', chiSquareTwoSample(histogram(zeros.map((h) => parseInt(h.at(-1), 16)), 16), histogram(ones.map((h) => parseInt(h.at(-1), 16)), 16)));
  add('lowest byte', chiSquareTwoSample(histogram(zeros.map((h) => parseInt(h.slice(-2), 16)), 256), histogram(ones.map((h) => parseInt(h.slice(-2), 16)), 256)));

  const popcount = (h) => {
    let total = 0;
    for (const ch of h) total += BITS[parseInt(ch, 16)];
    return total;
  };
  const pop = meanDifference(zeros.map(popcount), ones.map(popcount));
  add('number of 1 bits (mean)', pop, `Enc(0) ${pop.meanA.toFixed(2)}, Enc(1) ${pop.meanB.toFixed(2)}`);

  const position = (h) => Number((big(h) << 53n) / nSquared) / 2 ** 53;
  add('position in [0, n^2) (Kolmogorov-Smirnov)', kolmogorovSmirnov(zeros.map(position), ones.map(position)));
  const residue = (h) => Number(((big(h) % n) << 53n) / n) / 2 ** 53;
  add('c mod n, position in [0, n) (Kolmogorov-Smirnov)', kolmogorovSmirnov(zeros.map(residue), ones.map(residue)));

  for (const prime of [3, 5, 7, 11, 13]) {
    const mod = (h) => Number(big(h) % BigInt(prime));
    add(`c mod ${prime}`, chiSquareTwoSample(histogram(zeros.map(mod), prime), histogram(ones.map(mod), prime)));
  }

  // The Jacobi symbol is the classic quantity an attacker can compute without
  // the factors of n. For Paillier it depends on r alone, not on the message.
  const symbol = (h) => jacobi(big(h), n) + 1;
  const sample = Math.min(jacobiSample, zeros.length, ones.length);
  add(`Jacobi symbol (c | n), ${sample} per class`, chiSquareTwoSample(histogram(zeros.slice(0, sample).map(symbol), 3), histogram(ones.slice(0, sample).map(symbol), 3)));

  const model = classifier(zeros, ones, random);
  rows.push({ name: 'logistic regression on 256 bits, held-out accuracy', statistic: model.accuracy, p: model.p,
    note: `${model.correct}/${model.total} correct, 95% interval ${(model.interval.low * 100).toFixed(1)}% to ${(model.interval.high * 100).toFixed(1)}%` });
  return rows;
}

function judge(rows) {
  const tested = rows.filter((r) => r.p !== null);
  const alpha = FAMILY_ALPHA / tested.length;
  const rejected = tested.filter((r) => r.p < alpha);
  const structural = rows.filter((r) => (r.name === 'length in hex characters' && r.statistic !== 1) || (r.name === 'repeated ciphertexts' && r.statistic !== 0));
  return { alpha, rejected: [...structural, ...rejected] };
}

function formatRows(rows, alpha) {
  const lines = ['distinguisher                                          statistic      p-value   verdict'];
  lines.push('-'.repeat(96));
  for (const r of rows) {
    const p = r.p === null ? '        -' : r.p.toExponential(2).padStart(9);
    const verdict = r.p === null ? '' : r.p < alpha ? 'DISTINGUISHES' : 'no signal';
    const statistic = Number.isInteger(r.statistic) ? String(r.statistic) : r.statistic.toFixed(4);
    lines.push(`${r.name.padEnd(52)} ${statistic.padStart(10)}  ${p}   ${verdict}${r.note ? `   ${r.note}` : ''}`);
  }
  return lines;
}

export async function run(cfg, args) {
  const report = new Report('H3', 'Indistinguishability: identical votes differ, and a DBA cannot tell Enc(0) from Enc(1)', DIR);
  const random = seededRandom(args.seed);
  const voters = args.quick ? 300 : 2000;
  const { publicKey } = await P.generateKeyPair(2048);
  const nHex = publicKey.n.toString(16);
  const factory = new BallotFactory();
  const conn = await connect(cfg, 'schema');
  const dba = await connect(cfg, 'dba');
  const owner = cfg.schema.toUpperCase();

  try {
    // ---- an election where the harness, and nobody else, knows every vote
    const choices = Array.from({ length: voters }, () => Math.floor(random() * 3));
    await openElection(conn, publicKey, voters);
    const { ballots, stats } = await factory.encrypt(nHex, choices, { pureCount: args.quick ? 20 : 60 });
    await castBallots(conn, ballots);

    // ---- (a) identical votes produce different ciphertexts
    const counts = (await dba.execute(`select count(*) as ciphertexts, count(distinct vote_enc) as distinct_values, count(distinct length(vote_enc)) as lengths from ${owner}.blind_ballots`)).rows[0];
    report.check('every stored ciphertext is unique', counts.CIPHERTEXTS === counts.DISTINCT_VALUES && counts.CIPHERTEXTS === voters * 3,
      `${counts.DISTINCT_VALUES} distinct values in ${counts.CIPHERTEXTS} rows`);

    const sameChoice = choices.map((c, i) => ({ c, i })).filter((v) => v.c === 0).slice(0, 2).map((v) => v.i + 1);
    const pair = (await dba.execute(
      `select ballot_id, candidate_id, substr(vote_enc, 1, 24) || '...' || substr(vote_enc, -12) as vote_enc
         from ${owner}.blind_ballots where ballot_id in (:a, :b) order by candidate_id, ballot_id`, { a: sameChoice[0], b: sameChoice[1] })).rows;
    const duplicates = (await dba.execute(`select vote_enc, count(*) as copies from ${owner}.blind_ballots group by vote_enc having count(*) > 1`)).rows;
    report.check('a DBA search for repeated ciphertexts returns nothing', duplicates.length === 0, 'group by vote_enc having count(*) > 1: no rows');

    const repeated = await factory.encrypt(nHex, new Array(args.quick ? 40 : 200).fill(0), { pureCount: args.quick ? 10 : 30 });
    const repeatedFlat = repeated.ballots.flat();
    report.check('the same vote encrypted again and again never repeats', new Set(repeatedFlat).size === repeatedFlat.length,
      `${repeated.ballots.length} ballots for option A: ${new Set(repeatedFlat).size} distinct ciphertexts out of ${repeatedFlat.length}`);

    writeText(cfg, report.file(`${DIR}/distinct-ciphertexts.txt`), [
      header('H3 (a): identical votes produce different ciphertexts', [`election of ${voters} voters, 2048-bit key, queries run as the DBA account`]),
      `SQL> select count(*) as ciphertexts, count(distinct vote_enc) as distinct_values, count(distinct length(vote_enc)) as lengths from ${owner.toLowerCase()}.blind_ballots;`,
      '', asTable([counts]),
      'SQL> select vote_enc, count(*) as copies from blind_ballots group by vote_enc having count(*) > 1;',
      '', asTable(duplicates),
      `Ballots ${sameChoice[0]} and ${sameChoice[1]} carry the same vote (the harness knows it, the database does not).`,
      'Their six ciphertexts, side by side:',
      '', asTable(pair, { maxWidth: 48 }),
      `Encrypting the same ballot ${repeated.ballots.length} more times gave ${new Set(repeatedFlat).size} distinct ciphertexts out of ${repeatedFlat.length}.`,
      '',
    ].join('\n'));

    // ---- (b) the DBA's view, with labels only the harness has
    const stored = (await dba.execute(`select ballot_id, candidate_id, vote_enc from ${owner}.blind_ballots order by ballot_id, candidate_id`)).rows;
    const ones = [];
    let zeros = [];
    for (const row of stored) (choices[row.BALLOT_ID - 1] === row.CANDIDATE_ID - 1 ? ones : zeros).push(row.VOTE_ENC);
    zeros = shuffle(zeros, random).slice(0, ones.length); // balanced classes
    report.note(`labelled sample: ${ones.length} ciphertexts of 1 and ${zeros.length} ciphertexts of 0, read back from BLIND_BALLOTS`);

    const first = battery(zeros, ones, publicKey, random);
    let verdict = judge(first);
    const sections = [`Sample 1: ${zeros.length} x Enc(0) and ${ones.length} x Enc(1) read from the database`, '', ...formatRows(first, verdict.alpha), ''];
    let replicated = [];
    if (verdict.rejected.length > 0) {
      // Pre-declared rule: a rejection counts only if a fresh sample confirms it.
      // Every fresh ballot votes for option A: its first ciphertext is an
      // Enc(1), its second one an Enc(0).
      const fresh = await factory.encrypt(nHex, new Array(ones.length).fill(0), {});
      const freshOnes = fresh.ballots.map((b) => b[0]);
      const freshZeros = fresh.ballots.map((b) => b[1]);
      const second = battery(freshZeros, freshOnes, publicKey, random);
      const secondVerdict = judge(second);
      replicated = verdict.rejected.filter((r) => secondVerdict.rejected.some((s) => s.name === r.name));
      sections.push('Sample 2: fresh ciphertexts, drawn because a test of sample 1 fell below the threshold', '', ...formatRows(second, secondVerdict.alpha), '');
      report.note(`sample 1 flagged ${verdict.rejected.map((r) => r.name).join(', ')}; on a fresh sample ${replicated.length} of them repeated`);
      verdict = { alpha: verdict.alpha, rejected: replicated };
    }
    report.check('no distinguisher in the battery separates Enc(0) from Enc(1)', verdict.rejected.length === 0,
      `${first.filter((r) => r.p !== null).length} statistical tests, family-wise error rate ${FAMILY_ALPHA}, lowest p-value ${Math.min(...first.filter((r) => r.p !== null).map((r) => r.p)).toExponential(2)}`);
    const model = first.at(-1);
    report.check('a trained classifier guesses no better than a coin', model.p >= verdict.alpha, model.note);

    // ---- positive controls: the same battery on two broken schemes
    const { n, nSquared } = publicKey;
    const width = publicKey.hexLength;
    const size = Math.min(ones.length, 600);
    const broken = (message, variant) => {
      const r = P.randomUnit(n);
      const value = variant === 'no exponent' ? ((1n + message * n) * r) % nSquared : (1n + message * n) % nSquared;
      return value.toString(16).padStart(width, '0');
    };
    const controls = [];
    for (const variant of ['no exponent', 'no randomness']) {
      const rows = battery(Array.from({ length: size }, () => broken(0n, variant)), Array.from({ length: size }, () => broken(1n, variant)), publicKey, random, { jacobiSample: 100 });
      const caught = judge(rows).rejected;
      controls.push({ variant, rows, caught });
    }
    report.check('positive control: the battery catches c = (1 + m n) r, the randomizer not raised to n', controls[0].caught.length > 0, `flagged by ${controls[0].caught.length} distinguishers`);
    report.check('positive control: the battery catches c = 1 + m n, no randomizer at all', controls[1].caught.length > 0, `flagged by ${controls[1].caught.length} distinguishers`);

    writeText(cfg, report.file(`${DIR}/distinguishers.txt`), [
      header('H3 (b): can a DBA tell Enc(0) from Enc(1)?', [
        `seed ${args.seed}${args.quick ? ' (quick mode: smaller sample)' : ''}`,
        'The harness labels each stored ciphertext with the plaintext only it knows, then plays the DBA.',
        'Each test asks: is this quantity distributed differently for Enc(0) and for Enc(1)?',
        `Decision rule, fixed before the run: family-wise error rate ${FAMILY_ALPHA} (Bonferroni), so one test "distinguishes"`,
        `when its p-value is below ${verdict.alpha.toExponential(2)}. A flagged test must repeat on a fresh sample to count.`,
        'Passing these tests is necessary, not sufficient. The security argument is the decisional composite',
        'residuosity assumption; no test in a lab can prove it.',
        `ciphertexts produced by the pure BigInt path: ${stats.pure}; with r^n computed by OpenSSL: ${stats.accelerated} (${stats.verified} cross-checked)`,
      ]),
      ...sections,
      'Positive control 1: c = (1 + m n) * r mod n^2   (the randomizer is not raised to the power n)',
      '', ...formatRows(controls[0].rows, verdict.alpha), '',
      'Positive control 2: c = (1 + m n) mod n^2   (no randomizer at all)',
      '', ...formatRows(controls[1].rows, verdict.alpha), '',
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'REFUTED',
      statement: ok
        ? `All ${counts.CIPHERTEXTS} stored ciphertexts are distinct, and none of ${first.filter((r) => r.p !== null).length} distinguishers separates Enc(0) from Enc(1) on ${ones.length + zeros.length} labelled ciphertexts (classifier accuracy ${(model.statistic * 100).toFixed(1)}%). Indistinguishability itself rests on the DCR assumption, which a test cannot prove.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { voters, ciphertexts: counts.CIPHERTEXTS, distinct: counts.DISTINCT_VALUES, labelled_sample: ones.length + zeros.length, tests: first.filter((r) => r.p !== null).length, alpha_per_test: verdict.alpha, lowest_p: Math.min(...first.filter((r) => r.p !== null).map((r) => r.p)), classifier_accuracy: model.statistic },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await factory.close();
    await conn.close();
    await dba.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
