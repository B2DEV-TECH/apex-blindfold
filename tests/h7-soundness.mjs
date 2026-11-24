// H7 - Soundness.
//
//   "A ballot that is not an honest one is rejected: the stuffed ballot of a thousand votes
//    that Layer 1 accepted (H4), negative values, two options set to 1, a replayed proof."
//
// Part 1 runs in a real browser, like H4 did. The attacker is a registered voter who pastes
// a console snippet on the Vote page. Two snippets:
//   tests/snippets/ballot-stuffing.js          the one of Layer 1, unchanged: ciphertexts only
//   tests/snippets/ballot-stuffing-layer2.js   an attacker who also builds proofs and a signature
// The authority is another browser context and decrypts the tally on the Tally page.
//
// Part 2 goes through the PL/SQL API: proofs copied from another ballot, from another election,
// and seeded random damage to a valid ballot.
//
// Negative control: the same Layer 2 snippet with an honest value, [1, 0, 0], must be accepted
// and counted as exactly one vote. Without it, "rejected" could mean "the snippet is broken".
//
//   node tests/h7-soundness.mjs [--quick] [--seed N]
import * as P from './lib/paillier.mjs';
import * as V from './lib/validity.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect } from './lib/db.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser, tallyInBrowser, stuffingSnippet, LETTERS } from './lib/app.mjs';
import { openElection, prepareBallot, castBallot, tryCastBallot, castChoices, countChoices, honest, voterCode, seededRandom, currentElectionId } from './lib/election.mjs';
import { writeText, header, evidencePath } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h7-soundness';
const HONEST = [0, 0, 0, 0, 1, 1, 1, 2, 2]; // nine honest voters: 4 for A, 3 for B, 2 for C (the election of H4)
const REGISTERED = 30;
const L2 = 'ballot-stuffing-layer2.js';

// What the attacker tries in the browser. `file` is the snippet that is pasted.
const ATTEMPTS = [
  { name: 'the Layer 1 snippet, unchanged: a thousand votes, no proof', weights: [1000, 0, 0], file: 'ballot-stuffing.js' },
  { name: 'a thousand votes for A, with forged proofs', weights: [1000, 0, 0], file: L2 },
  { name: 'three for A, minus two for B: the plaintexts add up to 1', weights: [3, -2, 0], file: L2 },
  { name: 'a negative value', weights: [-1, 1, 1], file: L2 },
  { name: 'two options set to 1', weights: [1, 1, 0], file: L2 },
  { name: 'all three options set to 1', weights: [1, 1, 1], file: L2 },
  { name: 'a blank ballot', weights: [0, 0, 0], file: L2 },
  { name: 'two votes for one option', weights: [2, 0, 0], file: L2 },
];

const fmt = (totals) => totals.map((v, i) => `${LETTERS[i]}=${v}`).join('  ');
const scalar = async (conn, sql, binds = {}) => Object.values((await conn.execute(sql, binds)).rows[0])[0];

export async function run(cfg, args) {
  const report = new Report('H7', 'Soundness: a ballot that is not an honest one is rejected (the stuffed ballot of H4, negative values, two options set to 1, a replayed proof)', DIR);
  const truth = countChoices(HONEST);
  const conn = await connect(cfg, 'schema');
  const browser = await launchBrowser(cfg);
  const viewport = { width: 1440, height: 900 };
  const lines = [];

  try {
    // ================= part 1: the browser console =================
    const authority = await (await browser.newContext({ viewport, deviceScaleFactor: 2 })).newPage();
    const voterContext = await browser.newContext({ viewport, deviceScaleFactor: 2 });
    watch(authority, 'authority');
    await openElectionInBrowser(authority, cfg, REGISTERED);
    const election = await currentElectionId(conn);
    const publicKey = P.publicKeyFromN(P.fromHex(await scalar(conn, 'select bf_election.public_key from dual')));
    await castChoices(conn, publicKey, HONEST);
    const before = await tallyInBrowser(authority);
    report.check('before the attacks the tally is the honest one', before.totals.join() === truth.join() && !before.flagged, fmt(before.totals));

    const paste = async (voter, weights, file) => {
      const page = await voterContext.newPage();
      watch(page, `voter ${voter}`);
      await page.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
      await page.waitForSelector('.bf-option');
      const answer = await page.evaluate(stuffingSnippet(voter, weights, file));
      await page.close();
      return answer;
    };
    const stored = () => scalar(conn, 'select count(*) from blind_ballots where election_id = :e', { e: election });

    // ---- negative control: the same snippet, an honest value
    let next = HONEST.length;
    const controlVoter = voterCode(next++);
    const control = await paste(controlVoter, [1, 0, 0], L2);
    const withControl = [truth[0] + 1, truth[1], truth[2]];
    report.check('negative control: the Layer 2 snippet with an honest ballot [1, 0, 0] is accepted', control.ok === true, JSON.stringify(control));

    // ---- the attacks
    const rowsBefore = await stored();
    lines.push(`Election ${election}: ${HONEST.length} honest ballots (${fmt(truth)}) cast through bf_election.cast_ballot.`,
      `Tally before the attacks, decrypted on the Tally page: ${fmt(before.totals)}`, '',
      `Negative control: ${controlVoter} pastes ${L2} with WEIGHTS = [1, 0, 0]`,
      `  database answer: ${JSON.stringify(control)}`, '');
    let rejected = 0;
    const outcomes = [];
    for (const attempt of ATTEMPTS) {
      const voter = voterCode(next++);
      const answer = await paste(voter, attempt.weights, attempt.file);
      const refused = answer.ok === false;
      if (refused) rejected += 1;
      outcomes.push({ name: attempt.name, weights: attempt.weights, snippet: attempt.file, rejected: refused, answer: answer.message ?? (answer.ok ? `accepted as ballot ${answer.ballot_id}` : JSON.stringify(answer)) });
      report.check(`rejected: ${attempt.name}`, refused, `[${attempt.weights.join(', ')}] -> ${answer.message ?? JSON.stringify(answer)}`);
      lines.push(`Attack: ${attempt.name}`,
        `  ${voter} pastes tests/snippets/${attempt.file} with WEIGHTS = [${attempt.weights.join(', ')}]`,
        `  database answer: ${JSON.stringify(answer)}`, '');
    }
    const rowsAfter = await stored();
    report.check('no attack left a row in BLIND_BALLOTS', rowsAfter === rowsBefore, `${rowsBefore} rows before the attacks, ${rowsAfter} after`);

    const after = await tallyInBrowser(authority);
    await authority.screenshot({ path: evidencePath(`${DIR}/01-tally-after-the-attacks.png`), fullPage: true });
    report.file(`${DIR}/01-tally-after-the-attacks.png`);
    report.check('after the attacks the tally is the honest one plus the control vote', after.totals.join() === withControl.join() && !after.flagged, `${fmt(after.totals)}; page says "${after.decryptStatus}"`);
    lines.push(`Tally after the attacks: ${fmt(after.totals)}`, `Tally page: ${after.tallyStatus}`, `Tally page: ${after.decryptStatus}`, '');

    // ================= part 2: replayed proofs, through the API =================
    const bits = args.quick ? 1024 : 2048;
    const pair = await P.generateKeyPair(bits);
    const key = pair.publicKey;

    await openElection(conn, key, 6);
    const first = await currentElectionId(conn);
    const old = await prepareBallot(conn, key, voterCode(0), honest(0));
    await castBallot(conn, old);
    await conn.commit();

    await openElection(conn, key, 6); // the same key, another election: ballot numbers start at 1 again
    const second = await currentElectionId(conn);
    const resign = async (mine, source) => {
      const copy = { ...mine, ciphertexts: source.ciphertexts, bitProofs: source.bitProofs, sumProof: source.sumProof };
      copy.signature = await V.signBallot(mine.voterKey.privateKey, key, mine.context, mine.voter, copy);
      return copy;
    };
    // (a) the accepted ballot of the earlier election, presented again under the same ballot number
    const mineA = await prepareBallot(conn, key, voterCode(0), honest(1));
    const replayElection = await tryCastBallot(conn, await resign(mineA, old));
    report.check('rejected: a ballot of an earlier election replayed in this one, same key, same ballot number',
      replayElection.code === 20006 && mineA.ballotId === old.ballotId, `election ${first} ballot ${old.ballotId} -> election ${second} ballot ${mineA.ballotId}: ${replayElection.error ?? 'accepted'}`);
    // (b) the ballot another voter has just cast, read from the table and presented under another number
    const victim = await prepareBallot(conn, key, voterCode(1), honest(2));
    await castBallot(conn, victim);
    const rows = (await conn.execute('select vote_enc, bit_proof from blind_ballots where election_id = :e and ballot_id = :b order by candidate_id', { e: second, b: victim.ballotId })).rows;
    const seal = (await conn.execute('select sum_proof from ballot_seals where election_id = :e and ballot_id = :b', { e: second, b: victim.ballotId })).rows[0];
    const copied = { ciphertexts: rows.map((r) => r.VOTE_ENC), bitProofs: rows.map((r) => r.BIT_PROOF), sumProof: seal.SUM_PROOF };
    const mineB = await prepareBallot(conn, key, voterCode(2), honest(0));
    const replayBallot = await tryCastBallot(conn, await resign(mineB, copied));
    report.check('rejected: the stored ballot of another voter, copied from the table under another ballot number',
      replayBallot.code === 20006, `ballot ${victim.ballotId} -> ballot ${mineB.ballotId}: ${replayBallot.error ?? 'accepted'}`);
    // (c) a voter asking for the number that was reserved for someone else
    const mineC = await prepareBallot(conn, key, voterCode(3), honest(0));
    const stolen = await tryCastBallot(conn, { ...mineC, ballotId: mineB.ballotId });
    report.check('rejected: a ballot under the number reserved for another voter', stolen.code === 20006, stolen.error ?? 'accepted');
    await conn.rollback();
    lines.push(`Replays, through bf_election.cast_ballot, ${bits}-bit key:`,
      `  earlier election, same ballot number:   ${replayElection.error ?? 'ACCEPTED'}`,
      `  another voter's stored ballot:          ${replayBallot.error ?? 'ACCEPTED'}`,
      `  another voter's reserved number:        ${stolen.error ?? 'ACCEPTED'}`, '');

    // ================= part 3: seeded damage to a valid ballot =================
    // The verifier is asked directly (bf_v2_verify_ballot): no voter code is used up.
    const random = seededRandom(args.seed);
    const pick = (n) => Math.floor(random() * n);
    const context = { electionId: second, ballotId: 77 };
    const good = await V.proveBallot(key, context, honest(1));
    const verify = async (b) => scalar(conn,
      'select bf_v2_verify_ballot(:n, :e, :b, :c1, :c2, :c3, :p1, :p2, :p3, :ps) from dual',
      { n: P.toHex(key.n), e: context.electionId, b: context.ballotId, c1: b.ciphertexts[0], c2: b.ciphertexts[1], c3: b.ciphertexts[2], p1: b.bitProofs[0], p2: b.bitProofs[1], p3: b.bitProofs[2], ps: b.sumProof });
    const intact = await verify(good);
    report.check('negative control: the verifier accepts the valid ballot that is about to be damaged', intact === 'OK', intact);
    const damages = args.quick ? 20 : 100;
    const HEX = '0123456789abcdef';
    let caught = 0;
    const reasons = new Map();
    const missed = [];
    for (let i = 0; i < damages; i++) {
      const b = { ciphertexts: [...good.ciphertexts], bitProofs: [...good.bitProofs], sumProof: good.sumProof };
      const field = pick(7); // 0..2 ciphertext, 3..5 bit proof, 6 sum proof
      const text = field < 3 ? b.ciphertexts[field] : field < 6 ? b.bitProofs[field - 3] : b.sumProof;
      const at = pick(text.length);
      const digit = HEX[(HEX.indexOf(text[at]) + 1 + pick(15)) % 16]; // always another digit
      const damaged = `${text.slice(0, at)}${digit}${text.slice(at + 1)}`;
      if (field < 3) b.ciphertexts[field] = damaged; else if (field < 6) b.bitProofs[field - 3] = damaged; else b.sumProof = damaged;
      const verdict = await verify(b);
      if (verdict !== 'OK') caught += 1; else missed.push(`field ${field}, position ${at}`);
      const reason = verdict.replace(/^FAIL /, '').replace(/option \d/, 'option N');
      reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
    }
    report.check(`rejected: every one of ${damages} valid ballots with one hexadecimal digit changed`, caught === damages, `${caught}/${damages} rejected${missed.length ? `; accepted: ${missed.join('; ')}` : ''}`);
    lines.push(`Seeded damage (seed ${args.seed}): one hexadecimal digit of a valid ballot changed, ${damages} times.`,
      `  rejected: ${caught}/${damages}`,
      ...[...reasons].sort((a, b) => b[1] - a[1]).map(([reason, count]) => `  ${String(count).padStart(4)}  ${reason}`), '');

    writeText(cfg, report.file(`${DIR}/attempts.txt`), [
      header('H7: soundness', [
        'The attacker is an ordinary registered voter with a browser console. No database access.',
        'Layer 1 accepted the first two attacks below: evidence/h4-ballot-stuffing/stuffing.txt (tag v1-layer1).',
        'Unaudited educational cryptography. A test that finds no accepted forgery is not a proof that none exists.',
      ]),
      ...lines,
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'REFUTED',
      statement: ok
        ? `The database rejected ${rejected} of ${ATTEMPTS.length} dishonest ballots pasted in the browser console, among them the ballot of 1000 votes and the balanced [3, -2, 0] that Layer 1 accepted, 3 of 3 replays, and ${caught} of ${damages} valid ballots with one digit changed. The tally stayed ${fmt(after.totals)}: the honest ballots and the control.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { honest: truth, control_accepted: control.ok === true, attempts: ATTEMPTS.length, attempts_rejected: rejected, outcomes, tally_before: before.totals, replays: 3, replays_rejected: [replayElection, replayBallot, stolen].filter((r) => r.code === 20006).length, damaged: damages, damaged_rejected: caught, tally_after: after.totals, replay_key_bits: bits, browser: `${browser.bfChannel} ${browser.version()}` },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await browser.close();
    await conn.rollback();
    await conn.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
