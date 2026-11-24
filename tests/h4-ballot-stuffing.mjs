// H4 - Ballot stuffing.
//
//   "A voter can submit Enc(1000) instead of Enc(1) and the tally will accept it."
//
// The attack runs in a real browser, with the same console snippet a person
// would paste (tests/snippets/ballot-stuffing.js). The election authority is
// another browser context: it generates the key, asks for the tally and
// decrypts it on the Tally page, and the test reads the result off the page.
//
// Two elections:
//   X  one voter submits [Enc(1000), Enc(0), Enc(0)]
//   Y  one voter submits [Enc(3), Enc(-2), Enc(0)]: the totals still add up
//
// The fix (a zero-knowledge proof that each ciphertext encrypts 0 or 1 and
// that the ballot sums to 1) is described in the article. It is NOT implemented.
//
//   node tests/h4-ballot-stuffing.mjs
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect, asTable } from './lib/db.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser, tallyInBrowser, stuffingSnippet, LETTERS } from './lib/app.mjs';
import { castBallots, countChoices } from './lib/election.mjs';
import { writeText, header, evidencePath } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';
import { runsOnTagOnly } from './lib/layer1.mjs';

// Layer 1 only: on main this script stops here and says where it runs (tests/lib/layer1.mjs).
if (isMain(import.meta.url)) runsOnTagOnly('H4', 'tests/h4-ballot-stuffing.mjs');

const DIR = 'h4-ballot-stuffing';
const HONEST = [0, 0, 0, 0, 1, 1, 1, 2, 2]; // nine honest voters: 4 for A, 3 for B, 2 for C
const REGISTERED = 12;
const ATTACKER = 'VOTER-0010';

const fmt = (totals) => totals.map((v, i) => `${LETTERS[i]}=${v}`).join('  ');

async function honestVotes(conn) {
  const nHex = (await conn.execute('select bf_election.public_key as n from dual')).rows[0].N;
  const publicKey = P.publicKeyFromN(P.fromHex(nHex));
  const ballots = HONEST.map((choice) => P.encryptBallot(publicKey, choice, 3));
  await castBallots(conn, ballots);
}

async function scenario({ report, cfg, conn, dba, authority, voterContext, name, weights, screenshot }) {
  await openElectionInBrowser(authority, cfg, REGISTERED);
  await honestVotes(conn);
  const before = await tallyInBrowser(authority);

  const voter = await voterContext.newPage();
  watch(voter, `voter ${name}`);
  await voter.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
  await voter.waitForSelector('.bf-option');
  const answer = await voter.evaluate(stuffingSnippet(ATTACKER, weights));
  await voter.close();

  const after = await tallyInBrowser(authority);
  await authority.screenshot({ path: evidencePath(`${DIR}/${screenshot}`), fullPage: true });
  report.file(`${DIR}/${screenshot}`);

  const owner = cfg.schema.toUpperCase();
  const rows = (await dba.execute(
    `select ballot_id, candidate_id, length(vote_enc) as hex_chars, substr(vote_enc, 1, 20) || '...' || substr(vote_enc, -10) as vote_enc
       from ${owner}.blind_ballots where ballot_id in (:honest, :stuffed) order by ballot_id, candidate_id`,
    { honest: HONEST.length, stuffed: answer.ballot_id ?? -1 })).rows;
  const turnout = (await dba.execute(`select count(voted_at) as turnout from ${owner}.voter_roll`)).rows[0].TURNOUT;
  return { name, weights, before, answer, after, rows, turnout };
}

export async function run(cfg, args) {
  const report = new Report('H4', 'Ballot stuffing: a voter can submit Enc(1000) instead of Enc(1) and the tally accepts it', DIR);
  const truth = countChoices(HONEST);
  const conn = await connect(cfg, 'schema');
  const dba = await connect(cfg, 'dba');
  const browser = await launchBrowser(cfg);
  const viewport = { width: 1440, height: 900 };

  try {
    // Two device pixels per CSS pixel: the screenshots go into an article.
    const authorityContext = await browser.newContext({ viewport, deviceScaleFactor: 2 });
    const voterContext = await browser.newContext({ viewport, deviceScaleFactor: 2 });
    const authority = await authorityContext.newPage();
    watch(authority, 'authority');

    // ---- election X: one ballot worth a thousand votes
    const x = await scenario({ report, cfg, conn, dba, authority, voterContext, name: 'X', weights: [1000, 0, 0], screenshot: '01-stuffed-tally.png' });
    report.check('before the attack the tally is the honest one', x.before.totals.join() === truth.join() && !x.before.flagged, fmt(x.before.totals));
    report.check('the database accepts a ballot that encrypts 1000', x.answer.ok === true, `CAST_BALLOT answered ok, ballot ${x.answer.ballot_id}`);
    report.check('the tally counts it as 1000 votes', x.after.totals.join() === [truth[0] + 1000, truth[1], truth[2]].join(), `${fmt(x.before.totals)}  ->  ${fmt(x.after.totals)}`);
    report.check('the only symptom is in the aggregate: totals no longer add up to the turnout', x.after.flagged,
      `${x.after.totals.reduce((a, b) => a + b, 0)} votes from ${x.turnout} voters; nothing tells which ballot or which option`);

    // ---- election Y: a ballot that keeps the totals plausible
    const y = await scenario({ report, cfg, conn, dba, authority, voterContext, name: 'Y', weights: [3, -2, 0], screenshot: '02-balanced-stuffing-undetected.png' });
    report.check('the database accepts a ballot that encrypts 3, -2 and 0', y.answer.ok === true, `CAST_BALLOT answered ok, ballot ${y.answer.ballot_id}`);
    report.check('the tally moves two votes from B to A and adds one', y.after.totals.join() === [truth[0] + 3, truth[1] - 2, truth[2]].join(), `${fmt(y.before.totals)}  ->  ${fmt(y.after.totals)}`);
    report.check('this time nothing is flagged: the totals add up to the turnout', !y.after.flagged,
      `${y.after.totals.reduce((a, b) => a + b, 0)} votes from ${y.turnout} voters; page says "${y.after.decryptStatus}"`);

    const section = (s, title) => [
      title,
      `  honest ballots: ${HONEST.length} (${fmt(truth)}), cast through bf_election.cast_ballot`,
      `  tally before the attack, decrypted on the Tally page:  ${fmt(s.before.totals)}`,
      `  attacker ${ATTACKER} pastes tests/snippets/ballot-stuffing.js with WEIGHTS = [${s.weights.join(', ')}]`,
      `  database answer: ${JSON.stringify(s.answer)}`,
      `  tally after the attack:                                 ${fmt(s.after.totals)}`,
      `  turnout in VOTER_ROLL: ${s.turnout}    sum of totals: ${s.after.totals.reduce((a, b) => a + b, 0)}`,
      `  Tally page message: ${s.after.decryptStatus}`,
      '',
      `  The last honest ballot (${HONEST.length}) and the stuffed ballot (${s.answer.ballot_id}), as the DBA sees them:`,
      '',
      ...asTable(s.rows, { maxWidth: 40 }).split('\n').map((l) => `  ${l}`),
    ];

    writeText(cfg, report.file(`${DIR}/stuffing.txt`), [
      header('H4: ballot stuffing', [
        'The attacker is an ordinary registered voter with a browser console. No database access.',
        'Server-side validation in bf_election.cast_ballot: fixed width, lower-case hexadecimal, 0 < c < n^2.',
        'A ciphertext of 1000 passes all three, exactly like a ciphertext of 1.',
      ]),
      ...section(x, 'Election X: one ballot worth a thousand votes'),
      ...section(y, 'Election Y: a ballot that keeps the totals plausible'),
      'What stops this in a real system (described, not implemented in this lab):',
      '  every ballot carries a zero-knowledge proof that each ciphertext encrypts 0 or 1',
      '  and that the three plaintexts sum to 1. The server, and anyone else, can verify',
      '  the proof without learning the vote, and rejects a ballot whose proof fails.',
      '',
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'REFUTED',
      statement: ok
        ? `The tally accepted a ballot encrypting 1000 (${fmt(x.before.totals)} became ${fmt(x.after.totals)}). A balanced ballot of [3, -2, 0] changed the result (${fmt(y.after.totals)}) while the totals still added up to the turnout.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { honest: truth, naive_after: x.after.totals, balanced_after: y.after.totals, turnout: x.turnout, browser: `${browser.bfChannel} ${browser.version()}` },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await browser.close();
    await conn.close();
    await dba.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
