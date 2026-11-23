// Rewrites the generated parts of README.md from the files in /evidence, so that
// the README can never state a number that the evidence does not.
//
//   node scripts/readme-sync.mjs           rewrite the generated blocks
//   node scripts/readme-sync.mjs --check   exit 1 if README.md is out of date
//
// A generated block is the text between <!-- name:start --> and <!-- name:end -->:
//   verdicts      one row per hypothesis        evidence/summary.json
//   attacks       what breaks the tally         H4 and H5 result.json
//   live          the live session              evidence/live-session: challenge-summary.json, timeline.txt
//   cost          time and storage              H6 result.json, timings.json
//   environment   versions the lab ran on       evidence/summary.json, timings.json
// Everything outside the blocks is written by hand and holds no measurement.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from '../tests/lib/config.mjs';

const read = (rel) => JSON.parse(readFileSync(join(ROOT, 'evidence', rel), 'utf8'));
const summary = read('summary.json');
const h4 = read('h4-ballot-stuffing/result.json').numbers;
const h5 = read('h5-limits/result.json').numbers;
const h6 = read('h6-cost/result.json').numbers;
const timings = read('h6-cost/timings.json');

const count = (value) => Number(value).toLocaleString('en-US');
const sum = (totals) => totals.reduce((a, b) => a + b, 0);
const tally = (totals) => `A=${totals[0]} B=${totals[1]} C=${totals[2]}`;
const change = (after, before) => `[${after.map((value, i) => value - before[i]).join(', ')}]`;
const list = (items) => (items.length > 1 ? `${items.slice(0, -1).join(', ')} and ${items.at(-1)}` : items[0]);
const cell = (text) => String(text).replace(/\|/g, '\\|').replace(/\s+/g, ' ');
const link = (file, text = file.split('/').pop()) => `[${text}](evidence/${file})`;

// ---- verdicts
const MAIN = { H1: 'elections.txt', H2: 'scan-summary.txt', H3: 'distinguishers.txt', H4: 'stuffing.txt', H5: 'a-dba-adds-votes.txt', H6: 'summary.txt' };
function verdicts() {
  const rows = summary.hypotheses.map((h) => {
    const folder = h.evidence.replace(/^evidence\//, '').replace(/\/result\.json$/, '');
    return `| ${h.id} | ${h.title} | **${h.verdict}** | ${cell(h.statement)} | ${link(`${folder}/${MAIN[h.id]}`)} |`;
  });
  return [
    '| # | Hypothesis | Verdict | Observed | Evidence |',
    '|---|---|---|---|---|',
    ...rows,
    '',
    `One run from a clean schema: ${summary.generated.slice(0, 10)}, ${summary.mode} mode, seed ${summary.seed}, ${Math.round(summary.duration_ms / 60000)} minutes.`,
    'Each row is the sentence the test itself wrote into its `result.json`. The same table, with the',
    'time of every step, is in [`evidence/summary.md`](evidence/summary.md).',
  ];
}

// ---- attacks
function attacks() {
  const stuffed = change(h4.naive_after, h4.honest);
  const balanced = change(h4.balanced_after, h4.honest);
  const moved = Math.max(...h5.tally_forged.map((value, i) => Math.abs(value - h5.tally_honest[i])));
  const extra = h5.extra_key_substitution;
  const loss = h5.extra_key_loss;
  const rows = [
    [
      `**Stuff a ballot.** Encrypt \`${stuffed}\` where an honest ballot encrypts a single 1.`,
      'A registered voter, from the browser console',
      `${tally(h4.honest)} became **${tally(h4.naive_after)}**`,
      `Only in the sum: ${count(sum(h4.naive_after))} votes from ${count(h4.turnout)} voters. Nothing says which ballot.`,
      link('h4-ballot-stuffing/stuffing.txt'),
    ],
    [
      `**Stuff it quietly.** Encrypt \`${balanced}\`, which still adds up to one vote.`,
      'A registered voter, from the browser console',
      `${tally(h4.honest)} became **${tally(h4.balanced_after)}**`,
      `No. ${count(sum(h4.balanced_after))} votes from ${count(h4.turnout)} voters.`,
      link('h4-ballot-stuffing/stuffing.txt'),
    ],
    [
      `**Move votes.** Multiply one stored ciphertext by \`Enc(${moved})\` and another by \`Enc(-${moved})\`.`,
      'A DBA with the public key and two `UPDATE` statements',
      `${tally(h5.tally_honest)} became **${tally(h5.tally_forged)}**`,
      `No. ${count(sum(h5.tally_forged))} votes from ${count(h5.turnout)} voters, and the same number of rows.`,
      link('h5-limits/a-dba-adds-votes.txt'),
    ],
    [
      '**Open single ballots.** Decrypt rows of the table, not the three totals.',
      'Whoever holds the private key',
      `**${h5.ballots_read} of ${h5.ballots}** ballots read`,
      'No.',
      link('h5-limits/b-key-holder-reads-ballots.txt'),
    ],
    [
      '**Re-link voters to ballots.** Sort `VOTER_ROLL` by `voted_at` and the ballots by `ballot_id`.',
      'Anyone who reads both tables',
      `**${h5.relinked_sequential} of ${h5.ballots}** voters paired with their own ballot when they vote one at a time. With ${h5.concurrent_sessions} sessions voting at once: ${h5.relinked_concurrent} of ${h5.concurrent_voters} exactly, ${h5.concurrent_within_window} of ${h5.concurrent_voters} within ${h5.concurrent_farthest_miss} positions.`,
      'No.',
      link('h5-limits/c-relinking.txt'),
    ],
    [
      '**Swap the public key** while voters are voting. An extra, not one of the hypotheses.',
      'A DBA who can write to the tables',
      `**${extra.ballots_read} of ${extra.ballots_exposed}** ballots cast under the swapped key were read${extra.worked ? ', and the tally the authority decrypted was still correct' : ''}`,
      'No.',
      link('h5-limits/extra-key-substitution.txt'),
    ],
    [
      '**Lose the key.** Reload the browser tab that holds the private key. An extra, found in the live session.',
      'The authority, by accident',
      `${tally(loss.true_tally)} was decrypted while the tab was alive. After a reload the encrypted totals could still be fetched and **${loss.lost_by_reload ? 'could not be decrypted' : 'were still decrypted'}**`,
      loss.questions.includes('beforeunload')
        ? 'It asks first, through the browser, whose question mentions unsaved information and no key.'
        : 'No.',
      link('h5-limits/extra-key-loss.txt'),
    ],
  ];
  return [
    '| Attack | Who can do it | What happened in the lab | Does the application notice? | Evidence |',
    '|---|---|---|---|---|',
    ...rows.map((row) => `| ${row.map(cell).join(' | ')} |`),
  ];
}

// ---- cost
function cost() {
  // Whole milliseconds from 100 up, one decimal from 10 up, the recorded value below that.
  const ms = (value) => `${value >= 100 ? count(Math.round(value)) : value >= 10 ? value.toFixed(1) : value} ms`;
  const browser = [
    ['Generate the 2048-bit key pair', "authority's browser", h6.keygen_2048_ms],
    ['Encrypt one ballot (three ciphertexts)', "voter's browser", h6.encrypt_ballot_ms],
    ['Cast one ballot, from the click to the receipt', "voter's browser and database", h6.cast_ballot_ui_ms],
    ['Decrypt one total', "authority's browser", h6.decrypt_one_ciphertext_ms],
  ];
  const machine = timings.machine;
  return [
    '| In the browser | Where | Median | Fastest and slowest | Samples |',
    '|---|---|---:|---:|---:|',
    ...browser.map(([what, where, s]) => `| ${what} | ${where} | **${ms(s.median)}** | ${ms(s.min)} to ${ms(s.max)} | ${s.n} |`),
    '',
    '| Voters | Blind tally | Plaintext `COUNT` | Ratio | Stored per ballot | Plaintext per ballot |',
    '|---:|---:|---:|---:|---:|---:|',
    ...h6.tally.map((t) => `| ${count(t.voters)} | **${ms(t.warm_ms)}** | ${ms(t.plaintext_ms)} | ${count(Math.round(t.warm_ms / t.plaintext_ms))}x | ${count(Math.round(t.bytes_per_ballot))} bytes | ${t.plaintext_bytes_per_ballot.toFixed(1)} bytes |`),
    '',
    `- The tally time is the median of repeated runs of one statement, seen from the client. The first tally of a new database session, which starts its Java virtual machine, took ${list(h6.tally.map((t) => ms(t.cold_ms)))}.`,
    `- One ballot travels as a request body of ${count(h6.request_bytes)} bytes. Storage is the size of the column values, without block or index overhead.`,
    `- Browser, ORDS and database ran on the same machine: ${machine.cpu.replace(/\((R|TM)\)/g, '').replace(/\s+/g, ' ')}, ${machine.logical_cores} logical cores, ${timings.browser.browser}.`,
    `- Raw measurements: ${link('h6-cost/timings.json')}. Summary: ${link('h6-cost/summary.txt')}.`,
  ];
}

// ---- environment
function environment() {
  const env = summary.environment;
  return [
    '| Component | Version the lab ran on |',
    '|---|---|',
    `| Database | ${env.database.split(' - ')[0]}, on ${env.database_platform} |`,
    `| Tally engine | Java stored procedure, database JVM ${env.database_jvm} |`,
    `| Oracle APEX | ${env.apex} |`,
    `| ORDS | ${env.ords.split('.r')[0]} |`,
    `| Node.js | ${env.node.replace(/^v/, '')} |`,
    `| Python (cross-check only) | ${env.python.replace(/^Python /, '')} |`,
    `| Browser | ${timings.browser.browser}, driven by Playwright |`,
  ];
}

// ---- live session
// The session is not regenerated by a run: its numbers are read from the files
// it left. The decrypted totals were typed into the snapshot labels from the
// voter's screenshots, so they are read back from the timeline.
function live() {
  const rounds = read('live-session/challenge-summary.json');
  const timeline = readFileSync(join(ROOT, 'evidence', 'live-session', 'timeline.txt'), 'utf8');
  const numbers = (match) => match.slice(1).map(Number);
  const honest = numbers(/honest tally decrypted[^\n]*?A=(\d+) B=(\d+) C=(\d+)/.exec(timeline));
  const corrupted = numbers(/decrypted A=(\d+) B=(\d+) C=(\d+) after ballot 13 and A=(\d+) B=(\d+) C=(\d+) after ballot 14/.exec(timeline));
  const receipts = (round) => ['A', 'B', 'C'].map((letter) => round.actual.filter((vote) => vote === letter).length);
  const [first, second] = rounds.rounds;
  // The receipts must agree with what was decrypted: the honest tally of the
  // first election, and the first corrupted tally of the second minus the thousand.
  const stuffedWith = corrupted[0] - receipts(second)[0];
  if (receipts(first).join() !== honest.join() || [corrupted[0] - stuffedWith, corrupted[1], corrupted[2]].join() !== receipts(second).join()) {
    throw new Error('The receipts of the live session do not match the totals that were decrypted.');
  }
  const percent = (value) => `${(100 * value).toFixed(1)}%`;
  const video = (name, text) => `[${text}](evidence/live-session/video/${name})`;
  const rows = [
    [
      '**The DBA guesses every vote**, with full DBA access and no view of the voter\'s screen.',
      `${rounds.rounds.length} rounds, ${rounds.ballots} ballots. The guesses were committed, and their hash pushed to this repository, before each reveal. **${rounds.hits} hits**, where blind guessing gives ${rounds.expected_hits_by_chance.toFixed(1)}; ${rounds.hits} or more come up by luck in ${percent(rounds.chance_of_this_many_or_more)} of attempts. Guesses that came from something the DBA had read: ${rounds.informed_guesses}.`,
      link('live-session/challenge-summary.txt'),
    ],
    [
      '**The authority counts the honest election.**',
      `${first.ballots} ballots, decrypted in his browser as **${tally(honest)}**: the counts of his ${first.ballots} receipts.`,
      link('live-session/screenshots/03-honest-tally-decrypted.png', 'screenshot'),
    ],
    [
      '**The voter looks for his own vote.** He runs the `SELECT` statements himself, as `SYSTEM`, knowing how he voted.',
      'Asked whether he could point to his own vote in those rows, he answered that he could not.',
      link('live-session/screenshots/04-dba-select-1-ballots.png', 'his five queries'),
    ],
    [
      '**The voter stuffs the ballot box**, with one snippet in the browser console.',
      `The database accepted a ballot worth ${count(stuffedWith)} votes. His ${second.ballots} honest ballots, ${tally(receipts(second))}, were tallied as **${tally(corrupted.slice(0, 3))}**. A ballot of \`[3, -2, 0]\` then made it ${tally(corrupted.slice(3))}.`,
      `${video('06-election-b-ballot-of-a-thousand.mp4', 'the console')}, ${video('07-election-b-stuffed-tally.mp4', 'the tally')}`,
    ],
    [
      '**The authority keeps the key**, which lives in the memory of one browser tab.',
      'He lost it twice: once before any ballot, once after the honest tally above. From then on neither election could be counted. The second time is on his recording: the browser asked whether to leave the page, and the answer was yes.',
      video('04-leave-page-question.mp4', 'the recording'),
    ],
  ];
  return [
    '| What was tried | What happened | Evidence |',
    '|---|---|---|',
    ...rows.map((row) => `| ${row.map(cell).join(' | ')} |`),
  ];
}

const BLOCKS = { verdicts, attacks, live, cost, environment };

const file = join(ROOT, 'README.md');
const readme = readFileSync(file, 'utf8');
let updated = readme;
for (const [name, build] of Object.entries(BLOCKS)) {
  const start = `<!-- ${name}:start -->`;
  const end = `<!-- ${name}:end -->`;
  const from = updated.indexOf(start);
  const to = updated.indexOf(end);
  if (from < 0 || to < from) throw new Error(`README.md has no ${name} block.`);
  updated = `${updated.slice(0, from)}${[start, ...build(), end].join('\n')}${updated.slice(to + end.length)}`;
}

if (process.argv.includes('--check')) {
  if (updated !== readme) {
    console.error('README.md does not match /evidence. Run: node scripts/readme-sync.mjs');
    process.exit(1);
  }
  console.log(`README.md matches /evidence (run of ${summary.generated}).`);
} else {
  writeFileSync(file, updated);
  console.log(`README.md: ${Object.keys(BLOCKS).join(', ')} rewritten from the run of ${summary.generated}.`);
}
