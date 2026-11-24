// H5 - Other limits, each one demonstrated.
//
//   (a) a DBA can add votes to any candidate, undetected;
//   (b) a single key holder can decrypt individual ballots;
//   (c) sequential ballot_id plus VOTER_ROLL.voted_at can re-link voters to ballots.
//
// Two additions that the original list does not have, kept separate and
// labelled as such:
//
//   (extra) a DBA who writes can swap the public key, read the ballots cast
//           meanwhile and put everything back;
//   (extra) the private key lives in one browser tab and is lost with it.
//           Found in the live session, where it happened twice.
//
// The harness plays three roles with three different powers:
//   authority  holds the private key (generated here, never sent anywhere)
//   voters     call bf_election.cast_ballot, exactly like the Ajax callback
//   DBA        the separate account with the DBA role, public key only
//
//   node tests/h5-limits.mjs [--quick] [--seed <n>]
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect, asTable } from './lib/db.mjs';
import { BallotFactory } from './lib/ballot-factory.mjs';
import { OPTIONS, voterCode, openElection, castBallot, encryptedTally, decryptTally, countChoices, seededRandom } from './lib/election.mjs';
import { LETTERS, watch, openElectionInBrowser, tallyInBrowser } from './lib/app.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { writeText, header } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';
import { runsOnTagOnly } from './lib/layer1.mjs';

// Layer 1 only: on main this script stops here and says where it runs (tests/lib/layer1.mjs).
if (isMain(import.meta.url)) runsOnTagOnly('H5', 'tests/h5-limits.mjs');

const DIR = 'h5-limits';
const fmt = (totals) => totals.map((v, i) => `${LETTERS[i]}=${v}`).join('  ');
const short = (hexText) => `${hexText.slice(0, 20)}...${hexText.slice(-10)}`;

function shuffle(items, random) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Plaintexts live modulo n: the upper half reads as negative numbers.
const signed = (publicKey) => (value) => Number(value > publicKey.n / 2n ? value - publicKey.n : value);

// What the DBA runs to pair voters with ballots: nothing but two ORDER BYs.
const RELINK_SQL = (owner) => `select r.voter_id, b.ballot_id
  from (select voter_id, row_number() over (order by voted_at, voter_id) as position
          from ${owner}.voter_roll
         where voted_at is not null) r
  join (select ballot_id, row_number() over (order by ballot_id) as position
          from (select distinct ballot_id from ${owner}.blind_ballots)) b
    on b.position = r.position
 order by b.ballot_id`;

// The Tally page in a real browser. The authority generates the key in one tab;
// three voters vote; a link of the page is followed; then the tab is reloaded.
async function loseTheKey(cfg, conn, random) {
  const browser = await launchBrowser(cfg);
  try {
    const context = await browser.newContext();
    const authority = await context.newPage();
    watch(authority, 'authority');
    await openElectionInBrowser(authority, cfg, 6);
    const questions = [];
    authority.on('dialog', (dialog) => questions.push(dialog.type())); // openElectionInBrowser answers them: "leave"

    const key = P.publicKeyFromN(P.fromHex((await conn.execute('select bf_election.public_key as n from dual')).rows[0].N));
    const choices = [];
    for (let voter = 0; voter < 3; voter++) {
      const choice = Math.floor(random() * OPTIONS);
      await castBallot(conn, voterCode(voter), P.encryptBallot(key, choice, OPTIONS));
      choices.push(choice);
    }
    await conn.commit();

    // 1. A link of the page itself, while the tab holds the key.
    const [beside] = await Promise.all([
      context.waitForEvent('page', { timeout: 30000 }),
      authority.locator('.bf-nav__link', { hasText: 'Vote' }).click(),
    ]);
    await beside.waitForURL(/^https?:/, { timeout: 60000 }); // a new tab starts empty
    const linkOpened = new URL(beside.url()).pathname.split('/').pop();
    const stayedOn = new URL(authority.url()).pathname.split('/').pop();
    const title = await authority.title();
    const withKey = await tallyInBrowser(authority);

    // 2. The tab is reloaded.
    await authority.reload({ waitUntil: 'networkidle' });
    await authority.waitForSelector('#bf-key-status.bf-message--error', { timeout: 60000 });
    const keyStatus = (await authority.textContent('#bf-key-status')).trim();
    await authority.click('#bf-tally');
    await authority.waitForSelector('#bf-totals .bf-total', { timeout: 120000 });
    const totalsFetched = await authority.locator('#bf-totals .bf-total').count();
    const decryptDisabled = await authority.isDisabled('#bf-decrypt');
    const decryptStatus = (await authority.textContent('#bf-decrypt-status')).trim();
    return { truth: countChoices(choices), linkOpened, stayedOn, title, withKey, questions, keyStatus, totalsFetched, decryptDisabled, decryptStatus, browser: browser.bfChannel };
  } finally {
    await browser.close();
  }
}

export async function run(cfg, args) {
  const report = new Report('H5', 'Other limits: a DBA can add votes, a key holder can read ballots, voters can be re-linked', DIR);
  const random = seededRandom(args.seed);
  const owner = cfg.schema.toUpperCase();
  const conn = await connect(cfg, 'schema');
  const dba = await connect(cfg, 'dba');
  const factory = new BallotFactory();

  try {
    const { publicKey, privateKey } = await P.generateKeyPair(2048);
    const toSigned = signed(publicKey);
    const readTally = async () => decryptTally(publicKey, privateKey, await encryptedTally(conn)).map(toSigned);
    const tableCounts = async () => (await dba.execute(
      `select (select count(*) from ${owner}.blind_ballots) as ciphertext_rows,
              (select count(distinct ballot_id) from ${owner}.blind_ballots) as ballots,
              (select count(voted_at) from ${owner}.voter_roll) as turnout
         from dual`)).rows[0];

    // ---- one election, voters arrive one at a time in a random order
    const registered = 30;
    const voting = shuffle(Array.from({ length: registered }, (_, i) => i), random).slice(0, 24);
    await openElection(conn, publicKey, registered);
    const cast = [];
    for (const voter of voting) {
      const choice = Math.floor(random() * OPTIONS);
      const ballotId = await castBallot(conn, voterCode(voter), P.encryptBallot(publicKey, choice, OPTIONS));
      await conn.commit(); // one transaction per ballot, as the Ajax callback does
      cast.push({ voter: voterCode(voter), choice, ballotId });
    }
    const truth = countChoices(cast.map((c) => c.choice));

    // ---- (b) the key holder opens every ballot, one by one
    const stored = (await dba.execute(`select ballot_id, candidate_id, vote_enc from ${owner}.blind_ballots order by ballot_id, candidate_id`)).rows;
    const opened = new Map();
    for (const row of stored) {
      const plaintext = P.decrypt(publicKey, privateKey, P.ciphertextFromHex(publicKey, row.VOTE_ENC));
      if (!opened.has(row.BALLOT_ID)) opened.set(row.BALLOT_ID, []);
      opened.get(row.BALLOT_ID)[row.CANDIDATE_ID - 1] = Number(plaintext);
    }
    const readChoice = (ballotId) => opened.get(ballotId).indexOf(1);
    const ballotsRead = cast.filter((c) => readChoice(c.ballotId) === c.choice).length;
    report.check('(b) the key holder decrypts every individual ballot', ballotsRead === cast.length,
      `${ballotsRead}/${cast.length} ballots opened correctly with the one private key`);

    // ---- (c) the DBA pairs voters with ballots by order of arrival
    const pairs = (await dba.execute(RELINK_SQL(owner))).rows;
    const actual = new Map(cast.map((c) => [c.voter, c.ballotId]));
    const linked = pairs.filter((p) => actual.get(p.VOTER_ID) === p.BALLOT_ID).length;
    report.check('(c) ordering by voted_at and by ballot_id re-links voters to ballots', linked === cast.length,
      `${linked}/${cast.length} voters paired with their own ballot, voters arriving one at a time`);

    const votesNamed = pairs.filter((p) => readChoice(p.BALLOT_ID) === cast.find((c) => c.voter === p.VOTER_ID).choice).length;
    report.check('(b) and (c) together name the vote of every voter', votesNamed === cast.length,
      `${votesNamed}/${cast.length} voters: voter code -> ballot -> decrypted choice`);

    writeText(cfg, report.file(`${DIR}/b-key-holder-reads-ballots.txt`), [
      header('H5 (b): a single key holder can decrypt individual ballots', [
        `election: ${registered} registered, ${cast.length} ballots, 2048-bit key`,
        'The design asks the authority to decrypt three totals and nothing else. Nothing enforces it:',
        'the same private key opens every row of BLIND_BALLOTS, which the application itself displays.',
        'Real systems split the key among trustees (threshold decryption), so that no single party can do this.',
      ]),
      'ballot_id  decrypted row (A, B, C)  choice read  true choice',
      '---------  -----------------------  -----------  -----------',
      ...cast.slice().sort((a, b) => a.ballotId - b.ballotId).map((c) => `${String(c.ballotId).padStart(9)}  ${opened.get(c.ballotId).join(', ').padEnd(23)}  ${LETTERS[readChoice(c.ballotId)].padEnd(11)}  ${LETTERS[c.choice]}`),
      '',
      `ballots opened correctly: ${ballotsRead}/${cast.length}`,
      '',
    ].join('\n'));

    // ---- (c) again, with voters arriving at the same time
    const crowd = args.quick ? 40 : 200;
    const sessions = 8;
    await openElection(conn, publicKey, crowd);
    const crowdChoices = Array.from({ length: crowd }, () => Math.floor(random() * OPTIONS));
    const { ballots: crowdBallots } = await factory.encrypt(publicKey.n.toString(16), crowdChoices, {});
    const queue = shuffle(Array.from({ length: crowd }, (_, i) => i), random);
    const crowdCast = new Map();
    const connections = await Promise.all(Array.from({ length: sessions }, () => connect(cfg, 'schema')));
    await Promise.all(connections.map(async (session) => {
      for (;;) {
        const voter = queue.pop();
        if (voter === undefined) break;
        const ballotId = await castBallot(session, voterCode(voter), crowdBallots[voter]);
        await session.commit();
        crowdCast.set(voterCode(voter), ballotId);
      }
    }));
    await Promise.all(connections.map((c) => c.close()));
    const crowdPairs = (await dba.execute(RELINK_SQL(owner))).rows;
    const crowdLinked = crowdPairs.filter((p) => crowdCast.get(p.VOTER_ID) === p.BALLOT_ID).length;
    // Ballot ids are consecutive, so a difference of ids is a distance in positions.
    const distances = crowdPairs.map((p) => Math.abs(crowdCast.get(p.VOTER_ID) - p.BALLOT_ID)).sort((a, b) => a - b);
    const within = (k) => distances.filter((d) => d <= k).length;
    const farthest = distances.at(-1);
    report.note(`(c) with ${sessions} database sessions casting at the same time: ${crowdLinked}/${crowd} voters paired with their own ballot (${((crowdLinked / crowd) * 100).toFixed(1)}%), ${within(sessions - 1)}/${crowd} within ${sessions - 1} positions, farthest miss ${farthest}`);

    writeText(cfg, report.file(`${DIR}/c-relinking.txt`), [
      header('H5 (c): sequential ballot_id plus VOTER_ROLL.voted_at re-links voters to ballots', [
        'BLIND_BALLOTS has no voter and no timestamp. VOTER_ROLL has no ballot. Both keep the order of arrival:',
        'ballot_id comes from a sequence, voted_at from the clock. Sorting the two tables side by side joins them.',
      ]),
      `SQL> ${RELINK_SQL(owner.toLowerCase())};`,
      '',
      `Election 1: ${cast.length} voters arriving one at a time, in a random order of voter codes`,
      '',
      'voter_id    ballot_id (DBA guess)  ballot_id (actual)  match',
      '----------  ---------------------  ------------------  -----',
      ...pairs.map((p) => `${p.VOTER_ID.padEnd(10)}  ${String(p.BALLOT_ID).padStart(21)}  ${String(actual.get(p.VOTER_ID)).padStart(18)}  ${actual.get(p.VOTER_ID) === p.BALLOT_ID ? 'yes' : 'NO'}`),
      '',
      `re-linked: ${linked}/${cast.length}`,
      `with the private key as well (limit b), voter -> vote: ${votesNamed}/${cast.length}`,
      '',
      `Election 2: ${crowd} voters, cast by ${sessions} database sessions at the same time`,
      `re-linked exactly: ${crowdLinked}/${crowd} (${((crowdLinked / crowd) * 100).toFixed(1)}%)`,
      `guess within 1 position of the real ballot: ${within(1)}/${crowd}; within 3: ${within(3)}/${crowd}; within ${sessions - 1}: ${within(sessions - 1)}/${crowd}; farthest miss: ${farthest} positions`,
      'Concurrency blurs the order only among ballots that overlap in time: the candidates for one voter',
      `shrink from ${crowd} ballots to a handful, even when the exact pairing fails.`,
      '',
      'Other traces of the same order, not exploited here: the physical order of rows, ORA_ROWSCN, flashback',
      'and redo data, and the APEX activity log, which stores a timestamp, a session and an IP address for',
      'every CAST_BALLOT request (see evidence/h2-blindness).',
      '',
    ].join('\n'));

    // ---- (a) the DBA adds votes: back to a quiet election with a known tally
    await openElection(conn, publicKey, registered);
    const quiet = [];
    for (let voter = 0; voter < 20; voter++) {
      const choice = Math.floor(random() * OPTIONS);
      const ballotId = await castBallot(conn, voterCode(voter), P.encryptBallot(publicKey, choice, OPTIONS));
      quiet.push({ choice, ballotId });
    }
    await conn.commit();
    const honest = countChoices(quiet.map((c) => c.choice));
    const before = await readTally();
    const countsBefore = await tableCounts();

    // Multiply one stored ciphertext by a fresh Enc(k). Needs the public key only.
    const forge = async (ballotId, candidateId, amount) => {
      const row = (await dba.execute(`select vote_enc from ${owner}.blind_ballots where ballot_id = :b and candidate_id = :c`, { b: ballotId, c: candidateId })).rows[0];
      const plaintext = ((BigInt(amount) % publicKey.n) + publicKey.n) % publicKey.n;
      const forged = P.ciphertextToHex(publicKey, P.add(publicKey, P.ciphertextFromHex(publicKey, row.VOTE_ENC), P.encrypt(publicKey, plaintext)));
      const result = await dba.execute(`update ${owner}.blind_ballots set vote_enc = :v where ballot_id = :b and candidate_id = :c`, { v: forged, b: ballotId, c: candidateId });
      await dba.commit();
      return { ballotId, candidateId, amount, old: row.VOTE_ENC, forged, rowsUpdated: result.rowsAffected };
    };

    const plus = await forge(quiet[4].ballotId, 2, 5);
    const afterPlus = await readTally();
    report.check('(a) the DBA adds 5 votes to option B with one UPDATE and the public key', afterPlus.join() === [honest[0], honest[1] + 5, honest[2]].join() && before.join() === honest.join(),
      `${fmt(before)}  ->  ${fmt(afterPlus)}`);

    const minus = await forge(quiet[11].ballotId, 1, -5);
    const afterMinus = await readTally();
    const countsAfter = await tableCounts();
    const sumAfter = afterMinus.reduce((a, b) => a + b, 0);
    report.check('(a) taking the same 5 votes from option A keeps the totals equal to the turnout', afterMinus.join() === [honest[0] - 5, honest[1] + 5, honest[2]].join() && sumAfter === countsAfter.TURNOUT,
      `${fmt(afterMinus)}: ${sumAfter} votes from ${countsAfter.TURNOUT} voters`);
    report.check('(a) row counts, ballot count and turnout are unchanged', JSON.stringify(countsBefore) === JSON.stringify(countsAfter),
      `${countsAfter.CIPHERTEXT_ROWS} rows, ${countsAfter.BALLOTS} ballots, turnout ${countsAfter.TURNOUT}, before and after`);

    const guards = (await dba.execute(
      `select 'trigger' as kind, trigger_name as name from dba_triggers where table_owner = :o and table_name = 'BLIND_BALLOTS'
       union all
       select 'constraint ' || constraint_type, constraint_name from dba_constraints where owner = :o and table_name = 'BLIND_BALLOTS'`, { o: owner })).rows;

    writeText(cfg, report.file(`${DIR}/a-dba-adds-votes.txt`), [
      header('H5 (a): a DBA can add votes to any candidate, undetected', [
        'The DBA has no private key. Paillier ciphertexts are malleable: multiplying a stored ciphertext',
        'by Enc(k) adds k to its plaintext. Enc(k) needs the public key only.',
      ]),
      `honest election: 20 ballots, true tally ${fmt(honest)}`,
      `tally before, decrypted by the authority:  ${fmt(before)}`,
      '',
      'Step 1. Add 5 votes to option B, inside an existing ballot',
      `SQL> update ${owner.toLowerCase()}.blind_ballots set vote_enc = :forged where ballot_id = ${plus.ballotId} and candidate_id = ${plus.candidateId};`,
      `     old vote_enc  ${short(plus.old)}`,
      `     new vote_enc  ${short(plus.forged)}     (old * Enc(5) mod n^2, ${plus.rowsUpdated} row updated)`,
      `tally after step 1:  ${fmt(afterPlus)}     sum ${afterPlus.reduce((a, b) => a + b, 0)}, turnout ${countsAfter.TURNOUT}: the totals no longer add up`,
      '',
      'Step 2. Take 5 votes from option A in another ballot, so that the totals add up again',
      `SQL> update ${owner.toLowerCase()}.blind_ballots set vote_enc = :forged where ballot_id = ${minus.ballotId} and candidate_id = ${minus.candidateId};`,
      `     old vote_enc  ${short(minus.old)}`,
      `     new vote_enc  ${short(minus.forged)}     (old * Enc(-5) mod n^2, ${minus.rowsUpdated} row updated)`,
      `tally after step 2:  ${fmt(afterMinus)}     sum ${sumAfter}, turnout ${countsAfter.TURNOUT}: plausible, and wrong`,
      '',
      'Row counts before and after:',
      '', asTable([{ WHEN_: 'before', ...countsBefore }, { WHEN_: 'after', ...countsAfter }]),
      'Everything the schema has to protect BLIND_BALLOTS:',
      '', asTable(guards),
      '"Undetected" means: nothing in the application or in the tally notices. The ciphertexts carry no',
      'signature and no proof, and the table has no history. Database auditing could log the UPDATE, but',
      'the account doing the UPDATE is the one that administers the audit.',
      '',
    ].join('\n'));

    // ---- extra: an active DBA swaps the public key
    await openElection(conn, publicKey, 12);
    const extra = [];
    const voteWithPublishedKey = async (voter) => {
      // An honest client: it asks the server for the key and trusts the answer.
      const published = (await conn.execute('select bf_election.public_key as n from dual')).rows[0].N;
      const key = P.publicKeyFromN(P.fromHex(published));
      const choice = Math.floor(random() * OPTIONS);
      const ballotId = await castBallot(conn, voterCode(voter), P.encryptBallot(key, choice, OPTIONS));
      await conn.commit();
      extra.push({ voter: voterCode(voter), choice, ballotId, key: published === publicKey.n.toString(16) ? 'authority' : 'DBA' });
    };
    for (let voter = 0; voter < 4; voter++) await voteWithPublishedKey(voter);

    const rogue = await P.generateKeyPair(2048);
    await dba.execute(`update ${owner}.election_key set n_hex = :n`, { n: rogue.publicKey.n.toString(16) });
    await dba.commit();
    for (let voter = 4; voter < 8; voter++) await voteWithPublishedKey(voter);

    // The DBA reads what was cast under its own key, re-encrypts under the real one, restores the key.
    const exposed = extra.filter((e) => e.key === 'DBA');
    const learned = new Map();
    for (const ballot of exposed) {
      const rows = (await dba.execute(`select candidate_id, vote_enc from ${owner}.blind_ballots where ballot_id = :b order by candidate_id`, { b: ballot.ballotId })).rows;
      const plain = rows.map((r) => P.decrypt(rogue.publicKey, rogue.privateKey, P.ciphertextFromHex(rogue.publicKey, r.VOTE_ENC)));
      learned.set(ballot.ballotId, plain.map(Number).indexOf(1));
      for (const [index, row] of rows.entries()) {
        await dba.execute(`update ${owner}.blind_ballots set vote_enc = :v where ballot_id = :b and candidate_id = :c`,
          { v: P.ciphertextToHex(publicKey, P.encrypt(publicKey, plain[index])), b: ballot.ballotId, c: row.CANDIDATE_ID });
      }
    }
    await dba.execute(`update ${owner}.election_key set n_hex = :n`, { n: publicKey.n.toString(16) });
    await dba.commit();
    for (let voter = 8; voter < 10; voter++) await voteWithPublishedKey(voter);

    const finalTally = await readTally();
    const extraTruth = countChoices(extra.map((e) => e.choice));
    const votesLearned = exposed.filter((e) => learned.get(e.ballotId) === e.choice).length;
    const extraWorked = votesLearned === exposed.length && exposed.length === 4 && finalTally.join() === extraTruth.join();
    report.note(`extra (not in the original list): a DBA who swaps the public key read ${votesLearned}/${exposed.length} ballots cast meanwhile, and the final tally was still correct (${fmt(finalTally)})`);

    writeText(cfg, report.file(`${DIR}/extra-key-substitution.txt`), [
      header('H5 extra: a DBA who writes can swap the public key', [
        'NOT one of the three limits in the original hypothesis. Added because it bounds the main claim:',
        'the database is blind to votes only as long as it is honest about the public key it hands out.',
        'Voters in this lab receive n from the server and have no independent copy to compare it with.',
      ]),
      'Timeline',
      '  1. the authority opens the election with its key; voters 1 to 4 vote',
      '  2. the DBA generates its own key pair and runs: update election_key set n_hex = :its_own_n',
      '  3. voters 5 to 8 ask the server for the key, receive the DBA key, encrypt and vote',
      '  4. the DBA decrypts those four ballots, re-encrypts each plaintext under the authority key,',
      '     overwrites the rows and restores election_key',
      '  5. voters 9 and 10 vote; the authority tallies',
      '',
      'voter       ballot  key the voter received  true choice  read by the DBA',
      '----------  ------  ----------------------  -----------  ---------------',
      ...extra.map((e) => `${e.voter.padEnd(10)}  ${String(e.ballotId).padStart(6)}  ${e.key.padEnd(22)}  ${LETTERS[e.choice].padEnd(11)}  ${learned.has(e.ballotId) ? LETTERS[learned.get(e.ballotId)] : '-'}`),
      '',
      `ballots read by the DBA: ${votesLearned}/${exposed.length}`,
      `true tally of the ten ballots:         ${fmt(extraTruth)}`,
      `tally decrypted by the authority:      ${fmt(finalTally)}     ${finalTally.join() === extraTruth.join() ? 'correct: the authority sees nothing unusual' : 'DIFFERENT'}`,
      '',
      'What this needs: write access to ELECTION_KEY and BLIND_BALLOTS. A DBA who only reads cannot do it.',
      'What prevents it in a real system: voters verify the public key against a copy published out of',
      'band (a key ceremony, a fingerprint on paper), and ballots are signed so they cannot be replaced.',
      '',
    ].join('\n'));

    // ---- extra: the private key lives in one browser tab
    const lost = await loseTheKey(cfg, conn, random);
    const keptByLink = lost.linkOpened === 'vote' && lost.stayedOn === 'tally' && lost.withKey.totals.join() === lost.truth.join() && !lost.withKey.flagged;
    const lostByReload = lost.decryptDisabled && lost.totalsFetched === OPTIONS;
    report.note(`extra (not in the original list, found in the live session): the private key lives in one browser tab. A link of the Tally page ${keptByLink ? 'opened beside the tab, which then decrypted the right totals' : 'did NOT leave the tab in place'} (${fmt(lost.withKey.totals)}); after a reload of the tab the ${lost.totalsFetched} encrypted totals could still be fetched and ${lostByReload ? 'could not be decrypted' : 'were STILL decrypted'}`);

    writeText(cfg, report.file(`${DIR}/extra-key-loss.txt`), [
      header('H5 extra: the private key lives in one browser tab, and is lost with it', [
        'NOT one of the three limits in the original hypothesis. Added after the live session, where it',
        'happened twice: the tab that held the key was taken to another page (first a new load of the Tally',
        'page, later the Vote link of the page itself), and neither election could be counted afterwards',
        '(evidence/live-session). The design keeps the private key in memory only, so that is all it takes:',
        'there is no copy to restore.',
      ]),
      `election: 6 registered, 3 ballots, true tally ${fmt(lost.truth)}; browser: ${lost.browser}, driven by Playwright`,
      '',
      'Step 1. In the tab that holds the key, the authority follows the "Vote" link of the page',
      `  the link opened:                  /${lost.linkOpened}, in a second tab`,
      `  the first tab stayed on:          /${lost.stayedOn}`,
      `  title of the first tab:           ${lost.title}`,
      `  tally decrypted there afterwards: ${fmt(lost.withKey.totals)}     ${lost.withKey.totals.join() === lost.truth.join() ? 'correct: the key is still in memory' : 'DIFFERENT'}`,
      '  Since the live session, the links of the page open beside the tab once it holds a key. During the',
      '  live session they replaced it.',
      '',
      'Step 2. The same tab is reloaded',
      `  questions the browser raised:     ${lost.questions.length ? lost.questions.join(', ') : 'none'}     (the test answers "leave", as the authority did)`,
      `  the page after the reload says:   ${lost.keyStatus}`,
      `  encrypted totals fetched again:   ${lost.totalsFetched} of ${OPTIONS}`,
      `  Decrypt button:                   ${lost.decryptDisabled ? 'disabled' : 'ENABLED'}`,
      `  the page says:                    ${lost.decryptStatus}`,
      '',
      'The ballots are intact and the database can still multiply them. Nobody can read the result, and',
      'nobody ever will: H2 shows that the private key is in no page item, session state, browser storage,',
      'request or log. The question a browser asks before a reload is worded by the browser: it mentions',
      'unsaved information, not a key, and the page cannot change that text.',
      'What prevents it in a real system: the key is generated in a ceremony, split among several trustees',
      '(threshold decryption) and kept on hardware, so that no single tab, person or machine is the only copy.',
      '',
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'PARTIAL',
      statement: ok
        ? `All three limits hold: a DBA with the public key moved 5 votes with two UPDATEs and the totals still matched the turnout; the key holder read ${ballotsRead}/${cast.length} individual ballots; ordering by voted_at and ballot_id re-linked ${linked}/${cast.length} voters arriving one at a time (${crowdLinked}/${crowd} exactly, ${within(sessions - 1)}/${crowd} within ${sessions - 1} positions, when ${sessions} sessions vote at once).`
        : `${report.failed.length} of the demonstrations did not behave as stated: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { ballots_read: ballotsRead, ballots: cast.length, relinked_sequential: linked, relinked_concurrent: crowdLinked, concurrent_voters: crowd, concurrent_sessions: sessions, concurrent_within_window: within(sessions - 1), concurrent_farthest_miss: farthest, tally_honest: honest, tally_forged: afterMinus, turnout: countsAfter.TURNOUT, extra_key_substitution: { worked: extraWorked, ballots_read: votesLearned, ballots_exposed: exposed.length }, extra_key_loss: { link_kept_the_tab: keptByLink, lost_by_reload: lostByReload, questions: lost.questions, tally_before_reload: lost.withKey.totals, true_tally: lost.truth } },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await factory.close();
    await conn.close();
    await dba.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
