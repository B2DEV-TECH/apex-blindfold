// H10 - What still breaks.
//
//   "Layer 2 does not protect against a DBA with full access, against JavaScript shipped by the
//    server, or against a dishonest key holder." A passing check here means the limit is real:
//    CONFIRMED = the attack works.
//
// Each limit is measured on its own, in the lab schema, on a fictional election:
//
//   1  the key holder reads every ballot, with the name of the voter next to it
//   2  the hidden insert time of a blockchain row re-links ballots to voters (decision 9c)
//   3  a DBA replaces the public key of a registered voter who has not voted, and votes in that
//      voter's name through the ordinary API (decision 6)
//   4  a DBA drops both ballot tables, rebuilds them and copies back every ballot but one
//      (decision 9a: NO DROP UNTIL 0 DAYS IDLE allows it)
//   5  the owner disables the primary key and drops the foreign key of BLIND_BALLOTS
//      (decision 9b), and adds rows that make the tally refuse honest ballots
//   6  the browser runs whatever JavaScript the server ships: a substituted vote.js reads the
//      choice before it is encrypted
//   7  the verifier is code in the schema, and whoever owns the schema can replace it
//
// For 6 and 7 the lab uses harmless replacements: the substituted vote.js only shows the
// choice to the voter, and the replaced verifier makes the same checks with one marker
// method added. They show that the replaced code runs, and where it runs; the lab does not
// build a replacement that changes votes.
//
// Every limit has a negative control: the same goal without the power in question fails.
// SYSDBA and operating system access are not used: everything here needed the DBA role or
// the schema owner. At the end the lab schema is reinstalled from db/install.sql.
//
//   node tests/h10-what-still-breaks.mjs [--quick] [--seed N]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as P from './lib/paillier.mjs';
import * as V from './lib/validity.mjs';
import { loadConfig, ROOT } from './lib/config.mjs';
import { connect, attempt, oracledb } from './lib/db.mjs';
import { sqlcl } from './lib/sqlcli.mjs';
import { installDatabase } from './lib/install.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser, castInBrowser, LETTERS } from './lib/app.mjs';
import { openElection, prepareBallot, castBallot, registerVoter, encryptedTally, decryptTally, countChoices, honest, voterCode, seededRandom, currentElectionId } from './lib/election.mjs';
import { writeText, header, evidencePath } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h10-what-still-breaks';
const CHOICES = [0, 1, 1, 2, 0, 1]; // six honest voters: 2 for A, 3 for B, 1 for C
const REGISTERED = 10;
const fmt = (totals) => totals.map((v, i) => `${LETTERS[i]}=${v}`).join('  ');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

function shuffle(items, random) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export async function run(cfg, args) {
  const report = new Report('H10', 'What still breaks: a DBA with full access, JavaScript shipped by the server and a dishonest key holder still defeat Layer 2 (CONFIRMED = the attack works)', DIR);
  const bits = args.quick ? 1024 : 2048;
  const owner = cfg.schema.toUpperCase();
  const random = seededRandom(args.seed);
  let conn = await connect(cfg, 'schema');
  const dba = await connect(cfg, 'dba');
  const scalar = async (c, sql, binds = {}) => Object.values((await c.execute(sql, binds)).rows[0])[0];
  const sections = [];
  const attacks = [];
  const record = (entry) => { attacks.push(entry); return entry.worked; };

  // One election through the API: the honest ballots of CHOICES, voters 1 to 6.
  const pair = await P.generateKeyPair(bits);
  const key = pair.publicKey;
  const castHonest = async () => {
    await openElection(conn, key, REGISTERED);
    const e = await currentElectionId(conn);
    for (let v = 0; v < CHOICES.length; v++) await castBallot(conn, await prepareBallot(conn, key, voterCode(v), honest(CHOICES[v]), { electionId: e }));
    await conn.commit();
    return e;
  };
  const truth = countChoices(CHOICES);

  try {
    // ================= 1. the key holder reads every ballot =================
    const e1 = await castHonest();
    const rows = (await conn.execute(
      `select s.voter_id, b.ballot_id, b.candidate_id, b.vote_enc
         from blind_ballots b join ballot_seals s on s.election_id = b.election_id and s.ballot_id = b.ballot_id
        where b.election_id = :e order by b.ballot_id, b.candidate_id`, { e: e1 })).rows;
    const readWith = (pk, sk) => {
      const byVoter = new Map();
      for (const row of rows) {
        let m = null;
        try { m = P.decrypt(pk, sk, P.ciphertextFromHex(pk, row.VOTE_ENC)); } catch { m = null; }
        if (!byVoter.has(row.VOTER_ID)) byVoter.set(row.VOTER_ID, []);
        byVoter.get(row.VOTER_ID).push(m);
      }
      return [...byVoter].map(([voter, ms]) => ({ voter, choice: ms.findIndex((m) => m === 1n), clean: ms.filter((m) => m === 0n).length === 2 && ms.filter((m) => m === 1n).length === 1 }));
    };
    const read = readWith(key, pair.privateKey);
    const right = read.filter((r) => r.clean && r.choice === CHOICES[Number(r.voter.slice(6)) - 1]).length;
    const other = await P.generateKeyPair(bits);
    const wrong = readWith(key, other.privateKey).filter((r) => r.clean && r.choice === CHOICES[Number(r.voter.slice(6)) - 1]).length;
    record({ id: 1, name: 'Read single ballots, with the voter name', who: 'Whoever holds the private key', worked: right === CHOICES.length, noticed: false, detail: `${right} of ${CHOICES.length} ballots read, each next to its voter code` });
    report.check('the key holder reads every ballot, with the voter code next to it', right === CHOICES.length, `${right}/${CHOICES.length} ballots of election ${e1}`);
    report.check('negative control: another private key reads none of them', wrong === 0, `${wrong}/${CHOICES.length}`);
    sections.push('1. The key holder reads every ballot',
      `  Election ${e1}, ${CHOICES.length} ballots. BALLOT_SEALS keeps the voter code of each ballot in the clear (decision 5).`,
      ...read.map((r) => `  ${r.voter}  ballot read as ${r.clean ? LETTERS[r.choice] : 'not a ballot'}`),
      `  with another private key (control): ${wrong} of ${CHOICES.length} read`, '');

    // ================= 2. the hidden insert time re-links =================
    // Asked as the DBA. The question is what would be left if the seal did not carry the voter code.
    const created = (await dba.execute(
      `select ballot_id, min(orabctab_creation_time$) as created from ${owner}.blind_ballots
        where election_id = :e group by ballot_id order by created, ballot_id`, { e: e1 })).rows;
    const voted = (await dba.execute(`select voter_id from ${owner}.voter_roll where voted_at is not null order by voted_at, voter_id`)).rows.map((r) => r.VOTER_ID);
    const sealOf = new Map((await dba.execute(`select ballot_id, voter_id from ${owner}.ballot_seals where election_id = :e`, { e: e1 })).rows.map((r) => [r.BALLOT_ID, r.VOTER_ID]));
    const pairs = created.map((row, i) => ({ ballot: row.BALLOT_ID, guess: voted[i], truth: sealOf.get(row.BALLOT_ID) }));
    const relinked = pairs.filter((p) => p.guess === p.truth).length;
    const shuffled = shuffle(voted, random);
    const byChance = created.filter((row, i) => shuffled[i] === sealOf.get(row.BALLOT_ID)).length;
    record({ id: 2, name: 'Re-link ballots to voters by the hidden insert time', who: 'Anyone who reads BLIND_BALLOTS and VOTER_ROLL', worked: relinked === CHOICES.length, noticed: false, detail: `${relinked} of ${CHOICES.length} paired by ORABCTAB_CREATION_TIME$ against VOTER_ROLL.voted_at, without reading BALLOT_SEALS` });
    report.check('the hidden insert time of BLIND_BALLOTS pairs every ballot with its voter', relinked === CHOICES.length, `${relinked}/${CHOICES.length}, checked against the voter codes in BALLOT_SEALS`);
    report.check('negative control: a random pairing does not', byChance < CHOICES.length, `${byChance}/${CHOICES.length} by a seeded shuffle`);
    sections.push('2. The hidden insert time re-links ballots to voters',
      `  select ballot_id, min(orabctab_creation_time$) from <owner>.blind_ballots where election_id = ${e1} group by ballot_id order by 2`,
      `  select voter_id from <owner>.voter_roll where voted_at is not null order by voted_at`,
      ...pairs.map((p) => `  ballot ${p.ballot} -> ${p.guess}   (seal says ${p.truth})`),
      `  re-linked: ${relinked} of ${CHOICES.length}; a seeded random pairing: ${byChance} of ${CHOICES.length}`,
      '  The voter code is in BALLOT_SEALS anyway (decision 5). This measures what removing it would not fix.', '');

    // ================= 3. a DBA votes in the name of a registered voter =================
    const victim = voterCode(CHOICES.length); // registers a key, does not vote
    const victimKey = await V.generateVoterKey();
    await registerVoter(conn, victim, victimKey.publicKeyHex);
    await conn.commit();
    const dbaKey = await V.generateVoterKey();
    // control: without touching VOTER_ROLL, another key cannot register for that voter
    const before3 = await attempt(conn, 'begin :id := bf_election.register_voter(:v, :k); end;', { id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, v: victim, k: dbaKey.publicKeyHex });
    const swap = await attempt(dba, `update ${owner}.voter_roll set public_key = :k where voter_id = :v`, { k: dbaKey.publicKeyHex, v: victim });
    await dba.commit();
    let forged = { ok: false, error: 'not attempted' };
    try {
      const ballot = await prepareBallot(conn, key, victim, honest(2), { electionId: e1, voterKey: dbaKey });
      forged = { ok: true, ballotId: await castBallot(conn, ballot) };
      await conn.commit();
    } catch (error) {
      await conn.rollback();
      forged = { ok: false, error: String(error.message).split('\n')[0] };
    }
    const tally3 = await encryptedTally(conn);
    const result3 = decryptTally(key, pair.privateKey, tally3).map(Number);
    const comeback = await attempt(conn, 'begin :id := bf_election.register_voter(:v, :k); end;', { id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, v: victim, k: victimKey.publicKeyHex });
    const worked3 = !before3.ok && swap.ok && forged.ok && tally3.ballots_counted === CHOICES.length + 1 && result3[2] === truth[2] + 1;
    record({ id: 3, name: 'Vote in the name of a registered voter who has not voted', who: 'A DBA who can write to VOTER_ROLL', worked: worked3, noticed: false, detail: `one UPDATE of VOTER_ROLL.public_key, then the ordinary API: ballot ${forged.ballotId ?? '-'} accepted and counted; the voter, coming back, is told the code has been used` });
    report.check('negative control: without writing to VOTER_ROLL, another key cannot register for that voter', !before3.ok, before3.error ?? 'accepted');
    report.check('after one UPDATE of VOTER_ROLL the DBA casts a ballot in that voter name and the tally counts it', worked3, `${forged.ok ? `ballot ${forged.ballotId} accepted` : forged.error}; tally ${fmt(result3)}, ${tally3.ballots_counted} counted, ${tally3.ballots_rejected} rejected`);
    report.check('the voter, coming back, finds the code used', !comeback.ok && /ORA-20004/.test(comeback.error), comeback.error ?? 'accepted');
    sections.push('3. A DBA votes in the name of a registered voter who has not voted',
      `  ${victim} registered a key and did not vote.`,
      `  control, register another key for ${victim}: ${before3.error ?? 'ACCEPTED'}`,
      `  update <owner>.voter_roll set public_key = <the DBA key> where voter_id = '${victim}'  -> ${swap.ok ? 'accepted' : swap.error}`,
      `  ballot for C, signed with the DBA key, through bf_election.cast_ballot: ${forged.ok ? `accepted as ballot ${forged.ballotId}` : forged.error}`,
      `  tally: ${tally3.ballots_counted} counted, ${tally3.ballots_rejected} rejected, decrypted ${fmt(result3)} (the honest ballots: ${fmt(truth)})`,
      `  ${victim} comes back with the key of the browser: ${comeback.error ?? 'ACCEPTED'}`, '');

    // ================= 4. drop and rebuild =================
    const e4 = await castHonest();
    const removed = 1; // the ballot that is not copied back
    const control4 = await attempt(dba, `delete from ${owner}.blind_ballots where election_id = :e and ballot_id = :b`, { e: e4, b: removed });
    await dba.rollback();
    const savedBallots = (await dba.execute(`select election_id, ballot_id, candidate_id, vote_enc, bit_proof from ${owner}.blind_ballots`, {}, { outFormat: oracledb.OUT_FORMAT_ARRAY })).rows;
    const savedSeals = (await dba.execute(`select election_id, ballot_id, voter_id, sum_proof, signature from ${owner}.ballot_seals`, {}, { outFormat: oracledb.OUT_FORMAT_ARRAY })).rows;
    const ddl = readFileSync(join(ROOT, 'db', '01_tables.sql'), 'utf8');
    const creates = [...ddl.matchAll(/create blockchain table (\w+) \([\s\S]*?version "v2";/g)].map((m) => m[0].replace(/;$/, '')
      .replace(`create blockchain table ${m[1]}`, `create blockchain table ${owner}.${m[1]}`)
      .replace(/references candidates/g, `references ${owner}.candidates`));
    const steps4 = [];
    for (const sql of [`drop table ${owner}.ballot_seals purge`, `drop table ${owner}.blind_ballots purge`, ...creates]) {
      const answer = await attempt(dba, sql);
      steps4.push(`  ${sql.split('\n')[0]}${sql.includes('\n') ? ' ...' : ''}  -> ${answer.ok ? 'done' : answer.error}`);
      if (!answer.ok) throw new Error(`The rebuild stopped: ${answer.error}`);
    }
    const keepBallots = savedBallots.filter((r) => !(r[0] === e4 && r[1] === removed));
    const keepSeals = savedSeals.filter((r) => !(r[0] === e4 && r[1] === removed));
    await dba.executeMany(`insert into ${owner}.blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:1, :2, :3, :4, :5)`, keepBallots);
    await dba.executeMany(`insert into ${owner}.ballot_seals (election_id, ballot_id, voter_id, sum_proof, signature) values (:1, :2, :3, :4, :5)`, keepSeals);
    await dba.commit();
    // The package of the owner was invalidated by the drop: a new session starts clean.
    await conn.close();
    conn = await connect(cfg, 'schema');
    const chain4 = JSON.parse(await scalar(conn, 'select bf_election.verify_chains from dual'));
    const tally4 = await encryptedTally(conn);
    const result4 = decryptTally(key, pair.privateKey, tally4).map(Number);
    const turnout4 = await scalar(conn, 'select count(voted_at) from voter_roll');
    const expected4 = [...truth];
    expected4[CHOICES[removed - 1]] -= 1;
    const worked4 = !control4.ok && chain4.blind_ballots === keepBallots.length && chain4.ballot_seals === keepSeals.length
      && tally4.ballots_counted === CHOICES.length - 1 && tally4.ballots_rejected === 0 && result4.join() === expected4.join();
    record({ id: 4, name: 'Remove a ballot by dropping and rebuilding the tables', who: 'A DBA', worked: worked4, noticed: false, detail: `the chain verified over the rebuilt tables; ${tally4.ballots_counted} ballots counted while VOTER_ROLL says ${turnout4} voted, and nothing compares the two` });
    report.check('negative control: the DBA cannot DELETE that ballot', !control4.ok, control4.error ?? 'accepted');
    report.check('after DROP and CREATE the chain verifies, one ballot is gone and the tally does not notice', worked4,
      `chain: ${chain4.blind_ballots} rows and ${chain4.ballot_seals} seals; tally ${fmt(result4)}, ${tally4.ballots_counted} counted, ${tally4.ballots_rejected} rejected; VOTER_ROLL: ${turnout4} voted`);
    sections.push('4. A DBA drops the ballot tables, rebuilds them and copies back every ballot but one',
      `  Election ${e4}, ${CHOICES.length} honest ballots (${fmt(truth)}). The ballot left out: ${removed}, a vote for ${LETTERS[CHOICES[removed - 1]]}.`,
      `  control, delete from <owner>.blind_ballots where ballot_id = ${removed}: ${control4.error ?? 'ACCEPTED'}`,
      ...steps4.map((s) => s.replaceAll(`${owner}.`, '<owner>.')),
      `  copied back: ${keepBallots.length} of ${savedBallots.length} ciphertext rows and ${keepSeals.length} of ${savedSeals.length} seals, every election`,
      `  chain verification: ${chain4.blind_ballots} rows and ${chain4.ballot_seals} seals verified`,
      `  tally: ${tally4.ballots_counted} counted, ${tally4.ballots_rejected} rejected, decrypted ${fmt(result4)}`,
      `  VOTER_ROLL: ${turnout4} voters marked as voted`,
      '  The insert time of every copied row is the time of the copy: the rebuilt chain starts on the day of the rebuild.', '');

    // ================= 5. the owner disables the primary key and drops the foreign key =================
    const fresh = (m) => P.ciphertextToHex(key, P.encrypt(key, BigInt(m)));
    const dummyProof = '0'.repeat(64 + 4 * V.modulusBytes(key));
    const duplicate = { e: e4, b: 2, c: 1, v: fresh(0), p: dummyProof };
    const control5 = await attempt(conn, 'insert into blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:e, :b, :c, :v, :p)', duplicate);
    await conn.rollback();
    const disable = await attempt(conn, 'alter table blind_ballots disable constraint blind_ballots_pk');
    const dropFk = await attempt(conn, 'alter table blind_ballots drop constraint blind_ballots_candidate_fk');
    const dup = await attempt(conn, 'insert into blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:e, :b, :c, :v, :p)', duplicate);
    const stray = await attempt(conn, 'insert into blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:e, :b, :c, :v, :p)', { e: e4, b: 3, c: 9, v: fresh(0), p: dummyProof });
    await conn.commit();
    const tally5 = await encryptedTally(conn);
    const refusedHonest = tally5.rejected.filter((r) => r.ballot_id === 2 || r.ballot_id === 3);
    const worked5 = !control5.ok && disable.ok && dropFk.ok && dup.ok && stray.ok && refusedHonest.length === 2;
    record({ id: 5, name: 'Make the tally refuse honest ballots, after disabling the primary key and dropping the foreign key', who: 'The owner of the tables', worked: worked5, noticed: true, detail: `${refusedHonest.length} honest ballots not counted; the tally lists them as rejected, with the reason` });
    report.check('negative control: with the primary key enabled a second row for a ballot is refused', !control5.ok, control5.error ?? 'accepted');
    report.check('the owner disables the key, drops the foreign key, and two honest ballots stop being counted', worked5,
      `disable: ${disable.ok ? 'done' : disable.error}; drop FK: ${dropFk.ok ? 'done' : dropFk.error}; ${tally5.ballots_counted} counted, ${tally5.ballots_rejected} rejected`);
    report.check('the tally says so: it lists both ballots as rejected, with the reason', refusedHonest.length === 2, refusedHonest.map((r) => `ballot ${r.ballot_id}: ${r.reason}`).join('; '));
    sections.push('5. The owner disables the primary key and drops the foreign key of BLIND_BALLOTS',
      `  control, a fourth row for ballot 2 with the key enabled: ${control5.error ?? 'ACCEPTED'}`,
      `  alter table blind_ballots disable constraint blind_ballots_pk   -> ${disable.ok ? 'done' : disable.error}`,
      `  alter table blind_ballots drop constraint blind_ballots_candidate_fk   -> ${dropFk.ok ? 'done' : dropFk.error}`,
      `  a fourth row for ballot 2 (candidate 1 again): ${dup.ok ? 'stored' : dup.error}`,
      `  a fourth row for ballot 3 (candidate 9): ${stray.ok ? 'stored' : stray.error}`,
      `  tally: ${tally5.ballots_counted} counted, ${tally5.ballots_rejected} rejected`,
      ...tally5.rejected.map((r) => `    ballot ${r.ballot_id} (${r.voter_id ?? 'no voter'}): ${r.reason}`), '');

    // ================= 6. JavaScript shipped by the server =================
    // The served file is a row in the database. Read, not changed.
    const served = await attempt(conn, "select file_content from apex_application_static_files where application_id = :app and file_name = 'blindfold/vote.js'", { app: cfg.app_id });
    const repoFile = readFileSync(join(ROOT, 'app', 'apexlang', 'shared-components', 'static-files', 'blindfold', 'vote.js'));
    let storedSha = null;
    if (served.ok && served.rows.length) {
      const lob = served.rows[0].FILE_CONTENT;
      const bytes = Buffer.isBuffer(lob) ? lob : await lob.getData();
      storedSha = sha(bytes);
    }
    const PAYLOAD = [
      '',
      '// Added by tests/h10-what-still-breaks.mjs. It stands for code that the server ships.',
      '// It reads the choice from the page when the voter casts, and only shows it to the voter.',
      "document.addEventListener('click', (event) => {",
      "  if (!event.target.closest('#bf-cast')) return;",
      "  const chosen = document.querySelector('.bf-option[aria-checked=\"true\"]');",
      "  let note = document.getElementById('bf-h10-note');",
      "  if (!note) { note = document.createElement('div'); note.id = 'bf-h10-note'; note.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px;background:#b00020;color:#fff;font:600 16px system-ui'; document.body.prepend(note); }",
      "  const parts = chosen ? [...chosen.querySelectorAll('span')].map((s) => s.textContent.trim()).filter(Boolean) : [];",
      "  note.textContent = 'Read by code the server shipped, before encryption: ' + (parts.length ? parts.join(' / ') : 'nothing');",
      '}, true);',
      '',
    ].join('\n');
    const browser = await launchBrowser(cfg);
    let shown = '';
    let plainNote = 0;
    let receipts = [];
    try {
      const viewport = { width: 1440, height: 900 };
      const authority = await (await browser.newContext({ viewport })).newPage();
      watch(authority, 'authority');
      await openElectionInBrowser(authority, cfg, 6);
      // control: the application as installed
      const plain = await (await browser.newContext({ viewport })).newPage();
      watch(plain, 'voter (as installed)');
      await plain.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
      await plain.waitForSelector('.bf-option');
      receipts.push(await castInBrowser(plain, voterCode(0), 0, { next: false }));
      plainNote = await plain.locator('#bf-h10-note').count();
      // the same page, with vote.js as a server could ship it
      const context = await browser.newContext({ viewport, deviceScaleFactor: 2 });
      await context.route(/\/blindfold\/vote\.js(\?.*)?$/, async (route) => {
        const response = await route.fetch();
        await route.fulfill({ response, body: `${await response.text()}${PAYLOAD}` });
      });
      const voter = await context.newPage();
      watch(voter, 'voter (substituted vote.js)');
      await voter.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
      await voter.waitForSelector('.bf-option');
      receipts.push(await castInBrowser(voter, voterCode(1), 1, { next: false }));
      shown = (await voter.textContent('#bf-h10-note').catch(() => '')) ?? '';
      await voter.screenshot({ path: evidencePath(`${DIR}/01-server-shipped-code-reads-the-choice.png`) });
      report.file(`${DIR}/01-server-shipped-code-reads-the-choice.png`);
    } finally {
      await browser.close();
    }
    const label = (await conn.execute('select label from candidates where candidate_id = 2')).rows[0].LABEL;
    const worked6 = shown.includes(label) && receipts.every((r) => Number.isInteger(r) && r > 0);
    record({ id: 6, name: 'Read the choice in the browser, with JavaScript shipped by the server', who: 'Whoever can change the static files of the application', worked: worked6, noticed: false, detail: 'a substituted vote.js ran in the voter tab and read the choice before it was encrypted; the ballot was accepted as usual' });
    report.check('negative control: the application as installed shows no such note', plainNote === 0, `${plainNote} note(s)`);
    report.check('a substituted vote.js runs in the voter tab and reads the choice before encryption', worked6, `"${shown.trim()}"; ballots ${receipts.join(' and ')} accepted`);
    report.note(storedSha
      ? `the vote.js that the browser receives is a row of APEX_APPLICATION_STATIC_FILES: SHA-256 ${storedSha.slice(0, 16)}..., the file in the repository ${sha(repoFile).slice(0, 16)}...`
      : `the static file could not be read from APEX_APPLICATION_STATIC_FILES: ${served.error ?? 'no row'}`);
    sections.push('6. JavaScript shipped by the server',
      '  The substitution is made with Playwright request routing, which stands for a server or an APEX developer',
      '  who changes the static file. The installed application is not modified.',
      `  vote.js in APEX_APPLICATION_STATIC_FILES: ${storedSha ? `SHA-256 ${storedSha}` : served.error ?? 'no row'}`,
      `  vote.js in the repository:                SHA-256 ${sha(repoFile)}`,
      `  control, as installed: ${plainNote} note on the page; ballot ${receipts[0]} accepted`,
      `  substituted, voter chooses B: "${shown.trim()}"; ballot ${receipts[1]} accepted`,
      '  The added lines read the page only. Code in that position also holds the voter signing key',
      '  handle and the values that get encrypted.', '');

    // ================= 7. the verifier is replaceable =================
    const javaFile = readFileSync(join(ROOT, 'db', '05_ballot_validity_java.sql'), 'utf8');
    const end = javaFile.indexOf('\n}\n/');
    if (end < 0) throw new Error('The end of the Java class was not found in db/05_ballot_validity_java.sql.');
    const replaced = `${javaFile.slice(0, end)}\n\n  // Added by tests/h10: the same checks, and one marker that says this class was replaced.\n  public static String marker() {\n    return "replaced by H10";\n  }\n${javaFile.slice(end + 1)}\n\ncreate or replace function bf_h10_marker return varchar2\nas language java name 'BlindfoldValidity.marker() return java.lang.String';\n/\n`;
    const ddlTime = async () => scalar(conn, "select to_char(last_ddl_time, 'yyyy-mm-dd hh24:mi:ss') from user_objects where object_type = 'JAVA SOURCE' and object_name = 'BlindfoldValidity'");
    const chainBefore = await scalar(conn, 'select bf_election.verify_chains from dual');
    const timeBefore = await ddlTime();
    const markerBefore = await attempt(conn, 'select bf_h10_marker as m from dual');
    await sqlcl(cfg, cfg.schema, cfg.schema_password, replaced, { cwd: join(ROOT, 'db') });
    await conn.close();
    conn = await connect(cfg, 'schema');
    const markerAfter = await attempt(conn, 'select bf_h10_marker as m from dual');
    const timeAfter = await ddlTime();
    const chainAfter = await scalar(conn, 'select bf_election.verify_chains from dual');
    const tally7 = await encryptedTally(conn);
    const worked7 = !markerBefore.ok && markerAfter.ok && markerAfter.rows[0].M === 'replaced by H10' && chainBefore === chainAfter;
    record({ id: 7, name: 'Replace the verifier', who: 'The owner of the schema (or a DBA)', worked: worked7, noticed: false, detail: 'the class that checks every proof and signature was replaced; the ballot tables, their chain and the tally answer show nothing' });
    report.check('negative control: before the replacement the marker does not exist', !markerBefore.ok, markerBefore.error ?? 'it exists');
    report.check('the owner replaces the verifier, and nothing that the tally checks records it', worked7,
      `marker: ${markerAfter.ok ? markerAfter.rows[0].M : markerAfter.error}; chain ${chainBefore} before and ${chainAfter} after; only USER_OBJECTS.LAST_DDL_TIME moved (${timeBefore} -> ${timeAfter})`);
    sections.push('7. The verifier is code in the schema',
      '  create or replace and compile java source named "BlindfoldValidity": the same checks plus one method, marker().',
      `  marker before: ${markerBefore.error ?? 'present'}; after: ${markerAfter.ok ? markerAfter.rows[0].M : markerAfter.error}`,
      `  LAST_DDL_TIME of the Java source: ${timeBefore} -> ${timeAfter}`,
      `  chain verification before: ${chainBefore}; after: ${chainAfter}`,
      `  tally after the replacement: ${tally7.ballots_counted} counted, ${tally7.ballots_rejected} rejected`,
      '  Whoever can replace this class decides what verifyBallot and verifySignature answer, at arrival and in the tally.', '');

    // ================= the lab schema, as installed =================
    await conn.close();
    conn = null;
    await attempt(dba, `drop function ${owner}.bf_h10_marker`);
    await installDatabase(cfg);
    conn = await connect(cfg, 'schema');
    const restored = await attempt(conn, 'select bf_h10_marker as m from dual');
    const pk = await scalar(conn, "select status from user_constraints where constraint_name = 'BLIND_BALLOTS_PK'");
    report.note(`lab schema reinstalled from db/install.sql: marker ${restored.ok ? 'STILL PRESENT' : 'gone'}, BLIND_BALLOTS_PK ${pk}`);
    sections.push('The lab schema was reinstalled from db/install.sql at the end of this test.',
      `  marker: ${restored.ok ? 'STILL PRESENT' : 'gone'}; BLIND_BALLOTS_PK: ${pk}`, '');

    writeText(cfg, report.file(`${DIR}/limits.txt`), [
      header('H10: what still breaks', [
        `${bits}-bit election key, fictional election, lab schema. CONFIRMED = the attack works.`,
        'Powers used: the private key (1), read access (2), the DBA role (3, 4), the schema owner (5, 7),',
        'the static files of the application (6). SYSDBA and operating system access were not needed.',
      ]),
      ...sections,
    ].join('\n'));

    const worked = attacks.filter((a) => a.worked).length;
    const verdict = report.failed.length === 0 ? 'CONFIRMED' : worked === 0 ? 'REFUTED' : 'PARTIAL';
    return report.close(cfg, {
      verdict,
      statement: verdict === 'CONFIRMED'
        ? `All ${attacks.length} limits held up in the lab: the key holder read ${right} of ${CHOICES.length} ballots with the voter code next to each; the hidden insert time re-linked ${relinked} of ${CHOICES.length}; a DBA voted in the name of a registered voter with one UPDATE; a DBA dropped and rebuilt the tables without one ballot and the chain still verified; the owner made the tally refuse ${refusedHonest.length} honest ballots (this one is reported by the tally); a substituted vote.js read the choice; the verifier was replaced without a trace in the tables.`
        : `${worked} of ${attacks.length} limits worked. Failed checks: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { key_bits: bits, ballots: CHOICES.length, attacks },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    if (conn) { await conn.rollback(); await conn.close(); }
    await dba.rollback();
    await dba.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
