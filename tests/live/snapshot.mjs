// Live session: captures the state of the database, as a DBA sees it.
//
//   node tests/live/snapshot.mjs "before key generation"   one numbered snapshot
//   node tests/live/snapshot.mjs --watch                    one snapshot per change, until stopped
//   node tests/live/snapshot.mjs --watch --hours 4          the same, for at most 4 hours (default 8)
//
// Read-only. Every snapshot is two files in evidence/live-session/state:
//   NN-<label>.txt   for people: tables with shortened ciphertexts, APEX session state, activity log
//   NN-<label>.json  complete: every ciphertext in full
// and one line in evidence/live-session/timeline.txt.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig } from '../lib/config.mjs';
import { connect, asTable } from '../lib/db.mjs';
import { writeText, writeJson, header } from '../lib/evidence.mjs';
import { fromHex, bitLength } from '../lib/paillier.mjs';
import {
  LIVE, LIVE_DIR, sha256, maskIds, addressAliases, shortHex, apexSchema, fingerprint, readTables, readApex,
  sessionStart, nextSnapshotNumber,
} from './lib.mjs';

const args = process.argv.slice(2);
const watch = args.includes('--watch');
const hoursAt = args.indexOf('--hours');
const hours = hoursAt >= 0 ? Number(args[hoursAt + 1]) : 8;
const label = args.filter((arg, index) => !arg.startsWith('--') && (hoursAt < 0 || index !== hoursAt + 1)).join(' ');
if (!watch && !label) throw new Error('Usage: node tests/live/snapshot.mjs "<label>"   or   node tests/live/snapshot.mjs --watch');

const cfg = loadConfig();
const owner = cfg.schema.toUpperCase();
const dba = await connect(cfg, 'dba');
const apex = await apexSchema(dba);
const alias = addressAliases();
const indent = (text) => text.split('\n').map((line) => (line ? `  ${line}` : line)).join('\n');
const slug = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'state';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// What changed between two readings of the tables, in one sentence.
function describe(before, after) {
  if (!before) return 'first reading';
  const parts = [];
  if (before.key.join() !== after.key.join()) {
    parts.push(after.key.length ? `new election opened: public key ${shortHex(after.key[0], 12, 6)}, ${after.roll.length} voters registered` : 'the public key was removed');
    // Opening an election empties the tables: what is there now is new, whatever its ballot number.
    before = { key: after.key, roll: after.roll.map((row) => ({ ...row, VOTED_AT: null })), ballots: [] };
  }
  const ids = (state) => [...new Set(state.ballots.map((row) => row.BALLOT_ID))];
  const added = ids(after).filter((id) => !ids(before).includes(id));
  const removed = ids(before).filter((id) => !ids(after).includes(id));
  if (added.length) parts.push(`ballot ${added.join(', ')} stored (+${after.ballots.filter((row) => added.includes(row.BALLOT_ID)).length} rows)`);
  if (removed.length) parts.push(`ballot ${removed.join(', ')} removed`);
  const changed = after.ballots.filter((row) => before.ballots.some((old) => old.BALLOT_ID === row.BALLOT_ID && old.CANDIDATE_ID === row.CANDIDATE_ID && old.VOTE_ENC !== row.VOTE_ENC));
  if (changed.length) parts.push(`${changed.length} stored ciphertext(s) rewritten in place: ${changed.map((row) => `ballot ${row.BALLOT_ID} option ${row.CANDIDATE_ID}`).join(', ')}`);
  const voted = (state) => state.roll.filter((row) => row.VOTED_AT !== null).length;
  if (voted(before) !== voted(after)) parts.push(`voters marked as voted: ${voted(before)} -> ${voted(after)} of ${after.roll.length}`);
  return parts.join('; ') || 'no change in the election tables';
}

async function snapshot(text, previous) {
  const number = nextSnapshotNumber();
  const taken = new Date();
  if (number === 0) writeJson(cfg, `${LIVE}/state/session.json`, { started: taken.toISOString() });
  const since = sessionStart() ?? taken;
  const tables = await readTables(dba, owner);
  const apexData = await readApex(dba, apex, cfg.app_id, since, alias);
  const what = text || describe(previous, tables);
  const name = `${String(number).padStart(2, '0')}-${slug(what)}`;
  const ballotIds = [...new Set(tables.ballots.map((row) => row.BALLOT_ID))];
  const voted = tables.roll.filter((row) => row.VOTED_AT !== null).length;
  const n = tables.key[0] ?? null;

  writeText(cfg, `${LIVE}/state/${name}.txt`, maskIds([
    header(`Live session: database state ${String(number).padStart(2, '0')}`, [
      what,
      'read as the account with the DBA role; nothing is written to the database',
      `complete values: ${name}.json`,
    ]),
    `ELECTION_KEY: ${tables.key.length} row${tables.key.length === 1 ? '' : 's'}`,
    n ? `  n = ${shortHex(n, 32, 12)}   (${n.length} hexadecimal characters, ${bitLength(fromHex(n))} bits; sha256 ${sha256(n).slice(0, 16)})` : '  no public key: no election is open',
    '',
    `VOTER_ROLL: ${tables.roll.length} registered, ${voted} voted`,
    '',
    indent(asTable(tables.roll)),
    `BLIND_BALLOTS: ${tables.ballots.length} rows, ${ballotIds.length} ballot${ballotIds.length === 1 ? '' : 's'}`,
    '',
    indent(asTable(tables.ballots.map((row) => ({ BALLOT_ID: row.BALLOT_ID, CANDIDATE_ID: row.CANDIDATE_ID, VOTE_ENC: shortHex(row.VOTE_ENC, 40, 12), CHARS: row.VOTE_ENC.length })), { maxWidth: 80 })),
    `APEX session state of the application (${apex}.WWV_FLOW_DATA): ${apexData.pageItems.length} page or application items with a value,`,
    `${apexData.state.length - apexData.pageItems.length} report paging positions`,
    apexData.pageItems.length ? indent(asTable(apexData.pageItems)) : '',
    `APEX activity log of the application since the session started (${since.toISOString()}): ${apexData.activity.length} requests`,
    '',
    indent(asTable(apexData.activity.slice(-60), { maxWidth: 48 })),
    apexData.activity.length > 60 ? `  (the last 60 of ${apexData.activity.length} requests)` : '',
    `PAGE, KIND and REQUEST are the STEP_ID, PAGE_VIEW_TYPE and REQUEST_VALUE columns of the log. CLIENT is the logged address,`,
    `renamed: this-pc is the machine that runs the database, device-2 and so on are other machines. APEX logged an address on`,
    `${apexData.activity.filter((row) => row.CLIENT).length} of the ${apexData.activity.length} requests; the session column ties the others to one of them.`,
    '',
  ].join('\n')));
  writeJson(cfg, `${LIVE}/state/${name}.json`, { number, taken: taken.toISOString(), what, election_key: tables.key, voter_roll: tables.roll, blind_ballots: tables.ballots, apex_page_items: apexData.pageItems, apex_activity: apexData.activity });

  const timeline = join(LIVE_DIR, 'timeline.txt');
  const lines = existsSync(timeline) ? readFileSync(timeline, 'utf8') : '# Live session: what changed in the database, and when\n# time (UTC)                snapshot  change\n';
  writeText(cfg, `${LIVE}/timeline.txt`, `${lines}${taken.toISOString()}  ${String(number).padStart(2, '0')}        ${what}\n`);
  console.log(`${taken.toISOString()}  snapshot ${String(number).padStart(2, '0')}: ${what}`);
  return tables;
}

try {
  if (!watch) {
    await snapshot(label, null);
  } else {
    const until = Date.now() + hours * 3600 * 1000;
    let seen = await fingerprint(dba, owner);
    let previous = await snapshot(label || 'watch started', null);
    console.log(`Watching ${owner} for changes, for at most ${hours} hours. Stop with Ctrl+C.`);
    while (Date.now() < until) {
      await sleep(2000);
      let now = await fingerprint(dba, owner);
      if (now === seen) continue;
      // Opening an election is several statements: wait until two readings agree.
      for (;;) {
        await sleep(400);
        const again = await fingerprint(dba, owner);
        if (again === now) break;
        now = again;
      }
      seen = now;
      previous = await snapshot('', previous);
    }
    console.log('Watch ended: time limit reached.');
  }
} finally {
  await dba.close();
}
