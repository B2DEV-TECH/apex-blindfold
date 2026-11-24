// Live session of Layer 2: captures the state of the database, as a DBA sees it.
//
//   node tests/live/snapshot-layer2.mjs "before key generation"   one numbered snapshot
//   node tests/live/snapshot-layer2.mjs --watch                    one snapshot per change, until stopped
//   node tests/live/snapshot-layer2.mjs --watch --hours 4          the same, for at most 4 hours (default 8)
//
// Read-only: it only runs SELECT. It is the Layer 2 counterpart of snapshot.mjs, which stays as it
// was for the record of the Layer 1 session. Every snapshot is two files in
// evidence/live-session-layer2/state:
//   NN-<label>.txt   for people: the current election, values shortened
//   NN-<label>.json  complete: every value in full
// and one line in evidence/live-session-layer2/timeline.txt.
//
// Besides the rows, it records the structure an attack of the DBA can change: the object number of
// both ballot tables (it changes when a table is dropped and created again), the state of their
// constraints, and when the Java verifier was last compiled. While a table is missing, in the
// middle of a drop and rebuild, the snapshot says so instead of failing.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig } from '../lib/config.mjs';
import { connect, asTable } from '../lib/db.mjs';
import { EVIDENCE, writeText, writeJson, header } from '../lib/evidence.mjs';
import { sha256, shortHex } from './lib.mjs';

const LIVE2 = 'live-session-layer2';
const LIVE2_DIR = join(EVIDENCE, LIVE2);

const args = process.argv.slice(2);
const watch = args.includes('--watch');
const hoursAt = args.indexOf('--hours');
const hours = hoursAt >= 0 ? Number(args[hoursAt + 1]) : 8;
const label = args.filter((arg, index) => !arg.startsWith('--') && (hoursAt < 0 || index !== hoursAt + 1)).join(' ');
if (!watch && !label) throw new Error('Usage: node tests/live/snapshot-layer2.mjs "<label>"   or   node tests/live/snapshot-layer2.mjs --watch');

const cfg = loadConfig();
const owner = cfg.schema.toUpperCase();
const dba = await connect(cfg, 'dba');
const indent = (text) => text.split('\n').map((line) => (line ? `  ${line}` : line)).join('\n');
const slug = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'state';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const utc = (column) => `to_char(sys_extract_utc(${column}), 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"')`;
const short = (hex, head = 16, tail = 6) => (hex ? shortHex(hex, head, tail) : null);

// A query on a table that may be missing for a moment: null instead of an error.
async function rows(sql, binds = {}) {
  try {
    return (await dba.execute(sql, binds)).rows;
  } catch (error) {
    if (/ORA-00942|ORA-04043/.test(error.message)) return null;
    throw error;
  }
}

// The structure that the DBA's attacks change. Owner and table names are bound, not concatenated.
async function readStructure() {
  const tables = await rows(
    `select object_name as name, object_id as id, to_char(created, 'YYYY-MM-DD HH24:MI:SS') as created
       from dba_objects
      where owner = :owner and object_type = 'TABLE' and object_name in ('BLIND_BALLOTS', 'BALLOT_SEALS')
      order by object_name`, { owner });
  const constraints = await rows(
    `select table_name, constraint_name, constraint_type as type, status
       from dba_constraints
      where owner = :owner and table_name in ('BLIND_BALLOTS', 'BALLOT_SEALS') and constraint_type in ('P', 'U', 'R')
      order by table_name, constraint_name`, { owner });
  const verifier = await rows(
    `select object_name as name, status, to_char(last_ddl_time, 'YYYY-MM-DD HH24:MI:SS') as last_ddl
       from dba_objects
      where owner = :owner and object_type = 'JAVA SOURCE' and object_name in ('BlindfoldValidity', 'BlindfoldTally')
      order by object_name`, { owner });
  return { tables, constraints, verifier };
}

async function readState() {
  const elections = (await rows(
    `select election_id, n_hex, ${utc('opened_at')} as opened_at from ${owner}.election_key order by election_id`)) ?? [];
  const current = elections.length ? elections[elections.length - 1].ELECTION_ID : null;
  const roll = (await rows(
    `select voter_id, ballot_id, public_key, ${utc('registered_at')} as registered_at, ${utc('voted_at')} as voted_at
       from ${owner}.voter_roll order by voter_id`)) ?? [];
  // Rows of the current election in full; of earlier elections, only how many there are.
  const ballots = await rows(
    `select election_id, ballot_id, candidate_id, vote_enc, bit_proof, ${utc('orabctab_creation_time$')} as created
       from ${owner}.blind_ballots where election_id = :election order by ballot_id, candidate_id`, { election: current });
  const seals = await rows(
    `select election_id, ballot_id, voter_id, sum_proof, signature, ${utc('orabctab_creation_time$')} as created
       from ${owner}.ballot_seals where election_id = :election order by ballot_id`, { election: current });
  const earlier = await rows(
    `select (select count(*) from ${owner}.blind_ballots where election_id <> :election) as ballot_rows,
            (select count(*) from ${owner}.ballot_seals where election_id <> :election) as seals
       from dual`, { election: current });
  return { elections, current, roll, ballots, seals, earlier: earlier?.[0] ?? null, structure: await readStructure() };
}

// What a watcher compares: everything, hashed.
const fingerprint = (state) => sha256(JSON.stringify(state));

const ofCurrent = (list, current) => (list ?? []).filter((row) => row.ELECTION_ID === current);
const ballotIds = (list) => [...new Set(list.map((row) => row.BALLOT_ID))];

// What changed between two readings, in one sentence.
function describe(before, after) {
  if (!before) return 'first reading';
  const parts = [];
  if (before.current !== after.current) {
    parts.push(`election ${after.current} opened: public key ${short(after.elections.at(-1)?.N_HEX, 12, 6)}, ${after.roll.length} voter codes`);
  }
  for (const [name, b, a] of [['BLIND_BALLOTS', before.ballots, after.ballots], ['BALLOT_SEALS', before.seals, after.seals]]) {
    if (b && !a) parts.push(`${name} is missing`);
    if (!b && a) parts.push(`${name} exists again`);
  }
  const tableIds = (state) => Object.fromEntries((state.structure.tables ?? []).map((row) => [row.NAME, row.ID]));
  for (const [name, id] of Object.entries(tableIds(after))) {
    const old = tableIds(before)[name];
    if (old && old !== id) parts.push(`${name} was created again (object ${old} -> ${id})`);
  }
  const status = (state) => Object.fromEntries((state.structure.constraints ?? []).map((row) => [row.CONSTRAINT_NAME, row.STATUS]));
  for (const [name, value] of Object.entries(status(before))) {
    const now = status(after)[name];
    if (now === undefined && after.ballots && after.seals) parts.push(`constraint ${name} dropped`);
    else if (now !== undefined && now !== value) parts.push(`constraint ${name} ${value} -> ${now}`);
  }
  const ddl = (state) => Object.fromEntries((state.structure.verifier ?? []).map((row) => [row.NAME, row.LAST_DDL]));
  for (const [name, value] of Object.entries(ddl(after))) {
    if (ddl(before)[name] && ddl(before)[name] !== value) parts.push(`Java class ${name} compiled again (${ddl(before)[name]} -> ${value})`);
  }
  if (after.ballots && before.ballots && before.current === after.current) {
    const was = ofCurrent(before.ballots, after.current);
    const now = ofCurrent(after.ballots, after.current);
    const added = ballotIds(now).filter((id) => !ballotIds(was).includes(id));
    const removed = ballotIds(was).filter((id) => !ballotIds(now).includes(id));
    if (added.length) parts.push(`ciphertexts of ballot ${added.join(', ')} stored`);
    if (removed.length) parts.push(`ciphertexts of ballot ${removed.join(', ')} gone`);
    if (now.length - was.length !== 3 * (added.length - removed.length)) parts.push(`BLIND_BALLOTS rows of this election: ${was.length} -> ${now.length}`);
  }
  if (after.seals && before.seals && before.current === after.current) {
    const was = ballotIds(ofCurrent(before.seals, after.current));
    const now = ballotIds(ofCurrent(after.seals, after.current));
    const added = now.filter((id) => !was.includes(id));
    const removed = was.filter((id) => !now.includes(id));
    if (added.length) parts.push(`seal of ballot ${added.join(', ')} stored`);
    if (removed.length) parts.push(`seal of ballot ${removed.join(', ')} gone`);
  }
  if (before.current === after.current) {
    const old = Object.fromEntries(before.roll.map((row) => [row.VOTER_ID, row]));
    for (const row of after.roll) {
      const was = old[row.VOTER_ID];
      if (!was) continue;
      if (!was.PUBLIC_KEY && row.PUBLIC_KEY) parts.push(`${row.VOTER_ID} registered a key, ballot number ${row.BALLOT_ID} reserved`);
      else if (was.PUBLIC_KEY && !row.PUBLIC_KEY) parts.push(`${row.VOTER_ID}: key cleared`);
      else if (was.PUBLIC_KEY !== row.PUBLIC_KEY) parts.push(`${row.VOTER_ID}: key replaced`);
      if (!was.VOTED_AT && row.VOTED_AT) parts.push(`${row.VOTER_ID} marked as voted`);
      if (was.VOTED_AT && !row.VOTED_AT) parts.push(`${row.VOTER_ID} no longer marked as voted`);
    }
  }
  return parts.join('; ') || 'no change in the election tables';
}

function nextNumber() {
  const dir = join(LIVE2_DIR, 'state');
  if (!existsSync(dir)) return 0;
  const numbers = readdirSync(dir).map((name) => /^(\d+)-/.exec(name)).filter(Boolean).map((match) => Number(match[1]));
  return numbers.length ? Math.max(...numbers) + 1 : 0;
}

function render(number, what, name, state) {
  const current = state.current;
  const ballots = state.ballots ? ofCurrent(state.ballots, current) : null;
  const seals = state.seals ? ofCurrent(state.seals, current) : null;
  const voted = state.roll.filter((row) => row.VOTED_AT !== null).length;
  const keyed = state.roll.filter((row) => row.PUBLIC_KEY !== null).length;
  const n = state.elections.at(-1)?.N_HEX ?? null;
  const tableOrMissing = (list, map) => (list === null ? '  the table does not exist at this moment\n' : indent(asTable(list.map(map), { maxWidth: 80 })));
  return [
    header(`Live session of Layer 2: database state ${String(number).padStart(2, '0')}`, [
      what,
      'read as the account with the DBA role; nothing is written to the database',
      `complete values: ${name}.json`,
    ]),
    `ELECTION_KEY: ${state.elections.length} election${state.elections.length === 1 ? '' : 's'}; the current one is ${current ?? 'none'}`,
    n ? `  n = ${shortHex(n, 32, 12)}   (${n.length} hexadecimal characters; sha256 ${sha256(n).slice(0, 16)})` : '  no public key: no election is open',
    '',
    `VOTER_ROLL: ${state.roll.length} voter codes, ${keyed} with a registered key, ${voted} voted`,
    '',
    indent(asTable(state.roll.map((row) => ({
      VOTER_ID: row.VOTER_ID, BALLOT_ID: row.BALLOT_ID, KEY: row.PUBLIC_KEY ? `sha256 ${sha256(row.PUBLIC_KEY).slice(0, 12)}` : null,
      REGISTERED_AT: row.REGISTERED_AT, VOTED_AT: row.VOTED_AT,
    })))),
    `BLIND_BALLOTS, election ${current}: ${ballots === null ? 'missing' : `${ballots.length} rows, ${ballotIds(ballots).length} ballots`}` +
      (state.earlier ? `; earlier elections: ${state.earlier.BALLOT_ROWS} rows, ${state.earlier.SEALS} seals` : ''),
    '',
    tableOrMissing(ballots, (row) => ({
      BALLOT_ID: row.BALLOT_ID, CANDIDATE_ID: row.CANDIDATE_ID, VOTE_ENC: short(row.VOTE_ENC), BIT_PROOF: short(row.BIT_PROOF), CREATED: row.CREATED,
    })),
    `BALLOT_SEALS, election ${current}: ${seals === null ? 'missing' : `${seals.length} seals`}`,
    '',
    tableOrMissing(seals, (row) => ({
      BALLOT_ID: row.BALLOT_ID, VOTER_ID: row.VOTER_ID, SUM_PROOF: short(row.SUM_PROOF), SIGNATURE: short(row.SIGNATURE), CREATED: row.CREATED,
    })),
    'STRUCTURE',
    '',
    indent(asTable(state.structure.tables ?? [])),
    indent(asTable(state.structure.constraints ?? [])),
    indent(asTable(state.structure.verifier ?? [])),
    'CREATED of a row is the hidden column ORABCTAB_CREATION_TIME$ of the blockchain tables, in UTC;',
    'CREATED of a table is the time of the database server.',
    '',
  ].join('\n');
}

async function snapshot(text, previous) {
  const number = nextNumber();
  const taken = new Date();
  const state = await readState();
  const what = text || describe(previous, state);
  const name = `${String(number).padStart(2, '0')}-${slug(what)}`;
  writeText(cfg, `${LIVE2}/state/${name}.txt`, render(number, what, name, state));
  writeJson(cfg, `${LIVE2}/state/${name}.json`, { number, taken: taken.toISOString(), what, ...state });
  const timeline = join(LIVE2_DIR, 'timeline.txt');
  const lines = existsSync(timeline) ? readFileSync(timeline, 'utf8') : '# Live session of Layer 2: what changed in the database, and when\n# time (UTC)                snapshot  change\n';
  writeText(cfg, `${LIVE2}/timeline.txt`, `${lines}${taken.toISOString()}  ${String(number).padStart(2, '0')}        ${what}\n`);
  console.log(`${taken.toISOString()}  snapshot ${String(number).padStart(2, '0')}: ${what}`);
  return state;
}

try {
  if (!watch) {
    await snapshot(label, null);
  } else {
    const until = Date.now() + hours * 3600 * 1000;
    let previous = await snapshot(label || 'watch started', null);
    let seen = fingerprint(previous);
    console.log(`Watching ${owner} for changes, for at most ${hours} hours. Stop with Ctrl+C.`);
    while (Date.now() < until) {
      await sleep(2000);
      let state = await readState();
      if (fingerprint(state) === seen) continue;
      // A drop and rebuild, or opening an election, is several statements: wait until two readings agree.
      for (;;) {
        await sleep(600);
        const again = await readState();
        if (fingerprint(again) === fingerprint(state)) break;
        state = again;
      }
      seen = fingerprint(state);
      previous = await snapshot('', previous);
    }
    console.log('Watch ended: time limit reached.');
  }
} finally {
  await dba.close();
}
