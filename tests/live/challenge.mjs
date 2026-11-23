// Live session, challenge round: the DBA tries to tell how each ballot voted.
//
//   node tests/live/challenge.mjs commit
//       Reads everything a DBA can read (tables, APEX session state, logs,
//       the SQL area), tries to open the ballots, writes one guess per ballot
//       and prints a commitment: the SHA-256 of the guess file. Read-only.
//       This runs BEFORE the voter reveals anything.
//
//   node tests/live/challenge.mjs reveal B,A,C,...
//       The real votes, in ballot order. Checks that the guess file still has
//       the committed hash, then writes the comparison.
//
// The attack is passive: the DBA reads, and changes nothing. What a DBA who
// writes can do is another matter, shown in H5 (forged votes, key substitution).
//
// Files, under evidence/live-session/challenge (or --out <folder under evidence>):
//   guesses.json  guesses.txt  guesses.sha256     written by "commit"
//   result.json   result.txt                      written by "reveal"
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig } from '../lib/config.mjs';
import { connect, asTable, attempt } from '../lib/db.mjs';
import { EVIDENCE, writeText, writeJson, header } from '../lib/evidence.mjs';
import * as P from '../lib/paillier.mjs';
import { LETTERS } from '../lib/app.mjs';
import { LIVE, sha256, maskIds, addressAliases, shortHex, apexSchema, readTables, readApex, sessionStart, relink } from './lib.mjs';

const argv = process.argv.slice(2);
const outAt = argv.indexOf('--out');
const OUT = outAt >= 0 ? argv[outAt + 1] : `${LIVE}/challenge`;
const [command, votes] = argv.filter((arg, index) => !arg.startsWith('--') && (outAt < 0 || index !== outAt + 1));
const SMALL_RANDOMIZERS = 256;
const indent = (text) => text.split('\n').map((line) => (line ? `  ${line}` : line)).join('\n');
const file = (name) => join(EVIDENCE, OUT, name);

// P(X >= hits) when every guess is right with probability 1/3.
function chanceOfAtLeast(hits, total) {
  const choose = (n, k) => { let c = 1; for (let i = 1; i <= k; i++) c = (c * (n - k + i)) / i; return c; };
  let sum = 0;
  for (let k = hits; k <= total; k++) sum += choose(total, k) * (1 / 3) ** k * (2 / 3) ** (total - k);
  return sum;
}

async function commit() {
  if (existsSync(file('guesses.json'))) throw new Error(`${OUT}/guesses.json already exists: the guesses are committed and are not rewritten.`);
  const cfg = loadConfig();
  const owner = cfg.schema.toUpperCase();
  const dba = await connect(cfg, 'dba');
  try {
    const apex = await apexSchema(dba);
    const started = sessionStart() ?? new Date(Date.now() - 24 * 3600 * 1000);
    const tables = await readTables(dba, owner);
    if (tables.key.length !== 1) throw new Error('No election is open.');
    const ballotIds = [...new Set(tables.ballots.map((row) => row.BALLOT_ID))].sort((a, b) => a - b);
    if (ballotIds.length === 0) throw new Error('No ballot has been cast yet.');
    const key = P.publicKeyFromN(P.fromHex(tables.key[0]));
    const { n, nSquared } = key;
    const stored = tables.ballots.map((row) => ({ ballot: row.BALLOT_ID, option: row.CANDIDATE_ID, hex: row.VOTE_ENC, c: P.fromHex(row.VOTE_ENC) }));
    const known = new Map(); // "ballot:option" -> plaintext the DBA managed to read
    const tag = (entry) => `${entry.ballot}:${entry.option}`;
    const attacks = [];
    const attack = (name, looked, found) => { attacks.push({ name, looked, found }); console.log(`  ${name}: ${found}`); };
    console.log(`\nChallenge round: ${ballotIds.length} ballots, ${stored.length} ciphertexts, read as DBA`);

    // 1. Is the vote simply written somewhere in the row?
    const columns = (await dba.execute(
      `select table_name, column_name, data_type from dba_tab_columns where owner = :owner and table_name in ('BLIND_BALLOTS', 'VOTER_ROLL', 'ELECTION_KEY') order by table_name, column_id`, { owner })).rows;
    attack('columns', `the columns of the three tables: ${columns.map((c) => `${c.TABLE_NAME}.${c.COLUMN_NAME}`).join(', ')}`,
      'no column holds a choice, and BLIND_BALLOTS has neither a voter nor a time');

    // 2. Ciphertexts that give themselves away.
    const odd = [];
    for (const entry of stored) {
      if (entry.c <= 0n || entry.c >= nSquared) odd.push(`${tag(entry)} is out of range`);
      else if (P.gcd(entry.c, n) !== 1n) odd.push(`${tag(entry)} shares a factor with n (that would factor the key)`);
      else if (entry.c % n === 1n) {
        const m = ((entry.c - 1n) / n) % n;
        odd.push(`${tag(entry)} was encrypted with a trivial randomizer and reads ${m}`);
        if (m === 0n || m === 1n) known.set(tag(entry), Number(m));
      }
    }
    attack('degenerate ciphertexts', 'every ciphertext: inside 1..n^2, coprime to n, not of the form 1 + m*n',
      odd.length ? odd.join('; ') : `none of ${stored.length}`);

    // 3. The same ciphertext twice would mean the same vote with the same randomizer.
    const groups = new Map();
    for (const entry of stored) groups.set(entry.hex, [...(groups.get(entry.hex) ?? []), tag(entry)]);
    const repeated = [...groups.values()].filter((list) => list.length > 1);
    attack('repeated ciphertexts', `${stored.length} ciphertexts compared with each other`,
      repeated.length ? repeated.map((list) => list.join(' = ')).join('; ') : `${groups.size} distinct values out of ${stored.length}`);

    // 4. Two ciphertexts built on the same randomizer differ by a factor 1 + d*n, and d is the difference of their plaintexts.
    const inverses = stored.map((entry) => P.modInv(entry.c, nSquared));
    const reused = [];
    let pairs = 0;
    for (let i = 0; i < stored.length; i++) {
      for (let j = i + 1; j < stored.length; j++) {
        pairs += 1;
        const ratio = (stored[i].c * inverses[j]) % nSquared;
        if (ratio % n !== 1n) continue;
        const d = ((ratio - 1n) / n) % n;
        reused.push(`${tag(stored[i])} and ${tag(stored[j])} share a randomizer, plaintext difference ${d === n - 1n ? '-1' : d}`);
        if (d === 1n) { known.set(tag(stored[i]), 1); known.set(tag(stored[j]), 0); }
        if (d === n - 1n) { known.set(tag(stored[i]), 0); known.set(tag(stored[j]), 1); }
      }
    }
    attack('reused randomizers', `${pairs} pairs: is c1 / c2 of the form 1 + d*n?`, reused.length ? reused.join('; ') : `none of ${pairs} pairs`);

    // 5. A weak random source would produce small randomizers: try the smallest ones.
    const unshift = P.modInv(1n + n, nSquared);
    const openings = new Map();
    for (const entry of stored) { openings.set(entry.c, [entry, 0]); openings.set((entry.c * unshift) % nSquared, [entry, 1]); }
    const opened = [];
    for (let r = 1n; r <= BigInt(SMALL_RANDOMIZERS); r++) {
      const hit = openings.get(P.modPow(r, n, nSquared));
      if (hit) { known.set(tag(hit[0]), hit[1]); opened.push(`${tag(hit[0])} = Enc(${hit[1]}) with r = ${r}`); }
    }
    attack('small randomizers', `r = 1..${SMALL_RANDOMIZERS}: does r^n open a stored ciphertext as Enc(0) or Enc(1)?`, opened.length ? opened.join('; ') : 'none');

    // 6. What the APEX engine and the database remember about the requests.
    const alias = addressAliases();
    const apexData = await readApex(dba, apex, cfg.app_id, started, alias);
    attack('APEX session state', `${apex}.WWV_FLOW_DATA for the application`,
      apexData.pageItems.length ? `${apexData.pageItems.length} items: ${apexData.pageItems.map((i) => `${i.ITEM_NAME}=${i.VALUE}`).join(', ')}` : `no page item and no application item has a value (${apexData.state.length} report paging positions)`);
    const casts = apexData.activity.filter((row) => /CAST_BALLOT/i.test(row.REQUEST ?? ''));
    // Every column of the log rows, searched for what a ballot request carried.
    const logColumns = `id, time_stamp_tz, elap, num_rows, userid, flow_id, step_id, session_id, page_mode, page_view_type, content_length, request_value,
                        sqlerrm, sqlerrm_component_type, sqlerrm_component_name, debug_page_view_id, ip_address, user_agent, ir_search`;
    const logText = JSON.stringify((await dba.execute(
      `select * from (select ${logColumns} from ${apex}.wwv_flow_activity_log1$ union all select ${logColumns} from ${apex}.wwv_flow_activity_log2$)
        where flow_id = :app and time_stamp_tz >= :since`, { app: cfg.app_id, since: started })).rows).toLowerCase();
    const ciphertextsInLog = stored.filter((entry) => logText.includes(entry.hex.slice(0, 24))).length;
    const votersInLog = tables.roll.filter((row) => logText.includes(row.VOTER_ID.toLowerCase())).length;
    const castsWithClient = casts.filter((row) => apexData.clients.has(row.SESSION)).length;
    attack('APEX activity log', `every column of the ${apexData.activity.length} requests of the application logged since ${started.toISOString()}`,
      `${casts.length} CAST_BALLOT requests with their time and session; the session gives the client address of ${castsWithClient} of them; `
      + `${ciphertextsInLog} of ${stored.length} ciphertexts and ${votersInLog} of ${tables.roll.length} voter codes appear in the log`);
    const logins = await attempt(dba,
      `select count(*) as logins from (select application, access_date from ${apex}.wwv_flow_user_access_log1$ union all select application, access_date from ${apex}.wwv_flow_user_access_log2$)
        where application = :app and access_date >= :since`, { app: cfg.app_id, since: started });
    attack('APEX login log', 'authentication attempts recorded for the application since the session started',
      logins.ok ? `${logins.rows[0].LOGINS} (the pages are public: nobody signs in)` : `not readable (${logins.error})`);
    // The debug trace exists when the voter opened the page with ?debug=LEVEL9. The DBA does not know
    // what to look for, so the traces of the ballot requests are compared with each other: whatever
    // depends on the choice has to differ between ballots.
    let debugDifferences = [];
    let debugTraceTimes = [];
    const debugColumns = 'id, page_view_id, message_level, message_timestamp, message, flow_id';
    const debug = await attempt(dba,
      `select id, page_view_id, message, to_char(sys_extract_utc(message_timestamp), 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"') as at
         from (select ${debugColumns} from ${apex}.wwv_flow_debug_messages union all select ${debugColumns} from ${apex}.wwv_flow_debug_messages2)
        where flow_id = :app and message_timestamp >= :since order by id`, { app: cfg.app_id, since: started });
    if (!debug.ok) {
      attack('APEX debug trace', 'debug messages of the application since the session started', `not readable (${debug.error})`);
    } else {
      const views = new Map(); // page view -> its messages, and the time of the first one
      for (const row of debug.rows) {
        if (!views.has(row.PAGE_VIEW_ID)) views.set(row.PAGE_VIEW_ID, { at: row.AT, messages: [] });
        views.get(row.PAGE_VIEW_ID).messages.push(String(row.MESSAGE ?? ''));
      }
      const ballotViews = [...views.values()].filter((view) => view.messages.some((m) => /ajax process CAST_BALLOT/.test(m)));
      debugTraceTimes = ballotViews.map((view) => view.at);
      const traces = ballotViews.map((view) => view.messages);
      // Remove what is known to differ and says nothing about the choice by itself: ciphertexts, voter codes, ids and timings.
      const normal = (message) => message.replace(/\s+/g, ' ')
        .replace(/[0-9a-f]{32,}/g, '<hex>')
        .replace(/VOTER-\d+/gi, '<voter>')
        .replace(/ECID=\S+/g, 'ECID=<ecid>')
        .replace(/\d+\.\d+/g, '<decimal>')
        .replace(/\d{5,}/g, '<id>');
      // The same message without any number: tells a counter that moved from a message only some ballots have.
      const shape = (message) => normal(message).replace(/\d+(?:,\d{3})*/g, '<n>');
      const lengths = [...new Set(traces.map((t) => t.length))].sort((a, b) => a - b);
      const count = (key) => { // key(message) -> how often each trace has it
        const map = new Map();
        traces.forEach((trace, index) => {
          for (const message of trace) {
            const k = key(message);
            if (!map.has(k)) map.set(k, new Array(traces.length).fill(0));
            map.get(k)[index] += 1;
          }
        });
        return map;
      };
      const uneven = (counts) => counts.some((value) => value !== counts[0]);
      const shapes = count(shape);
      // 1. A kind of message that some ballot requests have more often than others.
      for (const [message, counts] of shapes) {
        if (uneven(counts)) debugDifferences.push({ kind: 'message', message: message.slice(0, 110), values: counts });
      }
      // 2. A kind of message every request has, with numbers in it that are not the same everywhere.
      const variantsOf = new Map(); // shape -> for each request, the exact messages of that shape
      traces.forEach((trace, index) => {
        for (const message of trace) {
          const s = shape(message);
          if (uneven(shapes.get(s))) continue;
          if (!variantsOf.has(s)) variantsOf.set(s, traces.map(() => []));
          variantsOf.get(s)[index].push(normal(message));
        }
      });
      for (const [message, perRequest] of variantsOf) {
        const values = perRequest.map((list) => list.join(' / '));
        if (!uneven(values)) continue;
        const labels = [...new Set(values)];
        debugDifferences.push({ kind: 'numbers', message: message.slice(0, 110), values: values.map((value) => labels.indexOf(value) + 1), variants: labels.length });
      }
      const withCiphertext = debug.rows.filter((row) => stored.some((entry) => String(row.MESSAGE ?? '').includes(entry.hex.slice(0, 24)))).length;
      const kinds = (kind) => debugDifferences.filter((d) => d.kind === kind).length;
      attack('APEX debug trace', `${debug.rows.length} debug messages of the application since the session started; the traces of the ${traces.length} CAST_BALLOT requests among them, compared with each other after removing ciphertexts, voter codes, ids and timings`,
        traces.length === 0 ? `${debug.rows.length} messages, no trace of a CAST_BALLOT request (the voter did not turn debug on)`
          : `${withCiphertext} messages quote a stored ciphertext; ${lengths.length === 1 ? `every trace has ${lengths[0]} messages` : `the traces have ${lengths.join(' or ')} messages`}; `
            + (debugDifferences.length === 0 ? 'every message is the same in every trace: nothing in them depends on the ballot'
              : `${kinds('message')} kinds of message occur in some traces more often than in others, and ${kinds('numbers')} kinds carry numbers that differ (listed below). `
                + 'Without knowing a vote, nothing says that any of them follows the choice; the reveal checks each one'));
    }
    const sqlArea = await attempt(dba,
      `select sql_id, executions, sql_fulltext from v$sql
        where upper(sql_fulltext) like '%BLIND_BALLOTS%' and upper(sql_fulltext) like 'INSERT%' and parsing_schema_name = :owner order by last_active_time`, { owner });
    const inserts = sqlArea.ok ? sqlArea.rows : [];
    const literals = inserts.filter((row) => /[0-9a-f]{64,}/i.test(row.SQL_FULLTEXT)).length;
    const binds = inserts.length
      ? await attempt(dba, `select name, datatype_string, value_string from v$sql_bind_capture where sql_id in (${inserts.map((_, i) => `:s${i}`).join(', ')})`,
        Object.fromEntries(inserts.map((row, i) => [`s${i}`, row.SQL_ID])))
      : { ok: true, rows: [] };
    // Every captured value is sorted into what it is; anything unexpected is listed.
    const kinds = { number: 0, ciphertext: 0, 'voter code': 0, empty: 0 };
    const unexpected = [];
    for (const row of binds.ok ? binds.rows : []) {
      const value = row.VALUE_STRING;
      if (value === null) kinds.empty += 1;
      else if (/^\d{1,12}$/.test(value)) kinds.number += 1;
      else if (stored.some((entry) => entry.hex.startsWith(value))) kinds.ciphertext += 1;
      else if (/^VOTER-\d+$/.test(value)) kinds['voter code'] += 1;
      else unexpected.push(`${row.NAME} = ${shortHex(value, 24, 8)}`);
    }
    attack('SQL area and captured binds', 'the INSERT statements on BLIND_BALLOTS in V$SQL and the bind values the database captured for them',
      !sqlArea.ok || !binds.ok ? `not readable (${sqlArea.error ?? binds.error})`
        : `${inserts.length} statement(s), ${literals} with a ciphertext written as a literal; ${binds.rows.length} captured bind values: ${Object.entries(kinds).map(([kind, count]) => `${count} ${kind}`).join(', ')}`
          + (unexpected.length ? `; UNEXPECTED: ${unexpected.join(', ')}` : '; nothing else'));

    // 7. What the database kept of the past: audit records, and older versions of the rows.
    const audit = await attempt(dba,
      'select count(*) as records from unified_audit_trail where object_schema = :owner and event_timestamp >= :since', { owner, since: started });
    attack('audit trail', `unified audit records about objects of ${owner} since the session started`,
      audit.ok ? `${audit.rows[0].RECORDS}` : `not readable (${audit.error})`);
    const history = await attempt(dba,
      `select ballot_id, candidate_id, vote_enc, versions_operation as operation
         from ${owner}.blind_ballots versions between scn minvalue and maxvalue`, {});
    if (history.ok) {
      const current = new Map(stored.map((entry) => [tag(entry), entry.hex]));
      const operations = {};
      for (const row of history.rows) operations[row.OPERATION ?? 'not recorded'] = (operations[row.OPERATION ?? 'not recorded'] ?? 0) + 1;
      const different = history.rows.filter((row) => current.get(`${row.BALLOT_ID}:${row.CANDIDATE_ID}`) !== row.VOTE_ENC).length;
      attack('row history', 'every version of the BLIND_BALLOTS rows that the undo data still holds (flashback version query)',
        `${history.rows.length} row versions, by operation: ${Object.entries(operations).map(([op, count]) => `${op} ${count}`).join(', ')}; `
        + `${different} of them hold a value other than the ciphertext stored now`);
    } else {
      attack('row history', 'every version of the BLIND_BALLOTS rows that the undo data still holds (flashback version query)', `not readable (${history.error})`);
    }

    // 8. What the DBA does learn: who cast which ballot.
    const links = relink(tables.roll, tables.ballots);
    // The request that stored a ballot is the CAST_BALLOT request logged closest to the voter's VOTED_AT.
    const clientOf = (link) => {
      if (!link?.votedAt) return null;
      const at = Date.parse(link.votedAt);
      const nearest = casts.map((row) => ({ row, gap: Math.abs(Date.parse(row.AT) - at) })).sort((x, y) => x.gap - y.gap)[0];
      return nearest && nearest.gap <= 5000 ? apexData.clients.get(nearest.row.SESSION) ?? null : null;
    };
    attack('who cast which ballot', 'VOTER_ROLL ordered by VOTED_AT next to the ballot ids, and the session and client address of the CAST_BALLOT request logged at that moment',
      `${links.filter((link) => link.voter).length} of ${links.length} ballots tied to a voter code. This tells who voted when, and from which machine, not what they voted`);
    // Which ballot each traced request stored: the one whose voter was marked within five seconds of the trace.
    const requestBallots = debugTraceTimes.map((at) => {
      const nearest = links.filter((link) => link.votedAt)
        .map((link) => ({ link, gap: Math.abs(Date.parse(link.votedAt) - Date.parse(at)) }))
        .sort((x, y) => x.gap - y.gap)[0];
      return nearest && nearest.gap <= 5000 ? nearest.link.ballot : null;
    });

    // ---- one guess per ballot
    const guesses = ballotIds.map((id, index) => {
      const rows = stored.filter((entry) => entry.ballot === id).sort((a, b) => a.option - b.option);
      const ones = rows.filter((entry) => known.get(tag(entry)) === 1);
      const zeros = rows.filter((entry) => known.get(tag(entry)) === 0);
      let choice;
      let basis;
      if (ones.length === 1) { choice = ones[0].option - 1; basis = 'read from the ciphertext'; }
      else if (zeros.length === rows.length - 1) { choice = rows.find((entry) => known.get(tag(entry)) !== 0).option - 1; basis = 'the other ciphertexts were read as zero'; }
      else {
        // No information: a fixed rule anyone can recompute from the table.
        choice = rows.reduce((best, entry) => (entry.c > best.c ? entry : best)).option - 1;
        basis = 'no signal; fixed rule: the numerically largest of the three ciphertexts';
      }
      return { ballot: id, voter: links[index]?.voter ?? null, voted_at: links[index]?.votedAt ?? null, client: clientOf(links[index]), guess: LETTERS[choice], basis };
    });
    const informed = guesses.filter((g) => !g.basis.startsWith('no signal')).length;

    const committed = new Date();
    const record = {
      committed: committed.toISOString(),
      nonce: randomBytes(32).toString('hex'),
      election_key_sha256: sha256(tables.key[0]),
      ciphertexts_sha256: sha256(stored.map((entry) => entry.hex).join('\n')),
      ballots: ballotIds.length,
      attacks,
      debug_trace_differences: { request_ballots: requestBallots, differences: debugDifferences },
      informed_guesses: informed,
      guesses,
    };
    const path = writeJson(cfg, `${OUT}/guesses.json`, record);
    const commitment = sha256(readFileSync(path));
    writeText(cfg, `${OUT}/guesses.sha256`, `${commitment}  guesses.json\n`);
    writeText(cfg, `${OUT}/guesses.txt`, maskIds([
      header('Live session, challenge round: the guesses of the DBA, written before the reveal', [
        `committed: ${record.committed}`,
        `state: ${ballotIds.length} ballots, ${stored.length} ciphertexts; sha256 of the ciphertexts in table order: ${record.ciphertexts_sha256}`,
        `public key n = ${shortHex(tables.key[0], 32, 12)}`,
        'passive attack: the DBA account reads and changes nothing',
        `commitment: sha256(guesses.json) = ${commitment}`,
      ]),
      'What was tried',
      '',
      ...attacks.flatMap((a, i) => [`  ${i + 1}. ${a.name}`, `     looked at: ${a.looked}`, `     found:     ${a.found}`, '']),
      ...(debugDifferences.length ? [
        'Differences between the debug traces of the CAST_BALLOT requests',
        `  requests in the order they were logged: ${requestBallots.map((ballot, index) => `${index + 1} = ${ballot === null ? 'stored no ballot' : `ballot ${ballot}`}`).join(', ')}`,
        '',
        '  Kinds of message that some requests have more often than others (how often, request by request):',
        ...debugDifferences.filter((d) => d.kind === 'message').map((d) => `    ${d.values.join(' ')}   ${d.message}`),
        '',
        '  Kinds of message whose numbers differ (which variant each request has, request by request):',
        ...debugDifferences.filter((d) => d.kind === 'numbers').map((d) => `    ${d.values.join(' ')}   ${d.message}`),
        '',
      ] : []),
      `Guesses (${informed} of ${guesses.length} based on something read; the others follow the fixed rule and are worth a coin with three sides)`,
      '',
      indent(asTable(guesses.map((g) => ({ BALLOT: g.ballot, VOTER: g.voter, VOTED_AT: g.voted_at, CLIENT: g.client, GUESS: g.guess, BASIS: g.basis })), { maxWidth: 80 })),
      `In ballot order: ${guesses.map((g) => g.guess).join(',')}`,
      '',
    ].join('\n')));
    console.log(`\nGuesses written to evidence/${OUT}/guesses.json at ${record.committed}`);
    console.log(`commitment (sha256 of that file): ${commitment}`);
  } finally {
    await dba.close();
  }
}

function reveal() {
  if (!votes) throw new Error('Usage: node tests/live/challenge.mjs reveal B,A,C,...   (the real votes, in ballot order)');
  const cfg = loadConfig();
  const bytes = readFileSync(file('guesses.json'));
  const committed = readFileSync(file('guesses.sha256'), 'utf8').split(/\s+/)[0];
  const current = sha256(bytes);
  if (current !== committed) throw new Error(`guesses.json no longer has the committed hash (${committed} committed, ${current} now).`);
  const record = JSON.parse(bytes.toString('utf8'));
  const actual = votes.toUpperCase().split(/[\s,;]+/).filter(Boolean);
  if (actual.length !== record.guesses.length || actual.some((letter) => !LETTERS.includes(letter))) {
    throw new Error(`Expected ${record.guesses.length} votes, each one of ${LETTERS.join(', ')}; got "${votes}".`);
  }
  const rows = record.guesses.map((g, i) => ({ BALLOT: g.ballot, VOTER: g.voter, GUESS: g.guess, ACTUAL: actual[i], HIT: g.guess === actual[i] ? 'yes' : 'no' }));
  const hits = rows.filter((row) => row.HIT === 'yes').length;
  const total = rows.length;
  const chance = chanceOfAtLeast(hits, total);
  // Now that the votes are known: does any difference between the debug traces follow them?
  // "Follows" = every ballot for the same option shows the same value, and the options do not all show the same.
  const voteOf = new Map(record.guesses.map((g, i) => [g.ballot, actual[i]]));
  const traced = record.debug_trace_differences ?? { request_ballots: [], differences: [] };
  const follows = traced.differences.filter((difference) => {
    const valueOf = new Map(); // option -> the value its ballots show
    let consistent = true;
    difference.values.forEach((value, index) => {
      const choice = voteOf.get(traced.request_ballots[index]);
      if (choice === undefined) return; // a request that stored no ballot
      if (!valueOf.has(choice)) valueOf.set(choice, value);
      else if (valueOf.get(choice) !== value) consistent = false;
    });
    return consistent && new Set(valueOf.values()).size > 1;
  });
  const result = {
    revealed: new Date().toISOString(),
    committed: record.committed,
    commitment: committed,
    commitment_verified: true,
    ballots: total,
    hits,
    hit_rate: hits / total,
    baseline: 1 / 3,
    expected_hits_by_chance: total / 3,
    chance_of_this_many_or_more: chance,
    informed_guesses: record.informed_guesses,
    guesses: record.guesses.map((g) => g.guess),
    actual,
    debug_trace_differences: traced.differences.length,
    debug_trace_differences_that_follow_the_votes: follows.map((difference) => difference.message),
  };
  writeJson(cfg, `${OUT}/result.json`, result);
  writeText(cfg, `${OUT}/result.txt`, [
    header('Live session, challenge round: guesses against the real votes', [
      `guesses committed: ${record.committed}`,
      `votes revealed:    ${result.revealed}`,
      `commitment checked: sha256(guesses.json) = ${committed}, unchanged since it was committed`,
    ]),
    indent(asTable(rows)),
    `Hits: ${hits} of ${total} (${(100 * hits / total).toFixed(0)}%). Guessing one of three at random gives ${(total / 3).toFixed(1)} on average (33%).`,
    `With no information at all, ${hits} or more hits out of ${total} happens in ${(100 * chance).toFixed(1)}% of attempts.`,
    `Guesses based on something the DBA read: ${record.informed_guesses} of ${total}.`,
    '',
    traced.differences.length === 0
      ? 'Debug trace: no difference between the traces of the ballot requests was on file (see guesses.txt).'
      : `Debug trace, checked after the reveal: of the ${traced.differences.length} differences between the traces of the ballot requests listed in guesses.txt,`
        + `\n${follows.length} follow the votes (the same value for every ballot of an option, and not the same for all options).`,
    ...follows.map((difference) => `  follows the votes: ${difference.message}   (request by request: ${difference.values.join(' ')})`),
    '',
    `${total} ballots are a demonstration, not a statistical test: the test with thousands of ciphertexts is H3`,
    '(evidence/h3-indistinguishability).',
    '',
  ].join('\n'));
  console.log(`Hits: ${hits} of ${total}. By chance, ${hits} or more: ${(100 * chance).toFixed(1)}%. Written to evidence/${OUT}/result.txt`);
}

if (command === 'commit') await commit();
else if (command === 'reveal') reveal();
else throw new Error('Usage: node tests/live/challenge.mjs commit | reveal B,A,C,...');
