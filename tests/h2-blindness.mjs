// H2 - Blindness.
//
//   "No vote and no private key ever exists server side."
//
// How do you search for a key that, by design, nobody but one browser tab
// knows? The test records the random bytes that tab draws (an instrument
// injected through the automation channel, not part of the application) and
// replays key generation with them. If the replay yields the modulus that the
// database published, the test now holds p, q, lambda and mu. The same trick
// gives the randomizer r of every ciphertext a voter sends, and r opens a vote.
//
// Which numbers count as secrets is not obvious, and the first version of this
// test got it wrong twice (see tests/lib/leaks.mjs): the upper half of phi(n)
// is public, and r^n is the ciphertext itself whenever the vote is zero.
//
// With the secrets in hand, every place a DBA could look is searched for them,
// whole or in fragments of 20 characters, in hexadecimal, decimal and base64:
//
//   network     everything the two browsers sent and received (HAR)
//   database    every table of the schema, its source code
//   APEX        session state, the LEVEL9 debug trace, activity and access logs
//   instance    SQL area, captured bind values, audit trail, alert log
//   browser     storage, cookies and form fields of the authority tab
//
// The search itself runs here in Node, on text already fetched: a secret is
// never sent to the database in order to look for it.
//
// Not inspected: the log files of ORDS (see the note in the result).
//
//   node tests/h2-blindness.mjs [--seed <n>]
import os from 'node:os';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import * as P from './lib/paillier.mjs';
import { loadConfig, ROOT } from './lib/config.mjs';
import { connect, attempt, asTable } from './lib/db.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser, castInBrowser, tallyInBrowser, LETTERS } from './lib/app.mjs';
import { OPTIONS, voterCode, countChoices, seededRandom } from './lib/election.mjs';
import { LeakScanner, privateKeySecrets, selfTest } from './lib/leaks.mjs';
import { writeText, writeJson, header } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h2-blindness';
const REGISTERED = 12;
const BALLOTS = 9;
const STATIC_FILES = join(ROOT, 'app', 'apexlang', 'shared-components', 'static-files', 'blindfold');

// Session ids, page view ids and salts are long decimal numbers. They are not
// secrets of the election, but they do not belong in a public file either.
// Two precautions. The lookarounds keep the pattern off the digits inside a
// lower-case hexadecimal string: a ciphertext must come out untouched. And a
// percent escape such as %22 is kept whole, so that its two digits are never
// taken for the start of an id in URL-encoded text.
const maskIds = (text) => String(text)
  .split(/(%[0-9A-Fa-f]{2})/)
  .map((part, index) => (index % 2 ? part : part.replace(/(?<![0-9a-f])\d{12,}(?![0-9a-f])/g, '<id>')))
  .join('');
const fmt = (totals) => totals.map((v, i) => `${LETTERS[i]}=${v}`).join('  ');
const indent = (text, pad = '  ') => String(text).split('\n').map((l) => (l ? pad + l : l)).join('\n');

// ------------------------------------------------------------- the instrument

// Runs inside the page before any script of the application. Records the bytes
// that paillier.js draws from the platform random source.
function entropyTap() {
  const original = Crypto.prototype.getRandomValues;
  const tape = [];
  let other = 0;
  Crypto.prototype.getRandomValues = function tapped(array) {
    const filled = original.call(this, array);
    if ((new Error().stack || '').includes('paillier.js')) {
      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      let hex = '';
      for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
      tape.push(hex);
    } else {
      other += 1;
    }
    return filled;
  };
  window.__bfEntropy = { tape, otherCalls: () => other };
}

// A random source that hands out the recorded bytes, in order.
function tapeReader(tape, what) {
  let next = 0;
  const read = (length) => {
    if (next >= tape.length) throw new Error(`Replay of ${what}: more random bytes are needed than the browser drew.`);
    const hex = tape[next++];
    if (hex.length !== length * 2) throw new Error(`Replay of ${what} is out of step at draw ${next}: the browser drew ${hex.length / 2} bytes, the replay asks for ${length}.`);
    return Uint8Array.from(Buffer.from(hex, 'hex'));
  };
  read.used = () => next;
  return read;
}

// ------------------------------------------------------------------- network

const TEXTUAL = /^(text\/|application\/(json|javascript|x-javascript|ecmascript|xml|xhtml\+xml|x-www-form-urlencoded))|\+json|\+xml/i;

function bodyOf(content) {
  if (!content || content.text === undefined) return { text: '', textual: true, bytes: 0, sha256: null };
  const buffer = content.encoding === 'base64' ? Buffer.from(content.text, 'base64') : Buffer.from(content.text, 'utf8');
  const textual = TEXTUAL.test(content.mimeType ?? '');
  return { text: textual ? buffer.toString('utf8') : '', textual, bytes: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex') };
}

const formFields = (entry) => {
  const data = entry.request.postData;
  return data && (data.mimeType ?? '').includes('x-www-form-urlencoded') ? [...new URLSearchParams(data.text ?? '')] : [];
};

// Everything one request carries, raw and decoded, as text for the scanner.
function requestText(entry) {
  const { request } = entry;
  const lines = [`${request.method} ${request.url}`];
  try {
    lines.push(decodeURIComponent(request.url));
  } catch {
    // not decodable: the raw form above is scanned anyway
  }
  for (const h of request.headers) lines.push(`${h.name}: ${h.value}`);
  const body = request.postData?.text ?? '';
  if (body) lines.push('', body, ...formFields(entry).map(([k, v]) => `${k}=${v}`));
  return lines.join('\n');
}

function responseText(entry) {
  const { response } = entry;
  return [`${response.status} ${response.statusText}`, ...response.headers.map((h) => `${h.name}: ${h.value}`), '', bodyOf(response.content).text].join('\n');
}

const maskCookies = (headers) => headers.map((h) => (/^(cookie|set-cookie)$/i.test(h.name)
  ? { name: h.name, value: h.value.replace(/=[^;]*/g, (m, offset, all) => (/^\s*(path|domain|expires|max-age|samesite)\b/i.test(all.slice(all.lastIndexOf(';', offset) + 1, offset)) ? m : '=<masked>')) }
  : h));

// The HAR that goes into the evidence: complete for requests, bodies of static
// files replaced by their SHA-256, cookie values and session ids masked.
function reducedHar(entries, origin) {
  const har = {
    log: {
      version: '1.2',
      creator: { name: 'APEX Blindfold tests/h2-blindness.mjs, reduced from a Playwright HAR', version: '1' },
      comment: 'Request bodies are complete. Response bodies are kept for pages and Ajax calls; static files carry their SHA-256 instead. Cookie values, session ids and the host are masked.',
      entries: entries.map((entry) => {
        const body = bodyOf(entry.response.content);
        const keep = /json|html/i.test(entry.response.content?.mimeType ?? '');
        return {
          startedDateTime: entry.startedDateTime,
          time: entry.time,
          request: {
            method: entry.request.method,
            url: entry.request.url,
            httpVersion: entry.request.httpVersion,
            headers: maskCookies(entry.request.headers),
            queryString: entry.request.queryString,
            ...(entry.request.postData ? { postData: { mimeType: entry.request.postData.mimeType, text: entry.request.postData.text } } : {}),
            bodySize: entry.request.bodySize,
          },
          response: {
            status: entry.response.status,
            statusText: entry.response.statusText,
            headers: maskCookies(entry.response.headers),
            content: { size: body.bytes, mimeType: entry.response.content?.mimeType, ...(keep ? { text: body.text } : { comment: `sha256:${body.sha256}` }) },
          },
        };
      }),
    },
  };
  // Mask the text values, never the serialized JSON: a number like 10.123456789012 is not an id.
  const masked = (value) => {
    if (typeof value === 'string') return maskIds(value.split(origin).join('http://blindfold.invalid'));
    if (Array.isArray(value)) return value.map(masked);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, masked(v)]));
    return value;
  };
  return JSON.stringify(masked(har), null, 1);
}

// ------------------------------------------------------------------ database

// Rows sorted by their first two columns, for display only.
const inOrder = (rows) => [...rows].sort((a, b) => {
  const [x, y] = [Object.values(a), Object.values(b)];
  for (let i = 0; i < Math.min(2, x.length); i++) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  }
  return 0;
});
const rowsText = (rows) => rows.map((row) => Object.entries(row).map(([k, v]) => `${k}=${v instanceof Date ? v.toISOString() : v ?? ''}`).join(' | ')).join('\n');
const dbNow = async (conn) => new Date((await conn.execute('select systimestamp as t from dual')).rows[0].T.getTime() - 2000);

async function fetchTables(dba, owner) {
  const names = (await dba.execute('select table_name from dba_tables where owner = :o order by table_name', { o: owner })).rows.map((r) => r.TABLE_NAME);
  const tables = [];
  for (const name of names) {
    const rows = (await dba.execute(`select * from ${owner}."${name}"`)).rows;
    tables.push({ name, rows, text: rowsText(rows) });
  }
  return tables;
}

async function fetchSessionState(dba, apex, appId, sessions) {
  const binds = Object.fromEntries(sessions.map((s, i) => [`s${i}`, s]));
  const list = sessions.map((_, i) => `:s${i}`).join(', ') || 'null';
  // Everything APEX keeps for the sessions of this run, and for any other session of the application.
  // An entry without an item name whose id is a report region is the paging position of that report.
  const all = (await dba.execute(
    `select d.flow_instance, d.flow_id, d.item_id, d.item_name, p.plug_name as report_region, d.is_encrypted, d.item_value_vc2, d.item_value_clob
       from ${apex}.wwv_flow_data d
       left join ${apex}.wwv_flow_page_plugs p on p.id = d.item_id and p.flow_id = d.flow_id
      where d.flow_id = :app or d.flow_instance in (${list})
      order by d.flow_instance, d.item_id`, { app: appId, ...binds })).rows;
  const isPaging = (row) => row.ITEM_NAME === null && row.REPORT_REGION !== null && /^\d+(:\d+){3}$/.test(row.ITEM_VALUE_VC2 ?? '') && row.ITEM_VALUE_CLOB === null;
  const items = all.filter((row) => sessions.includes(row.FLOW_INSTANCE));
  const others = all.filter((row) => !sessions.includes(row.FLOW_INSTANCE));
  const rows = (await dba.execute(
    `select id, username, to_char(created_on, 'YYYY-MM-DD HH24:MI:SS') as created_on, remote_addr, debug_level, on_new_instance_fired_for
       from ${apex}.wwv_flow_sessions$ where id in (${list}) order by 3`, binds)).rows;
  const collections = await attempt(dba, `select count(*) as collections from ${apex}.wwv_flow_collections$ where session_id in (${list})`, binds);
  return {
    all,
    items,
    others,
    pageItems: all.filter((row) => !isPaging(row)),
    sessions: rows,
    collections: collections.ok ? collections.rows[0].COLLECTIONS : `not readable (${collections.error})`,
  };
}

async function fetchDebug(dba, apex, appId, since) {
  const columns = 'id, page_view_id, page_id, session_id, message_level, message_timestamp, message, call_stack, flow_id';
  return (await dba.execute(
    `select id, page_view_id, page_id, session_id, message_level, message, call_stack
       from (select ${columns} from ${apex}.wwv_flow_debug_messages union all select ${columns} from ${apex}.wwv_flow_debug_messages2)
      where flow_id = :app and message_timestamp >= :since order by id`, { app: appId, since })).rows;
}

async function fetchActivity(dba, apex, appId, since) {
  const columns = `id, time_stamp_tz, elap, num_rows, userid, flow_id, step_id, session_id, page_mode, page_view_type, content_length, request_value,
                   sqlerrm, sqlerrm_component_type, sqlerrm_component_name, debug_page_view_id, ip_address, user_agent, ir_search`;
  return (await dba.execute(
    `select * from (select ${columns} from ${apex}.wwv_flow_activity_log1$ union all select ${columns} from ${apex}.wwv_flow_activity_log2$)
      where flow_id = :app and time_stamp_tz >= :since order by id`, { app: appId, since })).rows;
}

async function fetchAccess(dba, apex, appId, since) {
  const columns = 'login_name, authentication_method, application, owner, access_date, ip_address, remote_user, authentication_result, custom_status_text';
  return (await dba.execute(
    `select * from (select ${columns} from ${apex}.wwv_flow_user_access_log1$ union all select ${columns} from ${apex}.wwv_flow_user_access_log2$)
      where application = :app and access_date >= :since`, { app: appId, since })).rows;
}

async function fetchSqlArea(dba, owner, apex, since) {
  return (await dba.execute(
    `select sql_id, parsing_schema_name, module, sql_fulltext from v$sql
      where last_active_time >= :since and parsing_schema_name in (:owner, :apex, 'APEX_PUBLIC_USER', 'ORDS_PUBLIC_USER')`, { since, owner, apex })).rows;
}

const fetchBinds = async (dba, since) => (await dba.execute(
  'select sql_id, name, datatype_string, value_string from v$sql_bind_capture where last_captured >= :since', { since })).rows;

// ---------------------------------------------------------------------- test

export async function run(cfg, args) {
  const report = new Report('H2', 'Blindness: no vote and no private key ever exists server side', DIR);
  const random = seededRandom(args.seed);
  const owner = cfg.schema.toUpperCase();
  if (!/^[A-Z][A-Z0-9_$#]*$/.test(owner)) throw new Error('Unexpected schema name.');
  const origin = new URL(cfg.ords_base).origin;
  const tmp = mkdtempSync(join(os.tmpdir(), 'blindfold-h2-'));
  const dba = await connect(cfg, 'dba');
  const browser = await launchBrowser(cfg);
  const viewport = { width: 1440, height: 900 };

  try {
    const apex = (await dba.execute("select schema from dba_registry where comp_id = 'APEX'")).rows[0].SCHEMA;
    const started = await dbNow(dba);

    // ---- 1. a monitored election, driven through the real pages with debug on
    const newContext = async (name) => {
      const context = await browser.newContext({ viewport, recordHar: { path: join(tmp, `${name}.har`), content: 'embed' } });
      await context.addInitScript(entropyTap);
      const seen = [];
      context.on('request', (request) => seen.push(request.url()));
      return { name, context, seen };
    };
    const authority = await newContext('authority');
    const voters = await newContext('voter');

    const authorityPage = await authority.context.newPage();
    watch(authorityPage, 'authority');
    await openElectionInBrowser(authorityPage, cfg, REGISTERED, { debug: true });

    const voterPage = await voters.context.newPage();
    watch(voterPage, 'voter');
    await voterPage.goto(appUrl(cfg, 'vote', '?debug=LEVEL9'), { waitUntil: 'networkidle' });
    await voterPage.waitForSelector('.bf-option');
    const cast = [];
    for (let i = 0; i < BALLOTS; i++) {
      const choice = Math.floor(random() * OPTIONS);
      cast.push({ voter: voterCode(i), choice, ballotId: await castInBrowser(voterPage, voterCode(i), choice) });
    }
    const truth = countChoices(cast.map((c) => c.choice));
    const shown = await tallyInBrowser(authorityPage);
    report.check('a monitored election ran end to end in two browsers, with debug at LEVEL9', shown.totals.join() === truth.join() && !shown.flagged,
      `${BALLOTS} ballots cast on the Vote page, tally decrypted on the Tally page: ${fmt(shown.totals)}`);

    // ---- 2. what the browsers hold, read through the automation channel
    const clientState = async ({ context }, page) => ({
      ...(await page.evaluate(async () => ({
        localStorage: Object.fromEntries(Object.entries(localStorage)),
        sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
        documentCookie: document.cookie,
        indexedDB: indexedDB.databases ? (await indexedDB.databases()).map((d) => d.name) : [],
        cacheStorage: 'caches' in window ? await caches.keys() : [],
        formFields: Array.from(document.querySelectorAll('input, textarea, select')).map((f) => ({ id: f.id, name: f.getAttribute('name'), type: f.type, value: f.value })),
        html: document.documentElement.outerHTML,
      }))),
      storageState: await context.storageState(),
      tape: await page.evaluate(() => window.__bfEntropy.tape),
      otherRandomCalls: await page.evaluate(() => window.__bfEntropy.otherCalls()),
    });
    const authorityState = await clientState(authority, authorityPage);
    const voterState = await clientState(voters, voterPage);

    // The third page of the application, in the voter's browser session: "What the database sees".
    const ledgerPage = await voters.context.newPage();
    watch(ledgerPage, 'ledger');
    await ledgerPage.goto(appUrl(cfg, 'ledger', '?debug=LEVEL9'), { waitUntil: 'networkidle' });
    await ledgerPage.waitForFunction(() => Array.from(document.querySelectorAll('#bf-ballots td')).some((cell) => cell.textContent.trim().length > 100));
    await authority.context.close(); // closing a context writes its HAR
    await voters.context.close();
    const har = {
      authority: JSON.parse(readFileSync(join(tmp, 'authority.har'), 'utf8')).log.entries,
      voter: JSON.parse(readFileSync(join(tmp, 'voter.har'), 'utf8')).log.entries,
    };

    // ---- 3. replay: the test learns the secrets it is going to look for
    const publishedN = (await dba.execute(`select n_hex from ${owner}.election_key`)).rows[0].N_HEX;
    const keyReader = tapeReader(authorityState.tape, 'key generation');
    const replayed = await P.generateKeyPair(2048, { random: keyReader });
    const { publicKey, privateKey } = replayed;
    const keyKnown = P.toHex(publicKey.n) === publishedN && keyReader.used() === authorityState.tape.length;
    report.check('the test knows the private key: key generation replayed from the bytes the tab drew', keyKnown,
      `${authorityState.tape.length} draws replayed, modulus equals ELECTION_KEY.n_hex: ${P.toHex(publicKey.n) === publishedN}`);
    if (!keyKnown) {
      return report.close(cfg, { verdict: 'PARTIAL', statement: 'The private key could not be reconstructed, so there was nothing to search for. No conclusion.', mode: { quick: args.quick, seed: args.seed } });
    }

    const stored = (await dba.execute(`select ballot_id, candidate_id, vote_enc from ${owner}.blind_ballots order by ballot_id, candidate_id`)).rows;
    const ballotPosts = har.voter.filter((e) => formFields(e).some(([k, v]) => k === 'p_request' && v === 'APPLICATION_PROCESS=CAST_BALLOT'));
    const randomizerReader = tapeReader(voterState.tape, 'the ballots');
    const randomizers = [];
    let ciphertextsExplained = 0;
    for (const [index, ballot] of cast.entries()) {
      const sent = formFields(ballotPosts[index] ?? { request: {} }).filter(([k]) => k === 'f01').map(([, v]) => v);
      for (let option = 0; option < OPTIONS; option++) {
        const r = P.randomUnit(publicKey.n, randomizerReader);
        const rn = P.modPow(r, publicKey.n, publicKey.nSquared);
        const expected = P.ciphertextToHex(publicKey, P.encryptWithRandomizer(publicKey, option === ballot.choice ? 1n : 0n, rn));
        const row = stored.find((s) => s.BALLOT_ID === ballot.ballotId && s.CANDIDATE_ID === option + 1);
        if (row?.VOTE_ENC === expected && sent[option] === expected) ciphertextsExplained += 1;
        randomizers.push({ name: `randomizer r of ballot ${ballot.ballotId}, option ${LETTERS[option]}`, value: r });
      }
    }
    const allExplained = ciphertextsExplained === BALLOTS * OPTIONS && stored.length === BALLOTS * OPTIONS && randomizerReader.used() === voterState.tape.length;
    report.check('the test knows the randomizer of every ciphertext: each one recomputed bit for bit', allExplained,
      `${ciphertextsExplained}/${BALLOTS * OPTIONS} ciphertexts equal (1 + m*n) * r^n mod n^2 for the choice made and the bytes drawn, in the request and in BLIND_BALLOTS`);

    // ---- 4. the scanner, and proof that it can find something
    const secrets = [...privateKeySecrets(privateKey), ...randomizers];
    const ciphertexts = stored.map((row) => P.ciphertextFromHex(publicKey, row.VOTE_ENC));
    const scanner = new LeakScanner(secrets, { publicKey, privateKey, ciphertexts });
    const controls = selfTest(publicKey, privateKey, randomBytes(600).toString('hex'), { r: randomizers[0].value, ciphertext: ciphertexts[0] });
    const controlsOk = controls.every((c) => c.detected === c.expectDetected);
    report.check('scanner controls: every planted leak is found, clean data is not flagged', controlsOk,
      `${controls.filter((c) => c.expectDetected && c.detected).length}/${controls.filter((c) => c.expectDetected).length} planted leaks found, ${controls.filter((c) => !c.expectDetected && c.detected).length} false alarms`);

    const groups = {};
    const scan = (group, label, text) => {
      const source = scanner.scan(label, text);
      (groups[group] ??= []).push(source);
      return source;
    };
    const hits = (group) => (groups[group] ?? []).reduce((n, s) => n + s.windowHits.length + s.structureHits.length, 0);

    // ---- 5. network: what left the browsers, and what came back
    for (const name of ['authority', 'voter']) {
      scan('network', `network: ${har[name].length} requests sent by the ${name} browser`, har[name].map(requestText).join('\n\n'));
      const textual = har[name].filter((e) => bodyOf(e.response.content).textual);
      scan('network', `network: ${textual.length} responses received by the ${name} browser`, textual.map(responseText).join('\n\n'));
    }
    const allEntries = [...har.authority, ...har.voter];
    const binaryResponses = allEntries.filter((e) => !bodyOf(e.response.content).textual);
    report.check('nothing the browsers sent or received holds a secret', hits('network') === 0,
      `${allEntries.length} requests with headers and bodies; ${allEntries.length - binaryResponses.length} text responses (${binaryResponses.length} fonts and images not searched)`);

    const origins = [...new Set(allEntries.map((e) => new URL(e.request.url).origin))];
    const seenCount = authority.seen.length + voters.seen.length;
    report.check('every request went to one origin, and the HAR has all of them', origins.length === 1 && origins[0] === origin && seenCount === allEntries.length,
      `${origins.length} origin, ${allEntries.length} requests in the HAR, ${seenCount} seen by the browser`);

    // The ballot requests: which bytes can depend on the choice?
    const anatomy = ballotPosts.map((entry) => {
      const fields = formFields(entry);
      return {
        fields,
        voter: fields.find(([k]) => k === 'x01')?.[1],
        ciphertexts: fields.filter(([k]) => k === 'f01').map(([, v]) => v),
        rest: JSON.stringify(fields.filter(([k]) => k !== 'x01' && k !== 'f01')),
        names: [...new Set(fields.map(([k]) => k))].sort().join(' '),
        headers: JSON.stringify(entry.request.headers.filter((h) => !/^content-length$/i.test(h.name)).map((h) => [h.name.toLowerCase(), h.value]).sort()),
        bodyBytes: Buffer.byteLength(entry.request.postData.text),
        url: entry.request.url,
        response: bodyOf(entry.response.content).text.replace(/\s+/g, ''),
      };
    });
    const first = anatomy[0];
    const uniform = anatomy.length === BALLOTS && anatomy.every((a) => a.rest === first.rest && a.names === first.names && a.headers === first.headers && a.url === first.url
      && a.bodyBytes === first.bodyBytes && a.ciphertexts.length === OPTIONS && a.ciphertexts.every((c) => new RegExp(`^[0-9a-f]{${publicKey.hexLength}}$`).test(c)));
    report.check('ballot requests differ only in the voter code and in three ciphertexts of fixed length', uniform,
      `${anatomy.length} CAST_BALLOT requests, fields "${first?.names}", ${first?.bodyBytes} bytes each whatever the choice`);

    const served = allEntries.filter((e) => /\/blindfold\/[a-z]+\.js(\?|$)/.test(e.request.url) && e.response.status === 200);
    const scripts = [...new Set(served.map((e) => new URL(e.request.url).pathname.split('/').pop()))].sort();
    const normalized = (buffer) => createHash('sha256').update(buffer.toString('utf8').replace(/\r\n/g, '\n')).digest('hex');
    const scriptRows = scripts.map((name) => {
      const entry = served.find((e) => new URL(e.request.url).pathname.endsWith(`/${name}`));
      const content = entry.response.content;
      const servedHash = normalized(content.encoding === 'base64' ? Buffer.from(content.text, 'base64') : Buffer.from(content.text ?? '', 'utf8'));
      const localHash = normalized(readFileSync(join(STATIC_FILES, name)));
      return { FILE: name, SHA256_SERVED: servedHash.slice(0, 16), SHA256_REPOSITORY: localHash.slice(0, 16), SAME: servedHash === localHash ? 'yes' : 'NO' };
    });
    report.check('the JavaScript the browsers ran is the JavaScript of this repository', scriptRows.length >= 5 && scriptRows.every((r) => r.SAME === 'yes'),
      `${scriptRows.filter((r) => r.SAME === 'yes').length}/${scriptRows.length} files identical: ${scripts.join(', ')}`);

    // ---- 6. database: every table of the schema, and its source code
    const tables = await fetchTables(dba, owner);
    for (const table of tables) scan('tables', `table ${table.name} (${table.rows.length} rows)`, table.text);
    const source = (await dba.execute('select name, type, line, text from dba_source where owner = :o order by name, type, line', { o: owner })).rows;
    scan('tables', `source code of the schema (${source.length} lines)`, source.map((s) => s.TEXT).join(''));
    report.check('no table of the schema holds a secret', hits('tables') === 0,
      `${tables.length} tables read in full as DBA: ${tables.map((t) => `${t.name} ${t.rows.length}`).join(', ')}`);

    // ---- 7. APEX session state
    const sessions = [...new Set(allEntries.flatMap((e) => formFields(e).filter(([k]) => k === 'p_instance').map(([, v]) => Number(v))))];
    const state = await fetchSessionState(dba, apex, cfg.app_id, sessions);
    scan('session state', `APEX session state (${state.all.length} entries, ${state.sessions.length} sessions of this run)`, `${rowsText(state.all)}\n${rowsText(state.sessions)}`);
    report.check('APEX session state holds no page item and no secret: only the paging position of two reports', state.pageItems.length === 0 && state.sessions.length === sessions.length && hits('session state') === 0,
      `${state.pageItems.length} page or application items; ${state.items.length} paging entries for the ${state.sessions.length} sessions of this run (${state.items.map((i) => `${i.REPORT_REGION} ${i.ITEM_VALUE_VC2}`).join(', ') || 'none'}), ${state.others.length} of the same kind left by other sessions; collections: ${state.collections}`);

    // ---- 8. debug trace
    const debug = await fetchDebug(dba, apex, cfg.app_id, started);
    scan('debug', `APEX debug trace (${debug.length} messages)`, debug.map((d) => `${d.MESSAGE ?? ''}\n${d.CALL_STACK ?? ''}`).join('\n'));
    const views = new Set(debug.map((d) => d.PAGE_VIEW_ID));
    const ballotViews = [...new Set(debug.filter((d) => /ajax process CAST_BALLOT/.test(d.MESSAGE ?? '')).map((d) => d.PAGE_VIEW_ID))];
    report.check('the LEVEL9 debug trace holds no secret', debug.length > 1000 && ballotViews.length === BALLOTS && hits('debug') === 0,
      `${debug.length} messages in ${views.size} page views, ${ballotViews.length} of them CAST_BALLOT requests`);

    // ---- 9. logs and instance
    const activity = await fetchActivity(dba, apex, cfg.app_id, started);
    scan('logs', `APEX activity log (${activity.length} rows)`, rowsText(activity));
    const access = await fetchAccess(dba, apex, cfg.app_id, started);
    scan('logs', `APEX access log (${access.length} rows)`, rowsText(access));
    const sqlArea = await fetchSqlArea(dba, owner, apex, started);
    scan('logs', `SQL area, V$SQL (${sqlArea.length} statements)`, sqlArea.map((s) => s.SQL_FULLTEXT).join('\n'));
    const binds = await fetchBinds(dba, started);
    scan('logs', `captured binds, V$SQL_BIND_CAPTURE (${binds.length} values)`, rowsText(binds));
    const audit = await attempt(dba, 'select dbusername, action_name, object_name, sql_text, sql_binds from unified_audit_trail where event_timestamp >= :since', { since: started });
    if (audit.ok) scan('logs', `unified audit trail (${audit.rows.length} records)`, rowsText(audit.rows));
    const alert = await attempt(dba, 'select message_text from v$diag_alert_ext where originating_timestamp >= :since', { since: started });
    if (alert.ok) scan('logs', `database alert log (${alert.rows.length} lines)`, rowsText(alert.rows));
    report.check('APEX logs, SQL area, captured binds, audit trail and alert log hold no secret', activity.length >= BALLOTS && hits('logs') === 0,
      `${activity.length} activity rows, ${access.length} logins, ${sqlArea.length} statements, ${binds.length} captured binds, audit ${audit.ok ? audit.rows.length : 'not readable'}, alert ${alert.ok ? alert.rows.length : 'not readable'}`);

    // ---- 10. the authority tab itself
    for (const [name, client] of [['authority', authorityState], ['voter', voterState]]) {
      const { html, tape, ...rest } = client;
      scan('browser', `browser: storage, cookies and form fields of the ${name} tab`, JSON.stringify(rest));
      scan('browser', `browser: page HTML of the ${name} tab`, html);
    }
    const stores = (c) => Object.keys(c.localStorage).length + Object.keys(c.sessionStorage).length + c.indexedDB.length + c.cacheStorage.length;
    report.check('storage, cookies, form fields and HTML of the tabs hold no secret', hits('browser') === 0,
      `authority tab: ${Object.keys(authorityState.localStorage).length} localStorage and ${Object.keys(authorityState.sessionStorage).length} sessionStorage entries, ${authorityState.storageState.cookies.length} cookies, ${authorityState.formFields.length} form fields`);

    // ---- 11. canary: would the same search have found a secret, had one been sent?
    const canary = await runCanary({ cfg, browser, dba, owner, apex, tmp, viewport });
    report.check('canary: a secret smuggled into a ballot is found by the same search', canary.rows.find((r) => r.id === 'table').found && canary.rows.find((r) => r.id === 'network').found,
      canary.rows.map((r) => `${r.id} ${r.found ? 'found' : 'not recorded'}`).join(', '));

    report.note('ORDS log files were not read: the lab account has no access to the ORDS configuration or console. ORDS can only log what it receives, and every byte it received is in the HAR above.');
    report.note(`getRandomValues calls from scripts other than paillier.js: ${authorityState.otherRandomCalls} (authority), ${voterState.otherRandomCalls} (voter).`);

    // ---- evidence
    const findings = scanner.findings;
    const fileHeader = (title, lines = []) => header(title, [`election: ${REGISTERED} registered voters, ${BALLOTS} ballots cast in the browser, 2048-bit key, debug LEVEL9`, ...lines]);

    writeText(cfg, report.file(`${DIR}/scan-summary.txt`), [
      fileHeader('H2: where the test looked for a vote or a private key, and what it found', [
        `browser: ${browser.bfChannel} ${browser.version()} (headless)`,
        `secrets searched for: ${secrets.length} numbers (p, q, lambda, mu, p-1, q-1, phi(n), p+q; the randomizer r of ${BALLOTS * OPTIONS} ciphertexts)`,
        `search windows: ${scanner.windowCount} fragments of 20 characters, in hex, little-endian hex, decimal, base64 and base64url`,
        `   (${scanner.publicWindowsDropped} fragments left out because they also occur in n, n^2 or n / gcd(p-1, q-1): the upper half of phi(n) and lambda is public)`,
        'long numbers: every hexadecimal run of 48+ characters and decimal run of 60+ digits, tested against the public key',
        '   (shares a factor with n? multiple of lambda? inverse of lambda? n-th root that opens a stored ciphertext?)',
      ]),
      'How the test knows the secrets',
      `  key generation: ${authorityState.tape.length} draws of random bytes recorded in the authority tab and replayed in Node;`,
      `                  the replay produced the modulus published in ELECTION_KEY: ${keyKnown ? 'yes' : 'NO'}`,
      `  ballots:        ${voterState.tape.length} draws recorded in the voter tab; ${ciphertextsExplained}/${BALLOTS * OPTIONS} stored ciphertexts recomputed bit for bit`,
      '',
      ...scanner.reportLines(),
      '',
      `findings: ${findings.length}`,
      ...findings.map((f) => `  ${f.source}: ${f.what} [${f.detector}] ${maskIds(f.excerpt)}`),
      '',
      'Not inspected',
      '  ORDS log files and console: no access from the lab account. ORDS receives what the HAR shows, nothing else.',
      '  Redo, undo and flashback data: they hold past images of the tables above.',
      '  Operating system: memory of the database and ORDS processes, swap, network captures.',
      '  Timing and traffic analysis.',
      '',
    ].join('\n'));

    writeText(cfg, report.file(`${DIR}/tables.txt`), [
      fileHeader('H2: every table of the schema, read as DBA', [`connected as the account with the DBA role, select * from ${owner.toLowerCase()}.<table>`]),
      ...tables.flatMap((t) => [`${owner}.${t.name}: ${t.rows.length} rows${t.rows.length > 12 ? ' (first 12 shown)' : ''}`, '', indent(asTable(inOrder(t.rows).slice(0, 12), { maxWidth: 48 })), '']),
    ].join('\n'));

    writeText(cfg, report.file(`${DIR}/session-state.txt`), maskIds([
      fileHeader('H2: APEX session state', [
        `${apex}.WWV_FLOW_DATA holds the value of every page and application item of every session.`,
        'The application has no page item and no application item: the voter code and the options are plain HTML,',
        'never submitted. What APEX does keep is the paging position of the two reports on the page',
        '"What the database sees": first row, rows per page, rows found, and a fourth field, keyed by the report region.',
      ]),
      `SQL> select d.*, p.plug_name as report_region from ${apex.toLowerCase()}.wwv_flow_data d left join ${apex.toLowerCase()}.wwv_flow_page_plugs p on p.id = d.item_id and p.flow_id = d.flow_id`,
      `      where d.flow_id = ${cfg.app_id} or d.flow_instance in (<the ${sessions.length} sessions of this run>);`,
      '',
      `Entries of the ${sessions.length} sessions of this run: ${state.items.length}`,
      '',
      indent(asTable(state.items.map((row) => ({ ...row, FLOW_INSTANCE: '<id>', ITEM_ID: '<id>' })))),
      `Entries of other sessions of the application still stored: ${state.others.length} (${[...new Set(state.others.map((row) => `${row.REPORT_REGION ?? row.ITEM_NAME} ${row.ITEM_VALUE_VC2}`))].join(', ') || 'none'})`,
      `Page items or application items with a value, in any session: ${state.pageItems.length}`,
      '',
      `Sessions of the two browsers (${apex}.WWV_FLOW_SESSIONS$, cookie and salt columns left out):`,
      '',
      indent(asTable(state.sessions.map((row) => ({ ...row, ID: '<id>' })))),
      `APEX collections owned by these sessions: ${state.collections}`,
      '',
    ].join('\n')));

    const levels = [...new Set(debug.map((d) => d.MESSAGE_LEVEL))].sort((a, b) => a - b);
    const oneBallot = debug.filter((d) => d.PAGE_VIEW_ID === ballotViews[0]);
    writeText(cfg, report.file(`${DIR}/debug-trace.txt`), maskIds([
      fileHeader('H2: APEX debug trace at LEVEL9', [
        `both pages were opened with ?debug=LEVEL9; rows read as DBA from ${apex}.WWV_FLOW_DEBUG_MESSAGES and ..._MESSAGES2`,
      ]),
      `messages: ${debug.length} in ${views.size} page views`,
      ...levels.map((level) => `  level ${level}: ${debug.filter((d) => d.MESSAGE_LEVEL === level).length}`),
      `page views that are CAST_BALLOT requests: ${ballotViews.length}`,
      `longest message: ${Math.max(...debug.map((d) => (d.MESSAGE ?? '').length))} characters`,
      `messages containing 64 or more hexadecimal characters in a row: ${debug.filter((d) => /[0-9a-f]{64}/i.test(d.MESSAGE ?? '')).length}`,
      `messages containing a voter code: ${debug.filter((d) => /VOTER-\d{4}/.test(d.MESSAGE ?? '')).length}`,
      '',
      `Complete trace of one CAST_BALLOT request (${oneBallot.length} messages):`,
      '',
      ...oneBallot.map((d) => `  [${d.MESSAGE_LEVEL}] ${(d.MESSAGE ?? '').replace(/\n/g, '\n      ')}`),
      '',
    ].join('\n')));

    const describe = (entry) => {
      const url = new URL(entry.request.url);
      const process = formFields(entry).find(([k]) => k === 'p_request')?.[1] ?? '';
      return { METHOD: entry.request.method, PATH: maskIds(url.pathname + url.search), PROCESS: process.replace('APPLICATION_PROCESS=', ''), STATUS: entry.response.status, TYPE: (entry.response.content?.mimeType ?? '').split(';')[0], SENT_BYTES: Buffer.byteLength(entry.request.postData?.text ?? '') };
    };
    const dynamic = (entries) => entries.filter((e) => e.request.method !== 'GET' || /html/.test(e.response.content?.mimeType ?? ''));
    const wrap = (hex) => hex.match(/.{1,96}/g).join(`\n${' '.repeat(19)}`);
    const sample = ballotPosts[0];
    writeText(cfg, report.file(`${DIR}/request-payloads.txt`), maskIds([
      fileHeader('H2: what the browsers sent', [
        'source: HAR recorded by Playwright in both browser contexts (authority.har and voter.har in this folder)',
      ]),
      `requests: ${har.authority.length} by the authority browser, ${har.voter.length} by the voter browser, all to one origin: ${origins.length === 1 ? 'yes' : 'NO'}`,
      `static files (scripts, styles, fonts, images): ${allEntries.length - dynamic(allEntries).length} GET requests`,
      'distinct query strings of static files (searched like everything else):',
      ...[...new Set(allEntries.filter((e) => !dynamic([e]).length).map((e) => new URL(e.request.url).search).filter(Boolean))].map((q) => `  ${q.length > 110 ? `${q.slice(0, 110)}… (${q.length} characters)` : q}`),
      '',
      'Pages and Ajax calls of the authority browser:',
      '', indent(asTable(dynamic(har.authority).map(describe), { maxWidth: 70 })),
      'Pages and Ajax calls of the voter browser:',
      '', indent(asTable(dynamic(har.voter).map(describe), { maxWidth: 70 })),
      'The ballot requests, field by field. "choice" is known to the test only: it is not in the request.',
      '',
      indent(asTable(anatomy.map((a, i) => ({
        BALLOT: cast[i].ballotId, CHOICE: LETTERS[cast[i].choice], X01: a.voter, F01_VALUES: a.ciphertexts.length, F01_CHARS: [...new Set(a.ciphertexts.map((c) => c.length))].join('/'),
        BODY_BYTES: a.bodyBytes, OTHER_FIELDS_AS_BALLOT_1: a.rest === first.rest ? 'identical' : 'DIFFERENT', HEADERS_AS_BALLOT_1: a.headers === first.headers ? 'identical' : 'DIFFERENT', RESPONSE: a.response,
      })), { maxWidth: 40 })),
      `fields other than x01 and f01, the same in every ballot request: ${formFields(sample).filter(([k]) => k !== 'x01' && k !== 'f01').map(([k, v]) => `${k}=${v}`).join('  ')}`,
      '',
      'One complete ballot request, as sent (ciphertexts wrapped for display, cookie value masked):',
      '',
      `  ${sample.request.method} ${sample.request.url}`,
      ...maskCookies(sample.request.headers).map((h) => `  ${h.name}: ${h.value}`),
      '',
      ...formFields(sample).map(([k, v]) => `  ${k.padEnd(14)} = ${k === 'f01' ? wrap(v) : v}`),
      '',
      'The JavaScript the browsers ran, against the files of this repository (SHA-256, first 16 characters, line endings normalized):',
      '', indent(asTable(scriptRows)),
    ].join('\n')));
    for (const name of ['authority', 'voter']) writeText(cfg, report.file(`${DIR}/${name}.har`), reducedHar(har[name], origin));

    writeText(cfg, report.file(`${DIR}/apex-logs.txt`), maskIds([
      fileHeader('H2: APEX logs and instance-level traces', ['everything recorded since the election of this run was opened, read as DBA']),
      `APEX activity log (${apex}.WWV_FLOW_ACTIVITY_LOG1$ and 2$): ${activity.length} rows`,
      '',
      indent(asTable(activity.map((a) => ({ TIME: a.TIME_STAMP_TZ.toISOString(), PAGE: a.STEP_ID, VIEW_TYPE: a.PAGE_VIEW_TYPE, REQUEST_VALUE: a.REQUEST_VALUE, USERID: a.USERID, ELAPSED_S: a.ELAP, BYTES: a.CONTENT_LENGTH, IP_ADDRESS: a.IP_ADDRESS, ERROR: a.SQLERRM })), { maxWidth: 44 })),
      'The activity log names the page, the time and the address of every ballot request. It says who voted when (see H5), not what.',
      '',
      `APEX access log (logins): ${access.length} rows. The application has no login.`,
      `SQL area: ${sqlArea.length} statements parsed by ${owner}, ${apex}, APEX_PUBLIC_USER or ORDS_PUBLIC_USER, full text searched`,
      `captured bind values (V$SQL_BIND_CAPTURE): ${binds.length}`,
      `unified audit trail: ${audit.ok ? `${audit.rows.length} records` : `not readable (${audit.error})`}`,
      `database alert log: ${alert.ok ? `${alert.rows.length} lines` : `not readable (${alert.error})`}`,
      '',
      'Statements of the schema seen in the SQL area (the application binds every value):',
      '',
      ...sqlArea.filter((s) => s.PARSING_SCHEMA_NAME === owner && !/OPT_DYN_SAMP|^\s*LOCK TABLE/.test(s.SQL_FULLTEXT)).map((s) => `  ${s.SQL_FULLTEXT.replace(/\s+/g, ' ').slice(0, 150)}`).filter((v, i, a) => a.indexOf(v) === i).slice(0, 25),
      '',
    ].join('\n')));

    const storageLines = (name, c) => [
      `${name} tab`,
      `  localStorage:   ${JSON.stringify(c.localStorage)}`,
      `  sessionStorage: ${JSON.stringify(c.sessionStorage)}`,
      `  IndexedDB databases: ${c.indexedDB.length}    Cache Storage caches: ${c.cacheStorage.length}`,
      `  cookies: ${c.storageState.cookies.map((k) => `${k.name}=<masked> (httpOnly ${k.httpOnly})`).join(', ') || 'none'}`,
      `  form fields in the page: ${c.formFields.length}`,
      ...c.formFields.map((f) => `    ${(f.id || '(no id)').padEnd(26)} name=${(f.name ?? '(none)').padEnd(22)} type=${f.type.padEnd(7)} value=${f.value.length > 40 ? `<${f.value.length} characters, searched>` : JSON.stringify(f.value)}`),
      `  page HTML searched: ${c.html.length} characters`,
      '',
    ];
    writeText(cfg, report.file(`${DIR}/client-side.txt`), maskIds([
      fileHeader('H2: where the private key is not, inside the browser', [
        'The key pair is a variable of one JavaScript module in the authority tab. This file shows the places',
        'it must never reach: storage, cookies, form fields (APEX page items are form fields) and the page itself.',
        'A field without a name attribute is not part of any form submission.',
      ]),
      ...storageLines('authority', authorityState),
      ...storageLines('voter', voterState),
      `stores in use (localStorage + sessionStorage + IndexedDB + Cache Storage): authority ${stores(authorityState)}, voter ${stores(voterState)}`,
      '',
    ].join('\n')));

    writeText(cfg, report.file(`${DIR}/controls.txt`), maskIds([
      fileHeader('H2: can this search find anything?', ['A search that finds nothing proves nothing unless it finds what is planted.']),
      'Control 1. Secrets of this election planted in text, whole and in fragments',
      '',
      indent(asTable(controls.map((c) => ({ PLANTED: c.name, EXPECTED: c.expectDetected ? 'found' : 'silent', RESULT: c.detected ? 'found' : 'silent', DETECTOR: c.by })), { maxWidth: 60 })),
      'Control 2. Canary: a decoy secret sent through the real application',
      `  A second key pair is generated in Node and never opens an election. Its lambda is sent twice from a browser`,
      '  console: as an extra parameter of an Ajax call, and in the place of the first ciphertext of a ballot.',
      `  ballot answer from the database: ${JSON.stringify(canary.answer)}`,
      '',
      indent(asTable(canary.rows.map((r) => ({ SURFACE: r.label, DECOY_FOUND: r.found ? 'yes' : 'no', DETAIL: r.detail })), { maxWidth: 90 })),
      'Reading: the ballot table and the network record whatever a browser sends, and the search finds it there.',
      'Surfaces marked "no" did not record request parameters at all in this run, so their silence in the main',
      'search says little by itself. The network record is the complete one.',
      '',
    ].join('\n')));

    const serverSide = hits('network') + hits('tables') + hits('session state') + hits('debug') + hits('logs');
    const verdict = serverSide > 0 ? 'REFUTED' : report.failed.length > 0 || hits('browser') > 0 ? 'PARTIAL' : 'CONFIRMED';
    const statements = {
      CONFIRMED: `Knowing the private key and the randomizer of all ${BALLOTS * OPTIONS} ciphertexts, the test found none of them, whole or in part, in ${scanner.sources.length} sources: ${allEntries.length} HTTP requests and their responses, ${tables.length} tables, APEX session state (${state.pageItems.length} page items; ${state.items.length} report paging positions), ${debug.length} LEVEL9 debug messages, the activity and access logs, ${sqlArea.length} SQL statements, captured binds, audit trail, alert log, and the storage of both tabs. Ballot requests differ only in the voter code and three ciphertexts. ORDS log files were not read.`,
      REFUTED: `A secret was found outside the browser: ${findings.map((f) => `${f.what} in ${f.source}`).join('; ')}.`,
      PARTIAL: `No secret was found server side, but ${report.failed.length} check(s) did not hold: ${report.failed.map((c) => c.name).join('; ')}.`,
    };
    return report.close(cfg, {
      verdict,
      statement: statements[verdict],
      numbers: {
        ballots: BALLOTS, ciphertexts: BALLOTS * OPTIONS, secrets: secrets.length, search_windows: scanner.windowCount, sources: scanner.sources.length,
        characters_searched: scanner.sources.reduce((n, s) => n + s.chars, 0), long_numbers_tested: scanner.sources.reduce((n, s) => n + s.numbersTested, 0), findings: findings.length,
        requests: allEntries.length, tables: tables.length, session_state_page_items: state.pageItems.length, session_state_paging_entries: state.items.length,
        debug_messages: debug.length, activity_rows: activity.length,
        sql_statements: sqlArea.length, captured_binds: binds.length, keygen_draws: authorityState.tape.length,
        canary: Object.fromEntries(canary.rows.map((r) => [r.id, r.found])), browser: `${browser.bfChannel} ${browser.version()}`,
      },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await browser.close();
    await dba.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

// A decoy secret travels through the real application. Where does it end up,
// and does the search find it there?
async function runCanary({ cfg, browser, dba, owner, apex, tmp, viewport }) {
  const decoy = await P.generateKeyPair(2048);
  const scanner = new LeakScanner(privateKeySecrets(decoy.privateKey), { publicKey: decoy.publicKey, privateKey: decoy.privateKey });
  const since = await dbNow(dba);
  const context = await browser.newContext({ viewport, recordHar: { path: join(tmp, 'canary.har'), content: 'embed' } });
  const page = await context.newPage();
  watch(page, 'canary');
  await page.goto(appUrl(cfg, 'vote', '?debug=LEVEL9'), { waitUntil: 'networkidle' });
  await page.waitForSelector('.bf-option');
  const answer = await page.evaluate(async ({ lambdaHex, voter }) => {
    const call = (name, data) => new Promise((resolve, reject) => {
      apex.server.process(name, data, { dataType: 'json', success: resolve, error: (xhr, status, message) => reject(new Error(message || status)) });
    });
    const info = await call('ELECTION_INFO', { x05: lambdaHex });
    const width = info.n_hex.length * 2;
    const trivial = '1'.padStart(width, '0'); // the number 1 is a valid encryption of zero
    return call('CAST_BALLOT', { x01: voter, f01: [lambdaHex.padStart(width, '0'), trivial, trivial] });
  }, { lambdaHex: P.toHex(decoy.privateKey.lambda), voter: voterCode(REGISTERED - 1) });
  await context.close();

  const entries = JSON.parse(readFileSync(join(tmp, 'canary.har'), 'utf8')).log.entries;
  const sessions = [...new Set(entries.flatMap((e) => formFields(e).filter(([k]) => k === 'p_instance').map(([, v]) => Number(v))))];
  const found = (source) => source.windowHits.length + source.structureHits.length > 0;
  const rows = [];
  const probe = (id, label, text, detail) => rows.push({ id, label, found: found(scanner.scan(label, text)), detail });

  const ballots = (await dba.execute(`select ballot_id, candidate_id, vote_enc from ${owner}.blind_ballots`)).rows;
  probe('table', 'table BLIND_BALLOTS', rowsText(ballots), `${ballots.length} rows`);
  probe('network', 'network record (HAR requests)', entries.map(requestText).join('\n\n'), `${entries.length} requests`);
  const state = await fetchSessionState(dba, apex, cfg.app_id, sessions);
  probe('session_state', 'APEX session state', rowsText(state.items), `${state.items.length} items`);
  const debug = await fetchDebug(dba, apex, cfg.app_id, since);
  probe('debug', 'APEX debug trace, LEVEL9', debug.map((d) => `${d.MESSAGE ?? ''}\n${d.CALL_STACK ?? ''}`).join('\n'), `${debug.length} messages`);
  const activity = await fetchActivity(dba, apex, cfg.app_id, since);
  probe('activity_log', 'APEX activity log', rowsText(activity), `${activity.length} rows`);
  const sqlArea = await fetchSqlArea(dba, owner, apex, since);
  probe('sql_area', 'SQL area (V$SQL)', sqlArea.map((s) => s.SQL_FULLTEXT).join('\n'), `${sqlArea.length} statements`);
  const binds = await fetchBinds(dba, since);
  probe('bind_capture', 'captured binds (V$SQL_BIND_CAPTURE)', rowsText(binds), `${binds.length} values`);
  return { answer, rows };
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
