// H6 - Cost.
//
//   "Time to cast one ballot in the browser; tally time at 100, 1,000 and
//    10,000 voters versus a plaintext COUNT; storage per ballot."
//
// Every raw measurement goes to evidence/h6-cost/timings.json. This file is
// the script that produced them.
//
//   node tests/h6-cost.mjs [--quick] [--seed <n>]
import os from 'node:os';
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect, attempt, oracledb } from './lib/db.mjs';
import { BallotFactory } from './lib/ballot-factory.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser, tallyInBrowser } from './lib/app.mjs';
import { OPTIONS, openElection, castBallots, encryptedTally, decryptTally, countChoices, seededRandom, voterCode } from './lib/election.mjs';
import { writeText, writeJson, header, stats } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';
import { runsOnTagOnly } from './lib/layer1.mjs';

// Layer 1 only: on main this script stops here and says where it runs (tests/lib/layer1.mjs).
if (isMain(import.meta.url)) runsOnTagOnly('H6', 'tests/h6-cost.mjs');

const DIR = 'h6-cost';
const now = () => Number(process.hrtime.bigint()) / 1e6;
const round = (x) => Math.round(x * 1000) / 1000;

// ---- part 1: what a voter and the authority pay, measured inside the browser
async function browserCost(cfg, args) {
  const casts = args.quick ? 5 : 30;
  const rounds = args.quick ? 6 : 30;
  const keys = args.quick ? 3 : 20;
  const browser = await launchBrowser(cfg);
  try {
    const authority = await (await browser.newContext()).newPage();
    watch(authority, 'authority');
    await openElectionInBrowser(authority, cfg, casts + 2);

    const voter = await (await browser.newContext()).newPage();
    watch(voter, 'voter');
    const requestBytes = [];
    voter.on('request', (request) => {
      const body = request.postData() ?? '';
      if (body.includes('CAST_BALLOT')) requestBytes.push(Buffer.byteLength(body));
    });
    await voter.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
    await voter.waitForSelector('.bf-option');

    // Click "Encrypt and cast ballot" and wait for the receipt: encryption,
    // the Ajax round trip and the database insert, as the voter experiences it.
    const castUi = [];
    for (let i = 0; i < casts; i++) {
      await voter.fill('#bf-voter', voterCode(i));
      await voter.locator('.bf-option').nth(i % OPTIONS).click();
      castUi.push(await voter.evaluate(() => new Promise((resolve) => {
        const receipt = document.querySelector('#bf-receipt');
        const started = performance.now();
        const observer = new MutationObserver(() => {
          if (receipt.hidden) return;
          observer.disconnect();
          resolve(performance.now() - started);
        });
        observer.observe(receipt, { attributes: true, attributeFilter: ['hidden'] });
        document.querySelector('#bf-cast').click();
      })));
      await voter.click('#bf-next');
    }

    // The library alone, loaded from the application's own static files.
    const micro = await voter.evaluate(async ({ rounds, keys }) => {
      const base = document.querySelector('script[src*="blindfold/boot.js"]').src.replace(/boot\.js.*$/, '');
      const P = await import(`${base}paillier.js`);
      const info = await new Promise((resolve, reject) => apex.server.process('ELECTION_INFO', {}, { dataType: 'json', success: resolve, error: reject }));
      const electionKey = P.publicKeyFromN(P.fromHex(info.n_hex));
      const encryptBallot = [];
      for (let i = 0; i < rounds; i++) {
        const started = performance.now();
        P.encryptBallot(electionKey, i % 3, 3);
        encryptBallot.push(performance.now() - started);
      }
      const keygen = [];
      let pair;
      for (let i = 0; i < keys; i++) {
        const started = performance.now();
        pair = await P.generateKeyPair(2048);
        keygen.push(performance.now() - started);
      }
      const ciphertext = P.encrypt(pair.publicKey, 12345n);
      const decrypt = [];
      for (let i = 0; i < rounds; i++) {
        const started = performance.now();
        P.decrypt(pair.publicKey, pair.privateKey, ciphertext);
        decrypt.push(performance.now() - started);
      }
      return { encryptBallot, keygen, decrypt, userAgent: navigator.userAgent, logicalCores: navigator.hardwareConcurrency };
    }, { rounds, keys });

    // The authority's side of the same election, read off the Tally page.
    const shown = await tallyInBrowser(authority);
    const number = (text, pattern) => Number((text.match(pattern) ?? [])[1]?.replace(/,/g, ''));
    return {
      browser: `${browser.bfChannel} ${browser.version()} (headless)`,
      user_agent: micro.userAgent.replace(/HeadlessChrome/, 'Chrome'),
      logical_cores: micro.logicalCores,
      cast_ballot_ui_ms: castUi.map(round),
      cast_ballot_request_bytes: requestBytes,
      encrypt_ballot_ms: micro.encryptBallot.map(round),
      keygen_2048_ms: micro.keygen.map(round),
      decrypt_one_ciphertext_ms: micro.decrypt.map(round),
      tally_page: {
        ballots: casts,
        database_tally_round_trip_ms: number(shown.tallyStatus, /in ([\d,]+) ms/),
        decrypt_three_totals_ms: number(shown.decryptStatus, /Decrypted in ([\d,]+) ms/),
        totals: shown.totals,
      },
    };
  } finally {
    await browser.close();
  }
}

// ---- part 2: what the database pays, against a plaintext table
async function databaseCost(cfg, args, report) {
  const sizes = args.quick ? [100, 400] : [100, 1000, 10000];
  const random = seededRandom(args.seed);
  const conn = await connect(cfg, 'schema');
  const dba = await connect(cfg, 'dba');
  const factory = new BallotFactory();
  const results = [];
  try {
    const jit = (await attempt(dba, "select value from v$parameter where name = 'java_jit_enabled'")).rows?.[0]?.VALUE ?? 'unknown';
    const version = (await dba.execute('select banner_full as banner from v$version')).rows[0].BANNER.split('\n')[0];

    for (const voters of sizes) {
      const { publicKey, privateKey } = await P.generateKeyPair(2048);
      const choices = Array.from({ length: voters }, () => Math.floor(random() * OPTIONS));
      await openElection(conn, publicKey, voters);
      const { ballots } = await factory.encrypt(publicKey.n.toString(16), choices, {});
      const castStarted = now();
      await castBallots(conn, ballots);
      const castMs = now() - castStarted;

      // Cold: a new database session, whose Java virtual machine starts on first use.
      const fresh = await connect(cfg, 'schema');
      let started = now();
      const tally = await encryptedTally(fresh);
      const cold = now() - started;
      const warm = [];
      for (let i = 0; i < 5; i++) {
        started = now();
        await encryptedTally(fresh);
        warm.push(now() - started);
      }
      await fresh.close();
      const decrypted = decryptTally(publicKey, privateKey, tally).map(Number);
      report.check(`tally of ${voters} voters is correct`, decrypted.join() === countChoices(choices).join(), decrypted.join('/'));

      // The same election in the clear: one row per ballot, one small number.
      await attempt(conn, 'drop table h6_plain_ballots purge');
      await conn.execute('create table h6_plain_ballots (ballot_id number not null, candidate_id number(1) not null, constraint h6_plain_ballots_pk primary key (ballot_id))');
      await conn.executeMany('insert into h6_plain_ballots (ballot_id, candidate_id) values (:1, :2)', choices.map((c, i) => [i + 1, c + 1]),
        { bindDefs: [{ type: oracledb.NUMBER }, { type: oracledb.NUMBER }] });
      await conn.commit();
      const plain = [];
      for (let i = 0; i < 25; i++) {
        started = now();
        await conn.execute('select candidate_id, count(*) as votes from h6_plain_ballots group by candidate_id order by candidate_id');
        plain.push(now() - started);
      }

      const segments = (await conn.execute(
        `select segment_name, bytes from user_segments
          where segment_name in ('BLIND_BALLOTS', 'BLIND_BALLOTS_PK', 'H6_PLAIN_BALLOTS', 'H6_PLAIN_BALLOTS_PK')`)).rows;
      const bytes = (name) => segments.filter((s) => s.SEGMENT_NAME.startsWith(name)).reduce((a, s) => a + s.BYTES, 0);
      const payload = (await conn.execute('select sum(vsize(vote_enc)) as cipher, sum(vsize(ballot_id) + vsize(candidate_id)) as ids from blind_ballots')).rows[0];
      const plainPayload = (await conn.execute('select sum(vsize(ballot_id) + vsize(candidate_id)) as ids from h6_plain_ballots')).rows[0];

      results.push({
        voters,
        ciphertexts: voters * OPTIONS,
        cast_all_ballots_ms: round(castMs),
        tally_cold_ms: round(cold),
        tally_warm_ms: warm.map(round),
        plaintext_count_ms: plain.map(round),
        storage: {
          encrypted_column_bytes: payload.CIPHER + payload.IDS,
          encrypted_column_bytes_per_ballot: round((payload.CIPHER + payload.IDS) / voters),
          encrypted_segment_bytes: bytes('BLIND_BALLOTS'),
          encrypted_segment_bytes_per_ballot: round(bytes('BLIND_BALLOTS') / voters),
          plaintext_column_bytes: plainPayload.IDS,
          plaintext_column_bytes_per_ballot: round(plainPayload.IDS / voters),
          plaintext_segment_bytes: bytes('H6_PLAIN_BALLOTS'),
          plaintext_segment_bytes_per_ballot: round(bytes('H6_PLAIN_BALLOTS') / voters),
        },
      });
      console.log(`  ${voters} voters: tally cold ${Math.round(cold)} ms, warm ${Math.round(stats(warm).median)} ms, plaintext count ${stats(plain).median} ms`);
    }
    await attempt(conn, 'drop table h6_plain_ballots purge');
    return { database: version, java_jit_enabled: jit, sizes: results };
  } finally {
    await factory.close();
    await conn.close();
    await dba.close();
  }
}

export async function run(cfg, args) {
  const report = new Report('H6', 'Cost: time to cast a ballot, tally time against a plaintext COUNT, storage per ballot', DIR);
  const browser = await browserCost(cfg, args);
  report.check('casting a ballot was measured in a real browser', browser.cast_ballot_ui_ms.length > 0 && browser.cast_ballot_request_bytes.length === browser.cast_ballot_ui_ms.length,
    `${browser.cast_ballot_ui_ms.length} ballots, median ${stats(browser.cast_ballot_ui_ms).median} ms from click to receipt`);
  const database = await databaseCost(cfg, args, report);

  const timings = {
    generated: new Date().toISOString(),
    script: 'tests/h6-cost.mjs',
    mode: { quick: args.quick, seed: args.seed },
    machine: { cpu: os.cpus()[0].model.trim(), logical_cores: os.cpus().length, memory_gb: Math.round(os.totalmem() / 2 ** 30), os: `${os.type()} ${os.release()}`, node: process.version },
    key_bits: 2048,
    notes: [
      'All times in milliseconds. Browser, ORDS and database run on the same machine.',
      'cast_ballot_ui_ms: click on "Encrypt and cast ballot" until the receipt is visible (three encryptions, one Ajax call, one transaction).',
      'tally_*_ms and plaintext_count_ms: wall time of one statement seen from the client, localhost round trip included.',
      'tally_cold_ms: first tally of a new database session (the session starts its Java virtual machine).',
      'storage: column bytes are sum(vsize(...)); segment bytes come from user_segments (table plus primary key index) and are rounded up to whole extents.',
    ],
    browser,
    database,
  };
  writeJson(cfg, report.file(`${DIR}/timings.json`), timings);

  const line = (label, values, unit = 'ms') => {
    const s = stats(values);
    return `  ${label.padEnd(46)} median ${String(s.median).padStart(9)} ${unit}   min ${String(s.min).padStart(9)}   max ${String(s.max).padStart(9)}   n=${s.n}`;
  };
  const big = database.sizes.at(-1);
  const summary = [
    header('H6: cost', [
      `machine: ${timings.machine.cpu}, ${timings.machine.logical_cores} logical cores, ${timings.machine.os}`,
      `browser: ${browser.browser}`,
      `database: ${database.database}`,
      `java_jit_enabled = ${database.java_jit_enabled}`,
      `2048-bit key${args.quick ? ', quick mode: fewer repetitions and smaller elections' : ''}`,
      'raw measurements: timings.json; script that took them: tests/h6-cost.mjs',
    ]),
    'In the browser',
    line('cast one ballot, click to receipt', browser.cast_ballot_ui_ms),
    line('  of which: encrypt three ciphertexts', browser.encrypt_ballot_ms),
    line('request body of one ballot', browser.cast_ballot_request_bytes, 'B '),
    line('generate a 2048-bit key pair', browser.keygen_2048_ms),
    line('decrypt one ciphertext', browser.decrypt_one_ciphertext_ms),
    '',
    'In the database',
    '  voters  ciphertexts  tally cold ms  tally warm ms (median)  plaintext COUNT ms (median)  ratio warm/plain',
    '  ------  -----------  -------------  ----------------------  ---------------------------  ----------------',
    ...database.sizes.map((s) => {
      const warm = stats(s.tally_warm_ms).median;
      const plain = stats(s.plaintext_count_ms).median;
      return `  ${String(s.voters).padStart(6)}  ${String(s.ciphertexts).padStart(11)}  ${String(Math.round(s.tally_cold_ms)).padStart(13)}  ${String(Math.round(warm)).padStart(22)}  ${String(plain).padStart(27)}  ${String(Math.round(warm / plain)).padStart(15)}x`;
    }),
    '',
    'Storage per ballot',
    '  voters  encrypted: column bytes  encrypted: segment bytes  plaintext: column bytes  plaintext: segment bytes',
    '  ------  -----------------------  ------------------------  -----------------------  ------------------------',
    ...database.sizes.map((s) => `  ${String(s.voters).padStart(6)}  ${String(s.storage.encrypted_column_bytes_per_ballot).padStart(23)}  ${String(s.storage.encrypted_segment_bytes_per_ballot).padStart(24)}  ${String(s.storage.plaintext_column_bytes_per_ballot).padStart(23)}  ${String(s.storage.plaintext_segment_bytes_per_ballot).padStart(24)}`),
    '',
  ];
  writeText(cfg, report.file(`${DIR}/summary.txt`), summary.join('\n'));

  const cast = stats(browser.cast_ballot_ui_ms).median;
  const warmBig = stats(big.tally_warm_ms).median;
  const plainBig = stats(big.plaintext_count_ms).median;
  const ok = report.failed.length === 0;
  return report.close(cfg, {
    verdict: ok ? 'CONFIRMED' : 'PARTIAL',
    statement: ok
      ? `Measured: casting a ballot takes a median ${Math.round(cast)} ms in the browser; tallying ${big.voters} voters takes ${(warmBig / 1000).toFixed(1)} s against ${plainBig} ms for a plaintext COUNT (${Math.round(warmBig / plainBig)}x); a ballot stores ${Math.round(big.storage.encrypted_column_bytes_per_ballot)} bytes against ${Math.round(big.storage.plaintext_column_bytes_per_ballot)}.`
      : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
    numbers: {
      cast_ballot_ui_ms: stats(browser.cast_ballot_ui_ms),
      encrypt_ballot_ms: stats(browser.encrypt_ballot_ms),
      keygen_2048_ms: stats(browser.keygen_2048_ms),
      decrypt_one_ciphertext_ms: stats(browser.decrypt_one_ciphertext_ms),
      request_bytes: stats(browser.cast_ballot_request_bytes).median,
      tally: database.sizes.map((s) => ({ voters: s.voters, cold_ms: s.tally_cold_ms, warm_ms: stats(s.tally_warm_ms).median, plaintext_ms: stats(s.plaintext_count_ms).median, bytes_per_ballot: s.storage.encrypted_column_bytes_per_ballot, plaintext_bytes_per_ballot: s.storage.plaintext_column_bytes_per_ballot })),
    },
    mode: { quick: args.quick, seed: args.seed },
  });
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
