// Screenshots for the article and the video, taken from a real run.
//
//   evidence/app/              the application, page by page
//   evidence/h2-blindness/     what a DBA sees in APEX SQL Workshop, the APEX
//                              debug trace of one ballot, one ballot request
//
// Nothing here is drawn by hand. Pages of the APEX builder are masked before
// the shot (workspace, schema and account names, host, session ids) and the
// script refuses to save a builder screenshot in which one of them is still
// visible. The ballot request is rendered from the HAR that the H2 test
// recorded, so run tests/h2-blindness.mjs first.
//
//   node tests/screenshots.mjs
import { existsSync, readFileSync } from 'node:fs';
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect } from './lib/db.mjs';
import { launchBrowser } from './lib/browser.mjs';
import { appUrl, watch, openElectionInBrowser, castInBrowser, LETTERS } from './lib/app.mjs';
import { voterCode } from './lib/election.mjs';
import { evidencePath, writeText, header } from './lib/evidence.mjs';
import { parseArgs, isMain, main } from './lib/harness.mjs';

const REGISTERED = 20;
// Twelve ballots for the tour: 6 for A, 2 for B, 4 for C.
const TOUR = [1, 0, 2, 0, 0, 2, 1, 0, 2, 0, 2, 0];
const DESKTOP = { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 };

const shots = [];
async function shoot(target, rel, description, options = {}) {
  await target.screenshot({ path: evidencePath(rel), ...options });
  shots.push({ rel, description });
  console.log(`  ${rel}`);
}

// ------------------------------------------------------------ the application

async function tour(cfg, browser) {
  const authorityContext = await browser.newContext(DESKTOP);
  const authority = await authorityContext.newPage();
  watch(authority, 'authority');
  await openElectionInBrowser(authority, cfg, REGISTERED);
  await shoot(authority, 'app/01-authority-key-generated.png', 'Tally page, step 1: the key pair was generated in this tab and the public key published', { fullPage: true });

  const voterContext = await browser.newContext(DESKTOP);
  const voter = await voterContext.newPage();
  watch(voter, 'voter');
  await voter.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
  await voter.waitForSelector('.bf-option');
  await voter.fill('#bf-voter', voterCode(0));
  await voter.locator('.bf-option').nth(TOUR[0]).click();
  await shoot(voter, 'app/02-vote.png', 'Vote page: a voter code and a choice, before casting', { fullPage: true });
  await castInBrowser(voter, voterCode(0), TOUR[0], { next: false });
  await shoot(voter, 'app/03-vote-receipt.png', 'Vote page after casting: the receipt and the log of what left the browser', { fullPage: true });
  await voter.click('#bf-next');
  for (let i = 1; i < TOUR.length; i++) await castInBrowser(voter, voterCode(i), TOUR[i]);

  const ledger = await voterContext.newPage();
  watch(ledger, 'ledger');
  await ledger.goto(appUrl(cfg, 'ledger'), { waitUntil: 'networkidle' });
  // The report is there when a cell holds a ciphertext.
  await ledger.waitForFunction(() => Array.from(document.querySelectorAll('#bf-ballots td')).some((cell) => cell.textContent.trim().length > 100));
  await shoot(ledger, 'app/04-what-the-database-sees.png', 'What the database sees: BLIND_BALLOTS and VOTER_ROLL, straight from the tables', { fullPage: true });

  await authority.click('#bf-tally');
  await authority.waitForSelector('#bf-totals .bf-total', { timeout: 120000 });
  await shoot(authority, 'app/05-tally-encrypted.png', 'Tally page, step 2: the database returned three encrypted totals it cannot read', { fullPage: true });
  await authority.click('#bf-decrypt');
  await authority.waitForSelector('#bf-results .bf-result', { timeout: 120000 });
  await shoot(authority, 'app/06-tally-decrypted.png', 'Tally page, step 3: the totals decrypted in the authority tab', { fullPage: true });
  const totals = await authority.$$eval('.bf-result__votes', (nodes) => nodes.map((n) => Number(n.textContent.replace(/,/g, ''))));

  const phoneContext = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
  const phone = await phoneContext.newPage();
  watch(phone, 'phone');
  await phone.goto(appUrl(cfg, 'vote'), { waitUntil: 'networkidle' });
  await phone.waitForSelector('.bf-option');
  await phone.fill('#bf-voter', voterCode(TOUR.length));
  await phone.locator('.bf-option').nth(2).tap();
  await shoot(phone, 'app/07-vote-phone.png', 'Vote page at phone width', { fullPage: true });

  await Promise.all([authorityContext.close(), voterContext.close(), phoneContext.close()]);
  return totals;
}

// One more ballot with debug on, so that the builder has a trace to show.
async function debugBallot(cfg, browser, dba) {
  const context = await browser.newContext(DESKTOP);
  const page = await context.newPage();
  watch(page, 'debug voter');
  await page.goto(appUrl(cfg, 'vote', '?debug=LEVEL9'), { waitUntil: 'networkidle' });
  await page.waitForSelector('.bf-option');
  await castInBrowser(page, voterCode(TOUR.length + 1), 0);
  await context.close();
  const apex = (await dba.execute("select schema from dba_registry where comp_id = 'APEX'")).rows[0].SCHEMA;
  const row = (await dba.execute(
    `select max(page_view_id) as page_view from ${apex}.wwv_flow_debug_messages where flow_id = :app and message like 'R E Q U E S T ajax process CAST_BALLOT'`, { app: cfg.app_id })).rows[0];
  if (!row.PAGE_VIEW) throw new Error('No debug trace of a CAST_BALLOT request was found.');
  return row.PAGE_VIEW;
}

// ----------------------------------------------------------- the APEX builder

// Replaces every visible trace of where the lab runs. Returns what is still visible, if anything.
async function maskBuilder(page, cfg) {
  const host = new URL(cfg.ords_base).host;
  const words = [...new Set([cfg.workspace, cfg.schema, cfg.ws_admin].filter(Boolean).map((w) => w.toLowerCase()))];
  return page.evaluate(({ host, hostname, words }) => {
    const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const patterns = words.map((w) => new RegExp(escape(w), 'gi'));
    const clean = (text) => {
      let out = text.split(host).join('[host]').split(hostname).join('[host]');
      for (const pattern of patterns) out = out.replace(pattern, '[masked]');
      // Session ids are long decimal numbers. The lookarounds keep the pattern off the digits
      // inside a hexadecimal string (a ciphertext must be shown exactly as stored), and a
      // percent escape such as %2F is kept whole.
      return out.split(/(%[0-9A-Fa-f]{2})/).map((part, index) => (index % 2 ? part : part.replace(/(?<![0-9a-f])\d{12,}(?![0-9a-f])/g, '[id]'))).join('');
    };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = clean(node.nodeValue);
      if (text !== node.nodeValue) node.nodeValue = text;
    }
    for (const field of document.querySelectorAll('input, textarea')) {
      if (clean(field.value) !== field.value) field.value = clean(field.value);
    }
    // The account menu shows the initials of the signed-in user.
    for (const node of document.querySelectorAll('#header-accountMenu, .a-Header-userInitials, [class*="userInitials"]')) node.textContent = '··';
    // What a reader of the screenshot can see: rendered text, field values, the selected option of every list.
    const visible = [
      document.body.innerText,
      ...Array.from(document.querySelectorAll('input, textarea'), (f) => f.value),
      ...Array.from(document.querySelectorAll('select'), (s) => s.selectedOptions[0]?.textContent ?? ''),
    ].join('\n').toLowerCase();
    return [host, hostname, ...words].filter((w) => visible.includes(w.toLowerCase()));
  }, { host, hostname: new URL(cfg.ords_base).hostname, words });
}

async function builderShot(page, cfg, rel, description, options = {}) {
  const left = await maskBuilder(page, cfg);
  if (left.length) throw new Error(`Refusing to save ${rel}: still visible after masking: ${left.join(', ')}.`);
  await shoot(page, rel, description, options);
}

async function builder(cfg, browser, dba, pageView) {
  if (!cfg.ws_admin || !cfg.ws_admin_password) {
    console.log('  no workspace developer configured: builder screenshots skipped');
    return false;
  }
  const context = await browser.newContext({ viewport: { width: 1440, height: 1100 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await page.goto(`${cfg.ords_base}/f?p=4550`, { waitUntil: 'networkidle' });
  await page.fill('#F4550_P1_COMPANY', cfg.workspace);
  await page.fill('#F4550_P1_USERNAME', cfg.ws_admin);
  await page.fill('#F4550_P1_PASSWORD', cfg.ws_admin_password);
  // The sign-in page already has a session in its URL: wait for the builder home page.
  await Promise.all([page.waitForURL(/workspace\/home/, { timeout: 60000 }), page.keyboard.press('Enter')]);
  const session = page.url().match(/session=(\d+)/)[1];

  // SQL Workshop > SQL Commands: the statement any developer of the workspace can run.
  const runSql = async (sql) => {
    await page.goto(`${cfg.ords_base}/f?p=4500:1003:${session}`, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.monaco && window.monaco.editor.getModels().length > 0);
    await page.selectOption('#P1003_ROWS', '50');
    await page.evaluate((text) => window.monaco.editor.getModels()[0].setValue(text), sql);
    await page.click('button:has-text("Run")');
    await page.waitForSelector('table.u-Report td', { timeout: 60000 });
    // Give the results most of the page: the statement is three lines, the answer is the point.
    await page.evaluate((height) => apex.jQuery('#SqlAndResults').splitter('option', 'position', height), 760).catch(() => {});
    await page.waitForTimeout(700);
  };
  await runSql('select ballot_id, candidate_id, vote_enc\n  from blind_ballots\n order by ballot_id, candidate_id');
  await maskBuilder(page, cfg);
  // Masking must not touch the data: every ciphertext on screen is compared with the table.
  const shown = await page.$$eval('table.u-Report tr', (rows) => rows.map((row) => row.cells[2]?.textContent.trim()).filter((text) => text && /^[0-9a-f]+$/.test(text)));
  const stored = (await dba.execute(`select vote_enc from ${cfg.schema.toUpperCase()}.blind_ballots order by ballot_id, candidate_id`)).rows.map((row) => row.VOTE_ENC);
  if (shown.length < 10 || shown.some((text, index) => text !== stored[index])) throw new Error('The ciphertexts shown in SQL Commands differ from the table. Screenshot not saved.');
  await builderShot(page, cfg, 'h2-blindness/dba-select.png', `APEX SQL Workshop: the SELECT a DBA or developer runs on BLIND_BALLOTS (${shown.length} ciphertexts on screen, identical to the table)`);
  await runSql('select candidate_id,\n       count(*) as ciphertexts,\n       count(distinct vote_enc) as distinct_values,\n       min(length(vote_enc)) as shortest,\n       max(length(vote_enc)) as longest\n  from blind_ballots\n group by candidate_id\n order by candidate_id');
  await builderShot(page, cfg, 'h2-blindness/dba-group-by.png', 'APEX SQL Workshop: what a GROUP BY tells about the result. Every option has the same number of rows');

  // App Builder > Utilities > Debug Messages: the trace of one ballot request at LEVEL9.
  await page.goto(`${cfg.ords_base}/f?p=4000:939:${session}::NO::P939_PAGE_VIEW_ID:${pageView}`, { waitUntil: 'networkidle' });
  await page.waitForSelector('table td');
  await builderShot(page, cfg, 'h2-blindness/debug-trace.png', 'APEX debug viewer: the LEVEL9 trace of one CAST_BALLOT request, top of the list');
  await builderShot(page, cfg, 'h2-blindness/debug-trace-full.png', 'APEX debug viewer: the complete LEVEL9 trace of one CAST_BALLOT request', { fullPage: true });
  await context.close();
  return true;
}

// ---------------------------------------------------------- one ballot request

const escapeHtml = (text) => String(text).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function requestCard(cfg, browser) {
  const file = evidencePath('h2-blindness/voter.har');
  if (!existsSync(file)) throw new Error('evidence/h2-blindness/voter.har is missing. Run tests/h2-blindness.mjs first.');
  const entries = JSON.parse(readFileSync(file, 'utf8')).log.entries;
  const index = entries.findIndex((e) => (e.request.postData?.text ?? '').includes('APPLICATION_PROCESS%3DCAST_BALLOT') || (e.request.postData?.text ?? '').includes('APPLICATION_PROCESS=CAST_BALLOT'));
  if (index < 0) throw new Error('No CAST_BALLOT request in evidence/h2-blindness/voter.har.');
  const entry = entries[index];
  const fields = [...new URLSearchParams(entry.request.postData.text)];
  const path = entry.request.url.replace(/^https?:\/\/[^/]+/, '');
  let ciphertext = 0;
  const rows = fields.map(([name, value]) => {
    const isCiphertext = name === 'f01';
    if (isCiphertext) ciphertext += 1;
    const label = isCiphertext ? `f01 <span>ciphertext ${ciphertext} of 3 · option ${LETTERS[ciphertext - 1]}</span>` : escapeHtml(name);
    const shown = isCiphertext ? value.match(/.{1,128}/g).map(escapeHtml).join('<br>') : escapeHtml(value);
    // A masked value no longer has its real length.
    const size = value.includes('<id>') ? 'masked' : value.length;
    return `<tr class="${isCiphertext ? 'enc' : ''}"><th>${label}</th><td>${shown}</td><td class="size">${size}</td></tr>`;
  }).join('');
  const html = `<!doctype html><meta charset="utf-8"><style>
    * { box-sizing: border-box; }
    body { margin: 0; padding: 40px 44px; background: #0A0A0A; color: #F2EFE8; font: 15px/1.5 "Segoe UI", system-ui, sans-serif; }
    h1 { margin: 0 0 4px; font-size: 26px; font-weight: 650; letter-spacing: -0.01em; }
    p { margin: 0; color: #A9A49A; }
    .line { margin: 22px 0 14px; padding: 12px 16px; border: 1px solid #2A2824; border-radius: 10px; background: #121210; font: 14px/1.5 Consolas, ui-monospace, monospace; }
    .line b { color: #E8B339; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; border: 1px solid #2A2824; border-radius: 10px; overflow: hidden; }
    th, td { padding: 9px 14px; border-bottom: 1px solid #1E1C19; vertical-align: top; text-align: left; }
    thead th { background: #161512; color: #A9A49A; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; font-weight: 600; }
    tbody th { width: 190px; font: 600 14px/1.5 Consolas, ui-monospace, monospace; color: #F2EFE8; white-space: nowrap; }
    tbody th span { display: block; font: 400 12px/1.4 "Segoe UI", system-ui, sans-serif; color: #A9A49A; }
    td { font: 13px/1.45 Consolas, ui-monospace, monospace; word-break: break-all; }
    tr.enc td { color: #E8B339; font-size: 11.5px; }
    td.size { width: 90px; text-align: right; color: #A9A49A; font-size: 13px; }
    .answer { margin-top: 14px; }
    footer { margin-top: 22px; color: #7C776E; font-size: 12.5px; }
    footer b { color: #F2EFE8; font-weight: 600; }
  </style>
  <h1>One ballot, as it left the browser</h1>
  <p>Every field of the request body. The voter chose one of three options. Which one is not in the request.</p>
  <div class="line"><b>${escapeHtml(entry.request.method)}</b> ${escapeHtml(path)} &nbsp;·&nbsp; ${escapeHtml(entry.request.postData.mimeType)} &nbsp;·&nbsp; ${entry.request.bodySize} bytes</div>
  <table><thead><tr><th>Field</th><th>Value</th><th style="text-align:right">Characters</th></tr></thead><tbody>${rows}</tbody></table>
  <div class="line answer"><b>${entry.response.status}</b> ${escapeHtml((entry.response.content.text ?? '').replace(/\s+/g, ''))}</div>
  <footer>Rendered from <b>evidence/h2-blindness/voter.har</b>, entry ${index + 1}, recorded by Playwright. Host, cookie and session id are masked in that file.</footer>`;
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await page.setContent(html, { waitUntil: 'load' });
  await shoot(page, 'h2-blindness/network-payload.png', 'One CAST_BALLOT request, field by field, rendered from the recorded HAR', { fullPage: true });
  await context.close();
}

// ----------------------------------------------------------------------- main

export async function run(cfg) {
  console.log('\nScreenshots');
  const browser = await launchBrowser(cfg);
  const dba = await connect(cfg, 'dba');
  try {
    const totals = await tour(cfg, browser);
    const expected = [0, 1, 2].map((option) => TOUR.filter((choice) => choice === option).length);
    if (totals.join() !== expected.join()) throw new Error(`The tour election decrypted to ${totals.join('/')} instead of ${expected.join('/')}.`);
    const pageView = await debugBallot(cfg, browser, dba);
    const builderDone = await builder(cfg, browser, dba, pageView);
    await requestCard(cfg, browser);
    writeText(cfg, 'app/README.txt', [
      header('Screenshots', [
        `browser: ${browser.bfChannel} ${browser.version()} (headless), taken by tests/screenshots.mjs`,
        `tour election: ${REGISTERED} registered voters, ${TOUR.length} ballots cast in the browser, decrypted tally ${totals.map((v, i) => `${LETTERS[i]}=${v}`).join(' ')}`,
        'builder pages: workspace, schema and account names, host and session ids are masked in the page before the shot',
        builderDone ? 'the script checks the page text after masking and refuses to save if a name is still visible' : 'builder screenshots were skipped: no workspace developer configured',
      ]),
      ...shots.map((s) => `evidence/${s.rel}\n    ${s.description}`),
      '',
    ].join('\n'));
    return shots;
  } finally {
    await dba.close();
    await browser.close();
  }
}

if (isMain(import.meta.url)) await main(async () => { parseArgs(); await run(loadConfig()); });
