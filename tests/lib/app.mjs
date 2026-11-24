// Drives the APEX application in a real browser, the way a person would.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './config.mjs';

export const LETTERS = ['A', 'B', 'C'];

// URL of an application page. query: for example '?debug=LEVEL9'.
export function appUrl(cfg, alias, query = '') {
  return `${cfg.ords_base}/r/${cfg.workspace.toLowerCase()}/${(cfg.app_alias ?? 'blindfold').toLowerCase()}/${alias}${query}`;
}

// Reports JavaScript errors of a page to the test output.
export function watch(page, name, sink = console.log) {
  page.on('console', (message) => {
    if (message.type() === 'error') sink(`[${name}] console error: ${message.text().slice(0, 300)}`);
  });
  page.on('pageerror', (error) => sink(`[${name}] page error: ${error.message.slice(0, 300)}`));
}

const confirming = new WeakSet(); // pages that already accept confirmation dialogs

// The authority opens the Tally page and generates a key pair in the browser.
export async function openElectionInBrowser(page, cfg, voters, { debug = false } = {}) {
  await page.goto(appUrl(cfg, 'tally', debug ? '?debug=LEVEL9' : ''), { waitUntil: 'networkidle' });
  if (!confirming.has(page)) {
    confirming.add(page);
    page.on('dialog', (dialog) => dialog.accept()); // "this erases the stored ballots"
  }
  await page.waitForSelector('#bf-generate');
  await page.fill('#bf-voters', String(voters));
  await page.evaluate(() => document.querySelectorAll('#bf-key-facts .bf-fact').forEach((n) => n.setAttribute('data-old', '')));
  await page.click('#bf-generate');
  await page.waitForSelector('#bf-key-facts .bf-fact:not([data-old])', { timeout: 300000 });
}

// A voter casts one ballot through the Vote page. Returns the ballot id shown on the receipt.
export async function castInBrowser(page, voter, choice, { next = true } = {}) {
  await page.fill('#bf-voter', voter);
  await page.locator('.bf-option').nth(choice).click();
  await page.click('#bf-cast');
  await page.waitForSelector('#bf-receipt:not([hidden])', { timeout: 120000 });
  const ballotId = Number(await page.textContent('#bf-receipt-id'));
  if (next) await page.click('#bf-next');
  return ballotId;
}

// The authority asks for the encrypted totals and decrypts them. Returns what the page shows.
export async function tallyInBrowser(page) {
  const markOld = () => page.evaluate(() => document.querySelectorAll('#bf-totals .bf-total, #bf-results .bf-result').forEach((n) => n.setAttribute('data-old', '')));
  await markOld();
  await page.click('#bf-tally');
  await page.waitForSelector('#bf-totals .bf-total:not([data-old])', { timeout: 600000 });
  await page.click('#bf-decrypt');
  await page.waitForSelector('#bf-results .bf-result:not([data-old])', { timeout: 120000 });
  return {
    totals: await page.$$eval('.bf-result__votes', (nodes) => nodes.map((n) => Number(n.textContent.replace(/,/g, '')))),
    tallyStatus: (await page.textContent('#bf-tally-status')).trim(),
    decryptStatus: (await page.textContent('#bf-decrypt-status')).trim(),
    flagged: await page.$eval('#bf-decrypt-status', (n) => n.classList.contains('bf-message--error')),
  };
}

// A console snippet with its two settings replaced: the one of Layer 1 (ciphertexts only) or
// the one of Layer 2 (ciphertexts, proofs and a signature).
export function stuffingSnippet(voter, weights, file = 'ballot-stuffing.js') {
  const source = readFileSync(join(ROOT, 'tests', 'snippets', file), 'utf8');
  let replaced = 0;
  const patched = source
    .replace(/const VOTER = '[^']*';/, () => { replaced += 1; return `const VOTER = '${voter}';`; })
    .replace(/const WEIGHTS = \[[^\]]*\];/, () => { replaced += 1; return `const WEIGHTS = [${weights.join(', ')}];`; });
  if (replaced !== 2) throw new Error('The snippet settings were not found.');
  return patched;
}
