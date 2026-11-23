/*
 * APEX Blindfold: the "What the database sees" page.
 * The two tables on this page are native APEX Classic Reports: their source
 * is the SELECT printed above each one, nothing else.
 */
import { callback, formatInt, mountChrome } from './shared.js';

export async function mount(root) {
  mountChrome(root, 'ledger');

  // The statistics are spread over two regions of the page, so look them up
  // in the whole document and not only inside the first region.
  const stat = (name) => document.querySelector(`[data-bf-stat="${name}"]`);

  const load = async () => {
    const info = await callback('ELECTION_INFO');
    const cipherChars = info.n_hex ? info.n_hex.length * 2 : 0; // a ciphertext is twice as wide as n
    stat('ballots').textContent = formatInt(info.ballot_rows / Math.max(info.candidates.length, 1));
    stat('rows').textContent = formatInt(info.ballot_rows);
    stat('bytes').textContent = formatInt(info.ballot_rows * cipherChars);
    stat('turnout').textContent = `${formatInt(info.turnout)} / ${formatInt(info.registered)}`;
  };

  const refresh = async () => {
    for (const id of ['bf-ballots', 'bf-roll']) {
      const region = apex.region(id);
      if (region) region.refresh();
    }
    await load();
  };

  root.querySelector('#bf-refresh').addEventListener('click', refresh);
  await load();
}
