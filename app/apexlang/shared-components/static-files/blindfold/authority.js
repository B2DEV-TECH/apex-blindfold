/*
 * APEX Blindfold: the Tally page, for the election authority.
 *
 * The key pair is generated in this browser tab. The public key n is published
 * to the database. The private key stays in the `keyPair` variable below: it
 * is never written to a page item, to session state, to browser storage or to
 * a request. Reload or close the tab and it is gone.
 */
import { P, callback, el, short, formatInt, repaint, mountChrome, say } from './shared.js';

let keyPair = null; // { publicKey, privateKey }: memory only

const LIVE_REFRESH_MS = 15000;

export async function mount(root) {
  mountChrome(root, 'tally');

  const $ = (selector) => root.querySelector(selector);
  const keyButton = $('#bf-generate');
  const keyStatus = $('#bf-key-status');
  const keyFacts = $('#bf-key-facts');
  const votersInput = $('#bf-voters');
  const liveLine = $('#bf-live');
  const tallyButton = $('#bf-tally');
  const tallyStatus = $('#bf-tally-status');
  const totalsBox = $('#bf-totals');
  const decryptButton = $('#bf-decrypt');
  const decryptStatus = $('#bf-decrypt-status');
  const resultsBox = $('#bf-results');

  // A failed request must never take this tab away from the page: the private
  // key would go with it. Failures become ordinary answers with ok = false.
  const ask = async (name, data) => {
    try {
      return await callback(name, data);
    } catch (error) {
      const advice = keyPair ? ' Keep this tab open: the private key exists only here.' : '';
      return { ok: false, message: `${error.message}.${advice}` };
    }
  };

  let info = { ok: false, candidates: [], ballot_rows: 0, registered: 0, turnout: 0, n_hex: null };
  let encrypted = null; // last answer of ENCRYPTED_TALLY

  const showLive = () => {
    if (!info.ok) {
      liveLine.textContent = '';
    } else if (!info.n_hex) {
      liveLine.textContent = 'No election is open.';
    } else {
      liveLine.textContent = `${formatInt(info.turnout)} of ${formatInt(info.registered)} voters have cast a ballot · ${formatInt(info.ballot_rows)} ciphertexts stored`;
    }
  };

  const refreshInfo = async () => {
    const answer = await ask('ELECTION_INFO');
    if (answer.ok) info = answer;
    showLive();
    return answer;
  };

  const describePublished = () => {
    if (keyPair) return;
    if (!info.ok) {
      say(keyStatus, 'The election status could not be read.', 'error');
    } else if (info.n_hex) {
      say(keyStatus, `An election is open with public key ${short(info.n_hex, 12, 8)}, but this tab does not hold its private key. Totals can be fetched here. They cannot be decrypted.`, 'error');
    } else {
      say(keyStatus, 'No election is open. Generate a key pair to open one.');
    }
  };

  await refreshInfo();
  describePublished();

  // Turnout is public information: keep it current while ballots arrive.
  window.setInterval(refreshInfo, LIVE_REFRESH_MS);

  // Leaving the page destroys the private key: ask first. The browser words
  // that question itself, and its text says nothing about a key.
  window.addEventListener('beforeunload', (event) => {
    if (!keyPair) return;
    event.preventDefault();
    event.returnValue = '';
  });

  // So the page does not rely on the question alone. Once this tab holds a
  // key, its own links open beside it instead of replacing it, and the title
  // tells this tab apart from the others.
  const pageTitle = document.title;
  const keepThisTab = () => {
    for (const link of root.querySelectorAll('.bf-top a')) {
      link.target = '_blank';
      link.rel = 'noopener';
      link.title = 'Opens in a new tab: this tab holds the private key';
    }
    document.title = `Key holder · ${pageTitle}`;
  };

  // ---- 1. key pair: generated here, only n goes to the database
  keyButton.addEventListener('click', async () => {
    const voters = Number(votersInput.value);
    if (!Number.isInteger(voters) || voters < 1 || voters > 100000) {
      say(keyStatus, 'The number of voters must be between 1 and 100000.', 'error');
      return;
    }
    if (info.ballot_rows > 0 && !window.confirm(`Opening a new election closes this one. Its ${formatInt(info.ballot_rows / 3)} ballots stay stored, they cannot be removed, and they will never be counted. Continue?`)) {
      return;
    }

    keyButton.disabled = true;
    let candidatesTested = 0;
    const started = performance.now();
    say(keyStatus, 'Searching for two 1024-bit primes in this browser…');
    const pair = await P.generateKeyPair(2048, {
      onCandidate: () => {
        candidatesTested += 1;
      },
      pause: async () => {
        keyStatus.textContent = `Searching for two 1024-bit primes in this browser… ${formatInt(candidatesTested)} candidates tested`;
        await repaint();
      },
    });
    const elapsed = performance.now() - started;

    // Only the public modulus n travels. The primes stay in `pair`.
    const answer = await ask('OPEN_ELECTION', { x01: P.toHex(pair.publicKey.n), x02: String(voters) });
    keyButton.disabled = false;
    if (!answer.ok) {
      say(keyStatus, answer.message, 'error');
      return;
    }

    keyPair = pair;
    keepThisTab();
    encrypted = null;
    await refreshInfo();
    totalsBox.replaceChildren();
    resultsBox.replaceChildren();
    say(tallyStatus, '');
    say(decryptStatus, '');
    decryptButton.disabled = true;

    say(keyStatus, `Key pair generated in ${formatInt(Math.round(elapsed))} ms after ${formatInt(candidatesTested)} prime candidates. Election open.`, 'ok');
    keyFacts.replaceChildren(
      el('div', { class: 'bf-fact' },
        el('span', { class: 'bf-fact__name' }, 'Public key n'),
        el('code', { class: 'bf-hex' }, short(P.toHex(pair.publicKey.n), 24, 12)),
        el('span', { class: 'bf-fact__where' }, `${pair.publicKey.bits} bits · published to ELECTION_KEY`)),
      el('div', { class: 'bf-fact bf-fact--secret' },
        el('span', { class: 'bf-fact__name' }, 'Private key'),
        el('code', { class: 'bf-hex' }, '•••••••• not shown, not stored, not sent'),
        el('span', { class: 'bf-fact__where' }, 'λ and μ live in the memory of this tab only · reload and they are gone')),
      el('div', { class: 'bf-fact' },
        el('span', { class: 'bf-fact__name' }, 'Voter codes'),
        el('code', { class: 'bf-hex' }, `VOTER-0001 … VOTER-${String(voters).padStart(4, '0')}`),
        el('span', { class: 'bf-fact__where' }, `${formatInt(voters)} registered in VOTER_ROLL`)));
  });

  // ---- 2. the database multiplies ciphertexts and returns encrypted totals
  tallyButton.addEventListener('click', async () => {
    tallyButton.disabled = true;
    say(tallyStatus, 'The database is verifying the chain, every proof and every signature, then multiplying ciphertexts…');
    const started = performance.now();
    const answer = await ask('ENCRYPTED_TALLY');
    const elapsed = performance.now() - started;
    tallyButton.disabled = false;
    if (!answer.ok) {
      say(tallyStatus, answer.message, 'error');
      return;
    }
    encrypted = answer;
    await refreshInfo();
    resultsBox.replaceChildren();
    say(decryptStatus, '');

    const tally = answer.tally;
    const audit = `Chain verified: ${formatInt(tally.chain.blind_ballots)} ciphertext rows and ${formatInt(tally.chain.ballot_seals)} seals. Proofs and signatures checked again: ${formatInt(tally.ballots_counted)} ballots counted, ${formatInt(tally.ballots_rejected)} rejected.`;
    say(tallyStatus, `${audit} ${formatInt(Math.round(elapsed))} ms. The database still does not know the result.`, tally.ballots_rejected > 0 ? 'error' : 'ok');
    totalsBox.replaceChildren(...tally.totals.map((total, index) => el('div', { class: 'bf-total' },
      el('span', { class: 'bf-total__letter' }, String.fromCharCode(65 + index)),
      el('span', { class: 'bf-total__label' }, info.candidates[index].label),
      el('code', { class: 'bf-hex' }, short(total.total_enc, 28, 12)))));
    if (tally.rejected.length > 0) {
      totalsBox.append(el('ul', { class: 'bf-rejected' }, tally.rejected.map((r) => el('li', {},
        `Ballot ${r.ballot_id}${r.voter_id ? ` (${r.voter_id})` : ''} was not counted: ${r.reason}.`))));
    }
    decryptButton.disabled = !keyPair;
    if (!keyPair) say(decryptStatus, 'This tab holds no private key, so these totals stay encrypted.', 'error');
  });

  // ---- 3. only the key holder can turn the totals into numbers
  decryptButton.addEventListener('click', async () => {
    if (!keyPair || !encrypted) return;
    if (info.n_hex !== P.toHex(keyPair.publicKey.n)) {
      say(decryptStatus, 'The published public key changed. The private key in this tab belongs to another election.', 'error');
      return;
    }
    decryptButton.disabled = true;
    say(decryptStatus, 'Decrypting three totals in this browser…');
    await repaint();

    const { publicKey, privateKey } = keyPair;
    const started = performance.now();
    const totals = encrypted.tally.totals.map((total) => {
      const value = P.decrypt(publicKey, privateKey, P.ciphertextFromHex(publicKey, total.total_enc));
      // Plaintexts live modulo n: a value in the upper half is a negative number.
      return value > publicKey.n / 2n ? value - publicKey.n : value;
    });
    const elapsed = performance.now() - started;
    decryptButton.disabled = false;

    const sum = totals.reduce((a, b) => a + b, 0n);
    const scale = totals.reduce((a, b) => (b > a ? b : a), 1n);
    resultsBox.replaceChildren(...totals.map((value, index) => {
      const share = sum > 0n && value >= 0n ? Math.round((Number(value) * 1000) / Number(sum)) / 10 : 0;
      const width = value > 0n ? Math.max(2, Number((value * 100n) / scale)) : 0;
      return el('div', { class: 'bf-result' },
        el('span', { class: 'bf-result__letter' }, String.fromCharCode(65 + index)),
        el('span', { class: 'bf-result__label' }, info.candidates[index].label),
        el('span', { class: 'bf-result__votes' }, formatInt(value)),
        el('span', { class: 'bf-result__share' }, `${share.toFixed(1)}%`),
        el('span', { class: 'bf-result__bar' }, el('span', { style: `width:${width}%` })));
    }));

    // The only sanity check a blind tally allows: totals must add up to turnout.
    // Layer 2: the reference is the number of ballots that passed verification.
    const turnout = BigInt(encrypted.tally.ballots_counted);
    const plausible = sum === turnout && totals.every((value) => value >= 0n && value <= turnout);
    if (plausible) {
      say(decryptStatus, `Decrypted in ${formatInt(Math.round(elapsed))} ms. ${formatInt(sum)} votes from ${formatInt(turnout)} verified ballots.`, 'ok');
    } else {
      say(decryptStatus, `Decrypted in ${formatInt(Math.round(elapsed))} ms. ${formatInt(sum)} votes from ${formatInt(turnout)} verified ballots: these totals cannot come from honest ballots, although every counted ballot passed its proofs.`, 'error');
    }
  });
}
