/*
 * APEX Blindfold: the Vote page.
 *
 * The choice never becomes an APEX item and is never submitted. The browser
 * encrypts it into three Paillier ciphertexts and sends only those through the
 * CAST_BALLOT Ajax Callback.
 *
 * Layer 2: the ballot also carries proofs that it is an honest one (each
 * ciphertext holds 0 or 1, and together they hold 1) and a signature. The
 * voter key pair is generated here, its public half is registered for the
 * voter code, and the private half never leaves this tab: it cannot even be
 * exported from the object that holds it.
 */
import { P, V, callback, el, short, formatInt, repaint, pageUrl, mountChrome, say } from './shared.js';

export async function mount(root) {
  mountChrome(root, 'vote');

  const voterInput = root.querySelector('#bf-voter');
  const optionsBox = root.querySelector('#bf-options');
  const castButton = root.querySelector('#bf-cast');
  const message = root.querySelector('#bf-message');
  const wire = root.querySelector('#bf-wire');
  const ballotPanel = root.querySelector('#bf-ballot');
  const receiptPanel = root.querySelector('#bf-receipt');

  let publicKey = null;
  let choice = null; // zero-based index of the selected option. Lives in this variable only.
  let candidates = [];
  const voterKeys = new Map(); // voter code -> key pair, for a retry in this tab. Memory only.

  const log = (title, ...body) => {
    const item = el('li', { class: 'bf-wire__item' }, el('span', { class: 'bf-wire__title' }, title), ...body);
    wire.append(item);
    return item;
  };

  const refresh = () => {
    castButton.disabled = !publicKey || choice === null || voterInput.value.trim() === '';
  };

  const select = (index) => {
    choice = index;
    optionsBox.querySelectorAll('.bf-option').forEach((button, i) => {
      button.setAttribute('aria-checked', i === index ? 'true' : 'false');
      button.tabIndex = i === index || (index === null && i === 0) ? 0 : -1;
    });
    refresh();
  };

  // ---- load the public key and the options
  const info = await callback('ELECTION_INFO');
  candidates = info.candidates;
  candidates.forEach((candidate, index) => {
    optionsBox.append(el('button', {
      class: 'bf-option',
      type: 'button',
      role: 'radio',
      'aria-checked': 'false',
      tabindex: index === 0 ? 0 : -1,
      onclick: () => select(index),
    },
    el('span', { class: 'bf-option__letter' }, String.fromCharCode(65 + index)),
    el('span', { class: 'bf-option__body' },
      el('span', { class: 'bf-option__tag' }, candidate.tag),
      el('span', { class: 'bf-option__label' }, candidate.label)),
    el('span', { class: 'bf-option__check', 'aria-hidden': 'true' })));
  });

  // Arrow keys move between options, as in a native radio group.
  optionsBox.addEventListener('keydown', (event) => {
    const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[event.key];
    if (!step) return;
    event.preventDefault();
    const next = ((choice ?? -1) + step + candidates.length) % candidates.length;
    select(next);
    optionsBox.querySelectorAll('.bf-option')[next].focus();
  });

  if (!info.n_hex) {
    say(message, 'No election is open yet. The election authority has to publish a public key on the Tally page first.', 'error');
    log('Public key', el('span', { class: 'bf-wire__note' }, 'none published'));
    return;
  }

  publicKey = P.publicKeyFromN(P.fromHex(info.n_hex));
  log('Public key received',
    el('code', { class: 'bf-hex' }, `n = ${short(info.n_hex)}`),
    el('span', { class: 'bf-wire__note' }, `${publicKey.bits} bits. It can encrypt. It cannot decrypt.`));

  voterInput.addEventListener('input', refresh);
  // The page lives inside the APEX form: Enter must not submit anything.
  voterInput.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    if (!castButton.disabled) castButton.click();
  });

  // ---- encrypt in the browser, send three ciphertexts
  castButton.addEventListener('click', async () => {
    const voter = voterInput.value.trim().toUpperCase();
    castButton.disabled = true;
    // Keep only the public key entry: a retry starts a fresh log.
    wire.querySelectorAll('.bf-wire__item:not(:first-child)').forEach((item) => item.remove());
    say(message, 'Registering a signing key for this voter code…');
    await repaint();

    // ---- a key for this voter, and the ballot number the proofs are bound to
    if (!voterKeys.has(voter)) voterKeys.set(voter, await V.generateVoterKey());
    const voterKey = voterKeys.get(voter);
    let reserved;
    try {
      reserved = await callback('REGISTER_VOTER', { x01: voter, x02: voterKey.publicKeyHex });
    } catch (error) {
      reserved = { ok: false, message: error.message };
    }
    if (!reserved.ok) {
      log('Rejected by the database', el('span', { class: 'bf-wire__note' }, reserved.message)).classList.add('is-rejected');
      say(message, reserved.message, 'error');
      refresh();
      return;
    }
    const context = { electionId: reserved.election_id, ballotId: reserved.ballot_id };
    log('Voter key registered',
      el('code', { class: 'bf-hex' }, `public key = ${short(voterKey.publicKeyHex, 14, 8)}`),
      el('span', { class: 'bf-wire__note' }, `ECDSA P-256, made in this tab. The private half cannot be exported. Ballot number ${reserved.ballot_id} of election ${reserved.election_id} is reserved for ${voter}.`));

    say(message, 'Encrypting and proving in this browser…');
    await repaint();

    const started = performance.now();
    const proven = await V.proveChoice(publicKey, context, choice, candidates.length);
    const ballot = proven.ciphertexts;
    const parts = { ciphertexts: proven.ciphertexts, bitProofs: proven.bitProofs, sumProof: proven.sumProof };
    const signature = await V.signBallot(voterKey.privateKey, publicKey, context, voter, parts);
    const encryptMs = performance.now() - started;

    const table = el('table', { class: 'bf-cipher' },
      el('thead', {}, el('tr', {},
        el('th', {}, 'Option'),
        el('th', {}, 'Plaintext'),
        el('th', {}, 'Ciphertext sent'))),
      el('tbody', {}, ballot.map((hex, index) => el('tr', { class: index === choice ? 'is-choice' : null },
        el('td', {}, String.fromCharCode(65 + index)),
        el('td', {}, `Enc(${index === choice ? 1 : 0})`),
        el('td', {}, el('code', { class: 'bf-hex' }, short(hex, 14, 6)))))));
    log('Ballot encrypted here', table,
      el('span', { class: 'bf-wire__note' }, `${formatInt(Math.round(encryptMs))} ms. The Plaintext column exists on this screen only.`));

    log('Proofs and signature made here',
      el('code', { class: 'bf-hex' }, `3 bit proofs + 1 sum proof = ${formatInt(parts.bitProofs.join('').length + parts.sumProof.length)} hex characters`),
      el('code', { class: 'bf-hex' }, `signature = ${short(signature, 14, 8)}`),
      el('span', { class: 'bf-wire__note' }, `Each ciphertext holds 0 or 1, and together they hold 1. The proofs are valid for ballot ${context.ballotId} only, and they do not say which option holds the 1.`));

    log('Request sent',
      el('code', { class: 'bf-hex' }, `x01 = ${voter}, x02 = ballot ${context.ballotId}`),
      el('code', { class: 'bf-hex' }, `f01 = 3 ciphertexts, ${formatInt(ballot.join('').length)} hex characters`),
      el('code', { class: 'bf-hex' }, 'f02 = 3 bit proofs, x03 = sum proof, x04 = signature'),
      el('span', { class: 'bf-wire__note' }, 'Choice sent: none.'));

    let answer;
    try {
      answer = await callback('CAST_BALLOT', { x01: voter, x02: String(context.ballotId), x03: parts.sumProof, x04: signature, f01: parts.ciphertexts, f02: parts.bitProofs });
    } catch (error) {
      answer = { ok: false, message: error.message };
    }

    if (!answer.ok) {
      log('Rejected by the database', el('span', { class: 'bf-wire__note' }, answer.message)).classList.add('is-rejected');
      say(message, answer.message, 'error');
      refresh();
      return;
    }

    log('Verified and stored', el('span', { class: 'bf-wire__note' }, `Ballot ${answer.ballot_id}: the database checked the proofs and the signature, then stored three rows in BLIND_BALLOTS and one in BALLOT_SEALS.`));
    say(message, '');

    // ---- receipt
    root.querySelector('#bf-receipt-id').textContent = answer.ballot_id;
    root.querySelector('#bf-receipt-choice').textContent = `${String.fromCharCode(65 + choice)} · ${candidates[choice].label}`;
    root.querySelector('#bf-receipt-link').href = pageUrl('ledger');
    ballotPanel.hidden = true;
    receiptPanel.hidden = false;
    receiptPanel.querySelector('#bf-next').focus();
  });

  // ---- next voter: forget the choice, suggest the following code
  root.querySelector('#bf-next').addEventListener('click', () => {
    const match = voterInput.value.trim().match(/^(.*?)(\d+)$/);
    voterInput.value = match ? `${match[1]}${String(Number(match[2]) + 1).padStart(match[2].length, '0')}`.toUpperCase() : '';
    select(null);
    wire.querySelectorAll('.bf-wire__item:not(:first-child)').forEach((item) => item.remove());
    receiptPanel.hidden = true;
    ballotPanel.hidden = false;
    voterInput.focus();
  });

  refresh();
}
