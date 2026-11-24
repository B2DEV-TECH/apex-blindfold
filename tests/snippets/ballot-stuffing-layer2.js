// APEX Blindfold, Layer 2 - ballot stuffing from the browser console (hypothesis H7).
//
// Open the Vote page, open the browser console, paste this whole file, press Enter.
// It tries to cast ONE ballot worth as many votes as WEIGHTS says, the way the Layer 1
// snippet did (tests/snippets/ballot-stuffing.js). The difference: this attacker knows that
// the database now wants proofs and a signature, and builds them as well as anyone can.
//
// The signature is easy: the attacker is a registered voter and signs with a key of their own.
// The proofs are the problem. A proof that a ciphertext holds 0 or 1 can only be completed
// when it does. For any other value the attacker has to claim one of the two and hope.
//
// An honest ballot for option A is [1, 0, 0]. With that value this snippet casts a valid ballot.
//   [1000, 0, 0]  one voter, a thousand votes for A
//   [3, -2, 0]    three votes for A, minus two for B: the plaintexts still add up to 1
//   [1, 1, 0]     two options set to 1: every ciphertext is a bit, the sum is not 1
(async () => {
  const VOTER = 'VOTER-0011'; // a registered voter code that has not voted yet
  const WEIGHTS = [1000, 0, 0]; // what the three ciphertexts encrypt, for options A, B, C
  const SIGNATURE = 'own'; // 'own': signed with the key registered for VOTER; 'other': with a key nobody registered

  // The callbacks used here exist on the Vote page only (page 1 of the application).
  const page = document.getElementById('pFlowStepId')?.value;
  if (page && page !== '1') throw new Error('Paste this on the Vote page. This page has no CAST_BALLOT callback, so nothing was sent.');

  const base = document.querySelector('script[src*="blindfold/boot.js"]').src.replace(/boot\.js.*$/, '');
  const P = await import(`${base}paillier.js`);
  const V = await import(`${base}validity.js`);
  const call = (name, data) => new Promise((resolve, reject) => {
    apex.server.process(name, data, { dataType: 'json', success: resolve, error: (xhr, status, message) => reject(new Error(message || status)) });
  });

  const info = await call('ELECTION_INFO', {});
  const key = P.publicKeyFromN(P.fromHex(info.n_hex));

  // A signing key of the attacker's own, registered for the attacker's own voter code.
  const voterKey = await V.generateVoterKey();
  const reserved = await call('REGISTER_VOTER', { x01: VOTER, x02: voterKey.publicKeyHex });
  if (!reserved.ok) {
    console.log(`No ballot number for ${VOTER}. The database answered:`, reserved);
    return reserved;
  }
  const context = { electionId: reserved.election_id, ballotId: reserved.ballot_id };

  // For each ciphertext the attacker claims a bit: 1 where the weight is not zero, 0 where it is.
  const claims = WEIGHTS.map((weight) => (weight === 0 ? 0 : 1));
  const ballot = await V.proveBallot(key, context, WEIGHTS, { claims });
  const signer = SIGNATURE === 'other' ? await V.generateVoterKey() : voterKey;
  const signature = await V.signBallot(signer.privateKey, key, context, VOTER, ballot);

  const answer = await call('CAST_BALLOT', {
    x01: VOTER, x02: String(context.ballotId), x03: ballot.sumProof, x04: signature,
    f01: ballot.ciphertexts, f02: ballot.bitProofs,
  });
  console.log(`Ballot ${context.ballotId} for ${VOTER} with weights [${WEIGHTS.join(', ')}]. The database answered:`, answer);
  return answer;
})();
