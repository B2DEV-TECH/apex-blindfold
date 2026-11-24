// APEX Blindfold, Layer 2 - one ballot cast twice, under two voter codes (live session, hypothesis H7).
//
// Open the Vote page, open the browser console, paste this whole file, press Enter.
// It builds ONE honest ballot (CHOICE) for FIRST, with its proofs and signature, and casts it, as
// any voter would. Then it casts the very same ciphertexts and proofs again for SECOND, which
// registers a key of its own, gets a ballot number of its own and signs the copy correctly. Only
// the proofs are copied, and they were made for the ballot number of FIRST: every proof is bound to
// the election and to the ballot number it was made for, so the database rejects the copy.
//
// The Layer 1 version of this attack is tests/snippets/replay-ballot.js.
(async () => {
  const FIRST = 'VOTER-0012'; // a registered voter code that has not voted yet: casts the honest ballot
  const SECOND = 'VOTER-0013'; // another one: casts the copy, with a key and a signature of its own
  const CHOICE = [0, 1, 0]; // the honest ballot, for options A, B, C: here option B

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

  // Registers a signing key for a voter code and casts the ballot under the number it reserves.
  const castAs = async (voter, ballot) => {
    const voterKey = await V.generateVoterKey();
    const reserved = await call('REGISTER_VOTER', { x01: voter, x02: voterKey.publicKeyHex });
    if (!reserved.ok) return { reserved };
    const context = { electionId: reserved.election_id, ballotId: reserved.ballot_id };
    const made = ballot ?? await V.proveBallot(key, context, CHOICE);
    const signature = await V.signBallot(voterKey.privateKey, key, context, voter, made);
    const answer = await call('CAST_BALLOT', {
      x01: voter, x02: String(context.ballotId), x03: made.sumProof, x04: signature,
      f01: made.ciphertexts, f02: made.bitProofs,
    });
    return { ballot: made, ballotId: context.ballotId, answer };
  };

  const first = await castAs(FIRST, null);
  if (!first.answer) {
    console.log(`No ballot number for ${FIRST}. The database answered:`, first.reserved);
    return first.reserved;
  }
  console.log(`The honest ballot [${CHOICE.join(', ')}] for ${FIRST}, ballot ${first.ballotId}. The database answered:`, first.answer);
  if (!first.answer.ok) return { first: first.answer };

  const second = await castAs(SECOND, first.ballot);
  if (!second.answer) {
    console.log(`No ballot number for ${SECOND}. The database answered:`, second.reserved);
    return { first: first.answer, second: second.reserved };
  }
  console.log(`The same ciphertexts and proofs, made for ballot ${first.ballotId}, cast for ${SECOND} as ballot ${second.ballotId} with its own signature. The database answered:`, second.answer);
  return { first: first.answer, second: second.answer };
})();
