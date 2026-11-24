// Worker thread for H11: builds honest ballots the way the browser does (voter key, encryption,
// proofs, signature), so that the 10,000 ballots of the tally measurement take minutes and not
// hours. Each worker gets a slice of the voters and sends back one ballot per voter.
import { parentPort, workerData } from 'node:worker_threads';
import * as P from './paillier.mjs';
import * as V from './validity.mjs';

const { nHex, electionId, jobs } = workerData;
const publicKey = P.publicKeyFromN(P.fromHex(nHex));
const out = [];
for (const job of jobs) {
  const voterKey = await V.generateVoterKey();
  const context = { electionId, ballotId: job.ballotId };
  const ballot = await V.proveChoice(publicKey, context, job.choice, 3);
  const wire = { ciphertexts: ballot.ciphertexts, bitProofs: ballot.bitProofs, sumProof: ballot.sumProof };
  const signature = await V.signBallot(voterKey.privateKey, publicKey, context, job.voter, wire);
  out.push({ ...job, ...wire, signature, publicKeyHex: voterKey.publicKeyHex });
  if (out.length % 50 === 0) parentPort.postMessage({ progress: 50 });
}
parentPort.postMessage({ done: out });
