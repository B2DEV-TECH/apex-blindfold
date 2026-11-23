// Worker thread that encrypts ballots for the bulk tests.
//
// Two paths produce the same ciphertext for the same (message, r):
//   pure         the library exactly as the browser runs it (BigInt only);
//   accelerated  the same library, except that r^n mod n^2 is computed by
//                OpenSSL through Node's built-in crypto module (about 25 times
//                faster). A sample of accelerated ciphertexts is recomputed
//                with the pure path and compared.
import { parentPort } from 'node:worker_threads';
import crypto from 'node:crypto';
import * as P from './paillier.mjs';

const toBuffer = (value) => {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, 'hex');
};

// r^n mod n^2 by OpenSSL: a Diffie-Hellman "shared secret" is peer^private mod p,
// so with p = n^2 and private = n the secret for peer r is r^n mod n^2.
function openSslPowN(publicKey) {
  try {
    const dh = crypto.createDiffieHellman(toBuffer(publicKey.nSquared), Buffer.from([2]));
    dh.setPrivateKey(toBuffer(publicKey.n));
    const powN = (r) => BigInt(`0x${dh.computeSecret(toBuffer(r)).toString('hex')}`);
    const probe = P.randomUnit(publicKey.n);
    return powN(probe) === P.modPow(probe, publicKey.n, publicKey.nSquared) ? powN : null;
  } catch {
    return null; // this OpenSSL build refuses the trick: stay on the pure path
  }
}

let cachedKey = null;
let cachedPowN = null;

parentPort.on('message', ({ id, nHex, jobs, verifyEvery }) => {
  try {
    if (!cachedKey || cachedKey.hex !== nHex) {
      const publicKey = P.publicKeyFromN(P.fromHex(nHex));
      cachedKey = { hex: nHex, publicKey };
      cachedPowN = openSslPowN(publicKey);
    }
    const { publicKey } = cachedKey;
    const stats = { pure: 0, accelerated: 0, verified: 0 };
    let sinceVerified = 0;

    const ballots = jobs.map(({ choice, pure }) => {
      const ballot = [];
      for (let option = 0; option < 3; option++) {
        const message = option === choice ? 1n : 0n;
        if (pure || !cachedPowN) {
          ballot.push(P.ciphertextToHex(publicKey, P.encrypt(publicKey, message)));
          stats.pure += 1;
          continue;
        }
        const r = P.randomUnit(publicKey.n);
        const ciphertext = P.encryptWithRandomizer(publicKey, message, cachedPowN(r));
        stats.accelerated += 1;
        sinceVerified += 1;
        if (sinceVerified >= verifyEvery) {
          sinceVerified = 0;
          const expected = P.encryptWithRandomizer(publicKey, message, P.modPow(r, publicKey.n, publicKey.nSquared));
          if (expected !== ciphertext) throw new Error('accelerated ciphertext differs from the pure BigInt ciphertext');
          stats.verified += 1;
        }
        ballot.push(P.ciphertextToHex(publicKey, ciphertext));
      }
      return ballot;
    });
    parentPort.postMessage({ id, ballots, stats, accelerated: Boolean(cachedPowN) });
  } catch (error) {
    parentPort.postMessage({ id, error: error.message });
  }
});
