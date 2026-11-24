// G1 - Cross-implementation test vectors.
//
//   "The Java verifier reproduces the challenge hashes of the browser byte for byte."
//
// tests/vectors/layer2-vectors.json holds fixed ballots that a browser exported, with their proofs,
// challenge hashes and signatures (tests/vectors/export-vectors.mjs). Nothing here computes a hash
// in JavaScript: every value compared comes from the file on one side and from the Java stored
// procedure in the database on the other. No hypothesis of Layer 2 runs before this passes.
//
// For every sample the database is asked for
//   - the challenge hash of each bit proof and of the sum proof, from the commitments, as the
//     prover computed them (the encoding alone);
//   - the same hashes from the stored proofs, as a verifier recomputes them (encoding and arithmetic);
//   - its verdict on the ballot;
//   - the SHA-256 of the bytes the voter signs, and its verdict on the signature.
//
// Negative controls: the same comparisons on vectors that were altered on purpose must fail.
//
//   node tests/g1-vectors.mjs
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, ROOT } from './lib/config.mjs';
import { connect, oracledb } from './lib/db.mjs';
import { writeText, writeJson, header } from './lib/evidence.mjs';
import { Report, isMain, main } from './lib/harness.mjs';

const DIR = 'g1-test-vectors';
const FILE = join(ROOT, 'tests', 'vectors', 'layer2-vectors.json');
const OUT = { dir: oracledb.BIND_OUT, type: oracledb.STRING, maxSize: 400 };

// One round trip per sample: everything the Java class says about it.
const ASK = `begin
  :bit1 := bf_v2_bit_challenge(:n, :made_election, :made_ballot, 1, :c1, :a10, :a11);
  :bit2 := bf_v2_bit_challenge(:n, :made_election, :made_ballot, 2, :c2, :a20, :a21);
  :bit3 := bf_v2_bit_challenge(:n, :made_election, :made_ballot, 3, :c3, :a30, :a31);
  :sum  := bf_v2_sum_challenge(:n, :made_election, :made_ballot, :c1, :c2, :c3, :asum);
  :vbit1 := bf_v2_bit_digest(:n, :election, :ballot, 1, :c1, :p1);
  :vbit2 := bf_v2_bit_digest(:n, :election, :ballot, 2, :c2, :p2);
  :vbit3 := bf_v2_bit_digest(:n, :election, :ballot, 3, :c3, :p3);
  :vsum  := bf_v2_sum_digest(:n, :election, :ballot, :c1, :c2, :c3, :psum);
  :verdict := bf_v2_verify_ballot(:n, :election, :ballot, :c1, :c2, :c3, :p1, :p2, :p3, :psum);
  :signed := bf_v2_ballot_digest(:n, :election, :ballot, :voter, :c1, :c2, :c3, :p1, :p2, :p3, :psum);
  :signature_verdict := bf_v2_verify_signature(:public_key, :signature, :n, :election, :ballot, :voter, :c1, :c2, :c3, :p1, :p2, :p3, :psum);
end;`;

async function ask(conn, set, s) {
  const result = await conn.execute(ASK, {
    n: set.n_hex,
    made_election: s.made_for.election_id,
    made_ballot: s.made_for.ballot_id,
    election: s.presented_as.election_id,
    ballot: s.presented_as.ballot_id,
    voter: s.voter_id,
    c1: s.ciphertexts[0], c2: s.ciphertexts[1], c3: s.ciphertexts[2],
    p1: s.bit_proofs[0], p2: s.bit_proofs[1], p3: s.bit_proofs[2], psum: s.sum_proof,
    a10: s.prover.bits[0].a0, a11: s.prover.bits[0].a1,
    a20: s.prover.bits[1].a0, a21: s.prover.bits[1].a1,
    a30: s.prover.bits[2].a0, a31: s.prover.bits[2].a1,
    asum: s.prover.sum.a,
    public_key: s.voter_public_key,
    signature: s.signature,
    bit1: OUT, bit2: OUT, bit3: OUT, sum: OUT, vbit1: OUT, vbit2: OUT, vbit3: OUT, vsum: OUT, verdict: OUT, signed: OUT, signature_verdict: OUT,
  });
  const o = result.outBinds;
  return {
    proverBits: [o.bit1, o.bit2, o.bit3],
    proverSum: o.sum,
    verifierBits: [o.vbit1, o.vbit2, o.vbit3],
    verifierSum: o.vsum,
    verdict: o.verdict,
    signed: o.signed,
    signatureVerdict: o.signature_verdict,
  };
}

// The comparisons of one sample. Returns { hashes: compared, equal, ... }.
function compare(s, java) {
  const pairs = [
    ...s.prover.bits.map((b, i) => [`prover, bit proof ${i + 1}`, b.challenge_hash, java.proverBits[i]]),
    ['prover, sum proof', s.prover.sum.challenge_hash, java.proverSum],
    ...s.verifier.bit_challenge_hashes.map((h, i) => [`verifier, bit proof ${i + 1}`, h, java.verifierBits[i]]),
    ['verifier, sum proof', s.verifier.sum_challenge_hash, java.verifierSum],
    ['bytes the voter signs', s.signed_bytes_sha256, java.signed],
  ];
  const different = pairs.filter(([, browser, database]) => browser !== database);
  return {
    hashes: pairs.length,
    equal: pairs.length - different.length,
    different,
    verdictAgrees: (java.verdict === 'OK') === s.verifier.valid,
    signatureOk: java.signatureVerdict === 'OK',
  };
}

// Changes one hexadecimal digit, keeping the text well formed.
const flip = (hexText, at) => `${hexText.slice(0, at)}${hexText[at] === '0' ? '1' : '0'}${hexText.slice(at + 1)}`;

export async function run(cfg) {
  const report = new Report('G1', 'Test vectors: the Java verifier reproduces the challenge hashes of the browser byte for byte', DIR);
  const vectors = JSON.parse(readFileSync(FILE, 'utf8'));
  const conn = await connect(cfg, 'schema');
  const lines = [];
  let hashes = 0;
  let equal = 0;
  let samples = 0;
  let verdicts = 0;
  let signatures = 0;
  let accepted = 0;
  let rejected = 0;

  try {
    for (const set of vectors.sets) {
      lines.push(`Key of ${set.modulus_bits} bits, seed ${set.seed}`, '');
      for (const s of set.samples) {
        const java = await ask(conn, set, s);
        const c = compare(s, java);
        samples += 1;
        hashes += c.hashes;
        equal += c.equal;
        if (c.verdictAgrees) verdicts += 1;
        if (c.signatureOk) signatures += 1;
        if (java.verdict === 'OK') accepted += 1; else rejected += 1;
        lines.push(
          `  ${s.name}`,
          `    plaintexts [${s.plaintexts.join(', ')}], made for election ${s.made_for.election_id} ballot ${s.made_for.ballot_id}, presented as election ${s.presented_as.election_id} ballot ${s.presented_as.ballot_id}`,
          `    challenge hashes equal, browser and database: ${c.equal}/${c.hashes}`,
          ...c.different.map(([what, browser, database]) => `      DIFFERENT ${what}: browser ${browser}  database ${database}`),
          `      sum proof, as the prover hashed it:  browser  ${s.prover.sum.challenge_hash}`,
          `                                           database ${java.proverSum}`,
          `    verdict: browser ${s.verifier.valid ? 'OK' : `FAIL ${s.verifier.reason}`}`,
          `             database ${java.verdict}`,
          `    signature: database ${java.signatureVerdict}`,
          '',
        );
      }
    }
    const expected = vectors.sets.flatMap((set) => set.samples);
    report.check('every challenge hash and every signed-bytes hash is the same in the browser and in the database', equal === hashes && hashes > 0, `${equal}/${hashes} hashes of 32 bytes, ${samples} samples`);
    report.check('the database accepts and rejects the same ballots as the browser', verdicts === samples, `${verdicts}/${samples}: ${accepted} accepted, ${rejected} rejected`);
    report.check('the samples contain both valid and invalid ballots', expected.some((s) => s.expected_valid) && expected.some((s) => !s.expected_valid), `${expected.filter((s) => s.expected_valid).length} valid, ${expected.filter((s) => !s.expected_valid).length} invalid`);
    report.check('the database verifies every WebCrypto signature', signatures === samples, `${signatures}/${samples} ECDSA P-256 signatures in P1363 format`);

    // ---- negative controls: altered vectors must be caught
    const set = vectors.sets[vectors.sets.length - 1];
    const good = set.samples[0];
    const controls = [];
    const control = async (name, altered, caught, detail) => {
      const java = await ask(conn, set, altered);
      const c = compare(altered, java);
      const ok = caught(c, java);
      controls.push(`  ${name}: ${ok ? 'caught' : 'NOT CAUGHT'} (${detail(c, java)})`);
      report.check(`negative control: ${name}`, ok, detail(c, java));
    };
    await control('one digit of a ciphertext changed, the recorded hashes no longer match',
      { ...good, ciphertexts: [flip(good.ciphertexts[0], 700), good.ciphertexts[1], good.ciphertexts[2]] },
      (c, java) => c.equal < c.hashes && java.verdict !== 'OK' && !c.signatureOk,
      (c, java) => `${c.hashes - c.equal} of ${c.hashes} hashes differ; ballot: ${java.verdict}; signature: ${java.signatureVerdict}`);
    await control('one digit of a response changed, the ballot is rejected',
      { ...good, bit_proofs: [flip(good.bit_proofs[0], 200), good.bit_proofs[1], good.bit_proofs[2]] },
      (c, java) => java.verdict !== 'OK' && c.equal < c.hashes,
      (c, java) => `${c.hashes - c.equal} of ${c.hashes} hashes differ; ballot: ${java.verdict}`);
    await control('the ballot number changed, the hashes change',
      { ...good, made_for: { ...good.made_for, ballot_id: good.made_for.ballot_id + 1 }, presented_as: { ...good.presented_as, ballot_id: good.presented_as.ballot_id + 1 } },
      (c, java) => c.equal === 0 && java.verdict !== 'OK',
      (c, java) => `${c.hashes - c.equal} of ${c.hashes} hashes differ; ballot: ${java.verdict}`);
    await control('one digit of the signature changed, the signature is rejected',
      { ...good, signature: flip(good.signature, 40) },
      (c, java) => !c.signatureOk && java.verdict === 'OK',
      (c, java) => `signature: ${java.signatureVerdict}; ballot: ${java.verdict}`);
    await control('the signature presented with another voter code is rejected',
      { ...good, voter_id: 'VOTER-9999' },
      (c, java) => !c.signatureOk && java.verdict === 'OK',
      (c, java) => `signature: ${java.signatureVerdict}; ballot: ${java.verdict}`);
    await control('the signature checked against another voter key is rejected',
      { ...good, voter_public_key: set.samples[1].voter_public_key },
      (c, java) => !c.signatureOk,
      (c, java) => `signature: ${java.signatureVerdict}`);

    writeText(cfg, report.file(`${DIR}/vectors.txt`), [
      header('G1: cross-implementation test vectors', [
        `Vector file: tests/vectors/layer2-vectors.json, exported by ${vectors.exported_by}, reproduced by ${vectors.reproduced_by}.`,
        'Left side of every comparison: the file. Right side: the Java stored procedure BlindfoldValidity in the database.',
        'A challenge hash is the SHA-256 of the framed fields; the challenge is its first 128 bits.',
      ]),
      ...lines,
      'Negative controls: the same comparisons on vectors altered on purpose',
      '',
      ...controls,
      '',
    ].join('\n'));

    const ok = report.failed.length === 0;
    const result = {
      id: 'G1',
      gate: report.hypothesis,
      verdict: ok ? 'PASS' : 'FAIL',
      statement: ok
        ? `The Java verifier in the database reproduced ${equal}/${hashes} hashes of the browser byte for byte, over ${samples} fixed ballots in ${vectors.sets.length} key sizes (${vectors.sets.map((v) => v.modulus_bits).join(' and ')} bits), agreed with the browser on every verdict (${accepted} accepted, ${rejected} rejected) and verified ${signatures}/${samples} WebCrypto signatures. ${controls.length} altered vectors were all caught.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { samples, hashes_compared: hashes, hashes_equal: equal, verdicts_agree: verdicts, accepted, rejected, signatures_verified: signatures, negative_controls: controls.length, exported_by: vectors.exported_by },
      checks: report.checks,
      evidence: report.files,
      started: report.started.toISOString(),
      finished: new Date().toISOString(),
    };
    writeJson(cfg, `${DIR}/result.json`, result);
    console.log(`  => G1 ${result.verdict}: ${result.statement}`);
    if (!ok) process.exitCode = 1;
    return result;
  } finally {
    await conn.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig()));
