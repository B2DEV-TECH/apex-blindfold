// H8 - Completeness.
//
//   "In 100 seeded random elections every honest ballot is accepted, and the decrypted tally
//    equals the true result."
//
// The seed fixes the shape of every election: how many voters are registered, who abstains and
// what everyone votes. The cryptographic randomness (keys, encryption, proofs, signatures) comes
// from the system generator, as it does in the browser, and is different in every run.
//
// Every ballot goes the whole way: voter key, registration, ballot number, encryption, proofs,
// signature, bf_election.cast_ballot (which verifies before storing), and the tally (which
// verifies the chain and every ballot again before counting).
//
// Negative controls, one extra election:
//   a dishonest ballot among honest ones must be refused and must not be counted;
//   the comparison itself must notice a tally that is off by one vote.
//
//   node tests/h8-completeness.mjs [--quick] [--seed N]
import * as P from './lib/paillier.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect } from './lib/db.mjs';
import { openElection, prepareBallot, castBallot, tryCastBallot, encryptedTally, decryptTally, countChoices, honest, voterCode, seededRandom, currentElectionId } from './lib/election.mjs';
import { writeText, header } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h8-completeness';
const same = (a, b) => a.map(Number).join() === b.map(Number).join();

export async function run(cfg, args) {
  const report = new Report('H8', 'Completeness: in 100 seeded random elections every honest ballot is accepted and the decrypted tally equals the true result', DIR);
  const elections = args.quick ? 10 : 100;
  const bits = args.quick ? 1024 : 2048;
  const perKey = 10; // a new key pair every ten elections
  const random = seededRandom(args.seed);
  const pick = (n) => Math.floor(random() * n);
  const conn = await connect(cfg, 'schema');
  const lines = [];
  const started = Date.now();

  try {
    let pair = null;
    let ballots = 0;
    let accepted = 0;
    let counted = 0;
    let rejectedByTally = 0;
    let exact = 0;
    let abstentions = 0;
    const failures = [];

    for (let e = 1; e <= elections; e++) {
      if ((e - 1) % perKey === 0) pair = await P.generateKeyPair(bits);
      const key = pair.publicKey;
      const registered = 2 + pick(9); // 2 to 10 registered voters
      const choices = []; // null = abstains
      for (let v = 0; v < registered; v++) choices.push(pick(6) === 0 ? null : pick(3));
      if (choices.every((c) => c === null)) choices[0] = pick(3); // at least one ballot
      const cast = choices.filter((c) => c !== null);
      const truth = countChoices(cast);

      await openElection(conn, key, registered);
      const id = await currentElectionId(conn);
      let ok = 0;
      for (let v = 0; v < registered; v++) {
        if (choices[v] === null) continue;
        const answer = await tryCastBallot(conn, await prepareBallot(conn, key, voterCode(v), honest(choices[v]), { electionId: id }));
        if (answer.ok) ok += 1; else failures.push(`election ${id}, ${voterCode(v)}: ${answer.error}`);
      }
      await conn.commit();
      const tally = await encryptedTally(conn);
      const result = decryptTally(key, pair.privateKey, tally).map(Number);
      const right = same(result, truth) && tally.ballots_counted === cast.length && tally.ballots_rejected === 0;

      ballots += cast.length;
      accepted += ok;
      counted += tally.ballots_counted;
      rejectedByTally += tally.ballots_rejected;
      abstentions += registered - cast.length;
      if (right) exact += 1; else failures.push(`election ${id}: true ${truth.join('/')}, decrypted ${result.join('/')}, counted ${tally.ballots_counted}, rejected ${tally.ballots_rejected}`);
      lines.push(`${String(e).padStart(3)}  election ${String(id).padStart(4)}  registered ${String(registered).padStart(2)}  ballots ${String(cast.length).padStart(2)}  accepted ${String(ok).padStart(2)}  counted ${String(tally.ballots_counted).padStart(2)}  true ${truth.join('/').padEnd(7)}  decrypted ${result.join('/').padEnd(7)}  ${right ? 'equal' : 'DIFFERENT'}`);
      if (e % 10 === 0) console.log(`  ... ${e}/${elections} elections, ${ballots} ballots, ${Math.round((Date.now() - started) / 1000)} s`);
    }

    report.check(`every honest ballot was accepted by cast_ballot`, accepted === ballots, `${accepted}/${ballots} ballots in ${elections} elections`);
    report.check('the tally counted every honest ballot and rejected none', counted === ballots && rejectedByTally === 0, `${counted} counted, ${rejectedByTally} rejected, after verifying each one again`);
    report.check('the decrypted tally equals the true result in every election', exact === elections, `${exact}/${elections} elections`);
    for (const failure of failures.slice(0, 10)) report.note(failure);

    // ---- negative controls
    const key = pair.publicKey;
    const controlChoices = [0, 1, 1, 2];
    await openElection(conn, key, 6);
    const controlId = await currentElectionId(conn);
    for (let v = 0; v < controlChoices.length; v++) await castBallot(conn, await prepareBallot(conn, key, voterCode(v), honest(controlChoices[v]), { electionId: controlId }));
    const dishonest = await tryCastBallot(conn, await prepareBallot(conn, key, voterCode(4), [2, -1, 0], { claims: [1, 0, 0], electionId: controlId }));
    await conn.commit();
    const controlTally = await encryptedTally(conn);
    const controlResult = decryptTally(key, pair.privateKey, controlTally).map(Number);
    const controlTruth = countChoices(controlChoices);
    report.check('negative control: a dishonest ballot [2, -1, 0] among honest ones is refused and not counted',
      dishonest.ok === false && same(controlResult, controlTruth) && controlTally.ballots_counted === controlChoices.length, `${dishonest.error ?? 'ACCEPTED'}; tally ${controlResult.join('/')}`);
    const offByOne = [controlTruth[0] + 1, controlTruth[1] - 1, controlTruth[2]];
    report.check('negative control: the comparison notices a result that is off by one vote', !same(controlResult, offByOne), `decrypted ${controlResult.join('/')} against a wrong expectation ${offByOne.join('/')}`);

    const seconds = Math.round((Date.now() - started) / 1000);
    writeText(cfg, report.file(`${DIR}/elections.txt`), [
      header('H8: completeness', [
        `${elections} elections, seed ${args.seed}, ${bits}-bit keys, a new key pair every ${perKey} elections.`,
        'Each ballot: voter key, registration, ballot number, encryption, proofs, signature, cast_ballot, tally.',
        'true / decrypted: votes for A/B/C.',
      ]),
      ...lines,
      '',
      `ballots cast: ${ballots}    accepted: ${accepted}    counted by the tally: ${counted}    rejected by the tally: ${rejectedByTally}`,
      `registered voters who abstained: ${abstentions}`,
      `elections whose decrypted tally equals the true result: ${exact}/${elections}`,
      `negative control election ${controlId}: dishonest ballot answered "${dishonest.error ?? 'ACCEPTED'}", tally ${controlResult.join('/')}`,
      `time: ${seconds} s`,
      '',
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'REFUTED',
      statement: ok
        ? `${elections} random elections with ${bits}-bit keys: ${accepted} of ${ballots} honest ballots accepted, all ${counted} counted after a second verification, and the decrypted tally equal to the true result in ${exact} of ${elections}. A dishonest ballot placed among honest ones was refused.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { elections, key_bits: bits, ballots, accepted, counted, rejected_by_tally: rejectedByTally, exact, abstentions, seconds },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await conn.rollback();
    await conn.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
