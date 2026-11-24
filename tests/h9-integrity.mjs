// H9 - Integrity.
//
//   "A DBA cannot update, delete or move a stored vote. A forged or unsigned ballot is rejected.
//    Chain verification passes."
//
// Two accounts try: the owner of the tables and the auditor account with the DBA role.
// The DBA role is what this test has. SYSDBA and operating system access are another matter,
// and so is dropping the tables: H10.
//
// What a blockchain table does allow is INSERT. So the DBA also inserts ballots directly, and
// the question becomes whether the tally counts them.
//
// Negative control: the same UPDATE and DELETE, by the same two accounts, against an ordinary
// copy of the ballot table, must succeed. Without it, a refusal could come from a missing
// privilege and not from the blockchain table.
//
//   node tests/h9-integrity.mjs [--quick] [--seed N]
import * as P from './lib/paillier.mjs';
import * as V from './lib/validity.mjs';
import { loadConfig } from './lib/config.mjs';
import { connect, attempt } from './lib/db.mjs';
import { openElection, prepareBallot, castBallot, tryCastBallot, registerVoter, encryptedTally, decryptTally, countChoices, honest, voterCode, currentElectionId } from './lib/election.mjs';
import { writeText, header } from './lib/evidence.mjs';
import { parseArgs, Report, isMain, main } from './lib/harness.mjs';

const DIR = 'h9-integrity';
const CHOICES = [0, 0, 1, 1, 1, 2]; // six honest voters: 2 for A, 3 for B, 1 for C
const REGISTERED = 10;
const ora = (answer) => (answer.ok ? 'no error' : (answer.error.match(/^ORA-\d+/) ?? ['?'])[0]);

export async function run(cfg, args) {
  const report = new Report('H9', 'Integrity: a DBA cannot update, delete or move a stored vote; a forged or unsigned ballot is rejected; chain verification passes', DIR);
  const bits = args.quick ? 1024 : 2048;
  const owner = cfg.schema.toUpperCase();
  const conn = await connect(cfg, 'schema');
  const dba = await connect(cfg, 'dba');
  const lines = [];
  const scalar = async (c, sql, binds = {}) => Object.values((await c.execute(sql, binds)).rows[0])[0];

  try {
    const pair = await P.generateKeyPair(bits);
    const key = pair.publicKey;
    await openElection(conn, key, REGISTERED);
    const e = await currentElectionId(conn);
    for (let v = 0; v < CHOICES.length; v++) await castBallot(conn, await prepareBallot(conn, key, voterCode(v), honest(CHOICES[v]), { electionId: e }));
    await conn.commit();
    const truth = countChoices(CHOICES);
    const snapshot = async () => JSON.stringify([
      (await conn.execute('select ballot_id, candidate_id, vote_enc, bit_proof from blind_ballots where election_id = :e and ballot_id <= :n order by 1, 2', { e, n: CHOICES.length })).rows,
      (await conn.execute('select ballot_id, voter_id, sum_proof, signature from ballot_seals where election_id = :e and ballot_id <= :n order by 1', { e, n: CHOICES.length })).rows,
    ]);
    const before = await snapshot();

    // ---------------- A. change, remove or move a stored vote ----------------
    // The UPDATE of H5 multiplied a stored ciphertext by Enc(5): five more votes, no trace.
    const enc5 = P.ciphertextToHex(key, P.encrypt(key, 5n));
    const statements = (t) => [
      ['change a ciphertext (the attack of H5)', `update ${t}blind_ballots set vote_enc = :c where election_id = :e and ballot_id = 1 and candidate_id = 1`, { c: enc5, e }],
      ['move a vote to another option', `update ${t}blind_ballots set candidate_id = 3 where election_id = :e and ballot_id = 1 and candidate_id = 1`, { e }],
      ['move a ballot to another voter', `update ${t}ballot_seals set voter_id = 'VOTER-0009' where election_id = :e and ballot_id = 1`, { e }],
      ['replace a signature', `update ${t}ballot_seals set signature = signature where election_id = :e and ballot_id = 1`, { e }],
      ['delete one ballot', `delete from ${t}blind_ballots where election_id = :e and ballot_id = 1`, { e }],
      ['delete one seal', `delete from ${t}ballot_seals where election_id = :e and ballot_id = 1`, { e }],
      ['delete every ballot', `delete from ${t}blind_ballots`, {}],
      ['truncate the ballot table', `truncate table ${t}blind_ballots`, {}],
      ['truncate the seal table', `truncate table ${t}ballot_seals`, {}],
      ['merge into the ballot table', `merge into ${t}blind_ballots b using (select 1 as id from dual) s on (b.election_id = :e and b.ballot_id = s.id and b.candidate_id = 1) when matched then update set b.bit_proof = b.bit_proof`, { e }],
    ];
    const refusedBy = {};
    for (const [who, c, prefix] of [['owner', conn, ''], ['DBA', dba, `${owner}.`]]) {
      lines.push(`As the ${who}${who === 'DBA' ? ' (an account with the DBA role)' : ' of the tables'}:`);
      let refused = 0;
      const list = statements(prefix);
      for (const [name, sql, binds] of list) {
        const answer = await attempt(c, sql, binds);
        await c.rollback();
        if (!answer.ok) refused += 1;
        lines.push(`  ${name}`, `    ${sql.replace(`${owner}.`, '<owner>.')}`, `    -> ${answer.ok ? 'ACCEPTED' : answer.error}`);
        if (answer.ok) report.note(`${who}: "${name}" was accepted`);
      }
      refusedBy[who] = refused;
      report.check(`the ${who} cannot update, delete, move, truncate or merge a stored vote`, refused === list.length, `${refused}/${list.length} statements refused`);
      lines.push('');
    }
    const untouched = (await snapshot()) === before;
    report.check('the stored ballots are byte for byte what they were', untouched, `${CHOICES.length} ballots, ${CHOICES.length * 3} ciphertext rows and ${CHOICES.length} seals compared`);

    // ---------------- negative control: an ordinary table ----------------
    await attempt(conn, 'drop table bf_control_ballots purge');
    // DDL takes no bind variable: the copy is created empty and filled by an INSERT.
    await conn.execute('create table bf_control_ballots as select election_id, ballot_id, candidate_id, vote_enc from blind_ballots where 1 = 0');
    await conn.execute('insert into bf_control_ballots select election_id, ballot_id, candidate_id, vote_enc from blind_ballots where election_id = :e', { e });
    await conn.commit();
    const control = [];
    for (const [who, c, prefix] of [['owner', conn, ''], ['DBA', dba, `${owner}.`]]) {
      const update = await attempt(c, `update ${prefix}bf_control_ballots set vote_enc = :c where ballot_id = 1 and candidate_id = 1`, { c: enc5 });
      const remove = await attempt(c, `delete from ${prefix}bf_control_ballots where ballot_id = 2`);
      await c.rollback();
      control.push(update.ok && remove.ok);
      lines.push(`Negative control, ${who}: the same UPDATE and DELETE on BF_CONTROL_BALLOTS, an ordinary copy of the table`,
        `    -> update: ${update.ok ? 'accepted' : update.error}; delete: ${remove.ok ? 'accepted' : remove.error}`);
    }
    await conn.execute('drop table bf_control_ballots purge');
    report.check('negative control: on an ordinary copy of the table both accounts can update and delete', control.every(Boolean), 'the refusals above come from the blockchain table, not from a missing privilege');
    lines.push('');

    // ---------------- B. forged or unsigned, through the API ----------------
    const forger = await V.generateVoterKey();
    const good = await prepareBallot(conn, key, voterCode(6), honest(0), { electionId: e }); // registered, not cast
    const other = await V.proveBallot(key, good.context, honest(1));
    const flip = (hex, at) => `${hex.slice(0, at)}${hex[at] === '0' ? '1' : '0'}${hex.slice(at + 1)}`;
    const forgeries = [
      ['no signature', { ...good, signature: null }],
      ['a signature with one digit changed', { ...good, signature: flip(good.signature, 20) }],
      ['a signature made with another key', { ...good, signature: await V.signBallot(forger.privateKey, key, good.context, good.voter, good) }],
      ['the voter signature of another ballot (same voter, same number, another choice)', { ...good, signature: await V.signBallot(good.voterKey.privateKey, key, good.context, good.voter, other) }],
      ['a valid ballot in the name of a voter who registered no key', { ...good, voter: voterCode(7) }],
    ];
    let refused = 0;
    lines.push('Forged or unsigned ballots, through bf_election.cast_ballot:');
    for (const [name, ballot] of forgeries) {
      const answer = await tryCastBallot(conn, ballot);
      if (answer.code === 20007) refused += 1;
      lines.push(`  ${name}`, `    -> ${answer.error ?? 'ACCEPTED'}`);
    }
    await conn.commit(); // keeps the registration of voter 7 (code index 6): used below
    report.check('a forged or unsigned ballot is rejected by cast_ballot', refused === forgeries.length, `${refused}/${forgeries.length} rejected with ORA-20007`);
    lines.push('');

    // ---------------- C. what a blockchain table allows: INSERT ----------------
    // The DBA has the public key of the election, like everyone, and can build ballots whose
    // proofs are valid. What the DBA does not have is the private key of any voter.
    const insertBallot = async (ballotId, voter, ballot, signature) => {
      for (let i = 0; i < 3; i++) {
        await dba.execute(`insert into ${owner}.blind_ballots (election_id, ballot_id, candidate_id, vote_enc, bit_proof) values (:e, :b, :c, :v, :p)`,
          { e, b: ballotId, c: i + 1, v: ballot.ciphertexts[i], p: ballot.bitProofs[i] });
      }
      if (voter) await dba.execute(`insert into ${owner}.ballot_seals (election_id, ballot_id, voter_id, sum_proof, signature) values (:e, :b, :voter, :s, :g)`, { e, b: ballotId, voter, s: ballot.sumProof, g: signature });
    };
    const width = 4 * V.modulusBytes(key);
    const inserted = [];
    const tryInsert = async (name, ballotId, voter, build) => {
      try {
        const ballot = await build({ electionId: e, ballotId });
        const signature = voter ? await V.signBallot(forger.privateKey, key, { electionId: e, ballotId }, voter, ballot) : null;
        await insertBallot(ballotId, voter, ballot, signature);
        await dba.commit();
        inserted.push({ name, ballotId, ok: true });
      } catch (error) {
        await dba.rollback();
        inserted.push({ name, ballotId, ok: false, error: String(error.message).split('\n')[0] });
      }
    };
    await tryInsert('five votes for A, no proof, no voter', 9001, null, async () => ({
      ciphertexts: [5n, 0n, 0n].map((m) => P.ciphertextToHex(key, P.encrypt(key, m))), bitProofs: Array(3).fill('0'.repeat(64 + width)), sumProof: '0'.repeat(32 + width / 2),
    }));
    await tryInsert('a valid ballot in the name of a voter who never registered a key', 9002, voterCode(8), (context) => V.proveBallot(key, context, honest(0)));
    await tryInsert('a valid ballot in the name of a voter who registered and did not vote', 9003, voterCode(6), (context) => V.proveBallot(key, context, honest(0)));
    await tryInsert('a second ballot in the name of a voter who voted', 9004, voterCode(0), (context) => V.proveBallot(key, context, honest(0)));
    const went = inserted.filter((i) => i.ok).length;
    report.note(`the DBA could INSERT ${went} of ${inserted.length} forged ballots directly into the blockchain tables: INSERT is what such a table allows`);

    const chain = JSON.parse(await scalar(conn, 'select bf_election.verify_chains from dual'));
    const total = { ballots: await scalar(conn, 'select count(*) from blind_ballots'), seals: await scalar(conn, 'select count(*) from ballot_seals') };
    report.check('chain verification passes on both tables, over every row they hold', chain.blind_ballots === total.ballots && chain.ballot_seals === total.seals,
      `DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS: ${chain.blind_ballots} of ${total.ballots} ciphertext rows, ${chain.ballot_seals} of ${total.seals} seals`);

    const tally = await encryptedTally(conn);
    const result = decryptTally(key, pair.privateKey, tally).map(Number);
    report.check('the tally counts none of the ballots that the DBA inserted', tally.ballots_counted === CHOICES.length && tally.ballots_rejected === went,
      `${tally.ballots_counted} counted, ${tally.ballots_rejected} rejected`);
    report.check('the decrypted tally is the true result', result.join() === truth.join(), `true ${truth.join('/')}, decrypted ${result.join('/')}`);

    lines.push('Ballots inserted directly by the DBA (INSERT into the two blockchain tables):');
    for (const i of inserted) {
      const verdict = tally.rejected.find((r) => r.ballot_id === i.ballotId);
      lines.push(`  ballot ${i.ballotId}: ${i.name}`, `    -> insert: ${i.ok ? 'accepted' : i.error}`, `    -> tally:  ${verdict ? `not counted: ${verdict.reason}` : i.ok ? 'COUNTED' : 'nothing to count'}`);
    }
    lines.push('',
      `Chain verification: ${chain.blind_ballots} ciphertext rows and ${chain.ballot_seals} seals verified (all elections stored in the tables).`,
      `Tally of election ${e}: ${tally.ballots_counted} ballots counted, ${tally.ballots_rejected} rejected.`,
      `True result ${truth.join('/')}, decrypted ${result.join('/')}.`, '');

    writeText(cfg, report.file(`${DIR}/statements.txt`), [
      header('H9: integrity', [
        `Election ${e}, ${CHOICES.length} honest ballots, ${bits}-bit key. Tables: BLIND_BALLOTS and BALLOT_SEALS, blockchain tables.`,
        'The DBA here is an account with the DBA role. Dropping the tables, replacing a voter key or the',
        'verifier, SYSDBA and operating system access are measured or discussed in H10.',
      ]),
      ...lines,
    ].join('\n'));

    const ok = report.failed.length === 0;
    return report.close(cfg, {
      verdict: ok ? 'CONFIRMED' : 'REFUTED',
      statement: ok
        ? `The owner and an account with the DBA role had ${statements('').length} of ${statements('').length} UPDATE, DELETE, TRUNCATE and MERGE statements refused each, where an ordinary copy of the table accepted them. ${refused} of ${forgeries.length} forged or unsigned ballots were rejected. The DBA could still INSERT ${went} forged ballots; the tally counted none of them (${tally.ballots_counted} counted, ${tally.ballots_rejected} rejected) and the chain verified over ${chain.blind_ballots} rows.`
        : `${report.failed.length} check(s) failed: ${report.failed.map((c) => c.name).join('; ')}.`,
      numbers: { key_bits: bits, ballots: CHOICES.length, statements: statements('').length, refused_owner: refusedBy.owner, refused_dba: refusedBy.DBA, control_ordinary_table: control.every(Boolean), forgeries: forgeries.length, forgeries_rejected: refused, dba_inserts: inserted.length, dba_inserts_stored: went, tally_counted: tally.ballots_counted, tally_rejected: tally.ballots_rejected, chain_rows: chain.blind_ballots, chain_seals: chain.ballot_seals, truth, decrypted: result },
      mode: { quick: args.quick, seed: args.seed },
    });
  } finally {
    await attempt(conn, 'drop table bf_control_ballots purge');
    await conn.rollback();
    await dba.rollback();
    await conn.close();
    await dba.close();
  }
}

if (isMain(import.meta.url)) await main(async () => run(loadConfig(), parseArgs()));
