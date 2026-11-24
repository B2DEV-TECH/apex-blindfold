# Layer 2: decision log

Every design decision of Layer 2 (ballot validity and ballot integrity) is recorded here: the date,
the options that were on the table, what Geraldo Viana Jr chose, and his reason in his own words.
The assistant that writes the code proposes and measures. It does not decide.

His reasons are in Portuguese, as he typed them, with typing slips corrected and nothing else
changed. The English is a translation. Where he gave no reason, the log says so.

## Gate G0: design review, 24 November 2026

Before the review, a throwaway probe ran on the lab database (Oracle AI Database 26ai Free
23.26.3.0.0 on Windows, `compatible` 23.6.0). It created a temporary user, tested inside it and
dropped it. Its numbers are scratch measurements, not lab evidence; the hypotheses measure them
again. What it found, and what the decisions below rest on:

- `CREATE BLOCKCHAIN TABLE` version 2 with `NO DROP UNTIL 0 DAYS IDLE` works, with a primary key, a
  foreign key and a `VARCHAR2(1024)` column. The licensing manual of 26ai neither lists nor
  restricts the feature for the Free offering, so the database was asked.
- `UPDATE`, `DELETE`, `TRUNCATE` and `MERGE` are refused with `ORA-05715`, for the owner and for a
  DBA.
- A DBA can `INSERT` a row, and `DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS` still passes.
- A DBA can drop the table right after an insert and create another one with a valid chain.
- The owner can disable the primary key and drop the foreign key of a blockchain table.
- Every row gets a hidden creation timestamp and the number of the inserting database user.
- The database JVM (11.0.32) verifies a WebCrypto ECDSA P-256 signature with
  `SHA256withECDSAinP1363Format` (provider SunEC), and its SHA-256 equals the WebCrypto digest.

| # | Decision | Options | Chosen | His reason |
|---|---|---|---|---|
| 1 | Form of the stored proof | **A.** Compact: challenges and responses only; the verifier recomputes the commitments. **B.** Complete: commitments stored as well, about three times larger. | **A** | "A pela simplicidade e performance." (A, for simplicity and performance.) |
| 2 | Challenge size and smallest modulus | **A.** 128-bit challenge; `open_election` accepts a modulus of 512 bits or more (it accepted 256). **B.** 128-bit challenge; 2048 bits or more. **C.** 120-bit challenge; the 256-bit minimum stays. | **A** | "Velocidade." (Speed.) |
| 3 | Bytes that enter the Fiat-Shamir hash | **A.** A domain label, then every field as a 4-byte length followed by its bytes, integers at fixed width. **B.** Hexadecimal text joined with a separator. | **A** | "Confiabilidade." (Reliability.) |
| 4 | Origin of `ballot_id`, which the proof must bind before the row exists | **A.** The server reserves the number first, one more request per ballot. **B.** The browser draws a random 128-bit identifier. **C.** Derived from the voter. | **A** | "Menos alteração." (Fewer changes.) |
| 5 | Signature model | **A.** Voter and signature stored with the ballot; anyone can verify again; the link between voter and ballot is written in the table. **B.** Verify on arrival and discard. **C.** Pseudonym, which needs blind signatures to be real. | **A** | "Controle." (Control.) |
| 6 | When the voter's key is registered | **A.** In the same visit: the browser generates the pair, registers the public key once for the voter code, signs and sends; the private key stays in the memory of the tab. **B.** A registration phase before the election, with the key kept in IndexedDB. | **A** | "Dispensa mudança de roteiro." (It needs no change to the script.) |
| 7 | Where proofs and signatures are verified | **A.** On arrival only. **B.** On arrival and again by the tally, before counting. **C.** On arrival always, in the tally as an option. | **B** | "A segurança e confiabilidade é o que importa no lab." (Security and reliability are what matters in the lab.) |
| 8a | Opening a new election without `TRUNCATE` | **A.** An `election_id` column; ballots of every election stay in the table and the tally filters. **B.** Drop and create the table for every election. | **A** | No reason given. |
| 8b | Where the per-ballot data lives (voter, sum proof, signature) | **A.** Two blockchain tables: `BLIND_BALLOTS` with one row per option, and a new one with one row per ballot. **B.** Everything repeated in the three rows of `BLIND_BALLOTS`. | **A** | No reason given. |
| 9a | "Drop and rebuild the table", which needs the DBA role only | **A.** In H9, as a limit of integrity. **B.** In H10, with what still breaks. | **B** | No reason given. |
| 9b | The owner disables the primary key and drops the foreign key | **A.** Measured in H10. **B.** A note only. | **A** | No reason given. |
| 9c | The hidden creation timestamp of every row | **A.** Declared as a cost, and the re-linking by that timestamp measured in H10. **B.** Declared only. | **A** | No reason given. |
| 10a | Tag `v1-layer1` | **A.** Push it now. **B.** Keep it local until Layer 2 is published. | **A** | No reason given. |
| 10b | `npm ci` (the `node_modules` folder was gone) | **A.** The assistant runs it. **B.** He runs it. | **A** | No reason given. |
| 10c | Where the work happens | **A.** A `layer2` branch. **B.** Directly on `main`, as Layer 1 was. | **B** | No reason given. |

Fixed by the brief, not decided here: blockchain table version 2 with `NO DROP UNTIL 0 DAYS IDLE`,
so that `npm run lab` can reinstall into a clean schema, and `NO DELETE UNTIL 16 DAYS AFTER INSERT`,
the smallest value the database accepts.

### What follows from these decisions

- A blank ballot is rejected: the sum of the three plaintexts must be 1. Not voting is the only
  abstention.
- With 5 = A, ballot secrecy rests on the encryption alone. Whoever holds the private key and opens
  one ballot knows whose vote it is.
- With 7 = B, a row that a DBA inserts directly is not counted: it has no valid proof and no valid
  signature. The price is time, and H11 measures it. The projection from the probe is about 0.76 s
  per ballot in the database.
- With 6 = A, the registration authenticates nobody beyond what the voter code already did, and
  `VOTER_ROLL` is an ordinary table: a DBA can replace the public key of a voter who has not voted
  yet. This goes to H10.
- With 10c = B, the Layer 1 state is reached through the tag `v1-layer1`.

### Reasons and opinions come at the end

Asked for the reasons that are missing above, he answered on the same day:

> "Pode, mas deixa pra eu opinar no final do lab. Por enquanto não tem como eu ter opinião formada."
>
> (Go ahead, but leave my opinion for the end of the lab. For now I cannot have a formed opinion.)

The empty reasons stay empty until he fills them.

## Gate G1: test vectors, 24 November 2026

`node tests/g1-vectors.mjs`, against the fixed file `tests/vectors/layer2-vectors.json`. The result
is in `evidence/g1-test-vectors`. His reading of it: not given yet.

## Gate G2: predictions

Before each hypothesis runs, his prediction is recorded here, and compared with the result
afterwards.

Asked for his predictions on 24 November 2026, he answered:

> "Pode rodar tudo até o final quando terminar tudo e eu for rodar o lab você vai pedindo minha opinião."
>
> (Run everything to the end; when it is all done and I run the lab, you ask me for my opinion as we go.)

So no prediction was recorded before the hypotheses ran. The table stays open for what he says when
he runs the lab himself; a prediction given after a result is known is labelled as such.

| Hypothesis | His prediction | Recorded on | Result | Compared |
|---|---|---|---|---|
| H7 Soundness | not given before the run | | | |
| H8 Completeness | not given before the run | | | |
| H9 Integrity | not given before the run | | | |
| H10 What still breaks | not given before the run | | | |
| H11 Cost | not given before the run | | | |

## Before the live session, 24 November 2026

| # | Question | Options | Chosen | His reason |
|---|---|---|---|---|
| 11a | Commit the Layer 2 work before the session, so that it runs on a known version | **Yes**, with his identity, no push. **No.** | **Yes** | No reason given. His answer: "Sim." |
| 11b | A second working copy on tag `v1-layer1` for part A, `../apex-blindfold-v1` (git worktree) | **Yes.** **No**: part A switches this copy to the tag and back. | **Yes** | No reason given. His answer: "Sim." |

## After the run, 24 November 2026

Asked one at a time, in a question dialog, after he read the results of the run. His answers are the
options he picked.

| # | Question | Options | Chosen | His reason |
|---|---|---|---|---|
| 12 | The scripts of H1 to H6 are still on `main`, where they no longer run: ballots need proofs and the tables are blockchain tables | **Keep them with a notice**: each one stops at its first line and says that it runs on tag `v1-layer1`, and how. **Delete them from `main`**: they stay on the tag only. **Leave them as they are**: run on `main`, they fail with a database or API error. | **Keep them with a notice** | No reason given. His answer: "Manter com aviso". |
| 13 | The three images at the top of the README (the vote receipt, What the database sees, the decrypted tally) show the screens of Layer 1 | **Redo them on Layer 2**, with a new script into a folder of their own. **Keep them and label them** as Layer 1. **Leave them as they are.** | **Leave them as they are** | No reason given. His answer: "Deixar como está". |
| 14 | Two attacks were left out of the live session: the key holder reading single ballots (it needs a new function in the application) and a voter replaying a ballot under another ballot number (it needs one more console snippet) | **Only the replay, with a snippet**: two new shots, no change to the application; the key holder stays out. **Both out.** **Both, with a change to the application**, designed as a separate decision. | **Only the replay, with a snippet** | No reason given. His answer: "Só o replay, por snippet". |
| 15 | The choices R1 to R10 below, which the assistant made while running to the end | Confirm each one as it is, or leave it unchecked to be asked about on its own. They were asked in three groups: R1, R2, R3 and R5; R4, R6 and R8; R9 and R10. | **All confirmed as they are.** R7 is replaced by decision 14. | No reason given. He checked every box. |

What was done after them:

- **12.** `tests/lib/layer1.mjs` prints where the script runs and exits with status 1; each of the six
  scripts calls it right after its imports, before anything touches the database. Four of the six
  import `castBallots`, which `main` no longer has, and a missing import stops a module before its
  first line runs. So `tests/lib/election.mjs` keeps a function of that name that only throws. Run on
  `main`, all six print the notice and exit with 1.
- **14.** `tests/snippets/replay-ballot.js` (Layer 1) and `tests/snippets/replay-ballot-layer2.js`
  build one honest ballot, cast it for a first voter code, then cast the same ballot again for a
  second one. In the Layer 2 version the second voter code registers a key of its own, gets a ballot
  number of its own and signs the copy correctly: only the proofs are copied. Both were run once on
  the real application, the Layer 1 one after installing the tag. Layer 1 stored both, ballots 1 and
  2. Layer 2 accepted the first and rejected the copy: *invalid proof: option 1: the challenges do
  not add up to the hash*, and stored nothing for it. The runbook has two new shots, 07 and 28, and
  every shot after them moved: 43 shots.

## Choices the assistant made while running to the end

With "run everything to the end", the assistant went on where a choice had to be made, picked the
option it had recommended, and lists each one here. None of them was his decision when it was made.
On 24 November he confirmed R1 to R6 and R8 to R10 as they are (decision 15); R7 is replaced by
decision 14.

| # | Question | Options | Applied for now | Why the assistant picked it |
|---|---|---|---|---|
| R1 | What happens to the Layer 1 hypotheses (H1 to H6) on `main`, where ballots now need proofs and the tables are blockchain tables | **A.** They stay on tag `v1-layer1`: `npm run lab` on `main` runs G1 and H7 to H11; the Layer 1 evidence stays in the repository, its summary moves to `evidence/summary-layer1.*`, and the README keeps its tables. **B.** Adapt H1 to H6 to the new API: H1 would take about 17 hours at its old size, so its numbers would change, and H4 and H5 are what H7 and H9 now answer. | **A** | No Layer 1 number changes; less work. The scripts `tests/h1-*.mjs` to `tests/h6-*.mjs` are still on `main` and no longer run there. Removing them from `main` is a further choice, not made. |
| R2 | Sizes of H8 and H11 | H8: 100 elections, 2 to 10 voters each, 2048-bit keys, a new key every 10 elections. H11: tallies of 100, 1,000 and 10,000 voters at 2048 bits, three runs at 100 and one run from 1,000 up; 20 samples in the browser and in the database. | as listed | The brief names 100 elections and 10,000 voters. One tally of 10,000 takes about 1.8 hours, so it runs once. |
| R3 | How the 10,000 ballots of H11 are made | **A.** Proven and signed in Node worker threads with the library of the application, inserted by the owner, the voter roll updated as `cast_ballot` would; the tally verifies each one again. **B.** Each one through `cast_ballot`, which verifies on arrival: about two more hours. | **A** | The tally is what is timed, and it verifies every ballot either way. Verification on arrival is measured on its own, per ballot. The README says how the ballots were made. |
| R4 | The two H10 limits about replaced code: the JavaScript shipped by the server, and the verifier | **A.** Harmless replacements: the substituted `vote.js` only shows the choice; the replaced verifier keeps the same checks and adds a marker. **B.** Replacements that change votes. | **A** | They show that the replaced code runs, and where. The lab does not build code that changes votes. The brief asks for "CONFIRMED = attack works": the verdict rests on the code running, and the evidence says so. |
| R5 | H10 changes the structure of the schema (drop and rebuild, keys disabled, verifier replaced) | **A.** H10 reinstalls the lab schema at its end. **B.** H10 leaves it changed. | **A** | H11 and any later run need the installed schema. |
| R6 | The screenshot step of Layer 1 (`tests/screenshots.mjs`) | **A.** Left out of the Layer 2 run. **B.** Kept. | **A** | It writes into `evidence/app` and `evidence/h2-blindness`, which are Layer 1 evidence and the source of the README images. H7 and H10 take their own screenshots. |
| R7 | The live session | 41 shots, every attack on `v1-layer1` and on Layer 2. Not by hand: the key holder opening single ballots (it needs a new function in the application), and a voter replaying a proof under another number (it needs one more snippet). | as listed; **replaced by decision 14**: 43 shots, the replay by a voter included | Both need something that is not in the application today; adding it is a design change. |
| R9 | What the tally does with a stored ballot that fails its second verification | **A.** Leaves it out, counts the others, and lists it with the reason; the Tally page shows the list in red. **B.** Refuses to count the election at all. A broken chain stops the tally in both. | **A** | One bad row inserted by a DBA would otherwise stop every count, which is an attack of its own. With A, H9 and H10 can show what was left out and why. |
| R10 | A voter whose tab registered a key and was closed before the ballot was accepted | **A.** The code is used up: it takes one key, once, and the key lived only in that tab. **B.** A way to register again, which a DBA could also use. | **A**, nothing built | It follows from 5 = A and 6 = A. Shot 38 of the live session (36 before decision 14) shows it, and H10 shows that a DBA can clear the key anyway. |
| R8 | The record of the Layer 2 live session | **A.** A new recorder for Layer 2, `tests/live/snapshot-layer2.mjs`, into `evidence/live-session-layer2/state`; part A uses the recorder of the tag, in its own working copy. **B.** Change `tests/live/snapshot.mjs` to read both layers. | **A**, written and tested on 24 November on a small election (6 changes, each recorded with the right sentence; the test output was removed) | The recorder of Layer 1 stays the one that produced the record of the first session. |
