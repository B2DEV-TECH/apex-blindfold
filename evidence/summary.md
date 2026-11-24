# APEX Blindfold Layer 2: results of one run

Generated 2026-11-24T17:44:56.310Z by `node tests/run-all.mjs` (full mode, seed 20261123, 190 min 19 s).

Environment: Oracle AI Database 26ai Free Release 23.26.3.0.0 on Microsoft Windows x86 64-bit, APEX 26.2.0, ORDS 26.3.0.r2721811, tally engine: Java stored procedure. Details in `evidence/00-environment`.

Gate G1, Test vectors: **PASS**. The Java verifier in the database reproduced 162/162 hashes of the browser byte for byte, over 18 fixed ballots in 2 key sizes (512 and 2048 bits), agreed with the browser on every verdict (6 accepted, 12 rejected) and verified 18/18 WebCrypto signatures. 6 altered vectors were all caught. [`evidence/g1-test-vectors/vectors.txt`](g1-test-vectors/vectors.txt)

| # | Hypothesis | Verdict | Observed in this run | Evidence |
|---|---|---|---|---|
| H7 | Soundness | **CONFIRMED** | The database rejected 8 of 8 dishonest ballots pasted in the browser console, among them the ballot of 1000 votes and the balanced [3, -2, 0] that Layer 1 accepted, 3 of 3 replays, and 100 of 100 valid ballots with one digit changed. The tally stayed A=5  B=3  C=2: the honest ballots and the control. | [`evidence/h7-soundness/attempts.txt`](h7-soundness/attempts.txt), [result.json](h7-soundness/result.json) |
| H8 | Completeness | **CONFIRMED** | 100 random elections with 2048-bit keys: 520 of 520 honest ballots accepted, all 520 counted after a second verification, and the decrypted tally equal to the true result in 100 of 100. A dishonest ballot placed among honest ones was refused. | [`evidence/h8-completeness/elections.txt`](h8-completeness/elections.txt), [result.json](h8-completeness/result.json) |
| H9 | Integrity | **CONFIRMED** | The owner and an account with the DBA role had 10 of 10 UPDATE, DELETE, TRUNCATE and MERGE statements refused each, where an ordinary copy of the table accepted them. 5 of 5 forged or unsigned ballots were rejected. The DBA could still INSERT 3 forged ballots; the tally counted none of them (6 counted, 3 rejected) and the chain verified over 1651 rows. | [`evidence/h9-integrity/statements.txt`](h9-integrity/statements.txt), [result.json](h9-integrity/result.json) |
| H10 | What still breaks | **CONFIRMED** | All 7 limits held up in the lab: the key holder read 6 of 6 ballots with the voter code next to each; the hidden insert time re-linked 6 of 6; a DBA voted in the name of a registered voter with one UPDATE; a DBA dropped and rebuilt the tables without one ballot and the chain still verified; the owner made the tally refuse 2 honest ballots (this one is reported by the tally); a substituted vote.js read the choice; the verifier was replaced without a trace in the tables. | [`evidence/h10-what-still-breaks/limits.txt`](h10-what-still-breaks/limits.txt), [result.json](h10-what-still-breaks/result.json) |
| H11 | Cost | **CONFIRMED** | Measured: proofs add 3808 hexadecimal characters to a ballot; encrypting and proving takes a median 283 ms in the browser and casting 1032 ms from the click to the receipt (Layer 1: 289 ms); the database verifies one ballot in 641 ms; the tally of 10000 voters takes 104.7 min against 4.9 s in Layer 1. | [`evidence/h11-cost/summary.txt`](h11-cost/summary.txt), [result.json](h11-cost/result.json) |

Every row is copied from the `result.json` that the test of that hypothesis wrote. The numbers change
from run to run where randomness or timing is involved; the verdicts should not.
Layer 1 (H1 to H6) is in [summary-layer1.md](summary-layer1.md), from the run of tag `v1-layer1`.

| Step | Result | Time |
|---|---|---|
| install: clean schema and APEX application | done | 0 min 23 s |
| unit tests: Paillier library and election API | done | 0 min 03 s |
| step 0: environment | done | 0 min 45 s |
| G1: Test vectors | done | 0 min 17 s |
| H7: Soundness | done | 1 min 50 s |
| H8: Completeness | done | 25 min 22 s |
| H9: Integrity | done | 0 min 30 s |
| H10: What still breaks | done | 1 min 16 s |
| H11: Cost | done | 159 min 53 s |
