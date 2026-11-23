# APEX Blindfold: results of one run

Generated 2026-11-23T15:47:40.850Z by `node tests/run-all.mjs` (full mode, seed 20261123, 19 min 15 s).

Environment: Oracle AI Database 26ai Free Release 23.26.3.0.0 on Microsoft Windows x86 64-bit, APEX 26.2.0, ORDS 26.3.0.r2721811, tally engine: Java stored procedure. Details in `evidence/00-environment`.

| # | Hypothesis | Verdict | Observed in this run | Evidence |
|---|---|---|---|---|
| H1 | Correctness | **CONFIRMED** | The decrypted tally equals the true tally in 100/100 randomized elections (10 to 5000 voters, 82874 ballots), and JavaScript, Java and Python agree on every value compared. | [`evidence/h1-correctness/elections.txt`](h1-correctness/elections.txt), [result.json](h1-correctness/result.json) |
| H2 | Blindness | **CONFIRMED** | Knowing the private key and the randomizer of all 27 ciphertexts, the test found none of them, whole or in part, in 21 sources: 231 HTTP requests and their responses, 4 tables, APEX session state (0 page items; 2 report paging positions), 4423 LEVEL9 debug messages, the activity and access logs, 172 SQL statements, captured binds, audit trail, alert log, and the storage of both tabs. Ballot requests differ only in the voter code and three ciphertexts. ORDS log files were not read. | [`evidence/h2-blindness/scan-summary.txt`](h2-blindness/scan-summary.txt), [result.json](h2-blindness/result.json) |
| H3 | Indistinguishability | **CONFIRMED** | All 6000 stored ciphertexts are distinct, and none of 13 distinguishers separates Enc(0) from Enc(1) on 4000 labelled ciphertexts (classifier accuracy 51.4%). Indistinguishability itself rests on the DCR assumption, which a test cannot prove. | [`evidence/h3-indistinguishability/distinguishers.txt`](h3-indistinguishability/distinguishers.txt), [result.json](h3-indistinguishability/result.json) |
| H4 | Ballot stuffing | **CONFIRMED** | The tally accepted a ballot encrypting 1000 (A=4  B=3  C=2 became A=1004  B=3  C=2). A balanced ballot of [3, -2, 0] changed the result (A=7  B=1  C=2) while the totals still added up to the turnout. | [`evidence/h4-ballot-stuffing/stuffing.txt`](h4-ballot-stuffing/stuffing.txt), [result.json](h4-ballot-stuffing/result.json) |
| H5 | Other limits | **CONFIRMED** | All three limits hold: a DBA with the public key moved 5 votes with two UPDATEs and the totals still matched the turnout; the key holder read 24/24 individual ballots; ordering by voted_at and ballot_id re-linked 24/24 voters arriving one at a time (59/200 exactly, 199/200 within 7 positions, when 8 sessions vote at once). | [`evidence/h5-limits/a-dba-adds-votes.txt`](h5-limits/a-dba-adds-votes.txt), [result.json](h5-limits/result.json) |
| H6 | Cost | **CONFIRMED** | Measured: casting a ballot takes a median 289 ms in the browser; tallying 10000 voters takes 4.9 s against 1.074 ms for a plaintext COUNT (4584x); a ballot stores 3087 bytes against 5. | [`evidence/h6-cost/timings.json`](h6-cost/timings.json), [result.json](h6-cost/result.json) |

Every row is copied from the `result.json` that the test of that hypothesis wrote. The numbers change
from run to run where randomness or timing is involved; the verdicts should not.

| Step | Result | Time |
|---|---|---|
| install: clean schema and APEX application | done | 0 min 22 s |
| unit tests: Paillier library and election API | done | 0 min 02 s |
| step 0: environment | done | 0 min 45 s |
| H1: Correctness | done | 13 min 28 s |
| H2: Blindness | done | 0 min 36 s |
| H3: Indistinguishability | done | 0 min 22 s |
| H4: Ballot stuffing | done | 0 min 19 s |
| H5: Other limits | done | 0 min 57 s |
| H6: Cost | done | 1 min 52 s |
| screenshots | done | 0 min 30 s |
