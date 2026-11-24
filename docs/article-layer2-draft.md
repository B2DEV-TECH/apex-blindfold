<!--
  DRAFT for b2dev.tech. NOT PUBLISHED. Nothing here goes to the site without Geraldo's review and OK.
  - The title is a working title: his choice.
  - "My Take" and "His reading" stay empty until he writes them, in his own words.
  - Every number comes from the evidence of one full run (evidence/summary.json and the result.json
    of each hypothesis). The run is named in "Results". Replace nothing by hand: rerun and copy.
  - The site renders Markdown with remark-directive: a colon directly followed by a letter or a
    digit in prose disappears. Keep a space after every colon.
-->

# A Ballot That Proves Itself: Zero-Knowledge Validity in Oracle APEX

*Working title. APEX Blindfold, Layer 2. Draft, not published.*

[Layer 1](https://b2dev.tech/blog/apex-blindfold-a-tally-the-database-cannot-read) built an election
in Oracle APEX where the database counts votes it cannot read. The browser encrypts each ballot with
Paillier, the database multiplies the ciphertexts, and only the holder of the private key decrypts
the three totals. The tally was blind, and it was also defenceless. A ballot that encrypted 1000
votes for one option was stored and counted like any other: the database cannot look inside a
ciphertext, so it could not tell. And an `UPDATE` on the stored ciphertexts moved votes from one
option to another without a trace.

Layer 2 asks whether the same database can refuse a dishonest ballot it still cannot read, and keep
the stored ballots from being changed. It keeps the application of Layer 1 and adds proofs,
signatures and blockchain tables. Then it measures what that stops, what it does not stop, and what
it costs.

The cryptography is written from its definition for this lab and has not been audited. The election
is fictional. This is not an Oracle feature and carries no endorsement by Oracle.

## The design

Four additions, each one checkable on its own.

**1. Validity proofs, made in the voter's browser.** Next to each of the three ciphertexts the
browser sends a zero-knowledge proof that it encrypts 0 or 1, and for the whole ballot a proof that
the three plaintexts add up to 1. The proofs reveal nothing about which option is the 1. They are
written with JavaScript `BigInt`, no library, in the same static file style as the encryption of
Layer 1.

**2. Verification inside the database.** A Java stored procedure, with `java.math.BigInteger`,
checks every proof before the ballot is stored, and the tally checks every proof again before it
counts. Before any hypothesis ran, a gate (G1) fed 18 fixed ballots to both implementations and
required the browser and the database to compute every hash byte for byte the same.

**3. Signed ballots.** On the first visit the browser makes an ECDSA P-256 key pair with WebCrypto,
with a private key that cannot be exported, and registers the public key for the voter code. The
database reserves a ballot number for that voter, the browser proves and signs the complete ballot
under that number, and the database verifies the signature against the registered key with
`SHA256withECDSAinP1363Format`, inside the database JVM.

**4. Tamper-evident storage.** The ciphertexts (`BLIND_BALLOTS`) and the per-ballot seal
(`BALLOT_SEALS`: voter code, sum proof, signature) are Oracle blockchain tables:

```sql
create blockchain table blind_ballots (
  election_id  number         not null,
  ballot_id    number         not null,
  candidate_id number(1)      not null,
  vote_enc     varchar2(1024) not null,
  bit_proof    varchar2(1088) not null,
  constraint blind_ballots_pk primary key (election_id, ballot_id, candidate_id)
)
no drop until 0 days idle
no delete until 16 days after insert
hashing using "SHA2_512" version "v2";
```

`UPDATE`, `DELETE`, `TRUNCATE` and `MERGE` are refused with `ORA-05715`, whoever runs them. The
tally calls `DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS` on both tables before it counts anything.
`NO DROP UNTIL 0 DAYS IDLE` is there so that the lab can reinstall itself; it also means a DBA can
drop the tables, and the lab measures that too.

A ballot travels like this:

```
browser                                   database
-------                                   --------
make the voter key pair         ------>   register_voter: store the public key, reserve a ballot number
encrypt 3 options, prove each
is 0 or 1, prove the sum is 1,
sign the whole ballot           ------>   cast_ballot: voter known and not voted, number is the reserved one,
                                          proofs verify, signature verifies -> 3 rows + 1 seal
                                          (anything else: rejected, nothing stored)

tally page                      ------>   encrypted_tally: verify both chains, verify every proof and
                                          signature again, multiply what passed, list what did not
decrypt the 3 totals, in the tab
```

Every design choice of Layer 2 (proof format, challenge size, what enters the hash, where the
ballot number comes from, the signature model, when proofs are checked) was put to Geraldo as
options with their trade-offs, and is recorded with his choice in
[`docs/decisions-layer2.md`](https://github.com/B2DEV-TECH/apex-blindfold/blob/main/docs/decisions-layer2.md).

## The math, in a few lines

Paillier with `g = n + 1`: a ciphertext of `m` is `c = (1 + m·n)·rⁿ mod n²`, and the product of
ciphertexts encrypts the sum of their plaintexts. That is the whole of Layer 1.

For a claimed value `k`, the number `u = c·(1 − k·n) mod n²` is an n-th power, `rⁿ`, exactly when
`m = k`. Only the voter knows `r`, so the voter can prove "`u` is an n-th power" without showing it:

```
prove     a = wⁿ mod n²     e = SHA-256(...) cut to 128 bits     z = w·rᵉ mod n
check     zⁿ ≡ a·uᵉ (mod n²)
0 or 1    a real proof for the true value, a simulated one for the other, e₀ + e₁ = e
sum 1     the same proof on c₁·c₂·c₃ with k = 1 and the witness r₁·r₂·r₃
binding   the hash covers n, the election, the ballot number, the option, c and every a
```

The "0 or 1" line is the OR-composition of Cramer, Damgård and Schoenmakers: the voter picks the
challenge of the false branch freely and simulates it, and the hash fixes the sum of the two
challenges, so at most one branch can be simulated. The challenge comes from the hash
(Fiat-Shamir), which makes the proof a string the server can check alone. Binding the election and
the ballot number into the hash is what stops a valid proof from being replayed on another ballot.

The stored proof is compact: two challenges and two responses per option (1088 hexadecimal
characters at 2048 bits) and one challenge and one response for the sum (544). The verifier
recomputes the commitments `a = zⁿ·u⁻ᵉ mod n²` and checks that the hash of them gives back the
challenges.

## Results

One run of the whole lab from a clean schema, on 24 November 2026: full mode, seed 20261123,
190 minutes, on one desktop machine (Intel Core i7-9700KF, 8 logical cores) running Oracle AI
Database 26ai Free 23.26.3, APEX 26.2 and ORDS 26.3. Every hypothesis has its own script, its own
evidence folder and a negative control that must fail the way the hypothesis says it would. The
sentences below are the ones the tests wrote.

| # | Hypothesis | Verdict | What the run measured |
|---|---|---|---|
| G1 | Test vectors (gate) | **PASS** | The Java verifier reproduced 162 of 162 hashes of the browser byte for byte, over 18 fixed ballots at 512 and 2048 bits, agreed on every verdict (6 accepted, 12 rejected) and verified 18 of 18 WebCrypto signatures. |
| H7 | Soundness | **CONFIRMED** | 8 of 8 dishonest ballots pasted in the browser console rejected, 3 of 3 replays rejected, 100 of 100 valid ballots with one digit changed rejected. The tally kept only the honest ballots and the control. |
| H8 | Completeness | **CONFIRMED** | 100 random elections with 2048-bit keys: 520 of 520 honest ballots accepted, all counted after the second verification, and the decrypted result right in 100 of 100. |
| H9 | Integrity | **CONFIRMED** | 10 of 10 `UPDATE`, `DELETE`, `TRUNCATE` and `MERGE` statements refused for the owner, and 10 of 10 for an account with the DBA role, where an ordinary copy of the table accepted them. 3 ballots forged by a DBA with `INSERT` were stored and none was counted. |
| H10 | What still breaks | **CONFIRMED** | 7 of 7 limits held: see below. For this hypothesis, CONFIRMED means the attack works. |
| H11 | Cost | **CONFIRMED** | Casting takes 1,032 ms from click to receipt (Layer 1: 289 ms); the database verifies one ballot in 641 ms; the tally of 10,000 voters takes 104.7 minutes (Layer 1: 4.9 s). |

The attacks that broke Layer 1, run again on Layer 2:

| Attack | Layer 1 | Layer 2 |
|---|---|---|
| A ballot of `[1000, 0, 0]` from the browser console | A=4 B=3 C=2 became **A=1004 B=3 C=2** | **Rejected** before anything was stored: invalid proof |
| The quiet version, `[3, -2, 0]`, which still adds up to 1 | A=4 B=3 C=2 became **A=7 B=1 C=2** | **Rejected**: invalid proof |
| `UPDATE` on the stored ciphertexts to move votes | A=6 B=7 C=7 became **A=1 B=12 C=7** | **Refused** with `ORA-05715`, for the owner and for a DBA |
| Forged ballots inserted directly by a DBA | not tried: an `UPDATE` was enough | stored, 3 of 4, and **counted: none** |

The attacker in H7 is generous to the attack. The snippet uses the library of the application to
build proofs for the values it claims, signs with a key it registered itself, and still fails,
because a false statement has no valid proof: the only way through is to guess the 128-bit
challenge before it is computed.

### What still breaks

Layer 2 moves trust; it does not remove it. The defences are code and tables in the database and a
key in a browser tab, so whoever controls those still decides the count. H10 tries seven attacks
and every one of them works:

| Attack | Who can do it | Does the application notice? |
|---|---|---|
| Read single ballots, each next to its voter code | whoever holds the private key | No |
| Re-link ballots to voters by the hidden insert time of the blockchain rows | anyone who can read the tables | No |
| Vote in the name of a registered voter who has not voted, after one `UPDATE` of the voter roll | a DBA | No |
| Remove a ballot by dropping and rebuilding the tables: the new chain verifies | a DBA | No |
| Make the tally refuse honest ballots, after disabling the primary key | the owner of the tables | **Yes**: the tally lists them, with the reason |
| Read the choice in the browser with JavaScript shipped by the server | whoever can change the static files | No |
| Replace the verifier itself | the owner of the schema, or a DBA | No |

Two of the rows use harmless stand-ins: the substituted `vote.js` only shows the choice it read, and
the replaced verifier runs the same checks with a marker added. They prove that the replaced code
runs where it matters, not what it could be made to do.

### What it costs

| What | Layer 1 | Layer 2 |
|---|---:|---:|
| Encrypt one ballot in the browser | 224 ms | 283 ms, with the proofs |
| Cast one ballot, click to receipt | 289 ms | 1,032 ms |
| Request body of one ballot | 3,284 bytes | 7,250 bytes |
| Verify one ballot in the database | nothing to verify | 635 ms for the proofs, 5.6 ms for the signature |
| Tally of 100 voters | 61 ms | 1.0 min |
| Tally of 1,000 voters | 504 ms | 10.4 min |
| Tally of 10,000 voters | 4.9 s | 104.7 min |
| Stored per ballot | 3,087 bytes | 7,044 bytes |

Almost all of the price is the verification, done twice: once on arrival and again in the tally,
which checks the chain of both tables and every proof and signature before it multiplies. At about
0.63 seconds per ballot in one database session, the tally grows linearly with the number of voters.
The 10,000 ballots of the largest tally were proven and signed in Node worker threads with the
library of the application and inserted by the owner of the tables; the tally verified each one of
them and decrypted to the true result.

### His reading

<!-- Geraldo's reading of the results, in his own words. Empty until he gives it. -->

## The live session

<!-- FILL AFTER THE LIVE SESSION (gate G3): every attack performed by Geraldo's hand on tag
     v1-layer1 and again on Layer 2, recorded, from tests/live/RUNBOOK-layer2.md. Link the
     recordings in evidence/live-session-layer2. -->

## What this is NOT

- **Not audited cryptography.** The proofs, the encryption and the verifier were written for this
  lab from their definitions. They passed their own tests and a cross-implementation gate; nobody
  has reviewed them as a cryptographer would. Do not use them to protect anything.
- **Not a voting system.** The election is fictional, with three options and voter codes printed
  by the database. Nothing here describes, tests or judges a system used in a real election.
- **Not secret from the key holder.** Whoever holds the private key can decrypt any single ballot,
  and with the seal next to it, knows whose it is (H10). Layer 2 makes ballots verifiable, and the
  price of the signature model chosen is that the link between voter and ballot is stored.
- **Not safe from the people who run the database.** A DBA can drop and rebuild the tables, take
  over a voter code that has not voted, or replace the verifier; the server can ship JavaScript that
  reads the choice before it is encrypted (H10).
- **Not an Oracle feature, and not endorsed by Oracle.** It is an independent experiment that uses
  Oracle APEX and Oracle AI Database 26ai Free, including blockchain tables and the database JVM.

## Reproduce it

Everything is in [github.com/B2DEV-TECH/apex-blindfold](https://github.com/B2DEV-TECH/apex-blindfold):
the application, the database objects, one script per hypothesis with its negative control, and the
evidence of the run quoted above.

```sh
git clone https://github.com/B2DEV-TECH/apex-blindfold.git
cd apex-blindfold
npm ci
mkdir .local
cp scripts/db.example.json .local/db.json
```

Fill in `.local/db.json` (the address of your database and three passwords of your choice), and
create the lab schema, its DBA account and the APEX workspace as the README describes. Then:

```sh
npm run lab:quick    # Layer 2 with small samples: G1, then H7 to H11, in about 6 minutes
npm run lab          # the full run, with the sizes quoted above
```

The run installs everything into a clean schema, stops if the gate G1 does not pass, and writes the
verdicts to `evidence/summary.md`. A hypothesis that comes out REFUTED is a result, not a failure.
Layer 1 as it was published stays on tag `v1-layer1`
(`git checkout v1-layer1 && npm ci && npm run lab`).

## My Take

<!-- Geraldo's words only. Empty until he writes it. -->

## References

1. P. Paillier, "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes",
   EUROCRYPT 1999.
2. R. Cramer, I. Damgård, B. Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of
   Witness Hiding Protocols", CRYPTO 1994.
3. I. Damgård, M. Jurik, "A Generalisation, a Simplification and Some Applications of Paillier's
   Probabilistic Public-Key System", PKC 2001.
4. A. Fiat, A. Shamir, "How to Prove Yourself: Practical Solutions to Identification and Signature
   Problems", CRYPTO 1986.
5. Oracle AI Database documentation: blockchain tables and `DBMS_BLOCKCHAIN_TABLE`.
