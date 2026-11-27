# Live session, Layer 2: part A

**Part A is complete: shots 01 to 19, recorded on 27 November 2026.** Part B, the same attacks on
Layer 2 (shots 20 to 43), will be recorded in one sitting and published with a second article
(decision 26 in `docs/decisions-layer2.md`).

Geraldo drives by hand, following `tests/live/RUNBOOK-layer2.md`. Every recording here is his,
unchanged. Before the next shot the assistant checked each one: that it opens, its length and picture
size, its frames one by one, and the state of the database at the same moment.

## What ran

- **Part A, before the fix:** tag `v1-layer1` (commit `07cc21f`), installed from a second working
  copy of the repository. Application 2620.
- **From `main`** (commit `4a7f967`): the runbook, `tests/live/attacks-v1.sql`, and the console
  snippets `tests/snippets/replay-ballot.js` (shot 07) and `tests/snippets/read-the-choice.js` (shot
  08). The tag does not have them. `tests/snippets/ballot-stuffing.js` is the same file on the tag
  and on `main`.
- **SQL:** PL/SQL Developer, connected as `SYSTEM@FREEPDB1` (decision 21). The title bar and status
  bar show that name. No password and no host name appear on screen.
- **Database record:** the recorder of the tag, `tests/live/snapshot.mjs --watch`. It is read-only:
  it only runs `SELECT` and sees committed data. Its output is in [`state-v1/`](state-v1/), with one
  snapshot per change and the timeline in [`state-v1/timeline.txt`](state-v1/timeline.txt). A few
  snapshots carry a label written by hand: 14, 37 and 43.
- **Recordings:** OBS, 1920 x 1080, `.mkv`. The full SHA-256 of every file is in
  [`SHA256SUMS`](SHA256SUMS), and each one matches the file OBS wrote. To check them:
  `sha256sum -c SHA256SUMS`.

## How this session differs from the runbook

Each point is a decision of his, recorded in `docs/decisions-layer2.md`.

- **`.mkv`, not `.mp4`** (16). The files keep the names of the runbook, with `.mkv`.
- **His own votes and settings** (17). The runbook lists six honest ballots and a value for every
  snippet setting. He chose his own, so ballot numbers and totals differ from the runbook. Each
  expected result below was computed from his receipts and from the answers on screen, before the
  tally was recorded.
- **The whole window**, address bar, tabs and taskbar included (18).
- **This is the second run** (22). The first run (25 and 26 November) stopped when the browser tab
  that held the private key of election A2 was closed overnight. Without that key the A2 totals could
  never be decrypted. He chose to record the whole of part A again, from shot 01, on a reinstalled
  database. The first run is kept unchanged in [`attempts/run-1/`](attempts/run-1/), with its own
  README, checksums and database record.

## Election A1: the voter's attacks

Key `c3addd91…c57360d`, 12 voter codes, opened at 08:12 local (snapshot 16). Times are local
(UTC−3) and come from the names OBS gave the files. Snapshot numbers refer to
[`state-v1/timeline.txt`](state-v1/timeline.txt).

| Shot | File | What he did | What the screen shows | Snapshot |
|---|---|---|---|---|
| 01 | [`01-v1-open-election.mkv`](01-v1-open-election.mkv) | 12 voters, generate | the key, `VOTER-0001` to `VOTER-0012` | 16 |
| 02 | [`02-v1-six-ballots.mkv`](02-v1-six-ballots.mkv) | six honest ballots: 1 A (`0001`), 2 C (`0002`), 3 B (`0003`), 4 A (`0004`), 5 C (`0005`), 6 C (`0006`) | six receipts | 17–22 |
| 03 | [`03-v1-honest-tally.mkv`](03-v1-honest-tally.mkv) | Tally, Decrypt | **A = 2, B = 1, C = 3**, *6 votes from 6 voters* | — |
| 04 | [`04-v1-stuff-1000.mkv`](04-v1-stuff-1000.mkv) | `ballot-stuffing.js`, `[1000, 0, 0]` | accepted, ballot 7. The snippet ran with its default code `VOTER-0011`, because the file was not edited (see below) | 23 |
| 05 | [`05-v1-stuff-quiet.mkv`](05-v1-stuff-quiet.mkv) | `VOTER-0008`, `[3, -2, 0]` | accepted, ballot 8 | 24 |
| 06 | [`06-v1-two-options.mkv`](06-v1-two-options.mkv) | `VOTER-0009`, `[1, 1, 0]` | accepted, ballot 9 | 25 |
| 07 | [`07-v1-replay-a-ballot.mkv`](07-v1-replay-a-ballot.mkv) | `replay-ballot.js`: honest `[0, 1, 0]` as `VOTER-0010`, the same ciphertexts again as `VOTER-0007` | both accepted, ballots 10 and 11 | 26 |
| 08 | [`08-v1-code-reads-the-choice.mkv`](08-v1-code-reads-the-choice.mkv) | `read-the-choice.js`, then `VOTER-0012`, option A | the red bar names *A / File-Level Import with APEXlang*; accepted, ballot 12 | 27 |
| 09 | [`09-v1-tally-after-voter-attacks.mkv`](09-v1-tally-after-voter-attacks.mkv) | Tally, Decrypt | **A = 1,007, B = 2, C = 3**: *1,012 votes from 12 voters: these totals cannot come from honest ballots. Some ciphertext did not encrypt 0 or 1, and the tally accepted it.* | — |

Expected at shot 09, from his choices: A = 2 + 1000 + 3 + 1 + 1 = 1,007 (shots 03, 04, 05, 06, 08);
B = 1 − 2 + 1 + 1 + 1 = 2 (shots 03, 05, 06, 07 twice); C = 3. The page showed exactly that.

## Election A2: the DBA's attacks

Key `e6090e60…485379`, 12 voter codes, opened at 08:34 local (snapshot 28). The attacks are the
sections of `tests/live/attacks-v1.sql`, pasted into the Command Window of PL/SQL Developer.

| Shot | File | What he did | What the screen shows | Snapshot |
|---|---|---|---|---|
| 10 | [`10-v1-second-election.mkv`](10-v1-second-election.mkv) | 12 voters, generate, confirm | *Opening a new election erases the 12 ballots that are stored. Continue?*, then the new key | 28 |
| 11 | [`11-v1-six-ballots-again.mkv`](11-v1-six-ballots-again.mkv) | after F5 on the Vote page, six honest ballots: 1 A (`0001`), 2 A (`0002`), 3 C (`0003`), 4 B (`0004`), 5 A (`0005`), 6 C (`0006`) | six receipts, each with the key `e6090e60…` | 29–34 |
| 12 | [`12-v1-honest-tally-again.mkv`](12-v1-honest-tally-again.mkv) | Tally, Decrypt | **A = 3, B = 1, C = 2**, *6 votes from 6 voters* | — |
| 13 | [`13-v1-relink-by-order.mkv`](13-v1-relink-by-order.mkv) | section *Shot 13* | six rows: `VOTER-0001` to `VOTER-0006` paired with ballots 1 to 6, in the order they voted | — |
| 14 | [`14-v1-move-a-vote.mkv`](14-v1-move-a-vote.mkv) | section *Shot 14*: swap the A and B ciphertexts of ballot 1 | `2 rows updated`, `Commit completed`; ballot 1 now counts for B | 38 |
| 15 | [`15-v1-delete-a-ballot.mkv`](15-v1-delete-a-ballot.mkv) | section *Shot 15*: delete ballot 2 (A) | `3 rows deleted`, `Commit completed` | 39 |
| 16 | [`16-v1-copy-a-ballot.mkv`](16-v1-copy-a-ballot.mkv) | section *Shot 16*: ballot 3 (C) again, as ballot 900, with no voter | `3 rows inserted`, `Commit completed` | 40 |
| 17 | [`17-v1-duplicate-rows.mkv`](17-v1-duplicate-rows.mkv) | section *Shot 17*: disable the primary key, store the rows of ballot 4 (B) a second time | `Table altered`, `3 rows inserted`, `Commit completed` | 41 |
| 18 | [`18-v1-unused-code.mkv`](18-v1-unused-code.mkv) | section *Shot 18*, then on the Vote page the first code listed, `VOTER-0007`, option B | `VOTER-0007` to `VOTER-0012` have not voted; accepted, ballot 7 | 42 |
| 19 | [`19-v1-tally-after-dba-attacks.mkv`](19-v1-tally-after-dba-attacks.mkv) | Tally, Decrypt | **A = 1, B = 4, C = 3**: *8 votes from 7 voters: these totals cannot come from honest ballots. Some ciphertext did not encrypt 0 or 1, and the tally accepted it.* | 43 |

Expected at shot 19, from his choices: A = 3 − 1 (shot 14) − 1 (shot 15) = 1; B = 1 + 1 (shot 14)
+ 1 (shot 17) + 1 (shot 18) = 4; C = 2 + 1 (shot 16) = 3. The page showed exactly that. Every
database change in snapshots 38 to 42 happened during the recording of its shot.

## Notes

- **Shot 04 ran as `VOTER-0011`.** The snippet file was opened in the browser and not edited, so
  its default settings ran: `VOTER-0011`, `[1000, 0, 0]`. The code typed in the form, `VOTER-0007`,
  is not what the snippet sends. The shot is kept, since the attack and its answer are what the
  runbook asks for. The codes of the next shots moved: 05 used `0008`, 06 used `0009`, 07 used `0010`
  and `0007`, 08 used `0012`.
- **Shot 17 is labelled *no change* by the recorder.** The recorder of the tag compares ballot
  numbers, and a duplicate adds rows without adding a number. The snapshot itself is right:
  snapshot 41 shows 21 rows, with six for ballot 4. The first run had the same label (snapshot 33
  of `attempts/run-1/state-v1`).
- **The second sentence of the shot 19 message is wrong for this election.** *Some ciphertext did
  not encrypt 0 or 1* is how Layer 1 explains impossible totals. In election A2, every stored
  ciphertext encrypts 0 or 1. The totals come from a moved, a deleted, a copied and a duplicated
  ballot. Layer 1 cannot tell these causes apart.
- **Layer 1 accepts a ballot encrypted with a key that is no longer the key of the election.** The
  first run found this by accident (`attempts/run-1/attempts/a2-attempt-1-stale-vote-tab/`): the
  Vote page fetches the public key only when it loads, so after shot 10 a page left open encrypted
  with the key of A1. `CAST_BALLOT` stored those ballots, and the tally decrypted to nonsense. In
  run 2 the Vote page was reloaded after shot 10, and every receipt of shot 11 shows the A2 key.
- [`run2-notes.md`](run2-notes.md) is the assistant's working log, written during the session, one
  line per shot. It still names shots 20 and 21 (below).

## Attempts

Nothing was deleted. Each recording that was not kept as the shot is in [`attempts/`](attempts/),
listed in `SHA256SUMS` and explained here.

| File | What happened | Decision |
|---|---|---|
| [`attempts/01-attempt-1.mkv`](attempts/01-attempt-1.mkv) | a valid shot 01 (key `c114c5a3…`), but the shot 02 that followed it used up the election | 23 |
| [`attempts/02-attempt-1-twelve-ballots.mkv`](attempts/02-attempt-1-twelve-ballots.mkv) | 12 ballots cast instead of 6, so no voter code was left for shots 04 to 08 (snapshots 01 to 14). The database was reinstalled off camera, and shots 01 and 02 were recorded again | 23 |
| [`attempts/14-attempt-1-swap-undone.mkv`](attempts/14-attempt-1-swap-undone.mkv) | the update of shot 14 had already run once off camera, in another PL/SQL Developer window (snapshot 35, 11:40:41 UTC). The run on camera (snapshot 36) swapped ballot 1 back to A. Shot 14 was recorded again and ran once (snapshot 38) | 24 |
| [`attempts/run-1/`](attempts/run-1/) | the first run: shots 01 to 10 of 25 and 26 November, the A2 attempt with the stale Vote page, and the database record 00 to 38 | 20, 21, 22 |

Shots 20 and 21 were recorded on 27 November, right after part A: Layer 2 installed, election B1
opened with 14 voter codes, six ballots. They are not in this folder. Part B will be recorded again
from shot 20 for the second article, because the private key of B1 lives only in the browser tab of
that session (decisions 26 and 27).
