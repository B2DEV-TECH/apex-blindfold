# Live session, Layer 2

**In progress.** Paused on 25 November 2026 after shot 09 of 43, at the end of election A1. Shots 10
to 43 are not recorded yet. This file grows with the session.

Geraldo drives, by hand, following `tests/live/RUNBOOK-layer2.md`. Every file here is one of his
recordings, unchanged. The assistant checked each one before the next shot: it opens, its length and
picture size, frames read one by one, and the state of the database at the same moment.

## What ran

- **Part A, before the fix:** tag `v1-layer1` (commit `07cc21f`), installed from a second working copy
  of the repository after `db/uninstall.sql` of `main` removed Layer 2. Application 2620.
- **From `main`** (commit `0fe0708`): the runbook, and two console snippets that the tag does not
  have, `tests/snippets/replay-ballot.js` (shot 07) and `tests/snippets/read-the-choice.js` (shot
  08). `tests/snippets/ballot-stuffing.js` is the same file on the tag and on `main`.
- **Database record:** the recorder of the tag, `tests/live/snapshot.mjs --watch`, read-only, from
  10:18:44 UTC. Its output is in [`state-v1/`](state-v1/): one snapshot per change, and
  [`state-v1/timeline.txt`](state-v1/timeline.txt). It was stopped at the pause, after a last snapshot
  with a label (12).
- **Recordings:** OBS, 1920 x 1080, `.mkv`. The full SHA-256 of every file is in
  [`SHA256SUMS`](SHA256SUMS); each one matches the file OBS wrote.

## How this session differs from the runbook

Each point is a decision of his, recorded in `docs/decisions-layer2.md` (16 to 19).

- **`.mkv`, not `.mp4`** (16). The files keep the names of the runbook, with `.mkv`.
- **His own votes and settings** (17). The runbook lists six honest ballots and a value for every
  snippet setting. He chose his own, so ballot numbers and totals differ from the runbook. Each
  expected result below was computed from his receipts and from the answers on screen.
- **The whole browser window from shot 03 on** (18): address bar (`localhost`, the path of the
  application, the APEX session number), tabs and taskbar. Shots 01 and 02 are in full screen; in shot
  02 the status bar shows the address of the *What the database sees* page for about one second, at
  about 80 s.
- **Committed while the session runs, pushed after it** (19).

## Timeline

Times of the recordings are local (UTC−3), from the names OBS gave the files. Database events are
UTC, from [`state-v1/timeline.txt`](state-v1/timeline.txt).

| Local | UTC | What happened |
|---|---|---|
| 07:18:44 | 10:18:44 | recorder started (snapshot 00) |
| 07:21:34 | | shot 01 starts |
| 07:21:49 | 10:21:49 | election A1 opened, 12 voters (snapshot 01) |
| 07:58:38 | | shot 02 starts |
| 07:59:05 to 07:59:54 | 10:59:05 to 10:59:54 | ballots 1 to 5 stored (snapshots 02 to 06) |
| 08:03:44 | | shot 03 starts |
| 08:08:55 | | shot 04 starts; ballot 6 stored at 11:09:27 (snapshot 07) |
| 08:10:41 | | shot 05 starts; ballot 7 stored at 11:11:16 (snapshot 08) |
| 08:12:06 | | shot 06 starts; ballot 8 stored at 11:12:32 (snapshot 09) |
| 08:13:19 | | shot 07, attempt 1: nothing stored |
| 08:14:50 | | shot 07 starts; ballots 9 and 10 stored at 11:15:01 (snapshot 10) |
| 08:16:23 | | shot 08 starts; ballot 11 stored at 11:17:00 (snapshot 11) |
| 08:18:29 | | shot 09 starts |
| 08:20:58 | 11:20:58 | session paused (snapshot 12) |

## Shots

| Shot | File | Starts (local) | Length | What it shows |
|---|---|---|---|---|
| 01 | [`01-v1-open-election.mkv`](01-v1-open-election.mkv) | 07:21:34 | 30 s | Tally page. Voters changed from 20 to 12, **Generate key pair and open election**. Public key `daffb1ab…7cedd7`, 2048 bits; private key "not shown, not stored, not sent"; voter codes `VOTER-0001` to `VOTER-0012`. |
| 02 | [`02-v1-six-ballots.mkv`](02-v1-six-ballots.mkv) | 07:58:38 | 110 s | Vote page, **five** honest ballots, his choices. The first code typed was `VOTER-001`: *Unknown voter code.*, nothing stored. Then `VOTER-0001` B, `VOTER-0002` A, `VOTER-0003` C, `VOTER-0004` A, `VOTER-0005` A: receipts for ballots 1 to 5, each with its option "on this screen only". Ends on *What the database sees*: turnout 5 of 12. `VOTER-0006` did not vote here. |
| 03 | [`03-v1-honest-tally.mkv`](03-v1-honest-tally.mkv) | 08:03:44 | 40 s | Tally page, whole window. **Tally encrypted ballots**: 15 ciphertexts multiplied, "It still does not know the result." **Decrypt three totals**: A = 3, B = 1, C = 1, *5 votes from 5 voters.* As his receipts say. |
| 04 | [`04-v1-stuff-1000.mkv`](04-v1-stuff-1000.mkv) | 08:08:55 | 52 s | Console of the Vote page: `allow pasting`, then `ballot-stuffing.js` with `VOTER = 'VOTER-0006'`, `WEIGHTS = [1000, 0, 0]`. Answer `{ok: true, ballot_id: 6}`: stored. |
| 05 | [`05-v1-stuff-quiet.mkv`](05-v1-stuff-quiet.mkv) | 08:10:41 | 46 s | The same snippet, `VOTER-0007`, `[3, -2, 0]`. Answer `{ok: true, ballot_id: 7}`. |
| 06 | [`06-v1-two-options.mkv`](06-v1-two-options.mkv) | 08:12:06 | 31 s | The same snippet, `VOTER-0008`, **`[1, 1, 1]`**: one vote for each of the three options (the runbook suggests `[1, 1, 0]`). Answer `{ok: true, ballot_id: 8}`. |
| 07, attempt 1 | [`attempts/07-attempt-1-wrong-snippet.mkv`](attempts/07-attempt-1-wrong-snippet.mkv) | 08:13:19 | 38 s | The settings of the replay snippet typed into `ballot-stuffing.js`. *ReferenceError: VOTER is not defined*, raised while building the request: no `CAST_BALLOT` was sent (the APEX activity log shows the snippet's `ELECTION_INFO` call from the Vote page at 11:13:49 UTC, and no `CAST_BALLOT` between ballot 8 at 11:12:30 and shot 07 at 11:15:00), and nothing was stored. |
| 07 | [`07-v1-replay-a-ballot.mkv`](07-v1-replay-a-ballot.mkv) | 08:14:50 | 24 s | `replay-ballot.js` with the settings it ships with: `FIRST = 'VOTER-0010'`, `SECOND = 'VOTER-0011'`, `CHOICE = [0, 1, 0]`. *The honest ballot [0, 1, 0] for VOTER-0010*: `{ok: true, ballot_id: 9}`. *The same three ciphertexts again, for VOTER-0011*: `{ok: true, ballot_id: 10}`. In snapshot 10, ballots 9 and 10 hold the same three ciphertexts. |
| 08 | [`08-v1-code-reads-the-choice.mkv`](08-v1-code-reads-the-choice.mkv) | 08:16:23 | 50 s | Vote page reloaded, `read-the-choice.js` pasted (*Installed.*), then a vote by hand: `VOTER-0012`, option C. Red bar: *Read by code in the page, before encryption: C / Deep Data Security Integration.* Receipt: ballot 11, C. `VOTER-0009` is the only code that never voted in election A1. |
| 09 | [`09-v1-tally-after-voter-attacks.mkv`](09-v1-tally-after-voter-attacks.mkv) | 08:18:29 | 50 s | Tally, then Decrypt: **A = 1,007, B = 2, C = 3**. *1,012 votes from 11 voters: these totals cannot come from honest ballots. Some ciphertext did not encrypt 0 or 1, and the tally accepted it.* |

The totals of shot 09, ballot by ballot:

| Ballots | What they encrypt | A | B | C |
|---|---|---|---|---|
| 1 to 5, honest | B, A, C, A, A | 3 | 1 | 1 |
| 6 | `[1000, 0, 0]` | +1000 | | |
| 7 | `[3, -2, 0]` | +3 | −2 | |
| 8 | `[1, 1, 1]` | +1 | +1 | +1 |
| 9 and 10 | the same B ballot, twice | | +2 | |
| 11 | C | | | +1 |
| **Total** | | **1,007** | **2** | **3** |

Eleven voters cast eleven ballots, and the database accepted every one. Nothing in Layer 1 tells a
ballot of 1,000 votes, a ballot of minus two, a ballot for every option or a copied ballot from an
honest one: only the totals, once decrypted, show that something is wrong, and not what.
