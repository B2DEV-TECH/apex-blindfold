# Live session runbook, Layer 2

The automated tests of Layer 2 (H7 to H11) were run by the hands that wrote them. This session puts
every attack in front of Geraldo instead. He drives: he opens the elections, casts the votes and
performs each attack himself, twice. First on tag `v1-layer1`, before the fix (part A), then on
Layer 2, after it (part B). The assistant cannot see his screen. It works from his recordings and
from the state of the database, and checks every file before the next shot.

Human-run evidence and automated evidence never mix. Everything recorded here goes to
`evidence/live-session-layer2/`. An automated shot never replaces a human one: if a shot fails, it is
recorded again.

## Recording standard

- **1080p, 16:9** (1920 x 1080). One shot per file, recorded in one take: **no cuts, no edits**.
- **Nothing private on screen**: no password, host name, account name, connection name or APEX
  workspace data. In practice:
  - browsers in full screen (F11), so the tabs and the address bar, which shows the host and the
    workspace, are not in the picture. Open and arrange every window before pressing record;
  - the SQL tool connected **before** the recording starts, with the connection panel closed, or
    SQLcl in a terminal with `set sqlprompt "SQL> "` and the screen cleared;
  - the browser console cleared (Ctrl+L) before each paste, and docked to the page. A console line
    can carry the address of the page: if one does, stop and record the shot again;
  - a terminal (shot 42) in full screen, with a prompt that shows no path: the path of the
    repository contains the Windows account name. In PowerShell: `function prompt { '> ' }`, then
    `Clear-Host`;
  - no notification, chat or e-mail window anywhere on the screen.
- **Voice is optional.** If you speak, speak English.
- **File name**: the one in the shot list, `NN-short-name.mp4`, in `evidence/live-session-layer2/`.
- Start recording a second before the first step and stop a second after the expected result is on
  screen. Each shot has a target length; it is a guide, not a limit.

After every file, tell the assistant it is there. It checks that the file opens, that it is the shot
of the list, and that the expected result is visible. If not, it says exactly what is wrong and asks
for a retake. Only then the next shot. The check runs `tests/live/check-recording.mjs`: Microsoft Edge
opens the file (no ffmpeg needed), reports its length and picture size, and saves evenly spaced
frames into a temporary folder outside the repository, where the assistant looks at them.

## The three pages and the tools

With `<base>` the ORDS address of the lab:

- Vote: `<base>/r/<workspace>/blindfold/vote`
- What the database sees: `<base>/r/<workspace>/blindfold/ledger`
- Tally: `<base>/r/<workspace>/blindfold/tally`

| Tool | What it is | Used in |
|---|---|---|
| `tests/snippets/ballot-stuffing.js` | the console snippet of Layer 1: three ciphertexts, no proof | shots 04 to 06, 23 |
| `tests/snippets/ballot-stuffing-layer2.js` | the same attack by an attacker who also forges proofs and signs | shots 24 to 27, 38 |
| `tests/snippets/replay-ballot.js` | one honest ballot cast twice, under two voter codes, on Layer 1 (in this copy only: the tag does not have it) | shot 07 |
| `tests/snippets/replay-ballot-layer2.js` | the same on Layer 2: the copy keeps the proofs of the first ballot and gets a key and a signature of its own | shot 28 |
| `tests/snippets/read-the-choice.js` | code in the page that reads the choice before encryption and only shows it | shots 08, 29 |
| `tests/live/attacks-v1.sql` | the statements of the DBA on Layer 1, one section per shot | shots 13 to 18 |
| `tests/live/attacks-v2.sql` | the statements of the DBA on Layer 2, one section per shot | shots 34 to 41 |
| `tests/live/replace-verifier.mjs` | replaces the Java verifier with the same checks plus one marker | shot 42 |

The snippets have their settings on the first lines: `VOTER`, `WEIGHTS` and, in the Layer 2
stuffing snippet, `SIGNATURE`; in the two replay snippets, `FIRST`, `SECOND` and `CHOICE`. Edit them
in a text editor before the shot, then copy the whole file. The replay snippets exist only in this
copy: in part A, copy `replay-ballot.js` from here, not from `../apex-blindfold-v1`.
Chromium browsers refuse the first paste into the console until you type `allow pasting`.

## Before the session (assistant, with your OK)

1. Commit the Layer 2 work, so that the session runs on a known version. Its hash goes into
   `evidence/live-session-layer2/README.md`.
2. Create a second working copy for part A, without touching this one:
   `git worktree add ../apex-blindfold-v1 v1-layer1`, then copy `.local/db.json` into it and run
   `npm ci` there.
3. Test the recorder of part B, `tests/live/snapshot-layer2.mjs`: read-only, the current election
   only, the structure the DBA's attacks change (object number of each ballot table, constraint
   state, last compilation of the Java verifier), into `evidence/live-session-layer2/state`. Part A
   uses the recorder of the tag, `tests/live/snapshot.mjs` inside `../apex-blindfold-v1`: it writes
   into that copy, and its output is copied to `evidence/live-session-layer2/state-v1` afterwards.
   The record of the Layer 1 session, `evidence/live-session`, stays as it is.
4. Install part A: `db/uninstall.sql` of this copy (Layer 2 has objects that Layer 1 does not know),
   then `node scripts/install.mjs` in `../apex-blindfold-v1`.
5. Start the recorder of each part with `--watch` before its first shot, and stop it after its last.

Between part A and part B the assistant runs `node scripts/install.mjs` in this copy. Neither
install is recorded.

## Part A: tag `v1-layer1`, before the fix

The six honest ballots of every election are always the same, so that every total can be checked:
`VOTER-0001` A, `VOTER-0002` B, `VOTER-0003` C, `VOTER-0004` A, `VOTER-0005` B, `VOTER-0006` A. Ballot 1 is A, ballot 2 is B, ballot 3 is C, ballot 4 is A, ballot 5 is B,
ballot 6 is A: **A = 3, B = 2, C = 1**. Each receipt shows its ballot number and its option.

### Election A1: the voter's attacks

| Shot | File | When to record and stop | What must be visible | Steps | Expected result | Target |
|---|---|---|---|---|---|---|
| 01 | `01-v1-open-election.mp4` | from the Tally page, until the key facts appear | the Tally page, the number of voters, the key facts | 1. Set the number of voters to `12`. <br>2. Press **Generate key pair and open election**. | the key facts appear; this tab now holds the only private key | 20 s |
| 02 | `02-v1-six-ballots.mp4` | from the Vote page, until the sixth receipt | each voter code, each choice, each receipt | `VOTER-0001` A, `VOTER-0002` B, `VOTER-0003` C, `VOTER-0004` A, `VOTER-0005` B, `VOTER-0006` A, one after the other | six receipts, ballots 1 to 6 | 90 s |
| 03 | `03-v1-honest-tally.mp4` | from the Tally page, until the totals are decrypted | both buttons, the three totals | 1. Press **Tally encrypted ballots**. <br>2. Press **Decrypt three totals**. | A = 3, B = 2, C = 1: *6 votes from 6 voters.* | 20 s |
| 04 | `04-v1-stuff-1000.mp4` | from the empty console, until the answer is printed | the snippet settings, the answer line | 1. In `ballot-stuffing.js` set `VOTER = 'VOTER-0007'`, `WEIGHTS = [1000, 0, 0]`. <br>2. Paste it on the Vote page, press Enter. | `{"ok":true,"ballot_id":7}`: accepted | 30 s |
| 05 | `05-v1-stuff-quiet.mp4` | the same | the same | 1. Set `VOTER = 'VOTER-0008'`, `WEIGHTS = [3, -2, 0]`. <br>2. Paste, Enter. | accepted, ballot 8 | 30 s |
| 06 | `06-v1-two-options.mp4` | the same | the same | 1. Set `VOTER = 'VOTER-0009'`, `WEIGHTS = [1, 1, 0]`. <br>2. Paste, Enter. | accepted, ballot 9 | 30 s |
| 07 | `07-v1-replay-a-ballot.mp4` | from the empty console, until the second answer is printed | the snippet settings, both answer lines | 1. In `replay-ballot.js` (from this copy) keep `FIRST = 'VOTER-0010'`, `SECOND = 'VOTER-0011'`, `CHOICE = [0, 1, 0]`. <br>2. Paste it on the Vote page, press Enter. | both accepted: ballot 10 for the honest ballot, ballot 11 for the copy. The same three ciphertexts now count twice | 40 s |
| 08 | `08-v1-code-reads-the-choice.mp4` | from the empty console, until the receipt | the paste, the option chosen, the red bar, the receipt | 1. Reload the Vote page. <br>2. Paste `read-the-choice.js`, Enter. <br>3. Vote as `VOTER-0012`, option C. | the red bar names option C; the receipt shows ballot 12 | 40 s |
| 09 | `09-v1-tally-after-voter-attacks.mp4` | from the Tally page, until the totals | the totals and the message under them | 1. Press **Tally encrypted ballots**. <br>2. Press **Decrypt three totals**. | A = 1007, B = 3, C = 2 (3 + 1000 + 3 + 1, 2 − 2 + 1 + 1 + 1, 1 + 1): *1012 votes from 12 voters: these totals cannot come from honest ballots.* | 20 s |

### Election A2: the DBA's attacks

| Shot | File | When to record and stop | What must be visible | Steps | Expected result | Target |
|---|---|---|---|---|---|---|
| 10 | `10-v1-second-election.mp4` | from the Tally page, until the key facts | the question about erasing the ballots, the key facts | 1. Set voters to `12`. <br>2. Press **Generate key pair and open election**. <br>3. Confirm. | a new key; the ballots of A1 are erased (Layer 1 truncates the table) | 20 s |
| 11 | `11-v1-six-ballots-again.mp4` | as shot 02 | as shot 02 | the same six ballots as shot 02 | six receipts, ballots 1 to 6 | 90 s |
| 12 | `12-v1-honest-tally-again.mp4` | as shot 03 | as shot 03 | Tally, then Decrypt | A = 3, B = 2, C = 1 | 20 s |
| 13 | `13-v1-relink-by-order.mp4` | from the SQL worksheet, until the result | the statement, the six rows | Run section *Shot 13* of `attacks-v1.sql`. | each ballot paired with the voter code that cast it, as your receipts say | 30 s |
| 14 | `14-v1-move-a-vote.mp4` | the same | the statement, `2 rows updated`, the commit | Run section *Shot 14*. | accepted | 20 s |
| 15 | `15-v1-delete-a-ballot.mp4` | the same | the statement, `3 rows deleted` | Run section *Shot 15*. | accepted | 20 s |
| 16 | `16-v1-copy-a-ballot.mp4` | the same | the statement, `3 rows inserted` | Run section *Shot 16*. | accepted | 20 s |
| 17 | `17-v1-duplicate-rows.mp4` | the same | both statements and their answers | Run section *Shot 17*. | the key is disabled, `3 rows inserted` | 30 s |
| 18 | `18-v1-unused-code.mp4` | from the SQL worksheet, until the receipt | the list of codes, the Vote page, the receipt | 1. Run section *Shot 18*. <br>2. On the Vote page, vote with the first code listed, option C. | a receipt: a code read from the table is enough to vote | 40 s |
| 19 | `19-v1-tally-after-dba-attacks.mp4` | from the Tally page, until the totals | the totals and the message | Tally, then Decrypt | A = 3, B = 2, C = 3: ballot 1 now counts for B, ballot 2 (B) is gone, ballot 3 (C) counts twice through ballot 900, ballot 4 (A) counts twice, and shot 18 adds a C. *8 votes from 7 voters: these totals cannot come from honest ballots.* | 20 s |

## Part B: Layer 2, after the fix

The six honest ballots are the same as in part A: `VOTER-0001` A, `VOTER-0002` B, `VOTER-0003` C, `VOTER-0004` A, `VOTER-0005` B, `VOTER-0006` A.

### Election B1: the voter's attacks

| Shot | File | When to record and stop | What must be visible | Steps | Expected result | Target |
|---|---|---|---|---|---|---|
| 20 | `20-v2-open-election.mp4` | as shot 01 | as shot 01 | voters `14`, generate | the key facts | 20 s |
| 21 | `21-v2-six-ballots.mp4` | as shot 02 | each receipt, and for the first ballot the wire log: key registered, proofs and signature made, verified and stored | the same six ballots as shot 02 | six receipts, ballots 1 to 6 | 120 s |
| 22 | `22-v2-honest-tally.mp4` | as shot 03 | the line that starts with *Chain verified*, the totals | Tally, then Decrypt | *... 6 ballots counted, 0 rejected*; A = 3, B = 2, C = 1: *6 votes from 6 verified ballots.* | 30 s |
| 23 | `23-v2-layer1-snippet.mp4` | as shot 04 | the settings, the answer | `ballot-stuffing.js` (the Layer 1 one), `VOTER-0007`, `[1000, 0, 0]` | rejected: *A ballot must carry exactly three ciphertexts and three bit proofs.* | 30 s |
| 24 | `24-v2-stuff-1000.mp4` | as shot 04 | the settings, the answer | `ballot-stuffing-layer2.js`, `VOTER-0008`, `[1000, 0, 0]`, `SIGNATURE = 'own'` | rejected: *invalid proof* | 40 s |
| 25 | `25-v2-stuff-quiet.mp4` | the same | the same | `VOTER-0009`, `[3, -2, 0]` | rejected: *invalid proof* | 40 s |
| 26 | `26-v2-two-options.mp4` | the same | the same | `VOTER-0010`, `[1, 1, 0]` | rejected: *invalid proof: sum* | 40 s |
| 27 | `27-v2-forged-signature.mp4` | the same | the same | `VOTER-0011`, `[1, 0, 0]`, `SIGNATURE = 'other'` | rejected: *signature: the signature does not match the ballot* | 40 s |
| 28 | `28-v2-replay-a-ballot.mp4` | as shot 07 | the snippet settings, both answer lines | `replay-ballot-layer2.js`, `FIRST = 'VOTER-0012'`, `SECOND = 'VOTER-0013'`, `CHOICE = [0, 1, 0]` | the honest ballot is accepted; the copy, signed correctly by `VOTER-0013` under its own ballot number, is rejected: *invalid proof: option 1: the challenges do not add up to the hash.* | 40 s |
| 29 | `29-v2-code-reads-the-choice.mp4` | as shot 08 | as shot 08 | reload, paste `read-the-choice.js`, vote as `VOTER-0014`, option C | the red bar names option C; the ballot is accepted as usual | 40 s |
| 30 | `30-v2-tally-after-voter-attacks.mp4` | as shot 22 | the *Chain verified* line, the totals | Tally, then Decrypt | *... 8 ballots counted, 0 rejected*; A = 3, B = 3, C = 2: *8 votes from 8 verified ballots.* None of the attempts of shots 23 to 27 left a row, and neither did the copy of shot 28 | 30 s |

### Election B2: the DBA's attacks

| Shot | File | When to record and stop | What must be visible | Steps | Expected result | Target |
|---|---|---|---|---|---|---|
| 31 | `31-v2-second-election.mp4` | as shot 10 | the question, the key facts | voters `14`, generate, confirm | a new election; the question now says that the earlier ballots stay stored | 20 s |
| 32 | `32-v2-six-ballots-again.mp4` | as shot 21 | each receipt | the same six ballots as shot 02 | six receipts, ballots 1 to 6 | 120 s |
| 33 | `33-v2-honest-tally-again.mp4` | as shot 22 | as shot 22 | Tally, then Decrypt | *... 6 ballots counted, 0 rejected*; A = 3, B = 2, C = 1 | 30 s |
| 34 | `34-v2-relink-by-insert-time.mp4` | from the SQL worksheet, until the result | the statement, the six rows | Run section *Shot 34* of `attacks-v2.sql`. | every `paired_voter` equals `seal_says`: the hidden insert time pairs each ballot with its voter | 30 s |
| 35 | `35-v2-move-a-vote.mp4` | the same | the statement and the error | Run section *Shot 35*. | `ORA-05715`: refused | 20 s |
| 36 | `36-v2-delete-a-ballot.mp4` | the same | the statement and the error | Run section *Shot 36*. | `ORA-05715`: refused | 20 s |
| 37 | `37-v2-copy-a-ballot.mp4` | the same | both inserts and their answers | Run section *Shot 37*. | the ciphertexts are stored (`3 rows inserted`); the seal is refused with `ORA-00001`, because the voter already has a ballot | 30 s |
| 38 | `38-v2-code-taken-elsewhere.mp4` | from the console of the first Vote window, until the message in the second | the snippet answer in the first window, the message in the second | 1. In window 1, paste `ballot-stuffing-layer2.js` with `VOTER-0007`, `[2, 0, 0]`. <br>2. In window 2, a second browser on the Vote page, vote as `VOTER-0007`. | window 1: rejected, *invalid proof*, but the code now has a key; window 2: *This voter code already has a key, registered by another browser tab.* | 60 s |
| 39 | `39-v2-dba-takes-over-code.mp4` | from the SQL worksheet, until the receipt in window 2 | the statement, then the receipt | 1. Run section *Shot 39*. <br>2. In window 2, vote as `VOTER-0007` again, option B. | the update is accepted, then the ballot is accepted and a receipt appears, with a new ballot number | 50 s |
| 40 | `40-v2-drop-and-rebuild.mp4` | from the SQL worksheet, until the last statement | every statement and its answer | Run section *Shot 40*. | every statement succeeds: the tables are dropped and rebuilt without ballot 1 | 60 s |
| 41 | `41-v2-duplicate-rows.mp4` | the same | the three statements and their answers | Run section *Shot 41*. | the key is disabled, the foreign key is dropped, `3 rows inserted` | 30 s |
| 42 | `42-v2-replace-verifier.mp4` | from a terminal in this copy of the repository, until the last line | the command and its five lines of output | `node tests/live/replace-verifier.mjs` | `marker after: replaced in the live session`; the chain is the same before and after | 30 s |
| 43 | `43-v2-tally-after-dba-attacks.mp4` | from the Tally page, until the totals and the list under them | the *Chain verified* line, the totals, the list of rejected ballots | Tally, then Decrypt | the chain verifies over the rebuilt tables. Counted: ballots 2, 3, 5 and 6, and the ballot of shot 39: *5 ballots counted, 2 rejected*; A = 1, B = 3, C = 1. Rejected, with the reason on the page: ballot 4 (six rows) and ballot 900 (no voter, no signature). Ballot 1 (A) is not there at all, and nothing on the page says so | 40 s |

After shot 40 the database recompiles the packages that used the dropped tables. A database session
that was already open can answer the next call once with an error about the state of packages
(`ORA-04068`). If the first **Tally encrypted ballots** of shot 43 shows it, press it again, keep
recording, and say so in your notes: it is part of what a rebuild leaves behind.

## Not in this session

- **The key holder reads single ballots** (H10, limit 1). The Tally page holds the private key in its
  memory and offers no way to use it on anything but the three totals. Doing it by hand needs a new
  function in the application, which is a design change: on 24 November it was left out (decision
  14 of `docs/decisions-layer2.md`). It is measured by the automated test, in
  `evidence/h10-what-still-breaks`.

The replay by a voter, left out of the first version of this runbook, is now shots 07 and 28
(decision 14). Shot 37 is the replay by a DBA, from the stored rows.

## What to keep

- The 43 files, named as above.
- Anything that surprised you or went wrong, in your own words. If a step was not done as written,
  say which and how: it goes into the record as it happened.
- The assistant writes `evidence/live-session-layer2/README.md`: the version that ran, the timeline
  from the recorder, and one line per shot with what it shows. After the session it reinstalls the
  lab (shots 40 to 42 changed its structure) and removes the second working copy, both with your OK.
