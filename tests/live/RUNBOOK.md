# Live session runbook

The automated tests are run by the same hands that wrote the lab. The live session puts the lab in
front of someone else: one person holds the key and votes, and a second party plays the DBA and tries
to learn the votes. It takes about twenty minutes.

| Role | Does | Uses |
|---|---|---|
| Authority | generates the key pair, later decrypts the totals | the **Tally** page, in a browser of its own |
| Voter | casts ten ballots and tells nobody how | the **Vote** page, in another browser or on a second device |
| DBA | reads everything the database and APEX hold, guesses each vote | `tests/live/*.mjs`, with the lab's DBA account |

Authority and voter can be the same person. The DBA must be someone else, or an assistant that cannot
see the voter's screen.

The three pages, with `<base>` being the ORDS address of the lab, for example `http://localhost:8080/ords`:

- Vote: `<base>/r/<workspace>/blindfold/vote`
- What the database sees: `<base>/r/<workspace>/blindfold/ledger`
- Tally: `<base>/r/<workspace>/blindfold/tally`

This runbook was corrected after its first use. What went wrong that day, and why each warning below
exists, is in [`evidence/live-session`](../../evidence/live-session/README.md).

## Before starting

The DBA starts the recorder. It is read-only, and writes one numbered snapshot of the database to
`evidence/live-session/state` every time the election tables change:

```
node tests/live/snapshot.mjs --watch
```

## Step 1. Authority: generate the key pair

1. Open the **Tally** page in a browser that will be used for nothing else during the session: a second
   browser, not a second tab. With every tab in one window, it is easy to lose track of which one holds
   the key.
2. Set the number of registered voters to `14` and press **Generate key pair and open election**. Ten
   codes are for the ballots, two for the attack of step 5, two are spare.
3. Leave this tab alone until the session is over. The private key exists only in its memory. A reload,
   or any other page loaded in this tab, destroys the only copy, and the election can never be counted.
   - The title of the tab now starts with **Key holder**, and the links of the page open in a new tab.
   - If the browser asks whether you want to leave the page, **stay**. The browser words that question
     itself: it mentions unsaved information, and says nothing about a key.

## Step 2. Voter: cast ten ballots

1. Open the **Vote** page in the other browser, or on a second device that can reach the lab. To give the
   DBA as much as possible to work with, add `?debug=LEVEL9` to the address: APEX then writes a debug
   trace of every request, and the DBA reads it.
2. Cast exactly ten ballots with the voter codes `VOTER-0001` to `VOTER-0010`, in any order, choosing
   freely. Each receipt shows the ballot number and, on that screen only, the choice. Keep a record the
   DBA cannot reach: `ballot number -> choice` on paper, or a recording of your own screen.
3. Tell the DBA that ten ballots are in. Nothing else.

## Step 3. DBA: the challenge round

1. The DBA runs the attack. It reads the tables, the APEX session state, the logs and the SQL area,
   tries to open the ballots, and writes one guess per ballot:

   ```
   node tests/live/challenge.mjs commit
   ```

   The command prints a commitment: the SHA-256 of the guess file. The DBA gives that hash to the
   voter, or publishes it where it gets a time the DBA does not control (a pushed commit, for example).
   The guesses are now fixed, and the voter has not seen them.
2. The voter reveals the ten votes, in ballot order. If the record is a screen recording, the voter hands
   it over now, not earlier.
3. The DBA records the comparison. The command first checks that the guess file still has the
   committed hash:

   ```
   node tests/live/challenge.mjs reveal B,A,C,A,A,B,C,C,A,B
   ```

   Add `--source "<where the votes come from>"` when they were not simply told by the voter, and
   `--out live-session/<folder>` with `--since <time>` on `commit` for a second election on the same day.

Guessing one of three blindly gives 3.3 hits out of 10 on average. The result is reported as it comes
out, whatever it is.

## Step 4. Voter: look for your own vote

Run the statements of `tests/live/dba-select.sql` yourself, in the SQL tool you trust, as a DBA.
You know how you voted. Try to find it.

## Step 5. Voter: stuff the ballot box

1. First count the honest election. In the authority's browser press **Tally encrypted ballots**, then
   **Decrypt three totals**. The result should match your record.
2. On the **Vote** page, in the voter's browser, open the console (F12), paste the whole of
   `tests/snippets/ballot-stuffing.js` and press Enter. It casts one ballot for `VOTER-0011` that is
   worth a thousand votes for option A. The database accepts it. The snippet refuses to run on any other
   page: only the Vote page can store a ballot. (Chromium browsers refuse the first paste into the
   console until you type `allow pasting`, as the warning there says.)
3. In the authority's browser press **Tally encrypted ballots** and **Decrypt three totals** again.
   Option A has a thousand votes more, and the page says that the totals cannot come from honest
   ballots: they no longer add up to the turnout.
4. Optional, one more minute: in the snippet set `VOTER` to `'VOTER-0012'` and `WEIGHTS` to
   `[3, -2, 0]`, paste it again, then tally and decrypt. This ballot adds three votes to A and takes
   two from B, and by itself it adds up to one vote. After the ballot of a thousand, the warning stays:
   the thousand votes are still in the sum. To see this ballot pass unnoticed it has to be the only
   dishonest one in the election, which is what the automated test `tests/h4-ballot-stuffing.mjs` does.

## Step 6. Authority: decrypt the final tally

The last **Decrypt three totals** of step 5 is the final result of the election. Take a screenshot.

## What to keep

- Screenshots from the voter's side: the Tally tab after step 1, one ballot receipt, the SQL tool in
  step 4, the browser console and the corrupted tally in step 5, the final tally. Before they are
  committed, `tests/live/mask-image.mjs` removes the browser's tabs and address bar and paints over host
  names and account names; the results go to `evidence/live-session/screenshots`.
- Screen recordings, if the voter made any. A recording of a desktop is never committed whole:
  `tests/live/clip-video.mjs` cuts the seconds that matter, keeps the page only, paints over host names
  and session identifiers, drops the sound, and lists every cut in `evidence/live-session/video/clips.txt`.
  Look at every segment before it is committed. A browser shows more than the page: previews of other
  tabs, the address of a link, the history under the address bar.
- Anything that surprised you or went wrong, in your own words.
- The DBA stops the recorder (Ctrl+C). `evidence/live-session/timeline.txt` then lists every change
  the database saw, with the snapshot taken after it.
