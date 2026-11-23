# Live session runbook

The automated tests are run by the same hands that wrote the lab. The live session puts the lab in
front of someone else: one person holds the key and votes, and a second party plays the DBA and tries
to learn the votes. It takes about twenty minutes.

| Role | Does | Uses |
|---|---|---|
| Authority | generates the key pair, later decrypts the totals | the **Tally** page, in one browser tab that stays open |
| Voter | casts ten ballots and tells nobody how | the **Vote** page, same browser or a second device |
| DBA | reads everything the database and APEX hold, guesses each vote | `tests/live/*.mjs`, with the lab's DBA account |

Authority and voter can be the same person. The DBA must be someone else, or an assistant that cannot
see the voter's screen.

The three pages, with `<base>` being the ORDS address of the lab, for example `http://localhost:8080/ords`:

- Vote: `<base>/r/<workspace>/blindfold/vote`
- What the database sees: `<base>/r/<workspace>/blindfold/ledger`
- Tally: `<base>/r/<workspace>/blindfold/tally`

## Before starting

The DBA starts the recorder. It is read-only, and writes one numbered snapshot of the database to
`evidence/live-session/state` every time the election tables change:

```
node tests/live/snapshot.mjs --watch
```

## Step 1. Authority: generate the key pair

1. Open the **Tally** page.
2. Set the number of registered voters to `12` and press **Generate key pair and open election**.
3. Leave this tab open until the session is over. **Do not reload it.** The private key exists only
   in the memory of this tab; a reload destroys the only copy, and the election can never be counted.

## Step 2. Voter: cast ten ballots

1. Open the **Vote** page in another tab, or on a second device that can reach the lab.
2. Cast ten ballots with the voter codes `VOTER-0001` to `VOTER-0010`, in any order, choosing freely.
   After each ballot the page shows its number: write down `ballot number -> choice` on paper.
   Do not tell the DBA, and keep the notes out of the DBA's reach.
3. Tell the DBA that ten ballots are in. Nothing else.

## Step 3. DBA: the challenge round

1. The DBA runs the attack. It reads the tables, the APEX session state, the logs and the SQL area,
   tries to open the ballots, and writes one guess per ballot:

   ```
   node tests/live/challenge.mjs commit
   ```

   The command prints a commitment: the SHA-256 of the guess file. The DBA gives that hash to the
   voter. The guesses are now fixed, and the voter has not seen them.
2. The voter reveals the ten votes, in ballot order.
3. The DBA records the comparison. The command first checks that the guess file still has the
   committed hash:

   ```
   node tests/live/challenge.mjs reveal B,A,C,A,A,B,C,C,A,B
   ```

Guessing one of three blindly gives 3.3 hits out of 10 on average. The result is reported as it comes
out, whatever it is.

## Step 4. Voter: look for your own vote

Run the statements of `tests/live/dba-select.sql` yourself, in the SQL tool you trust, as a DBA.
You know how you voted. Try to find it.

## Step 5. Voter: stuff the ballot box

1. First count the honest election. On the **Tally** tab press **Tally encrypted ballots**, then
   **Decrypt three totals**. The result should match your notes.
2. On the **Vote** page open the browser console (F12), paste the whole of
   `tests/snippets/ballot-stuffing.js` and press Enter. It casts one ballot for `VOTER-0011` that is
   worth a thousand votes for option A. The database accepts it. (Chromium browsers refuse the first
   paste into the console until you type `allow pasting`, as the warning there says.)
3. On the **Tally** tab press **Tally encrypted ballots** and **Decrypt three totals** again.
   Option A has a thousand votes more, and the page says that the totals cannot come from honest
   ballots: they no longer add up to the turnout.
4. Optional, one more minute: in the snippet set `VOTER` to `'VOTER-0012'` and `WEIGHTS` to
   `[3, -2, 0]`, paste it again, then tally and decrypt. This ballot adds three votes to A and takes
   two from B. The totals add up to the turnout again, the warning is gone, and the result is wrong.

## Step 6. Authority: decrypt the final tally

The last **Decrypt three totals** of step 5 is the final result of the election. Take a screenshot.

## What to keep

- Screenshots from the voter's side: the Tally tab after step 1, one ballot receipt, the SQL tool in
  step 4, the browser console and the corrupted tally in step 5, the final tally. They go to
  `evidence/live-session/screenshots`, after masking host names and addresses.
- Anything that surprised you or went wrong, in your own words.
- The DBA stops the recorder (Ctrl+C). `evidence/live-session/timeline.txt` then lists every change
  the database saw, with the snapshot taken after it.
