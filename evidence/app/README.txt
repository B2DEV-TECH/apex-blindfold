# Screenshots
# generated: 2026-11-23T15:47:40.578Z
# browser: msedge 158.0.4370.33 (headless), taken by tests/screenshots.mjs
# tour election: 20 registered voters, 12 ballots cast in the browser, decrypted tally A=6 B=2 C=4
# builder pages: workspace, schema and account names, host and session ids are masked in the page before the shot
# the script checks the page text after masking and refuses to save if a name is still visible

evidence/app/01-authority-key-generated.png
    Tally page, step 1: the key pair was generated in this tab and the public key published
evidence/app/02-vote.png
    Vote page: a voter code and a choice, before casting
evidence/app/03-vote-receipt.png
    Vote page after casting: the receipt and the log of what left the browser
evidence/app/04-what-the-database-sees.png
    What the database sees: BLIND_BALLOTS and VOTER_ROLL, straight from the tables
evidence/app/05-tally-encrypted.png
    Tally page, step 2: the database returned three encrypted totals it cannot read
evidence/app/06-tally-decrypted.png
    Tally page, step 3: the totals decrypted in the authority tab
evidence/app/07-vote-phone.png
    Vote page at phone width
evidence/h2-blindness/dba-select.png
    APEX SQL Workshop: the SELECT a DBA or developer runs on BLIND_BALLOTS (39 ciphertexts on screen, identical to the table)
evidence/h2-blindness/dba-group-by.png
    APEX SQL Workshop: what a GROUP BY tells about the result. Every option has the same number of rows
evidence/h2-blindness/debug-trace.png
    APEX debug viewer: the LEVEL9 trace of one CAST_BALLOT request, top of the list
evidence/h2-blindness/debug-trace-full.png
    APEX debug viewer: the complete LEVEL9 trace of one CAST_BALLOT request
evidence/h2-blindness/network-payload.png
    One CAST_BALLOT request, field by field, rendered from the recorded HAR
