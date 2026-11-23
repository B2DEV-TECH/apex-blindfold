# Live session, 23 November 2026

The automated tests were written and run by the same hands that built the lab. This folder is the other
experiment: Geraldo Viana Jr ran the lab himself, as election authority and as voter, in his own
browsers. The DBA was the AI assistant that wrote the lab's code under his supervision. It had the
lab's DBA account and could not see his screen. The script was [`tests/live/RUNBOOK.md`](../../tests/live/RUNBOOK.md),
in the version of commit `a1332de`.

Times are UTC. His local time was three hours behind, which is the clock on his screenshots.

## What happened

The session did not follow the script, and the deviations are part of the result.

| Time | What happened | Evidence |
|---|---|---|
| 13:07 | The recorder starts: one snapshot of the database per change, read-only. | [`timeline.txt`](timeline.txt), [`state`](state) |
| 13:52 | **A first key.** The authority generates a key pair and opens an election. Twenty seconds later the Tally page is loaded again in the same tab, and the private key is gone. No ballot had been cast. | snapshot 01; requests of 13:52:52 and 13:53:12 in [`state`](state) |
| 13:54 | **Election A.** A new key pair, in 685 ms. | snapshot 02, [`video/01-key-generation.mp4`](video/01-key-generation.mp4) |
| 13:56 | Eleven ballots, not the ten of the script. No notes were kept. | snapshots 03 to 14, [`video/02-ballot-1.mp4`](video/02-ballot-1.mp4), [`video/03-ballots-2-to-11.mp4`](video/03-ballots-2-to-11.mp4) |
| 14:00 | **Challenge round 1.** The DBA commits eleven guesses and pushes their hash. | [`challenge`](challenge), commit `fbfe6cf` |
| 14:26 | The voter presses Tally in the voter's tab. That tab has no key: the totals arrive and stay encrypted. | [`screenshots/01`](screenshots/01-tally-in-a-tab-without-the-key.png) |
| 14:29 | In the authority's tab the honest tally is decrypted: A=4, B=3, C=4. | [`screenshots/02`](screenshots/02-authority-tab-encrypted-totals.png), [`03`](screenshots/03-honest-tally-decrypted.png), snapshot 15 |
| 14:30 | Round 1 is revealed: 5 hits out of 11. | [`challenge/result.txt`](challenge/result.txt) |
| 14:31 | The voter runs the five statements of `dba-select.sql` himself, as `SYSTEM`, and looks for his own vote. | [`screenshots/04`](screenshots/04-dba-select-1-ballots.png) to [`08`](screenshots/08-dba-select-5-columns.png), snapshot 16 |
| 14:45 | First attempt at the ballot stuffing: the snippet is pasted on the Tally page, which cannot store a ballot. Nothing is stored. | [`screenshots/10`](screenshots/10-console-snippet-on-the-tally-page-fails.png), snapshot 17 |
| 14:48:07 | In the tab that holds the key, the voter follows the page's own Vote link. The browser asks whether to leave the page. The answer is yes, and **the second private key is gone**. | [`video/04-leave-page-question.mp4`](video/04-leave-page-question.mp4) |
| 14:48:25 | From the console of the Vote page, one ballot worth a thousand votes is accepted as ballot 12. Its election can no longer be counted. | [`screenshots/11`](screenshots/11-console-ballot-stuffing-accepted.png), [`console`](console), snapshots 18 and 19 |
| 14:58 | **Election B.** The authority moves to a second browser. A new key pair, in 403 ms. | snapshot 20, [`screenshots/12`](screenshots/12-election-b-authority-tab-in-edge.png) |
| 14:59 | Twelve ballots, with the debug trace on. | snapshots 21 to 33, [`video/05-election-b-twelve-ballots.mp4`](video/05-election-b-twelve-ballots.mp4) |
| 15:02 | **Challenge round 2.** The DBA commits twelve guesses and pushes their hash. | [`challenge-round-2`](challenge-round-2), commit `a1332de` |
| 15:02:45 | All twelve voter codes are used, so the lab's schema owner registers two more for the attack. | snapshots 34 and 35 |
| 15:04 | One ballot worth a thousand votes for A is accepted as ballot 13. | [`screenshots/14`](screenshots/14-election-b-console-1000-votes-accepted.png), [`video/06-election-b-ballot-of-a-thousand.mp4`](video/06-election-b-ballot-of-a-thousand.mp4), snapshot 36 |
| 15:05 | The authority tallies and decrypts: **A=1,006, B=3, C=3**. The page says that these totals cannot come from honest ballots. | [`screenshots/15`](screenshots/15-election-b-stuffed-tally-1006-3-3.png), [`video/07-election-b-stuffed-tally.mp4`](video/07-election-b-stuffed-tally.mp4) |
| 15:06 | A ballot of `[3, -2, 0]` is accepted as ballot 14. The final tally: **A=1,009, B=1, C=3**. | [`screenshots/16`](screenshots/16-election-b-console-quiet-ballot-accepted.png), [`17`](screenshots/17-election-b-final-tally-1009-1-3.png), [`video/08-election-b-final-tally.mp4`](video/08-election-b-final-tally.mp4), snapshots 37 and 38 |
| 15:09 | Round 2 is revealed: 5 hits out of 12. | [`challenge-round-2/result.txt`](challenge-round-2/result.txt) |
| 15:18 | The recorder stops. | snapshot 39 |

## The challenge rounds

Before each round the DBA tried thirteen things, and the `guesses.txt` of the round lists them with
what each one found: the columns of the three tables, four attacks on the ciphertexts themselves, the
APEX session state, the activity, login and debug logs, the SQL area with its captured bind values, the
audit trail, the row history, and the order in which voters and ballots arrived. None of them said
anything about a vote. So every guess follows one fixed rule, written down before the reveal: the
option with the numerically largest ciphertext.

| Round | Ballots | Guesses committed | Hash published | Votes revealed | Hits | By chance | This many or more, by chance |
|---|---|---|---|---|---|---|---|
| 1, election A | 11 | 14:00:22 | 14:00:57, commit `fbfe6cf` | 14:30:45 | **5** | 3.7 | 28.9% |
| 2, election B | 12 | 15:02:06 | 15:02:22, commit `a1332de` | 15:09:03 | **5** | 4.0 | 36.8% |
| Both | 23 | | | | **10** | 7.7 | 20.6% |

Both rounds are reported, and they are added up in [`challenge-summary.txt`](challenge-summary.txt).
None of the 23 guesses was based on something the DBA had read. In each round, 14 values differed
between the debug traces of the ballot requests, and none of them followed the votes. Twenty-three
ballots are a demonstration, not a statistical test: the test with 6,000 ciphertexts is
[H3](../h3-indistinguishability).

**Where the votes come from.** The script asks the voter to write the votes down. He did not, so in both
rounds they were read from the receipts on his own screen recordings. The order of events is what keeps
the rounds honest, and each step left a trace:

1. The recordings with the receipts arrived before the commitment. Only their size, time and SHA-256
   were read; the table below has the hashes.
2. The DBA committed the guesses and pushed the hash to GitHub, which stamped the push.
3. Only then were the recordings opened.

Two independent checks agree with the receipts. In round 1 the honest tally that the voter decrypted,
A=4, B=3, C=4, has the same counts. In round 2 the first corrupted tally, A=1,006, B=3, C=3, is the
twelve receipts (A=6, B=3, C=3) plus the thousand.

## The key that was lost twice

The design keeps the private key in the memory of one browser tab and nowhere else. During the session
that tab was taken to another page twice, and both times the election could not be counted from then
on. No copy exists to restore: [H2](../h2-blindness) shows that the key is in no page item, session state,
browser storage, request or log.

The second loss is on his recording. The Tally page did ask before letting go: it has had a
`beforeunload` handler since its first version. The browser showed its own dialog, in the browser's
language and words: *"Esta página pede que você confirme se quer sair. Informações inseridas podem não
ser salvas."* (This page asks you to confirm that you want to leave. Information you entered may not be
saved.) Nothing in it mentions a key, and a page cannot change that text. He clicked *Sair da página*
(Leave page). For the first loss there is no recording, only the request log.

No honest tally was decrypted in election B: he went straight to the attack. The honest count of this
session is the one of election A.

What changed in the lab because of this:

- Once the Tally tab holds a key, its own links open in a new tab, and its title starts with
  *Key holder*.
- The automated run now reproduces the loss: [`h5-limits/extra-key-loss.txt`](../h5-limits/extra-key-loss.txt).
- The snippet of the attack refuses to run on any page other than Vote.
- The runbook asks for a browser of its own for the authority, spare voter codes, and a record of the
  votes. It also corrects its step 5.4, which promised that the warning would disappear after the
  second dishonest ballot. With the ballot of a thousand still in the sum, it does not.

## In his words

Portuguese as he typed it during the session, with typing slips corrected and nothing else changed.
The English is a translation.

| When | What he was answering | Portuguese | English |
|---|---|---|---|
| after commitment 1 | The request to reveal his eleven votes | "Ish, eu não anotei." | "Oops, I did not write them down." |
| 14:50 | Whether he could find his own vote in the rows he had selected, knowing how he had voted | "Resposta honesta: eu não saberia meu voto." | "Honest answer: I would not know my vote." |
| 14:53 | Whether pressing Back had brought the key back | "Não volta. Acho que precisaremos refazer." | "It does not come back. I think we will have to do it again." |

His closing statement, after the explanation that the lab hides the votes and does not protect the
count:

> "Minha intenção com esse lab é exatamente simular e estudar os casos de uso para homomorfismo aditivo
> e iniciar um lab com que eu consiga atingir um nível de estado da arte da criptografia e segurança de
> banco de dados Oracle, onde o banco de dados e a aplicação Oracle APEX consigam de fato ser avaliados
> e interpretados sem a necessidade de descriptografar nada. A validade do lab se dá em que o Oracle
> conseguiu realizar a operação, porém ainda preciso testar e estudar uma forma de validar a
> autenticidade dos votos de maneira que não exista a possibilidade de fraude, e é nesse caminho que
> irei seguir. A intenção não é substituir nenhum sistema de votação oficial, e sim estudar a fundo a
> tecnologia para propor e sugerir estudos e melhorias nessa área, para garantir segurança e
> confiabilidade em sistemas de votação e eleitorais, sejam para órgãos governamentais ou privados.
> Irei continuar esse lab e em breve irei seguir a sequência, e também irei criar um episódio do APEX
> X-Ray explicando detalhadamente o funcionamento da tecnologia. Resumindo: ainda não sinto confiança,
> mas sinto esperança de que irá funcionar."

> "My intention with this lab is exactly to simulate and study the use cases for additive homomorphism,
> and to start a lab with which I can reach the state of the art in cryptography and Oracle Database
> security, where the database and the Oracle APEX application can really be evaluated and interpreted
> without the need to decrypt anything. The lab is valid in that Oracle was able to carry out the
> operation. I still need to test and study a way to validate the authenticity of the votes so that
> fraud is not possible, and that is the path I will follow. The intention is not to replace any
> official voting system. It is to study the technology in depth, in order to propose and suggest
> studies and improvements in this area, for the security and reliability of voting and electoral
> systems, whether for government bodies or private ones. I will continue this lab, the next part will
> follow soon, and I will also make an APEX X-Ray episode explaining in detail how the technology works.
> In short: I do not feel confident yet, but I am hopeful that it will work."

## Files

| Path | Content |
|---|---|
| [`timeline.txt`](timeline.txt) | every change the database saw, with the number of the snapshot taken after it |
| [`state`](state) | the snapshots: tables, APEX session state and activity log, as text and as complete JSON |
| [`challenge`](challenge), [`challenge-round-2`](challenge-round-2) | per round: the guesses, their hash, what the DBA read, and the comparison with the votes |
| [`challenge-summary.txt`](challenge-summary.txt) | the two rounds in one table, added up |
| [`console`](console) | the exact snippets he pasted into the browser console |
| [`screenshots`](screenshots) | his screenshots, cropped and masked |
| [`video`](video) | eight segments of his screen recordings, cut to the page, without sound; [`video/clips.txt`](video/clips.txt) says which seconds of which recording each one is, and what was painted over. GitHub does not play an MP4 in the page: open a segment and choose *View raw* to download it |

Snapshot 34 reads "no change in the election tables". The recorder of that day did not describe a
change in the number of registered voters: it is the two voter codes of snapshot 35, taken a moment
later. The recorder has been corrected, and the snapshot is left as it was written.

## What he sent, and when

Recordings and screenshots stay on his machine. They show his whole desktop, so what is published here
is cut from them: the page only, without the browser's tabs and address bar, with host names and
session identifiers painted over. The segments were made with
[`tests/live/clip-video.mjs`](../../tests/live/clip-video.mjs) and the screenshots with
[`tests/live/mask-image.mjs`](../../tests/live/mask-image.mjs). Before publication every segment was
looked at on contact sheets of one frame per second, every short change between those frames was
looked at as well, and the painted areas were measured on every frame. The hashes below are of the
original files.

| File | Bytes | SHA-256 | Noted by the DBA | Opened |
|---|---|---|---|---|
| `2026-11-23 10-54-27.mkv` | 9,172,337 | `bdf58fdb50258abb51060d1d9cd63d344422770b143f42aa078da66c0a60d820` | 13:58:09 | after commitment 1 |
| `2026-11-23 10-58-00.mkv` | 3,771,923 | `f39885fe9eb7163d075401d24c56158246c71cf6037a489b695c09a9ef79aa5f` | 13:58:59 | after commitment 1 |
| `2026-11-23 11-00-12.mkv` | 6,171,618 | `3a1145733c8bba041db76d0b1dc1a6c68a94b95eaeacc81be463e3b771d6ac5f` | 14:01:09 | after commitment 1 |
| `2026-11-23 11-48-04.mkv` | 3,446,428 | `3ebd154df10b5deb39ed5ad9bec853a8ff8bf0b2dec7cb93b1fc2d8d42f19d25` | 14:49:20 | after reveal 1 |
| `2026-11-23 11-58-21.mkv` | 9,667,585 | `7ef4a1bb5b48b5971b300d4c82082815e34d785649397b5e773d7d793265f9ec` | 15:00:52 | after commitment 2 |
| `2026-11-23 12-04-08.mkv` | 13,980,177 | `7656ec3a1c8e662c43b2c7c6dfb87cd0cc76e44eb8412789ff2587d794cc8e4f` | 15:07:35 | after commitment 2 |

Two screenshots that arrived with the first recording were never opened and are not used.
