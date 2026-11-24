// APEX Blindfold - the hypotheses of Layer 1 (H1 to H6) on main.
//
// They run on tag v1-layer1, where a ballot is three ciphertexts and nothing else and the ballot
// table is an ordinary table. On main a ballot needs proofs and a signature, and the tables are
// blockchain tables, so their scripts cannot run here. They stay on main next to the evidence they
// produced, and stop at their first line with this message (decision 12 of docs/decisions-layer2.md).

/** Prints where the script runs and exits with status 1. Nothing has touched the database yet. */
export function runsOnTagOnly(id, script) {
  console.error([
    `${id} belongs to Layer 1 and runs on tag v1-layer1, where ballots carry no proofs:`,
    '  git worktree add ../apex-blindfold-v1 v1-layer1',
    '  copy .local/db.json into ../apex-blindfold-v1/.local/',
    `  cd ../apex-blindfold-v1 && npm ci && node ${script}`,
    'On main, `npm run lab` runs G1 and H7 to H11.',
  ].join('\n'));
  process.exit(1);
}
