// One command for the whole lab, Layer 2, starting from a clean schema.
//
//   install       drops and recreates every database object, imports the APEX app
//   unit tests    the Paillier library against known answers, the PL/SQL API against its contract
//   step 0        environment report (versions, MLE or Java, big-number timing)
//   G1            test vectors: the Java verifier must reproduce every hash of the browser,
//                 byte for byte. If it does not, no hypothesis runs.
//   H7 .. H11     one script per hypothesis; each leaves evidence/<dir>/result.json
//   summary       evidence/summary.md and evidence/summary.json
//
// Layer 1 (H1 .. H6) runs on the tag v1-layer1: git checkout v1-layer1 && npm run lab.
// Its evidence stays in evidence/h1-* .. evidence/h6-*, evidence/app and evidence/summary-layer1.*,
// and this runner never touches it.
//
//   node tests/run-all.mjs                 the full lab (evidence/summary.md records how long it took)
//   node tests/run-all.mjs --quick         smaller samples
//   node tests/run-all.mjs --seed 7        another replayable run
//   node tests/run-all.mjs --only h7,h9    some steps only, no reinstall
//
// A hypothesis that comes out REFUTED is a result, not a failure of the run.
// The run fails (exit code 1) only when a step crashes or leaves no result.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, ROOT } from './lib/config.mjs';
import { installDatabase, installApp } from './lib/install.mjs';
import { EVIDENCE, writeText, writeJson } from './lib/evidence.mjs';
import { DEFAULT_SEED } from './lib/harness.mjs';

const GATE = { key: 'g1', id: 'G1', title: 'Test vectors', script: 'g1-vectors.mjs', dir: 'g1-test-vectors', main: 'vectors.txt' };
const HYPOTHESES = [
  { key: 'h7', id: 'H7', title: 'Soundness', script: 'h7-soundness.mjs', dir: 'h7-soundness', main: 'attempts.txt' },
  { key: 'h8', id: 'H8', title: 'Completeness', script: 'h8-completeness.mjs', dir: 'h8-completeness', main: 'elections.txt' },
  { key: 'h9', id: 'H9', title: 'Integrity', script: 'h9-integrity.mjs', dir: 'h9-integrity', main: 'statements.txt' },
  { key: 'h10', id: 'H10', title: 'What still breaks', script: 'h10-what-still-breaks.mjs', dir: 'h10-what-still-breaks', main: 'limits.txt' },
  { key: 'h11', id: 'H11', title: 'Cost', script: 'h11-cost.mjs', dir: 'h11-cost', main: 'summary.txt' },
];
const OWNED = ['00-environment', GATE.dir, ...HYPOTHESES.map((h) => h.dir), 'summary.md', 'summary.json'];

function options(argv) {
  const out = { quick: false, seed: DEFAULT_SEED, only: null, skipInstall: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--quick') out.quick = true;
    else if (arg === '--skip-install') out.skipInstall = true;
    else if (arg === '--seed') out.seed = Number(argv[++i]);
    else if (arg.startsWith('--seed=')) out.seed = Number(arg.slice(7));
    else if (arg === '--only') out.only = argv[++i].toLowerCase().split(',');
    else if (arg.startsWith('--only=')) out.only = arg.slice(7).toLowerCase().split(',');
    else throw new Error(`Unknown option: ${arg}`);
  }
  if (!Number.isInteger(out.seed)) throw new Error('--seed expects an integer');
  return out;
}

function runNode(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, stdio: 'inherit' });
    child.on('close', (code) => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  });
}

const minutes = (ms) => `${Math.floor(ms / 60000)} min ${String(Math.round((ms % 60000) / 1000)).padStart(2, '0')} s`;
const readJson = (rel) => (existsSync(join(EVIDENCE, rel)) ? JSON.parse(readFileSync(join(EVIDENCE, rel), 'utf8')) : null);

const opts = options(process.argv.slice(2));
const cfg = loadConfig();
const wanted = (key) => !opts.only || opts.only.includes(key);
const passArgs = [...(opts.quick ? ['--quick'] : []), '--seed', String(opts.seed)];
const steps = [];
const started = Date.now();

async function step(name, fn) {
  const t0 = Date.now();
  console.log(`\n=== ${name} ${'='.repeat(Math.max(3, 70 - name.length))}`);
  let ok = true;
  try {
    ok = (await fn()) !== false;
  } catch (error) {
    ok = false;
    console.error(error.message);
  }
  steps.push({ name, ok, ms: Date.now() - t0 });
  console.log(`--- ${name}: ${ok ? 'done' : 'FAILED'} in ${minutes(Date.now() - t0)}`);
  return ok;
}

if (!opts.only) {
  // A full run owns these folders. Layer 1 evidence and evidence/live-session* are never touched.
  for (const name of OWNED) rmSync(join(EVIDENCE, name), { recursive: true, force: true });
}

let installed = true;
if (!opts.only && !opts.skipInstall) {
  installed = await step('install: clean schema and APEX application', async () => {
    const db = await installDatabase(cfg);
    console.log(db.trim().split('\n').slice(-6).join('\n'));
    const app = await installApp(cfg);
    console.log(app.trim().split('\n').slice(-4).join('\n'));
  });
}

let gatePassed = true;
if (installed) {
  if (wanted('unit')) await step('unit tests: Paillier library and election API', async () => (await runNode(['--test', 'tests/unit/paillier.test.mjs', 'tests/unit/election-api.test.mjs'])) === 0);
  if (wanted('step0')) await step('step 0: environment', async () => (await runNode(['tests/step0-environment.mjs', ...(opts.quick ? ['--quick'] : [])])) === 0);
  if (wanted(GATE.key) || HYPOTHESES.some((h) => wanted(h.key))) {
    rmSync(join(EVIDENCE, GATE.dir, 'result.json'), { force: true });
    await step(`${GATE.id}: ${GATE.title}`, async () => (await runNode([`tests/${GATE.script}`])) === 0);
    gatePassed = readJson(`${GATE.dir}/result.json`)?.verdict === 'PASS';
    if (!gatePassed) console.error('\nG1 did not pass: the browser and the database do not agree on the hashes. No hypothesis runs.');
  }
  for (const h of HYPOTHESES) {
    if (!wanted(h.key) || !gatePassed) continue;
    rmSync(join(EVIDENCE, h.dir, 'result.json'), { force: true });
    await step(`${h.id}: ${h.title}`, async () => (await runNode([`tests/${h.script}`, ...passArgs])) === 0 && existsSync(join(EVIDENCE, h.dir, 'result.json')));
  }
}

// ---- summary: what the gate and every hypothesis file say, in one table
const gate = readJson(`${GATE.dir}/result.json`);
const results = HYPOTHESES.map((h) => ({ ...h, result: readJson(`${h.dir}/result.json`) }));
const environment = readJson('00-environment/environment.json');

const summary = {
  layer: 2,
  generated: new Date().toISOString(),
  command: `node tests/run-all.mjs ${process.argv.slice(2).join(' ')}`.trim(),
  mode: opts.quick ? 'quick' : 'full',
  seed: opts.seed,
  duration_ms: Date.now() - started,
  environment: environment?.environment ?? null,
  tally_engine: environment?.tally_engine ?? null,
  steps,
  gate: {
    id: GATE.id,
    title: GATE.title,
    verdict: gate?.verdict ?? 'NO RESULT',
    statement: gate?.statement ?? 'The test left no result file.',
    evidence: `evidence/${GATE.dir}/${GATE.main}`,
  },
  hypotheses: results.map((h) => ({
    id: h.id,
    title: h.title,
    verdict: h.result?.verdict ?? (gatePassed ? 'NO RESULT' : 'NOT RUN'),
    statement: h.result?.statement ?? (gatePassed ? 'The test left no result file.' : 'Not run: G1 did not pass.'),
    checks: h.result ? `${h.result.checks.filter((c) => c.pass).length}/${h.result.checks.length}` : '0/0',
    mode: h.result?.mode ?? null,
    evidence: `evidence/${h.dir}/result.json`,
    main: `evidence/${h.dir}/${h.main}`,
    files: h.result?.evidence?.map((f) => `evidence/${f}`) ?? [],
  })),
};
writeJson(cfg, 'summary.json', summary);

const env = summary.environment;
const rel = (path) => path.replace(/^evidence\//, '');
const lines = [
  '# APEX Blindfold Layer 2: results of one run',
  '',
  `Generated ${summary.generated} by \`${summary.command}\` (${summary.mode} mode, seed ${summary.seed}, ${minutes(summary.duration_ms)}).`,
  '',
  env ? `Environment: ${env.database.split(' - ')[0]} on ${env.database_platform}, APEX ${env.apex}, ORDS ${env.ords}, tally engine: ${summary.tally_engine === 'java' ? 'Java stored procedure' : 'MLE JavaScript'}. Details in \`evidence/00-environment\`.` : 'Environment: step 0 did not run.',
  '',
  `Gate ${GATE.id}, ${GATE.title}: **${summary.gate.verdict}**. ${summary.gate.statement.replace(/\|/g, '\\|')} [\`${summary.gate.evidence}\`](${rel(summary.gate.evidence)})`,
  '',
  '| # | Hypothesis | Verdict | Observed in this run | Evidence |',
  '|---|---|---|---|---|',
  ...summary.hypotheses.map((h) => `| ${h.id} | ${h.title} | **${h.verdict}** | ${h.statement.replace(/\|/g, '\\|')} | [\`${h.main}\`](${rel(h.main)}), [result.json](${rel(h.evidence)}) |`),
  '',
  'Every row is copied from the `result.json` that the test of that hypothesis wrote. The numbers change',
  'from run to run where randomness or timing is involved; the verdicts should not.',
  'Layer 1 (H1 to H6) is in [summary-layer1.md](summary-layer1.md), from the run of tag `v1-layer1`.',
  '',
  '| Step | Result | Time |',
  '|---|---|---|',
  ...steps.map((s) => `| ${s.name} | ${s.ok ? 'done' : 'FAILED'} | ${minutes(s.ms)} |`),
  '',
];
writeText(cfg, 'summary.md', lines.join('\n'));

console.log(`\n=== summary ${'='.repeat(63)}`);
console.log(`${GATE.id}  ${summary.gate.verdict}`);
for (const h of summary.hypotheses) console.log(`${h.id.padEnd(4)} ${h.verdict.padEnd(10)} ${h.checks.padEnd(6)} ${h.title}`);
console.log(`\n${steps.filter((s) => s.ok).length}/${steps.length} steps done in ${minutes(Date.now() - started)}. Table: evidence/summary.md`);

const broken = steps.some((s) => !s.ok) || !installed || !gatePassed || results.some((h) => wanted(h.key) && !h.result);
process.exitCode = broken ? 1 : 0;
