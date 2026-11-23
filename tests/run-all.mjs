// One command for the whole lab, starting from a clean schema.
//
//   install       drops and recreates every database object, imports the APEX app
//   unit tests    the Paillier library against known answers, the PL/SQL API against its contract
//   step 0        environment report (versions, MLE or Java, big-number timing)
//   H1 .. H6      one script per hypothesis; each leaves evidence/<dir>/result.json
//   screenshots   the application and what a DBA sees
//   summary       evidence/summary.md and evidence/summary.json
//
//   node tests/run-all.mjs                 the full lab (evidence/summary.md records how long it took)
//   node tests/run-all.mjs --quick         smaller samples, a few minutes
//   node tests/run-all.mjs --seed 7        another replayable run
//   node tests/run-all.mjs --only h2,h4    some steps only, no reinstall
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

const HYPOTHESES = [
  { key: 'h1', id: 'H1', title: 'Correctness', script: 'h1-correctness.mjs', dir: 'h1-correctness' },
  { key: 'h2', id: 'H2', title: 'Blindness', script: 'h2-blindness.mjs', dir: 'h2-blindness' },
  { key: 'h3', id: 'H3', title: 'Indistinguishability', script: 'h3-indistinguishability.mjs', dir: 'h3-indistinguishability' },
  { key: 'h4', id: 'H4', title: 'Ballot stuffing', script: 'h4-ballot-stuffing.mjs', dir: 'h4-ballot-stuffing' },
  { key: 'h5', id: 'H5', title: 'Other limits', script: 'h5-limits.mjs', dir: 'h5-limits' },
  { key: 'h6', id: 'H6', title: 'Cost', script: 'h6-cost.mjs', dir: 'h6-cost' },
];
const OWNED = ['00-environment', 'app', ...HYPOTHESES.map((h) => h.dir), 'summary.md', 'summary.json'];

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
  // A full run owns these folders. evidence/live-session is never touched.
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

if (installed) {
  if (wanted('unit')) await step('unit tests: Paillier library and election API', async () => (await runNode(['--test', 'tests/unit/paillier.test.mjs', 'tests/unit/election-api.test.mjs'])) === 0);
  if (wanted('step0')) await step('step 0: environment', async () => (await runNode(['tests/step0-environment.mjs', ...(opts.quick ? ['--quick'] : [])])) === 0);
  for (const h of HYPOTHESES) {
    if (!wanted(h.key)) continue;
    rmSync(join(EVIDENCE, h.dir, 'result.json'), { force: true });
    await step(`${h.id}: ${h.title}`, async () => (await runNode([`tests/${h.script}`, ...passArgs])) === 0 && existsSync(join(EVIDENCE, h.dir, 'result.json')));
  }
  if (wanted('screenshots')) await step('screenshots', async () => (await runNode(['tests/screenshots.mjs'])) === 0);
}

// ---- summary: what every hypothesis file says, in one table
const readJson = (rel) => (existsSync(join(EVIDENCE, rel)) ? JSON.parse(readFileSync(join(EVIDENCE, rel), 'utf8')) : null);
const results = HYPOTHESES.map((h) => ({ ...h, result: readJson(`${h.dir}/result.json`) }));
const environment = readJson('00-environment/environment.json');
const main = { H1: 'elections.txt', H2: 'scan-summary.txt', H3: 'distinguishers.txt', H4: 'stuffing.txt', H5: 'a-dba-adds-votes.txt', H6: 'timings.json' };

const summary = {
  generated: new Date().toISOString(),
  command: `node tests/run-all.mjs ${process.argv.slice(2).join(' ')}`.trim(),
  mode: opts.quick ? 'quick' : 'full',
  seed: opts.seed,
  duration_ms: Date.now() - started,
  environment: environment?.environment ?? null,
  tally_engine: environment?.tally_engine ?? null,
  steps,
  hypotheses: results.map((h) => ({
    id: h.id,
    title: h.title,
    verdict: h.result?.verdict ?? 'NO RESULT',
    statement: h.result?.statement ?? 'The test left no result file.',
    checks: h.result ? `${h.result.checks.filter((c) => c.pass).length}/${h.result.checks.length}` : '0/0',
    mode: h.result?.mode ?? null,
    evidence: `evidence/${h.dir}/result.json`,
    files: h.result?.evidence?.map((f) => `evidence/${f}`) ?? [],
  })),
};
writeJson(cfg, 'summary.json', summary);

const env = summary.environment;
const lines = [
  '# APEX Blindfold: results of one run',
  '',
  `Generated ${summary.generated} by \`${summary.command}\` (${summary.mode} mode, seed ${summary.seed}, ${minutes(summary.duration_ms)}).`,
  '',
  env ? `Environment: ${env.database.split(' - ')[0]} on ${env.database_platform}, APEX ${env.apex}, ORDS ${env.ords}, tally engine: ${summary.tally_engine === 'java' ? 'Java stored procedure' : 'MLE JavaScript'}. Details in \`evidence/00-environment\`.` : 'Environment: step 0 did not run.',
  '',
  '| # | Hypothesis | Verdict | Observed in this run | Evidence |',
  '|---|---|---|---|---|',
  ...summary.hypotheses.map((h) => `| ${h.id} | ${h.title} | **${h.verdict}** | ${h.statement.replace(/\|/g, '\\|')} | [\`${h.evidence.replace('result.json', main[h.id])}\`](${h.evidence.replace('evidence/', '').replace('result.json', main[h.id])}), [result.json](${h.evidence.replace('evidence/', '')}) |`),
  '',
  'Every row is copied from the `result.json` that the test of that hypothesis wrote. The numbers change',
  'from run to run where randomness or timing is involved; the verdicts should not.',
  '',
  '| Step | Result | Time |',
  '|---|---|---|',
  ...steps.map((s) => `| ${s.name} | ${s.ok ? 'done' : 'FAILED'} | ${minutes(s.ms)} |`),
  '',
];
writeText(cfg, 'summary.md', lines.join('\n'));

console.log(`\n=== summary ${'='.repeat(63)}`);
for (const h of summary.hypotheses) console.log(`${h.id}  ${h.verdict.padEnd(10)} ${h.checks.padEnd(6)} ${h.title}`);
console.log(`\n${steps.filter((s) => s.ok).length}/${steps.length} steps done in ${minutes(Date.now() - started)}. Table: evidence/summary.md`);

const broken = steps.some((s) => !s.ok) || !installed || results.some((h) => wanted(h.key) && !h.result);
process.exitCode = broken ? 1 : 0;
