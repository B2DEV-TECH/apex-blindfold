// Plumbing shared by the hypothesis tests: command-line options and the
// result file that every test leaves next to its evidence.
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { writeJson } from './evidence.mjs';

export const DEFAULT_SEED = 20261123;

// --quick          smaller samples, for a fast smoke run
// --seed <number>  replays the randomized parts of a run
export function parseArgs(argv = process.argv.slice(2)) {
  const args = { quick: false, seed: DEFAULT_SEED };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--quick') args.quick = true;
    else if (arg === '--seed') args.seed = Number(argv[++i]);
    else if (arg.startsWith('--seed=')) args.seed = Number(arg.slice('--seed='.length));
    else throw new Error(`Unknown option: ${arg}`);
  }
  if (!Number.isInteger(args.seed)) throw new Error('--seed expects an integer');
  return args;
}

// True when the module is the script that node was started with.
export function isMain(metaUrl) {
  return Boolean(process.argv[1]) && resolve(process.argv[1]) === fileURLToPath(metaUrl);
}

export const VERDICTS = ['CONFIRMED', 'REFUTED', 'PARTIAL'];

// Collects the checks of one hypothesis and writes <dir>/result.json.
// A check records an observation. `pass` means "what we observed agrees with
// the hypothesis as stated", so for an attack hypothesis (H4, H5) a passing
// check means the attack worked.
export class Report {
  constructor(id, hypothesis, dir) {
    this.id = id;
    this.hypothesis = hypothesis;
    this.dir = dir;
    this.checks = [];
    this.notes = [];
    this.files = [];
    this.started = new Date();
    console.log(`\n${id}  ${hypothesis}`);
  }

  check(name, pass, detail = '') {
    this.checks.push({ name, pass: Boolean(pass), detail: String(detail) });
    console.log(`  [${pass ? ' ok ' : 'FAIL'}] ${name}${detail ? `: ${detail}` : ''}`);
    return Boolean(pass);
  }

  note(text) {
    this.notes.push(text);
    console.log(`  note: ${text}`);
  }

  // Registers an evidence file (path relative to /evidence).
  file(rel) {
    if (!this.files.includes(rel)) this.files.push(rel);
    return rel;
  }

  get failed() {
    return this.checks.filter((c) => !c.pass);
  }

  close(cfg, { verdict, statement, numbers = {}, mode = {} }) {
    if (!VERDICTS.includes(verdict)) throw new Error(`Invalid verdict: ${verdict}`);
    const result = {
      id: this.id,
      hypothesis: this.hypothesis,
      verdict,
      statement,
      numbers,
      mode,
      checks: this.checks,
      notes: this.notes,
      evidence: this.files,
      started: this.started.toISOString(),
      finished: new Date().toISOString(),
    };
    writeJson(cfg, `${this.dir}/result.json`, result);
    console.log(`  => ${this.id} ${verdict}: ${statement}`);
    return result;
  }
}

// Runs a test's main function with uniform error reporting.
export async function main(fn) {
  try {
    await fn();
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
