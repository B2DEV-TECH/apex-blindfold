// Calls the independent Python reference (tests/crosscheck/paillier_ref.py).
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { ROOT } from './config.mjs';

const SCRIPT = join(ROOT, 'tests', 'crosscheck', 'paillier_ref.py');

function candidates() {
  if (process.env.BF_PYTHON) return [[process.env.BF_PYTHON, []]];
  return process.platform === 'win32' ? [['py', ['-3']], ['python', []]] : [['python3', []], ['python', []]];
}

function runOnce(exe, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, [...args, SCRIPT], { windowsHide: true });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`python exited ${code}: ${err}`))));
    child.stdin.end(input);
  });
}

// request: one operation object or an array of them. Returns the parsed answer.
export async function pythonRef(request) {
  const input = JSON.stringify(request);
  let lastError;
  for (const [exe, args] of candidates()) {
    try {
      return JSON.parse(await runOnce(exe, args, input));
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(`Python 3 is required for the cross-check (set BF_PYTHON). Last error: ${lastError.message}`);
}

export async function pythonVersion() {
  for (const [exe, args] of candidates()) {
    try {
      return await new Promise((resolve, reject) => {
        const child = spawn(exe, [...args, '--version'], { windowsHide: true });
        let out = '';
        child.stdout.on('data', (d) => { out += d; });
        child.stderr.on('data', (d) => { out += d; });
        child.on('error', reject);
        child.on('close', () => resolve(out.trim()));
      });
    } catch { /* try the next candidate */ }
  }
  return 'not found';
}
