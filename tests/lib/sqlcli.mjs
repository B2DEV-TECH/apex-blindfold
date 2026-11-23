// Runs SQL scripts through SQLcl (or SQL*Plus). The connect statement travels
// on standard input, so passwords never show up in a process argument list.
import { spawn } from 'node:child_process';

function run(exe, args, stdinText, { cwd, env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, args, { cwd, env: { ...process.env, ...env }, windowsHide: true });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out }));
    child.stdin.end(stdinText);
  });
}

// Run statements as a database user through SQLcl in thin mode.
export async function sqlcl(cfg, user, password, body, { cwd } = {}) {
  const text = [
    'whenever sqlerror exit failure rollback',
    `connect ${user}/"${password}"@${cfg.connect}`,
    'set define off',
    body,
    'exit',
    '',
  ].join('\n');
  const { code, out } = await run(cfg.sql_cli, ['-thin', '-nohistory', '-noupdates', '-S', '/nolog'], text, { cwd });
  if (code !== 0) throw new Error(`SQLcl failed (exit ${code}):\n${scrub(out, [password])}`);
  return scrub(out, [password]);
}

// Local convenience only: operating-system authenticated SYSDBA through SQL*Plus.
export async function sysdba(container, body, { oracleSid = process.env.ORACLE_SID ?? 'FREE' } = {}) {
  const text = [
    'whenever sqlerror exit failure rollback',
    'whenever oserror exit failure rollback',
    `alter session set container = ${container};`,
    body,
    'exit',
    '',
  ].join('\n');
  const { code, out } = await run('sqlplus', ['-L', '-S', '/ as sysdba'], text, { env: { ORACLE_SID: oracleSid } });
  if (code !== 0) throw new Error(`SQL*Plus failed (exit ${code}):\n${out}`);
  return out;
}

export function scrub(text, secrets) {
  let clean = text;
  for (const s of secrets) if (s) clean = clean.split(s).join('********');
  return clean;
}
