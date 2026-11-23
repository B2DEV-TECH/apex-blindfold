// Looks for things that must not leave this machine, in every file git would
// publish: the lab passwords, host names, the operating-system account, home
// directory paths, private network addresses, e-mail addresses, and the names
// of other APEX workspaces and schemas of the database the lab ran on.
//
//   node scripts/prepush-scan.mjs                 exit code 1 when something is found
//   node scripts/prepush-scan.mjs --word <text>   also look for this text (repeatable)
//
// The words it looks for are read at run time from the local configuration and
// from the database. None of them is written in this file or in its output:
// a finding names the file, the line and the kind of thing, not the value.
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { loadConfig, secretsOf, ROOT } from '../tests/lib/config.mjs';
import { connect } from '../tests/lib/db.mjs';

const cfg = loadConfig();
const extra = process.argv.flatMap((arg, i, all) => (arg === '--word' && all[i + 1] ? [all[i + 1]] : []));
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const word = (text) => new RegExp(`(?<![A-Za-z0-9_])${escape(text)}(?![A-Za-z0-9_])`, 'i');

// ---- what to look for
const needles = [];
const add = (kind, value, pattern) => { if (value && String(value).length >= 3) needles.push({ kind, pattern: pattern ?? new RegExp(escape(String(value)), 'i') }); };
for (const secret of secretsOf(cfg)) needles.push({ kind: 'a lab password', pattern: new RegExp(escape(secret)) });
add('the machine name', os.hostname(), word(os.hostname()));
add('the operating-system account', os.userInfo().username, word(os.userInfo().username));
add('the home directory', os.homedir());
add('the home directory', os.homedir().replace(/\\/g, '/'));
const hosts = [String(cfg.connect).split('/')[0].split(':')[0]];
try { hosts.push(new URL(cfg.ords_base).hostname); } catch { /* not a URL */ }
for (const host of hosts) if (!/^(localhost|127\.0\.0\.1|::1)$/i.test(host)) add('a lab host name', host, word(host));
for (const text of extra) add('a word given on the command line', text);

// Other tenants of the same database: workspaces and schemas that are not the lab's.
const own = new Set([cfg.workspace, cfg.schema, cfg.dba, cfg.ws_admin].filter(Boolean).map((name) => name.toUpperCase()));
let tenants = 0;
if (cfg.dba && cfg.dba_password) {
  const dba = await connect(cfg, 'dba');
  try {
    const names = new Set();
    for (const row of (await dba.execute('select workspace as name from apex_workspaces')).rows) names.add(row.NAME);
    for (const row of (await dba.execute("select username as name from dba_users where oracle_maintained = 'N'")).rows) names.add(row.NAME);
    for (const name of names) {
      // Short or generic names would match ordinary words; the lab's own names are public.
      if (own.has(name.toUpperCase()) || name.length < 5 || /^(APEX|ORDS|INTERNAL|PUBLIC|ADMIN|HR|SCOTT)/i.test(name)) continue;
      needles.push({ kind: 'another workspace or schema of this database', pattern: word(name) });
      tenants += 1;
    }
  } finally {
    await dba.close();
  }
}

const patterns = [
  { kind: 'a private network address', pattern: /(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])/ },
  { kind: 'an e-mail address', pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}/ },
  { kind: 'a private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { kind: 'a Windows user path', pattern: /[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"']+/ },
];
// Addresses that belong to nobody: the domains reserved for examples, GitHub's
// no-reply addresses and the user name of its SSH remotes.
const allowed = [/@(example\.(com|org|net)|[a-z0-9.-]+\.(invalid|example|test)|users\.noreply\.github\.com)$/i, /^git@github\.com$/i];

// ---- every file git would publish
const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: ROOT, encoding: 'utf8' }).split('\0').filter(Boolean);
const findings = [];
const forbiddenNames = /(^|\/)(\.env(\..*)?|.*\.env|db\.json|oracle\.json|tnsnames\.ora|sqlnet\.ora|[ce]wallet\..*|.*\.(sso|p12|jks|pem|key|pfx))$/i;
let bytes = 0;
for (const file of files) {
  if (forbiddenNames.test(file)) findings.push({ file, line: 0, kind: 'a file that should never be committed' });
  const full = join(ROOT, file);
  if (!statSync(full).isFile()) continue;
  const buffer = readFileSync(full);
  bytes += buffer.length;
  // Text is searched line by line. Binary files are searched as Latin-1, which finds any ASCII text inside them.
  const binary = buffer.subarray(0, 8000).includes(0);
  const lines = buffer.toString(binary ? 'latin1' : 'utf8').split('\n');
  lines.forEach((line, index) => {
    for (const { kind, pattern } of [...needles, ...patterns]) {
      // Every match of the line is looked at, so that an allowed address cannot hide another one.
      const everywhere = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
      for (const match of line.matchAll(everywhere)) {
        if (kind === 'an e-mail address' && allowed.some((ok) => ok.test(match[0]))) continue;
        findings.push({ file, line: binary ? 0 : index + 1, kind });
        break;
      }
    }
  });
}

console.log(`Scanned ${files.length} files, ${(bytes / 1e6).toFixed(1)} MB, for ${needles.length} local values (${tenants} of them other workspaces or schemas) and ${patterns.length} patterns.`);
if (findings.length === 0) {
  console.log('Nothing found.');
} else {
  const grouped = new Map();
  for (const f of findings) {
    const key = `${f.file}: ${f.kind}`;
    grouped.set(key, [...(grouped.get(key) ?? []), f.line]);
  }
  for (const [key, lines] of grouped) console.log(`  ${key}${lines[0] ? ` (line ${[...new Set(lines)].slice(0, 8).join(', ')}${new Set(lines).size > 8 ? ', ...' : ''})` : ''}`);
  console.log(`${findings.length} finding(s) in ${new Set(findings.map((f) => f.file)).size} file(s).`);
  process.exitCode = 1;
}
