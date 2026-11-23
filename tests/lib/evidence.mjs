// Writes evidence files under /evidence. Every write is scrubbed of the
// configured secrets, so a credential can never land in a committed file.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ROOT, secretsOf, masksOf } from './config.mjs';
import { scrub } from './sqlcli.mjs';

export const EVIDENCE = join(ROOT, 'evidence');

export function evidencePath(rel) {
  const full = join(EVIDENCE, rel);
  mkdirSync(dirname(full), { recursive: true });
  return full;
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Removes credentials and local details (host names, the OS account) from a text.
export function sanitize(cfg, text) {
  let clean = scrub(text, secretsOf(cfg));
  for (const [value, placeholder] of masksOf(cfg)) clean = clean.replace(new RegExp(escapeRegExp(value), 'gi'), placeholder);
  return clean;
}

export function writeText(cfg, rel, text) {
  const full = evidencePath(rel);
  writeFileSync(full, sanitize(cfg, text).replace(/\r\n/g, '\n'));
  return full;
}

export function writeJson(cfg, rel, value) {
  return writeText(cfg, rel, `${JSON.stringify(value, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2)}\n`);
}

// Header that goes on top of every text evidence file.
export function header(title, lines = []) {
  return [`# ${title}`, `# generated: ${new Date().toISOString()}`, ...lines.map((l) => `# ${l}`), ''].join('\n');
}

export function median(values) {
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

export function stats(values) {
  const s = [...values].sort((a, b) => a - b);
  const sum = s.reduce((a, b) => a + b, 0);
  const round = (x) => Math.round(x * 1000) / 1000;
  return { n: s.length, min: round(s[0]), median: round(median(s)), mean: round(sum / s.length), max: round(s[s.length - 1]) };
}
