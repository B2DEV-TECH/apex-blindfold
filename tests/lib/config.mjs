// Loads lab configuration from environment variables or the git-ignored
// .local/db.json file. Secrets are never printed by this module.
import { readFileSync, existsSync } from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const FIELDS = {
  connect: 'BF_CONNECT',                    // host:port/service of the PDB
  schema: 'BF_SCHEMA',                      // application owner (parsing schema)
  schema_password: 'BF_SCHEMA_PASSWORD',
  dba: 'BF_DBA',                            // the "curious DBA" account used by the audits
  dba_password: 'BF_DBA_PASSWORD',
  workspace: 'BF_WORKSPACE',                // APEX workspace that owns the app
  ws_admin: 'BF_WS_ADMIN',                  // workspace developer (builder screenshots only)
  ws_admin_password: 'BF_WS_ADMIN_PASSWORD',
  ords_base: 'BF_ORDS_BASE',                // e.g. http://localhost:8080/ords
  app_id: 'BF_APP_ID',                      // application id to install under
  browser_channel: 'BF_BROWSER_CHANNEL',    // optional: msedge | chrome (default: bundled chromium)
  sql_cli: 'BF_SQLCL',                      // optional: path to SQLcl (default: sql on PATH)
};

export function loadConfig() {
  const file = join(ROOT, '.local', 'db.json');
  // PowerShell writes a byte-order mark; strip it before parsing.
  const fromFile = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, '')) : {};
  const cfg = {};
  for (const [key, env] of Object.entries(FIELDS)) cfg[key] = process.env[env] ?? fromFile[key];
  cfg.app_id = Number(cfg.app_id ?? 2620);
  cfg.sql_cli = cfg.sql_cli ?? 'sql';
  const required = ['connect', 'schema', 'schema_password', 'workspace', 'ords_base'];
  const missing = required.filter((k) => !cfg[k]);
  if (missing.length) {
    throw new Error(`Missing configuration: ${missing.join(', ')}. Set ${missing.map((k) => FIELDS[k]).join(', ')} or create .local/db.json (see README).`);
  }
  cfg.ords_base = cfg.ords_base.replace(/\/+$/, '');
  return cfg;
}

// Values that must never appear in any committed evidence file.
export function secretsOf(cfg) {
  return [cfg.schema_password, cfg.dba_password, cfg.ws_admin_password].filter(Boolean);
}

// Where the lab ran is nobody's business: host names, ports and the operating
// system account are replaced by placeholders in every evidence file.
// Returns [text, placeholder] pairs, matched without regard to case.
export function masksOf(cfg) {
  const masks = [];
  const add = (value, placeholder) => {
    if (value && String(value).length >= 3) masks.push([String(value), placeholder]);
  };
  try {
    add(new URL(cfg.ords_base).host, '<host>');
  } catch {
    // not a URL: nothing to mask
  }
  add(String(cfg.connect ?? '').split('/')[0], '<db-host>');
  add(os.hostname(), '<hostname>');
  add(os.userInfo().username, '<os-user>');
  return masks;
}
