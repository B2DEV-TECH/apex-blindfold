// Local convenience: creates (or drops) the lab schema, the auditor account and
// the APEX workspace using operating-system authenticated SYSDBA.
// Readers without OS authentication run db/admin/create_schema.sql by hand.
//
//   node scripts/bootstrap-local.mjs            create
//   node scripts/bootstrap-local.mjs --drop     drop everything
import { join } from 'node:path';
import { loadConfig, secretsOf, ROOT } from '../tests/lib/config.mjs';
import { sysdba, scrub } from '../tests/lib/sqlcli.mjs';

const cfg = loadConfig();
const container = cfg.connect.split('/').pop();
const drop = process.argv.includes('--drop');
const script = join(ROOT, 'db', 'admin', drop ? 'drop_schema.sql' : 'create_schema.sql');

const defines = [
  `define BF_SCHEMA=${cfg.schema}`,
  `define BF_DBA=${cfg.dba}`,
  `define BF_WORKSPACE=${cfg.workspace}`,
];
if (!drop) {
  defines.push(
    `define BF_SCHEMA_PW=${cfg.schema_password}`,
    `define BF_DBA_PW=${cfg.dba_password}`,
    `define BF_WS_ADMIN=${cfg.ws_admin}`,
    `define BF_WS_ADMIN_PW=${cfg.ws_admin_password}`,
  );
}

const out = await sysdba(container, ['set verify off feedback on', ...defines, `@"${script}"`].join('\n'));
console.log(scrub(out, secretsOf(cfg)).trim());
console.log(drop ? 'Lab schema, auditor account and workspace dropped.' : 'Lab schema, auditor account and workspace created.');
