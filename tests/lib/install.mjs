// Installation steps shared by the test runner and scripts/install.mjs.
import { join } from 'node:path';
import { ROOT } from './config.mjs';
import { sqlcl } from './sqlcli.mjs';

const DB = join(ROOT, 'db');

// Drops and recreates every database object of the lab: a clean schema.
export async function installDatabase(cfg) {
  const out = [];
  out.push(await sqlcl(cfg, cfg.schema, cfg.schema_password, `@"${join(DB, 'uninstall.sql')}"`, { cwd: DB }));
  out.push(await sqlcl(cfg, cfg.schema, cfg.schema_password, `@"${join(DB, 'install.sql')}"`, { cwd: DB }));
  return out.join('\n');
}

// Imports the APEX application from its APEXlang source.
export async function installApp(cfg) {
  return sqlcl(cfg, cfg.schema, cfg.schema_password,
    `apex import -input "${join(ROOT, 'app', 'apexlang')}" -workspace ${cfg.workspace} -schema ${cfg.schema} -id ${cfg.app_id}`);
}
