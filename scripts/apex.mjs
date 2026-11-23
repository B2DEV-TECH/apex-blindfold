// APEXlang helper around SQLcl's `apex` command.
//
//   node scripts/apex.mjs validate [dir]    check that the APEXlang source compiles
//   node scripts/apex.mjs import   [dir]    import app/apexlang into the workspace
//   node scripts/apex.mjs export            write app/f<id>.sql from the installed app
//
// The connection comes from the lab configuration. Requires SQLcl 26.3 or later.
import { join, resolve } from 'node:path';
import { loadConfig, ROOT } from '../tests/lib/config.mjs';
import { sqlcl } from '../tests/lib/sqlcli.mjs';

const cfg = loadConfig();
const [command, dirArg] = process.argv.slice(2);
const source = resolve(dirArg ?? join(ROOT, 'app', 'apexlang'));

export async function apexValidate(dir = source) {
  return sqlcl(cfg, cfg.schema, cfg.schema_password, `apex validate -input "${dir}" -workspace ${cfg.workspace}`);
}

export async function apexImport(dir = source) {
  return sqlcl(cfg, cfg.schema, cfg.schema_password,
    `apex import -input "${dir}" -workspace ${cfg.workspace} -schema ${cfg.schema} -id ${cfg.app_id}`);
}

export async function apexExportSql() {
  return sqlcl(cfg, cfg.schema, cfg.schema_password,
    `apex export -applicationid ${cfg.app_id} -exptype SQL -skipexportdate -overwrite-files -dir "${join(ROOT, 'app')}"`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, '$1'))) {
  const actions = { validate: apexValidate, import: apexImport, export: apexExportSql };
  if (!actions[command]) {
    console.error('usage: node scripts/apex.mjs validate|import|export [dir]');
    process.exit(2);
  }
  try {
    console.log((await actions[command]()).trim());
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
