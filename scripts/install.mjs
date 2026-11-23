// Installs the lab into a clean schema: database objects, then the APEX app.
//
//   node scripts/install.mjs          database objects + APEX application
//   node scripts/install.mjs --db     database objects only
//   node scripts/install.mjs --app    APEX application only
import { loadConfig } from '../tests/lib/config.mjs';
import { installDatabase, installApp } from '../tests/lib/install.mjs';

const cfg = loadConfig();
const only = process.argv[2];

try {
  if (only !== '--app') console.log((await installDatabase(cfg)).trim());
  if (only !== '--db') console.log((await installApp(cfg)).trim());
} catch (e) {
  console.error(e.message);
  process.exit(1);
}
