// Live session of Layer 2, shot 42: replace the verifier, harmlessly.
//
//   node tests/live/replace-verifier.mjs
//
// Recreates the Java class BlindfoldValidity, as the owner of the schema, from
// db/05_ballot_validity_java.sql with one method added, marker(), and a function that calls it.
// The checks stay the same. Then it prints what the marker answers and when the class was last
// changed. The ballot tables and their chain are not touched.
//
// To undo it, reinstall the lab: node scripts/install.mjs --db  (the assistant does this after
// the session, with your OK).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, ROOT } from '../lib/config.mjs';
import { connect, attempt } from '../lib/db.mjs';
import { sqlcl } from '../lib/sqlcli.mjs';

const cfg = loadConfig();
const source = readFileSync(join(ROOT, 'db', '05_ballot_validity_java.sql'), 'utf8');
const end = source.indexOf('\n}\n/');
if (end < 0) throw new Error('The end of the Java class was not found in db/05_ballot_validity_java.sql.');
const replaced = `${source.slice(0, end)}\n\n  // Added by tests/live/replace-verifier.mjs: the same checks, and one marker.\n  public static String marker() {\n    return "replaced in the live session";\n  }\n${source.slice(end + 1)}\n\ncreate or replace function bf_h10_marker return varchar2\nas language java name 'BlindfoldValidity.marker() return java.lang.String';\n/\n`;

const ddlTime = "select to_char(last_ddl_time, 'yyyy-mm-dd hh24:mi:ss') as t from user_objects where object_type = 'JAVA SOURCE' and object_name = 'BlindfoldValidity'";
let conn = await connect(cfg, 'schema');
const before = await attempt(conn, 'select bf_h10_marker as m from dual');
const timeBefore = (await conn.execute(ddlTime)).rows[0].T;
const chainBefore = (await conn.execute('select bf_election.verify_chains as c from dual')).rows[0].C;
await conn.close();

await sqlcl(cfg, cfg.schema, cfg.schema_password, replaced, { cwd: join(ROOT, 'db') });

conn = await connect(cfg, 'schema');
const after = await attempt(conn, 'select bf_h10_marker as m from dual');
const timeAfter = (await conn.execute(ddlTime)).rows[0].T;
const chainAfter = (await conn.execute('select bf_election.verify_chains as c from dual')).rows[0].C;
await conn.close();

console.log(`marker before:  ${before.ok ? before.rows[0].M : before.error}`);
console.log(`marker after:   ${after.ok ? after.rows[0].M : after.error}`);
console.log(`class changed:  ${timeBefore} -> ${timeAfter}`);
console.log(`chain before:   ${chainBefore}`);
console.log(`chain after:    ${chainAfter}`);
