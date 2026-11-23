// Step 0: environment check.
//
//   1. Record database, APEX and ORDS versions.
//   2. Find out, by trying, whether MLE JavaScript is available and which
//      privileges it needs.
//   3. Prove that modular exponentiation with 4096-bit operands works inside
//      the database, check the answers against Python and Node, and time it.
//      MLE JavaScript (BigInt) is tried first. When MLE is not available, the
//      same proof runs on a Java stored procedure (java.math.BigInteger).
//
// Evidence: evidence/00-environment/
import { randomBytes } from 'node:crypto';
import { loadConfig } from './lib/config.mjs';
import { connect, connectAs, attempt, asTable } from './lib/db.mjs';
import { writeText, writeJson, header, stats } from './lib/evidence.mjs';
import { pythonRef, pythonVersion } from './lib/python.mjs';

const cfg = loadConfig();
const quick = process.argv.includes('--quick');
const DIR = '00-environment';

// MLE probe: plain square-and-multiply on BigInt, nothing else.
const MLE_MODULE = `
export function modpowHex(baseHex, expHex, modHex, reps) {
  const base = BigInt('0x' + baseHex);
  const mod = BigInt('0x' + modHex);
  const bits = BigInt('0x' + expHex).toString(2);
  let result = 0n;
  const started = Date.now();
  for (let i = 0; i < reps; i++) {
    let acc = 1n;
    for (let k = 0; k < bits.length; k++) {
      acc = (acc * acc) % mod;
      if (bits[k] === '1') acc = (acc * base) % mod;
    }
    result = acc;
  }
  const elapsedMs = Date.now() - started;
  return JSON.stringify({ result: result.toString(16), reps, elapsedMs });
}
`;
const MLE_DDL = [
  `create or replace mle module bf_probe_mod language javascript as ${MLE_MODULE}`,
  `create or replace function bf_probe_modpow(p_base in varchar2, p_exp in varchar2, p_mod in varchar2, p_reps in number) return varchar2
     as mle module bf_probe_mod signature 'modpowHex(string, string, string, number)';`,
];
const MLE_DROP = ['drop function bf_probe_modpow', 'drop mle module bf_probe_mod'];

// Java probe: the fallback named in the lab design.
const JAVA_DDL = [
  `create or replace and compile java source named "BfProbe" as
import java.math.BigInteger;
public class BfProbe {
  public static String modPowHex(String baseHex, String expHex, String modHex, int reps) {
    BigInteger base = new BigInteger(baseHex, 16);
    BigInteger exp = new BigInteger(expHex, 16);
    BigInteger mod = new BigInteger(modHex, 16);
    BigInteger result = BigInteger.ZERO;
    long started = System.nanoTime();
    for (int i = 0; i < reps; i++) {
      result = base.modPow(exp, mod);
    }
    double elapsedMs = (System.nanoTime() - started) / 1000000.0;
    return "{\\"result\\":\\"" + result.toString(16) + "\\",\\"reps\\":" + reps + ",\\"elapsedMs\\":" + elapsedMs + "}";
  }
}`,
  `create or replace function bf_probe_modpow(p_base in varchar2, p_exp in varchar2, p_mod in varchar2, p_reps in number) return varchar2
     as language java name 'BfProbe.modPowHex(java.lang.String, java.lang.String, java.lang.String, int) return java.lang.String';`,
];
const JAVA_DROP = ['drop function bf_probe_modpow', 'drop java source "BfProbe"'];

const randomHex = (bits) => {
  const bytes = randomBytes(bits / 8);
  bytes[0] |= 0x80; // force the top bit so the operand really has the full size
  return bytes.toString('hex');
};
const bitLength = (hex) => BigInt(`0x${hex}`).toString(2).length;

function nodeModPow(baseHex, expHex, modHex) {
  const base = BigInt(`0x${baseHex}`);
  const mod = BigInt(`0x${modHex}`);
  let acc = 1n;
  for (const bit of BigInt(`0x${expHex}`).toString(2)) {
    acc = (acc * acc) % mod;
    if (bit === '1') acc = (acc * base) % mod;
  }
  return acc.toString(16);
}

// ---------------------------------------------------------------- 1. versions
async function versions(dba) {
  const one = async (sql) => (await attempt(dba, sql)).rows?.[0] ?? null;
  const banner = await one('select banner_full from v$version');
  const apex = await one('select version_no from apex_release');
  const ords = await one('select version from ords_metadata.ords_version');
  const platform = await one('select platform_name from v$database');
  const params = await attempt(dba, "select name, value from v$parameter where name in ('mle_prog_languages', 'compatible') order by name");
  const registry = await attempt(dba, "select comp_name, version, status from dba_registry where comp_id in ('APEX', 'JAVAVM', 'CATJAVA', 'CATPROC') order by comp_name");
  const mleLang = await attempt(dba, "select owner, object_name, object_type, status from dba_objects where object_type = 'MLE LANGUAGE' order by 1, 2");
  const javaVersion = await one("select dbms_java.get_ojvm_property('java.version') as java_version from dual");

  const env = {
    database: banner?.BANNER_FULL?.replace(/\s+/g, ' ').trim() ?? null,
    database_platform: platform?.PLATFORM_NAME ?? null,
    apex: apex?.VERSION_NO ?? null,
    ords: ords?.VERSION ?? null,
    database_jvm: javaVersion?.JAVA_VERSION ?? null,
    parameters: Object.fromEntries((params.rows ?? []).map((r) => [r.NAME, r.VALUE])),
    node: process.version,
    python: await pythonVersion(),
    client_platform: `${process.platform} ${process.arch}`,
  };
  const text = [
    header('Step 0: environment versions'),
    `Database          : ${env.database}`,
    `Database platform : ${env.database_platform}`,
    `APEX              : ${env.apex}`,
    `ORDS              : ${env.ords}`,
    `Database JVM      : ${env.database_jvm}`,
    `Node.js           : ${env.node}`,
    `Python            : ${env.python}`,
    '',
    '-- v$parameter',
    asTable(params.rows),
    '-- dba_registry',
    asTable(registry.rows),
    "-- dba_objects where object_type = 'MLE LANGUAGE'",
    asTable(mleLang.rows),
  ].join('\n');
  writeText(cfg, `${DIR}/versions.txt`, text);
  return env;
}

// Creates the probe objects, executes 4^13 mod 497 and reports what happened.
async function tryEngine(conn, ddl, drop) {
  const created = [];
  for (const statement of ddl) created.push(await attempt(conn, statement));
  const objects = await attempt(conn, "select object_type, object_name, status from user_objects where object_name in ('BF_PROBE_MOD', 'BF_PROBE_MODPOW', 'BfProbe') order by 1, 2");
  const errors = await attempt(conn, "select name, type, text from user_errors where name in ('BF_PROBE_MOD', 'BF_PROBE_MODPOW', 'BfProbe') order by name, sequence");
  const execute = await attempt(conn, "select bf_probe_modpow('4', 'd', '1f1', 1) as answer from dual");
  const answer = execute.ok ? JSON.parse(execute.rows[0].ANSWER).result : null;
  for (const statement of drop) await attempt(conn, statement);
  return {
    create_source: created[0].ok ? 'OK' : created[0].error,
    create_call_spec: created[1].ok ? 'OK' : created[1].error,
    objects: (objects.rows ?? []).map((r) => `${r.OBJECT_TYPE} ${r.OBJECT_NAME} ${r.STATUS}`),
    compile_errors: (errors.rows ?? []).map((r) => `${r.TYPE} ${r.NAME}: ${String(r.TEXT).trim()}`),
    execute: execute.ok ? `OK, answer 0x${answer}` : execute.error,
    works: answer === '1bd',
  };
}

// ------------------------------------------------------- 2. privilege probing
// A throwaway user receives privileges one at a time. After each grant the same
// actions are tried again, for MLE JavaScript and for Java.
async function privilegeProbe(dba) {
  const user = `BF_PROBE_${randomBytes(3).toString('hex').toUpperCase()}`;
  const password = `Pr${randomBytes(12).toString('hex')}9x`;
  const log = [];
  const stages = [
    { grant: 'create session', label: 'CREATE SESSION only' },
    { grant: 'create procedure', label: '+ CREATE PROCEDURE' },
    { grant: 'create mle', label: '+ CREATE MLE' },
    { grant: 'execute on javascript', label: '+ EXECUTE ON JAVASCRIPT' },
  ];
  await dba.execute(`create user ${user} identified by "${password}"`);
  try {
    for (const stage of stages) {
      await dba.execute(`grant ${stage.grant} to ${user}`);
      // Privileges are read at logon, so each stage uses a fresh connection.
      const conn = await connectAs(cfg, user, password);
      try {
        log.push({ stage: stage.label, mle: await tryEngine(conn, MLE_DDL, MLE_DROP), java: await tryEngine(conn, JAVA_DDL, JAVA_DROP) });
      } finally {
        await conn.close();
      }
    }
  } finally {
    await dba.execute(`drop user ${user} cascade`);
  }
  const block = (name, r) => [
    `   ${name}`,
    `     create source/module : ${r.create_source}`,
    `     create call spec     : ${r.create_call_spec}`,
    `     objects              : ${r.objects.join(' | ') || '(none)'}`,
    ...r.compile_errors.map((e) => `     compile error        : ${e}`),
    `     execute              : ${r.execute}`,
  ].join('\n');
  const text = [
    header('Step 0: MLE JavaScript and Java availability, by privilege', [
      'A throwaway user receives one privilege at a time.',
      'After each grant: create the source, create its PL/SQL call spec, execute it.',
      'The execute step computes 4^13 mod 497. The expected answer is 445 = 0x1bd.',
    ]),
    ...log.map((s) => [`== ${s.stage}`, block('MLE JavaScript', s.mle), block('Java stored procedure', s.java), ''].join('\n')),
  ].join('\n');
  writeText(cfg, `${DIR}/engine-privileges.txt`, text);
  return log;
}

// ------------------------------------- 3. modular exponentiation, 4096 bits
async function modexpProbe(conn, engine) {
  const ddl = engine === 'mle' ? MLE_DDL : JAVA_DDL;
  const drop = engine === 'mle' ? MLE_DROP : JAVA_DROP;
  for (const statement of ddl) await conn.execute(statement);
  const call = async (b, e, m, reps) => {
    const r = await conn.execute('select bf_probe_modpow(:b, :e, :m, :reps) as answer from dual', { b, e, m, reps });
    return JSON.parse(r.rows[0].ANSWER);
  };
  try {
    // Correctness: random vectors, three implementations must agree.
    const vectors = [];
    for (let i = 0; i < (quick ? 3 : 8); i++) {
      // Vector 0 is the hardest case (every operand 4096 bits). The others use a
      // 2048-bit exponent, which is the shape of r^n mod n^2 in Paillier.
      vectors.push({ base: randomHex(4096), exp: randomHex(i === 0 ? 4096 : 2048), mod: randomHex(4096).replace(/.$/, 'd') });
    }
    const python = await pythonRef(vectors.map((v) => ({ op: 'modpow', base: v.base, exp: v.exp, mod: v.mod })));
    const results = [];
    for (let i = 0; i < vectors.length; i++) {
      const v = vectors[i];
      const inDatabase = (await call(v.base, v.exp, v.mod, 1)).result;
      results.push({
        vector: i,
        base_bits: bitLength(v.base),
        exponent_bits: bitLength(v.exp),
        modulus_bits: bitLength(v.mod),
        database_equals_python: inDatabase === python[i].result,
        database_equals_node: inDatabase === nodeModPow(v.base, v.exp, v.mod),
        result_bits: bitLength(inDatabase),
        result_prefix: `${inDatabase.slice(0, 24)}…`,
      });
    }

    // Timing: repetitions inside one call, so the SQL round trip is excluded.
    const timing = {};
    for (const expBits of [2048, 4096]) {
      const v = { base: randomHex(4096), exp: randomHex(expBits), mod: randomHex(4096).replace(/.$/, 'd') };
      await call(v.base, v.exp, v.mod, 3); // warm-up
      const reps = quick ? 5 : 20;
      const runs = [];
      for (let i = 0; i < (quick ? 3 : 7); i++) runs.push((await call(v.base, v.exp, v.mod, reps)).elapsedMs / reps);
      timing[`base_4096_exponent_${expBits}_modulus_4096`] = { reps_per_call: reps, ms_per_modexp: stats(runs), raw_ms_per_modexp: runs };
    }
    return { engine, all_agree: results.every((r) => r.database_equals_python && r.database_equals_node), vectors: results, timing };
  } finally {
    for (const statement of drop) await attempt(conn, statement);
  }
}

// ------------------------------------------------------------------- main
const dba = await connect(cfg, 'dba');
const schema = await connect(cfg, 'schema');
try {
  const env = await versions(dba);
  const probe = await privilegeProbe(dba);
  const last = probe[probe.length - 1];
  const mleAvailable = last.mle.works;
  const javaAvailable = last.java.works;
  if (!mleAvailable && !javaAvailable) throw new Error('Neither MLE JavaScript nor Java can run in this database. The lab cannot continue.');

  const engine = mleAvailable ? 'mle' : 'java';
  const modexp = await modexpProbe(schema, engine);
  const sessionPrivs = await attempt(schema, 'select privilege from session_privs order by 1');
  const firstWorking = (key) => probe.find((s) => s[key].works)?.stage ?? null;

  const summary = {
    generated: new Date().toISOString(),
    environment: env,
    mle_javascript: {
      available: mleAvailable,
      first_stage_that_works: firstWorking('mle'),
      compile_errors_with_all_privileges: last.mle.compile_errors,
      privileges_tried: ['CREATE PROCEDURE', 'CREATE MLE', 'EXECUTE ON JAVASCRIPT'],
    },
    java_stored_procedure: { available: javaAvailable, first_stage_that_works: firstWorking('java') },
    tally_engine: engine,
    tally_engine_reason: mleAvailable
      ? 'MLE JavaScript is available and computes 4096-bit modular exponentiation correctly.'
      : `MLE JavaScript is not available in this database (${last.mle.compile_errors.join('; ') || last.mle.execute}). Fallback: Java stored procedure with java.math.BigInteger.`,
    privilege_probe: probe,
    lab_schema_session_privs: (sessionPrivs.rows ?? []).map((r) => r.PRIVILEGE),
    modexp_4096: modexp,
  };
  writeJson(cfg, `${DIR}/environment.json`, summary);

  console.log(`[step0] ${env.database} on ${env.database_platform}`);
  console.log(`[step0] APEX ${env.apex} | ORDS ${env.ords} | database JVM ${env.database_jvm} | mle_prog_languages=${env.parameters.mle_prog_languages ?? '(unset)'}`);
  for (const s of probe) console.log(`[step0] ${s.stage.padEnd(26)} MLE: ${s.mle.works ? 'works' : (s.mle.compile_errors[0] ?? s.mle.create_source)} | Java: ${s.java.works ? 'works' : s.java.create_source}`);
  console.log(`[step0] tally engine: ${engine.toUpperCase()} (${summary.tally_engine_reason})`);
  console.log(`[step0] 4096-bit modexp in ${engine}: ${modexp.vectors.length} vectors, all agree with Python and Node: ${modexp.all_agree}`);
  for (const [k, v] of Object.entries(modexp.timing)) console.log(`[step0] ${k}: median ${v.ms_per_modexp.median} ms`);
  if (!modexp.all_agree) process.exitCode = 1;
} finally {
  await dba.close();
  await schema.close();
}
