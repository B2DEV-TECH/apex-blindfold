// node-oracledb (thin mode) helpers shared by every test.
import oracledb from 'oracledb';

oracledb.fetchAsString = [oracledb.CLOB];
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

export { oracledb };

// who: 'schema' = application owner, 'dba' = the auditor account with the DBA role.
export async function connect(cfg, who = 'schema') {
  const user = who === 'dba' ? cfg.dba : cfg.schema;
  const password = who === 'dba' ? cfg.dba_password : cfg.schema_password;
  if (!user || !password) throw new Error(`No credentials configured for "${who}".`);
  return oracledb.getConnection({ user, password, connectString: cfg.connect });
}

export async function connectAs(cfg, user, password) {
  return oracledb.getConnection({ user, password, connectString: cfg.connect });
}

// Runs a statement and returns { ok, rows } or { ok: false, error: 'ORA-…' }.
// Used by probes that expect some statements to fail.
export async function attempt(conn, sql, binds = {}) {
  try {
    const r = await conn.execute(sql, binds);
    return { ok: true, rows: r.rows ?? null, outBinds: r.outBinds ?? null };
  } catch (e) {
    return { ok: false, error: String(e.message).split('\n')[0] };
  }
}

// Formats rows as a fixed-width text table, similar to SQL*Plus output.
export function asTable(rows, { maxWidth = 64 } = {}) {
  if (!rows || rows.length === 0) return 'no rows selected\n';
  const cols = Object.keys(rows[0]);
  const cell = (v) => {
    const s = v === null || v === undefined ? '' : v instanceof Date ? v.toISOString() : String(v);
    return s.length > maxWidth ? `${s.slice(0, maxWidth - 1)}…` : s;
  };
  const widths = cols.map((c) => Math.max(c.length, ...rows.map((r) => cell(r[c]).length)));
  const line = (vals) => vals.map((v, i) => v.padEnd(widths[i])).join('  ').trimEnd();
  return [
    line(cols),
    line(widths.map((w) => '-'.repeat(w))),
    ...rows.map((r) => line(cols.map((c) => cell(r[c])))),
    '',
    `${rows.length} row${rows.length === 1 ? '' : 's'} selected`,
    '',
  ].join('\n');
}
