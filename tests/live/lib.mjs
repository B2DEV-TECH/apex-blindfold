// Shared by the live-session scripts: everything a DBA can read about the
// election, fetched read-only and turned into text for /evidence/live-session.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { EVIDENCE } from '../lib/evidence.mjs';

export const LIVE = 'live-session';
export const LIVE_DIR = join(EVIDENCE, LIVE);

export const sha256 = (text) => createHash('sha256').update(text).digest('hex');

// Session ids are long decimal numbers. The lookarounds keep the pattern off
// the digits inside a hexadecimal string, and off the two ends of a shortened
// one (shortHex puts an ellipsis there): a ciphertext must stay untouched.
export const maskIds = (text) => String(text).replace(/(?<![0-9a-f…])\d{12,}(?![0-9a-f…])/g, '<id>');

// Client addresses. The machine that runs the database stays readable as
// "this-pc"; every other address becomes device-2, device-3, ... so that a
// reader can see that two devices voted without learning a network address.
export function addressAliases() {
  const seen = new Map();
  return (address) => {
    if (address === null || address === undefined) return address;
    const text = String(address).trim();
    if (/^\[?(0:0:0:0:0:0:0:1|::1)\]?$/.test(text) || text.startsWith('127.')) return 'this-pc';
    if (!seen.has(text)) seen.set(text, `device-${seen.size + 2}`);
    return seen.get(text);
  };
}

export const shortHex = (hex, head = 24, tail = 8) => (hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`);

export async function apexSchema(dba) {
  return (await dba.execute("select schema from dba_registry where comp_id = 'APEX'")).rows[0].SCHEMA;
}

// One round trip that changes whenever the election tables change.
export async function fingerprint(dba, owner) {
  const row = (await dba.execute(
    `select (select max(n_hex) from ${owner}.election_key) as n_hex,
            (select count(*) from ${owner}.blind_ballots) as ballot_rows,
            (select nvl(sum(ora_hash(ballot_id || ':' || candidate_id || ':' || vote_enc)), 0) from ${owner}.blind_ballots) as ballot_hash,
            (select count(*) from ${owner}.voter_roll) as registered,
            (select count(voted_at) from ${owner}.voter_roll) as voted
       from dual`)).rows[0];
  return JSON.stringify(row);
}

// The three election tables, complete. Times are UTC.
export async function readTables(dba, owner) {
  const key = (await dba.execute(`select n_hex from ${owner}.election_key`)).rows.map((row) => row.N_HEX);
  const roll = (await dba.execute(
    `select voter_id, to_char(sys_extract_utc(voted_at), 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"') as voted_at
       from ${owner}.voter_roll order by voter_id`)).rows;
  const ballots = (await dba.execute(
    `select ballot_id, candidate_id, vote_enc from ${owner}.blind_ballots order by ballot_id, candidate_id`)).rows;
  return { key, roll, ballots };
}

// What APEX keeps about the application: session state and the activity log.
export async function readApex(dba, apex, appId, since, alias) {
  const state = (await dba.execute(
    `select d.item_name, p.plug_name as report_region, d.item_value_vc2 as value
       from ${apex}.wwv_flow_data d
       left join ${apex}.wwv_flow_page_plugs p on p.id = d.item_id and p.flow_id = d.flow_id
      where d.flow_id = :app`, { app: appId })).rows;
  const columns = 'id, time_stamp_tz, elap, flow_id, step_id, session_id, page_view_type, request_value, ip_address, sqlerrm';
  const activity = (await dba.execute(
    `select to_char(sys_extract_utc(time_stamp_tz), 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"') as at, step_id as page, page_view_type as kind, request_value as request,
            round(elap, 3) as seconds, session_id, ip_address, sqlerrm as error
       from (select ${columns} from ${apex}.wwv_flow_activity_log1$ union all select ${columns} from ${apex}.wwv_flow_activity_log2$)
      where flow_id = :app and time_stamp_tz >= :since
      order by time_stamp_tz, id`, { app: appId, since })).rows;
  const sessions = new Map();
  const clients = new Map(); // session -> the client address APEX logged for it
  const rows = activity.map((row) => {
    if (!sessions.has(row.SESSION_ID)) sessions.set(row.SESSION_ID, `session-${sessions.size + 1}`);
    const session = sessions.get(row.SESSION_ID);
    const client = alias(row.IP_ADDRESS);
    if (client && !clients.has(session)) clients.set(session, client);
    return { AT: row.AT, PAGE: row.PAGE, KIND: row.KIND, REQUEST: row.REQUEST, SECONDS: row.SECONDS, SESSION: session, CLIENT: client, ERROR: row.ERROR };
  });
  return {
    state,
    pageItems: state.filter((row) => row.ITEM_NAME !== null),
    activity: rows,
    // APEX logs the address with a page load and leaves it empty on the Ajax
    // requests of the same session: the session is what ties the two together.
    clients,
  };
}

// When the live session started: written by the first snapshot.
export function sessionStart() {
  const file = join(LIVE_DIR, 'state', 'session.json');
  return existsSync(file) ? new Date(JSON.parse(readFileSync(file, 'utf8')).started) : null;
}

export function nextSnapshotNumber() {
  const dir = join(LIVE_DIR, 'state');
  if (!existsSync(dir)) return 0;
  const numbers = readdirSync(dir).map((name) => /^(\d+)-/.exec(name)).filter(Boolean).map((match) => Number(match[1]));
  return numbers.length ? Math.max(...numbers) + 1 : 0;
}

// Rank join of the two tables: the DBA's way of telling who cast which ballot.
export function relink(roll, ballots) {
  const voters = roll.filter((row) => row.VOTED_AT !== null).sort((a, b) => (a.VOTED_AT < b.VOTED_AT ? -1 : a.VOTED_AT > b.VOTED_AT ? 1 : a.VOTER_ID < b.VOTER_ID ? -1 : 1));
  const ids = [...new Set(ballots.map((row) => row.BALLOT_ID))].sort((a, b) => a - b);
  return ids.map((id, index) => ({ ballot: id, voter: voters[index]?.VOTER_ID ?? null, votedAt: voters[index]?.VOTED_AT ?? null }));
}
