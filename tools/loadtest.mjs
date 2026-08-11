#!/usr/bin/env node
// How many concurrent gates can one Warp Gate process actually hold?
//
//   node tools/loadtest.mjs [rooms] [participants] [origin] [--spread] [--rss=<pid>]
//
// A gate seats up to WG_MAX_PARTICIPANTS devices (default 6), so a gate is no longer
// one fixed unit of cost: each gate built here is `participants` slots (default 2),
// which is N*P live SSE streams plus N*P room slots for N rooms. This measures the
// signalling server only, which is the honest thing to measure: once peers connect,
// their data never touches the server, so file and message volume cost it nothing.
// What costs it is concurrent open gates and how many seats each holds. The fifteen
// WebRTC links of a full six-seat mesh live in the browsers; the server's share of a
// six-seat gate is six slots, six streams, and a relay budget that scales with the
// seat count (relayPerMinutePerRoom x (slots - 1), server/rooms.js relayAllowed).
//
// --spread      rotate loopback source addresses (127.77.x.y), one per participant,
//               so the PER-CLIENT caps (5 rooms per key, 4 SSE streams per key, the
//               create/join windows) do not bound the run. Only meaningful against a
//               server on this same host; Linux answers all of 127.0.0.0/8.
// --rss=<pid>   read VmRSS/VmHWM from /proc/<pid>/status before, at full load, and
//               after teardown, and report bytes per gate. Same-host only.
//
// Reports whether relays still get delivered, across every link of one gate, under load.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';

const args = process.argv.slice(2);
const flags = args.filter((a) => a.startsWith('--'));
const pos = args.filter((a) => !a.startsWith('--'));
const ROOMS = Number(pos[0] || 200);
const PARTS = Number(pos[1] || 2);
const ORIGIN = pos[2] || 'http://127.0.0.1:3095';
const SPREAD = flags.includes('--spread');
const rssFlag = flags.find((a) => a.startsWith('--rss='));
const RSS_PID = rssFlag ? Number(rssFlag.slice('--rss='.length)) : null;
const { hostname, port } = new URL(ORIGIN);

if (!Number.isInteger(ROOMS) || ROOMS < 1) { process.stdout.write('BAD  rooms must be a positive integer\n'); process.exit(2); }
if (!Number.isInteger(PARTS) || PARTS < 2) { process.stdout.write('BAD  participants must be an integer >= 2\n'); process.exit(2); }

// One loopback source address per participant, so every simulated device gets its own
// rate-limit key, exactly as distinct real clients would. 127.77.0.0/16 leaves .0.1
// and friends alone for anything else bound to loopback.
const addrFor = (n) => `127.77.${Math.floor(n / 250) % 256}.${(n % 250) + 1}`;

// VmRSS is the resident set now; VmHWM is the high-water mark, which catches a spike
// during the build that has already been given back by the time the gates are held.
function readRss(pid) {
  try {
    const text = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const grab = (key) => {
      const m = text.match(new RegExp(`^${key}:\\s+(\\d+) kB`, 'm'));
      return m ? Number(m[1]) * 1024 : null;
    };
    return { rss: grab('VmRSS'), peak: grab('VmHWM') };
  } catch (err) {
    process.stdout.write(`BAD  --rss=${pid}: ${err.message}\n`);
    process.exit(2);
    return null;
  }
}
const mb = (b) => `${(b / 1024 / 1024).toFixed(1)} MB`;

// A joiner must present J = HKDF(room secret, "wg/v1/join") and the creator registers
// H = SHA-256(J). This tool has no room secret, so it mints a matching pair per room:
// what it is measuring is server capacity, not the browser's key schedule.
function joinProofPair() {
  const proof = crypto.randomBytes(16).toString('base64url');
  return { proof, hash: crypto.createHash('sha256').update(Buffer.from(proof, 'base64url')).digest('base64url') };
}

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const roomId = (n) => {
  let s = '';
  let v = n + 1;
  for (let i = 0; i < 8; i += 1) { s = ALPHABET[v % 32] + s; v = Math.floor(v / 32); }
  return s;
};

function request(method, path, body, localAddress) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: hostname, port, method, path,
      ...(localAddress ? { localAddress } : {}),
      headers: payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {} },
    (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try { resolve({ status: res.statusCode, json: JSON.parse(text) }); }
        catch { resolve({ status: res.statusCode, json: null, text }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('timeout')));
    if (payload) req.write(payload);
    req.end();
  });
}

const streams = [];
function openStream(room, token, localAddress) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: hostname, port,
      path: `/api/events?room=${room}&token=${token}`,
      ...(localAddress ? { localAddress } : {}) },
    (res) => {
      if (res.statusCode !== 200) { reject(new Error(`stream ${res.statusCode}`)); return; }
      const state = { events: 0, relays: 0 };
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        state.events += 1;
        if (chunk.includes('event: relay')) state.relays += 1;
      });
      streams.push({ req, res, state });
      resolve(state);
    });
    req.on('error', reject);
  });
}

// Liveness gate. Nothing may be measured against a server that did not answer: an
// unanswered port yields zero rooms and zero refusals, which reads exactly like a
// clean run. `ok` is the whole contract of /api/health, so it is what is checked.
const health = await request('GET', '/api/health');
if (health.status !== 200 || health.json?.ok !== true) {
  process.stdout.write(`BAD  server at ${ORIGIN} did not answer {"ok":true} (http ${health.status} ${health.text ?? JSON.stringify(health.json)})\n`);
  process.stdout.write('BAD  aborting rather than reporting zeros measured against nothing\n');
  process.exit(2);
}
const rss0 = RSS_PID ? readRss(RSS_PID) : null;
process.stdout.write(`target ${ORIGIN}, building ${ROOMS} gates of ${PARTS} seats (${ROOMS * PARTS} streams)`);
process.stdout.write(`${SPREAD ? ', one loopback source address per participant' : ''}\n`);
if (rss0) process.stdout.write(`server rss before: ${mb(rss0.rss)}\n`);
process.stdout.write('\n');

const t0 = Date.now();
const created = [];
let refused = 0;

const refusals = new Map();
const note = (status, code) => {
  const key = `${status} ${code ?? ''}`.trim();
  refusals.set(key, (refusals.get(key) ?? 0) + 1);
  refused += 1;
};

build:
for (let i = 0; i < ROOMS; i += 1) {
  const id = roomId(i);
  const jp = joinProofPair();
  // participant p of room i is global participant i*PARTS + p
  const addr = (p) => (SPREAD ? addrFor(i * PARTS + p) : undefined);
  const c = await request('POST', '/api/create', { roomId: id, sessionMinutes: 60, joinProofHash: jp.hash }, addr(0));
  if (c.status !== 200) { note(c.status, c.json?.error); continue; }
  const seats = [{ token: c.json.token, slotId: c.json.slotId }];
  for (let p = 1; p < PARTS; p += 1) {
    const j = await request('POST', '/api/join', { roomId: id, joinProof: jp.proof }, addr(p));
    if (j.status !== 200) { note(j.status, j.json?.error); continue build; }
    seats.push({ token: j.json.token, slotId: j.json.slotId });
  }
  try {
    const sa = await openStream(id, seats[0].token, addr(0));
    for (let p = 1; p < PARTS; p += 1) await openStream(id, seats[p].token, addr(p));
    // addr0 is kept because teardown must speak AS the creator, from the creator's
    // source address: 2,000 byes from one shared address exhaust that one key's API
    // window, and the refusals then read as the server failing when it is the tool
    // rate-limiting itself.
    created.push({ id, seats, sa, addr0: addr(0) });
  } catch (err) {
    note('stream', err.message);
  }
  if ((i + 1) % 50 === 0) {
    // /api/health reports liveness and nothing else: a live count of open gates is an
    // attack progress meter and a usage side channel on a tool whose premise is that
    // the server learns nothing. Progress is counted here, where it is known first
    // hand, rather than read back off the process under test.
    process.stdout.write(`  ${String(i + 1).padStart(4)} attempted, ${created.length} gates built, ${refused} refused\n`);
  }
}
const buildMs = Date.now() - t0;

process.stdout.write(`\nbuilt ${created.length} gates in ${(buildMs / 1000).toFixed(1)}s`);
process.stdout.write(`${refused ? `, ${refused} refused` : ''}\n`);
if (refusals.size) {
  for (const [reason, count] of [...refusals].sort((x, y) => y[1] - x[1])) {
    process.stdout.write(`  ${String(count).padStart(5)} x ${reason}\n`);
  }
}
// Without --spread every request here comes from one address, so the PER-KEY caps bite
// long before the server's actual capacity does. Say so: otherwise "built 2 gates"
// reads as a capacity finding when it is only this tool measuring itself against a
// limit meant for clients.
if (!SPREAD && [...refusals.keys()].some((r) => /too_many_rooms|too_many_streams|429/.test(r))) {
  process.stdout.write('\nNOTE  the run was bounded by per-client limits, not by server capacity.\n');
  process.stdout.write('      Re-run with --spread against a local server, or drive it from several\n');
  process.stdout.write('      addresses; raising the per-key caps on the target also works.\n');
}
process.stdout.write(`${created.length} gates held open, ${streams.length} open streams\n`);

const rssHeld = RSS_PID ? readRss(RSS_PID) : null;
if (rssHeld && created.length) {
  const perGate = (rssHeld.rss - rss0.rss) / created.length;
  process.stdout.write(`server rss at full load: ${mb(rssHeld.rss)} (peak ${mb(rssHeld.peak)}), `);
  process.stdout.write(`${(perGate / 1024).toFixed(1)} KB per ${PARTS}-seat gate over baseline\n`);
}

// Does signalling still work while all of that is held open? Every link of one gate is
// exercised: each joiner relays to the creator, whose stream is the one counted, so a
// full mesh's worth of addressed relays is proven delivered, not just one.
if (created.length) {
  const victim = created[Math.floor(created.length / 2)];
  const before = victim.sa.relays;
  const t1 = Date.now();
  let relayed = 0;
  for (let p = 1; p < victim.seats.length; p += 1) {
    // A relay is addressed at one slot. There is no broadcast to fall back on, so an
    // unaddressed probe here would measure a 400 rather than the signalling path.
    const r = await request('POST', '/api/relay', {
      roomId: victim.id, token: victim.seats[p].token, to: victim.seats[0].slotId,
      envelope: { n: 'x', c: 'y' },
    });
    if (r.status === 200 && r.json?.delivered) relayed += 1;
  }
  await new Promise((res) => setTimeout(res, 400));
  const latency = Date.now() - t1;
  const arrived = victim.sa.relays - before;
  const want = victim.seats.length - 1;
  process.stdout.write(`\nrelay under load: ${relayed}/${want} accepted, ${arrived}/${want} arrived, `);
  process.stdout.write(`${latency}ms for the batch (incl. 400ms settle)\n`);
}

process.stdout.write('\ncleaning up\n');
for (const { req } of streams) { try { req.destroy(); } catch { /* already gone */ } }
let severed = 0;
for (const c of created) {
  const r = await request('POST', '/api/bye', { roomId: c.id, token: c.seats[0].token }, c.addr0);
  if (r.status === 200) severed += 1;
}

// Whether the rooms really went away, without any occupancy gauge to read. A create for
// an id that is still held is refused as room_exists; one for an id that is gone
// succeeds, and is immediately severed again so this probe leaves nothing behind.
let stillHeld = 0;
let unknown = 0;
// Fresh source addresses past the range the build used, because the create cap is 10
// per 5 minutes per key: probing 25 ids from one address answers 429 from the 11th on,
// and a 429 counted as "not held" is a check that cannot fail. A verdict this probe
// cannot reach is reported as unknown, never as a pass.
let probeIdx = ROOMS * PARTS;
const sample = created.slice(0, Math.min(created.length, 25));
for (const c of sample) {
  const probe = await request('POST', '/api/create', {
    roomId: c.id, sessionMinutes: 10, joinProofHash: joinProofPair().hash,
  }, SPREAD ? addrFor(probeIdx++) : undefined);
  if (probe.status === 409) stillHeld += 1;
  else if (probe.status === 200) await request('POST', '/api/bye', { roomId: c.id, token: probe.json.token }, SPREAD ? addrFor(probeIdx - 1) : undefined);
  else unknown += 1;
}
process.stdout.write(`severed ${severed}/${created.length} gates\n`);
const verdict = stillHeld === 0 && unknown === 0 ? 'OK  ' : 'BAD ';
process.stdout.write(`${verdict} of ${sample.length} sampled ids, ${stillHeld} still held, ${unknown} unanswerable\n`);
const end = await request('GET', '/api/health', undefined, SPREAD ? addrFor(probeIdx++) : undefined);
const healthy = end.json?.ok === true;
process.stdout.write(`${healthy ? 'OK  ' : 'BAD '} server still answering after the run\n`);
// A run that printed BAD and exited 0 is a load test nothing can gate on.
process.exit(stillHeld === 0 && unknown === 0 && healthy ? 0 : 1);
