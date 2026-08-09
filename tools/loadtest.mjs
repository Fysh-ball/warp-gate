#!/usr/bin/env node
// How many concurrent gates can one Warp Gate process actually hold?
//
//   node tools/loadtest.mjs [rooms] [origin]
//
// Each gate is two participants, so N rooms means 2N live SSE streams plus 2N room
// slots. This measures the signalling server only, which is the honest thing to
// measure: once two peers connect, their data never touches the server, so file and
// message volume cost it nothing. What costs it is concurrent open gates.
//
// Reports memory per room and whether relays still get delivered under load.

import http from 'node:http';

const ROOMS = Number(process.argv[2] || 200);
const ORIGIN = process.argv[3] || 'http://127.0.0.1:3095';
const { hostname, port } = new URL(ORIGIN);

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const roomId = (n) => {
  let s = '';
  let v = n + 1;
  for (let i = 0; i < 8; i += 1) { s = ALPHABET[v % 32] + s; v = Math.floor(v / 32); }
  return s;
};

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: hostname, port, method, path,
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
function openStream(room, token) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: hostname, port, path: `/api/events?room=${room}&token=${token}` }, (res) => {
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

const health = await request('GET', '/api/health');
if (health.status !== 200) {
  process.stdout.write(`BAD  server not reachable at ${ORIGIN}\n`);
  process.exit(2);
}
process.stdout.write(`target ${ORIGIN}, building ${ROOMS} gates (${ROOMS * 2} streams)\n\n`);

const t0 = Date.now();
const created = [];
let refused = 0;

for (let i = 0; i < ROOMS; i += 1) {
  const id = roomId(i);
  const c = await request('POST', '/api/create', { roomId: id, sessionMinutes: 60 });
  if (c.status !== 200) { refused += 1; continue; }
  const j = await request('POST', '/api/join', { roomId: id });
  if (j.status !== 200) { refused += 1; continue; }
  try {
    const sa = await openStream(id, c.json.token);
    await openStream(id, j.json.token);
    created.push({ id, a: c.json.token, b: j.json.token, sa });
  } catch (err) {
    refused += 1;
    void err;
  }
  if ((i + 1) % 50 === 0) {
    const h = await request('GET', '/api/health');
    process.stdout.write(`  ${String(i + 1).padStart(4)} attempted, server holds ${h.json.rooms} rooms\n`);
  }
}
const buildMs = Date.now() - t0;

const after = await request('GET', '/api/health');
process.stdout.write(`\nbuilt ${created.length} gates in ${(buildMs / 1000).toFixed(1)}s`);
process.stdout.write(`${refused ? `, ${refused} refused (capacity or rate limit)` : ''}\n`);
process.stdout.write(`server reports ${after.json.rooms} live rooms, ${streams.length} open streams\n`);

// Does signalling still work while all of that is held open?
if (created.length) {
  const victim = created[Math.floor(created.length / 2)];
  const before = victim.sa.relays;
  const t1 = Date.now();
  const r = await request('POST', '/api/relay', {
    roomId: victim.id, token: victim.b, envelope: { n: 'x', c: 'y' },
  });
  await new Promise((res) => setTimeout(res, 400));
  const latency = Date.now() - t1;
  process.stdout.write(`\nrelay under load: http ${r.status}, delivered=${r.json?.delivered}, `);
  process.stdout.write(`arrived=${victim.sa.relays > before}, round trip ${latency}ms\n`);
}

process.stdout.write('\ncleaning up\n');
for (const { req } of streams) { try { req.destroy(); } catch { /* already gone */ } }
for (const c of created) await request('POST', '/api/bye', { roomId: c.id, token: c.a });
const end = await request('GET', '/api/health');
process.stdout.write(`server now holds ${end.json.rooms} rooms\n`);
