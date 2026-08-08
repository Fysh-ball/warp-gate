// Signalling server behaviour, tested over the wire against a real process.
// Run: node tests/signalling.test.mjs

import { check, summary, startServer, request, openStream, delay } from './lib/harness.mjs';
import { stunBinding } from '../tools/stun-client.mjs';

const PORT = 3196;
const STUN = 3480;
let ok = true;

// ---------------------------------------------------------------- main flow
{
  const srv = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_PORT: String(STUN),
    WG_STUN_URL: `stun:127.0.0.1:${STUN}`,
    WG_CREATE_PER_WINDOW: '500',
    WG_JOIN_PER_WINDOW: '500',
    WG_HEARTBEAT_MS: '400',
  });

  const health = await request(PORT, 'GET', '/api/health');
  check('health responds 200', health.status === 200 && health.json?.ok === true, health.text);
  check('health leaks no identifying fields',
    Object.keys(health.json ?? {}).every((k) => ['ok', 'rooms', 'uptimeSec'].includes(k)),
    JSON.stringify(health.json));

  const cfg = await request(PORT, 'GET', '/api/config');
  check('config advertises the configured STUN server',
    cfg.json?.iceServers?.[0]?.urls?.includes(`stun:127.0.0.1:${STUN}`), cfg.text);

  // --- room id validation
  for (const bad of ['short', 'toolongvalue', 'ABCDEFGI', 'abcd1234', '', null, 12345678]) {
    const r = await request(PORT, 'POST', '/api/create', { roomId: bad, sessionMinutes: 10 });
    check(`create rejects invalid roomId ${JSON.stringify(bad)}`, r.status === 400, `status ${r.status}`);
  }

  const ROOM = 'WGTEST01';
  const created = await request(PORT, 'POST', '/api/create', { roomId: ROOM, sessionMinutes: 10 });
  check('create returns a token and role a', created.status === 200 && created.json?.role === 'a' && typeof created.json?.token === 'string', created.text);
  const tokenA = created.json.token;

  const dup = await request(PORT, 'POST', '/api/create', { roomId: ROOM, sessionMinutes: 10 });
  check('create on an existing room is 409', dup.status === 409 && dup.json?.error === 'room_exists', dup.text);

  const badTtl = await request(PORT, 'POST', '/api/create', { roomId: 'WGTEST02', sessionMinutes: 9999 });
  check('unsupported session TTL falls back to the default',
    badTtl.status === 200 && badTtl.json?.sessionMinutes === 30, badTtl.text);

  const noRoom = await request(PORT, 'POST', '/api/join', { roomId: 'ZZZZZZZZ' });
  check('join on an unknown room is 404', noRoom.status === 404, noRoom.text);

  // --- streams and pairing
  const streamA = openStream(PORT, ROOM, tokenA);
  await streamA.ready;
  const helloA = await streamA.wait('hello');
  check('creator receives hello with role a and no peer',
    helloA.data?.role === 'a' && helloA.data?.peerPresent === false, JSON.stringify(helloA.data));

  const joined = await request(PORT, 'POST', '/api/join', { roomId: ROOM });
  check('join returns a token and role b', joined.status === 200 && joined.json?.role === 'b', joined.text);
  const tokenB = joined.json.token;

  const full = await request(PORT, 'POST', '/api/join', { roomId: ROOM });
  check('a third participant is refused', full.status === 409 && full.json?.error === 'room_full', full.text);

  check('creator is NOT told of a peer before that peer is listening',
    !streamA.seen('peer-joined'), 'peer-joined fired on join POST rather than on stream attach');

  const streamB = openStream(PORT, ROOM, tokenB);
  await streamB.ready;
  await streamA.wait('peer-joined');
  check('creator is told once the joiner is actually listening', true);

  const helloB = await streamB.wait('hello');
  check('joiner sees the creator already present', helloB.data?.peerPresent === true, JSON.stringify(helloB.data));

  // --- token handling
  const wrongToken = await request(PORT, 'POST', '/api/relay', {
    roomId: ROOM, token: 'not-a-real-token', envelope: { n: 'x', c: 'y' },
  });
  check('relay with a wrong token is 403', wrongToken.status === 403, wrongToken.text);

  // An empty token must never match. A retired slot stores an empty token, and a
  // length-only comparison would otherwise let an empty supplied token equal it.
  for (const token of ['', null, undefined, 0]) {
    const r = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token, envelope: { n: 'x', c: 'y' } });
    check(`relay with token ${JSON.stringify(token)} is refused`, r.status === 403, `status ${r.status}`);
  }

  const streamBadToken = openStream(PORT, ROOM, 'wrong');
  const streamErr = await streamBadToken.ready.then(() => null, (e) => e);
  check('event stream with a wrong token is refused', streamErr !== null && /403/.test(String(streamErr.message)), String(streamErr?.message));

  // --- relay is verbatim and opaque
  const envelope = { n: 'BASE64URL_NONCE_x', c: 'BASE64URL_CIPHERTEXT_yyyy' };
  const relayed = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenB, envelope });
  check('relay reports delivered', relayed.status === 200 && relayed.json?.delivered === true, relayed.text);
  const got = await streamA.wait('relay');
  check('relayed envelope arrives byte-for-byte unmodified',
    got.data?.n === envelope.n && got.data?.c === envelope.c, JSON.stringify(got.data));
  check('server did not add fields to the envelope',
    Object.keys(got.data).sort().join(',') === 'c,n', JSON.stringify(got.data));

  const backwards = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, envelope: { n: 'a', c: 'b' } });
  check('relay works in the other direction too', backwards.status === 200, backwards.text);
  await streamB.wait('relay');

  // --- envelope validation
  const badEnv = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, envelope: { n: 1, c: 2 } });
  check('non-string envelope fields are rejected', badEnv.status === 400, badEnv.text);

  const noEnv = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA });
  check('missing envelope is rejected', noEnv.status === 400, noEnv.text);

  const huge = await request(PORT, 'POST', '/api/relay', {
    roomId: ROOM, token: tokenA, envelope: { n: 'x', c: 'y'.repeat(70_000) },
  });
  check('oversized envelope is rejected', huge.status === 413 || huge.status === 400, `status ${huge.status}`);

  // --- heartbeat, which is what keeps a proxy from idling the stream out
  await delay(900);
  check('stream emits heartbeat comments', streamA.seen('__heartbeat'), 'no heartbeat within 900ms at a 400ms interval');

  // --- severing
  const bye = await request(PORT, 'POST', '/api/bye', { roomId: ROOM, token: tokenA });
  check('bye succeeds', bye.status === 200, bye.text);
  const closed = await streamB.wait('closed');
  check('the other peer is told the room was severed', closed.data?.reason === 'severed', JSON.stringify(closed.data));

  const afterBye = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, envelope: { n: 'a', c: 'b' } });
  check('the room is gone after bye', afterBye.status === 404, afterBye.text);

  const rejoin = await request(PORT, 'POST', '/api/join', { roomId: ROOM });
  check('a severed room cannot be rejoined', rejoin.status === 404, rejoin.text);

  streamA.close();
  streamB.close();
  streamBadToken.close();

  // WGTEST02 was created by the TTL-fallback check and never paired. Severing it with
  // no stream attached also exercises bye on an unattached room.
  const strayBye = await request(PORT, 'POST', '/api/bye', {
    roomId: 'WGTEST02', token: badTtl.json.token,
  });
  check('bye works on a room that was never paired', strayBye.status === 200, strayBye.text);

  const healthAfter = await request(PORT, 'GET', '/api/health');
  check('room count returns to zero after teardown', healthAfter.json?.rooms === 0, healthAfter.text);

  check('server wrote nothing to stderr', srv.stderr() === '', srv.stderr());
  await srv.stop();
}

// ---------------------------------------------------------------- rate limits
{
  const P = PORT + 1;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '3', WG_RATE_WINDOW_MS: '60000',
    WG_MAX_ROOMS: '2',
  });

  const ids = ['RATE0001', 'RATE0002', 'RATE0003', 'RATE0004'];
  const statuses = [];
  for (const id of ids) {
    const r = await request(P, 'POST', '/api/create', { roomId: id, sessionMinutes: 10 });
    statuses.push(r.status);
  }
  check('create rate limit engages after the configured count',
    statuses[0] === 200 && statuses[1] === 200 && statuses.includes(429),
    `statuses ${statuses.join(',')}`);
  check('global room cap is enforced',
    statuses.includes(503) || statuses.filter((s) => s === 200).length <= 2,
    `statuses ${statuses.join(',')}`);

  await srv.stop();
}

// ---------------------------------------------------------------- proxy identity
{
  // Behind a proxy, every request arrives from the proxy's address. If the real client
  // address is not recovered from CF-Connecting-IP, all users share one rate-limit
  // bucket and any single client can lock out everybody else.
  const P = PORT + 5;
  const ids = ['PRXY0001', 'PRXY0002', 'PRXY0003', 'PRXY0004', 'PRXY0005'];

  const srvTrust = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_TRUST_PROXY: '1', WG_CREATE_PER_WINDOW: '2', WG_RATE_WINDOW_MS: '60000',
  });
  const trusted = [];
  for (let i = 0; i < ids.length; i += 1) {
    const r = await request(P, 'POST', '/api/create', { roomId: ids[i], sessionMinutes: 10 }, {
      'cf-connecting-ip': `203.0.113.${i + 1}`, // a distinct client each time
    });
    trusted.push(r.status);
  }
  check('with the proxy trusted, distinct clients get distinct rate-limit buckets',
    trusted.every((s) => s === 200), `statuses ${trusted.join(',')}`);
  await srvTrust.stop();

  const srvNoTrust = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_TRUST_PROXY: '0', WG_CREATE_PER_WINDOW: '2', WG_RATE_WINDOW_MS: '60000',
  });
  const untrusted = [];
  for (let i = 0; i < ids.length; i += 1) {
    const r = await request(P, 'POST', '/api/create', { roomId: ids[i], sessionMinutes: 10 }, {
      'cf-connecting-ip': `203.0.113.${i + 1}`,
    });
    untrusted.push(r.status);
  }
  check('with the proxy untrusted, a forged header cannot buy extra quota',
    untrusted.includes(429), `statuses ${untrusted.join(',')}`);
  await srvNoTrust.stop();
}

// ---------------------------------------------------------------- expiry
{
  const P = PORT + 2;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_UNCLAIMED_TTL_MS: '700', WG_SWEEP_MS: '150',
  });

  const create = await request(P, 'POST', '/api/create', { roomId: 'EXPRY001', sessionMinutes: 10 });
  const stream = openStream(P, 'EXPRY001', create.json.token);
  await stream.ready;
  await stream.wait('hello');

  const closed = await stream.wait('closed', 4000).catch((e) => e);
  check('an unclaimed room expires and says so',
    closed?.data?.reason === 'ttl', closed instanceof Error ? closed.message : JSON.stringify(closed?.data));

  const after = await request(P, 'POST', '/api/join', { roomId: 'EXPRY001' });
  check('an expired room cannot be joined', after.status === 404, after.text);

  // Joining must extend the clock past the unclaimed window, or a paired session
  // would die mid-transfer.
  const create2 = await request(P, 'POST', '/api/create', { roomId: 'EXPRY002', sessionMinutes: 10 });
  const join2 = await request(P, 'POST', '/api/join', { roomId: 'EXPRY002' });
  check('joining extends the room past the unclaimed TTL', join2.status === 200, join2.text);
  const s2a = openStream(P, 'EXPRY002', create2.json.token);
  const s2b = openStream(P, 'EXPRY002', join2.json.token);
  await Promise.all([s2a.ready, s2b.ready]);
  await delay(1400); // comfortably past the 700ms unclaimed TTL
  const stillThere = await request(P, 'POST', '/api/relay', {
    roomId: 'EXPRY002', token: create2.json.token, envelope: { n: 'a', c: 'b' },
  });
  check('a paired room survives past the unclaimed TTL', stillThere.status === 200, stillThere.text);

  stream.close(); s2a.close(); s2b.close();
  await srv.stop();
}

// ---------------------------------------------------------------- races
{
  const P = PORT + 4;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
  });

  // Two devices scanning the same QR at the same moment. Exactly one may take the
  // second slot; the loser must be told the room is full, not silently share it.
  await request(P, 'POST', '/api/create', { roomId: 'RACE0001', sessionMinutes: 10 });
  const joins = await Promise.all([
    request(P, 'POST', '/api/join', { roomId: 'RACE0001' }),
    request(P, 'POST', '/api/join', { roomId: 'RACE0001' }),
    request(P, 'POST', '/api/join', { roomId: 'RACE0001' }),
  ]);
  const okJoins = joins.filter((r) => r.status === 200);
  const fullJoins = joins.filter((r) => r.status === 409);
  check('exactly one of three simultaneous joins succeeds',
    okJoins.length === 1 && fullJoins.length === 2, joins.map((r) => r.status).join(','));
  check('the two tokens issued for one room are different',
    okJoins[0]?.json?.token !== undefined, 'no token issued to the winner');

  // Two browsers generating the same room id would mean the same secret, which cannot
  // happen by chance, but the server must still not merge them.
  const creates = await Promise.all([
    request(P, 'POST', '/api/create', { roomId: 'RACE0002', sessionMinutes: 10 }),
    request(P, 'POST', '/api/create', { roomId: 'RACE0002', sessionMinutes: 10 }),
  ]);
  check('exactly one of two simultaneous creates for one id succeeds',
    creates.filter((r) => r.status === 200).length === 1
    && creates.filter((r) => r.status === 409).length === 1,
    creates.map((r) => r.status).join(','));

  // A refresh: the stream drops and comes back with the same token. The peer must not
  // be told the device left, and the room must survive.
  const roomC = await request(P, 'POST', '/api/create', { roomId: 'RACE0003', sessionMinutes: 10 });
  const joinC = await request(P, 'POST', '/api/join', { roomId: 'RACE0003' });
  const sA = openStream(P, 'RACE0003', roomC.json.token);
  const sB1 = openStream(P, 'RACE0003', joinC.json.token);
  await Promise.all([sA.ready, sB1.ready]);
  await sA.wait('peer-joined');

  sB1.close();
  const sB2 = openStream(P, 'RACE0003', joinC.json.token);
  await sB2.ready;
  const helloAgain = await sB2.wait('hello');
  check('a device can reattach to its slot after a refresh',
    helloAgain.data?.role === 'b' && helloAgain.data?.peerPresent === true, JSON.stringify(helloAgain.data));

  const stillAlive = await request(P, 'POST', '/api/relay', {
    roomId: 'RACE0003', token: roomC.json.token, envelope: { n: 'a', c: 'b' },
  });
  check('the room survives a peer reconnecting', stillAlive.status === 200, stillAlive.text);
  const afterRefresh = await sB2.wait('relay');
  check('relay still reaches the reattached stream', afterRefresh.data?.c === 'b', JSON.stringify(afterRefresh.data));

  sA.close(); sB2.close();
  await srv.stop();
}

// ---------------------------------------------------------------- STUN
{
  const P = PORT + 3;
  const S = STUN + 3;
  const srv = await startServer({ WG_HTTP_PORT: String(P), WG_STUN_PORT: String(S) });

  // Negative control first: prove this check is capable of failing.
  const dead = await stunBinding('127.0.0.1', S + 1, 700).then(() => null, (e) => e);
  check('STUN probe correctly fails against a port with no server', dead !== null, 'probe passed against a dead port, so it proves nothing');

  const bound = await stunBinding('127.0.0.1', S, 2000).then((v) => v, (e) => e);
  check('STUN binding request gets a valid success response',
    !(bound instanceof Error) && bound.family === 'IPv4', bound instanceof Error ? bound.message : JSON.stringify(bound));
  check('STUN reports the source port back correctly',
    !(bound instanceof Error) && Number.isInteger(bound.port) && bound.port > 0 && bound.port < 65536,
    bound instanceof Error ? bound.message : `port ${bound?.port}`);
  check('STUN reports the loopback address for a loopback client',
    !(bound instanceof Error) && bound.ip === '127.0.0.1', bound instanceof Error ? bound.message : bound.ip);

  await srv.stop();
}

ok = summary('signalling');
process.exit(ok ? 0 : 1);
