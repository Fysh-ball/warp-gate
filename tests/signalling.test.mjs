// Signalling server behaviour, tested over the wire against a real process.
// Run: node tests/signalling.test.mjs

import crypto from 'node:crypto';
import dgram from 'node:dgram';
import http from 'node:http';
import net from 'node:net';
import {
  check, summary, startServer, request, openStream, delay, makeJoinProof, distinctTokens,
} from './lib/harness.mjs';
import { stunBinding } from '../tools/stun-client.mjs';

const PORT = 3196;
const STUN = 3480;
let ok = true;

/**
 * Prove a room is really gone, without asking the server how many rooms it holds.
 *
 * /api/health used to report a live room count and half a dozen assertions leaned on it.
 * It no longer does, and it should not: a live gauge of open gates is an attack progress
 * meter on a tool whose whole premise is that the server learns nothing. Destruction is
 * observed instead through behaviour that only a destroyed room can produce.
 *
 * `no_room` is returned before the join proof is even looked at, so this says "the id is
 * not in the map", not "your proof was wrong".
 */
async function roomIsGone(port, roomId, joinProof = makeJoinProof().proof) {
  const r = await request(port, 'POST', '/api/join', { roomId, joinProof });
  return { gone: r.status === 404 && r.json?.error === 'no_room', status: r.status, body: r.text };
}

/**
 * Relay events a stream has seen, and a wait for one it has NOT seen yet.
 *
 * `arrivedWithin` is the wrong tool once a stream has already received a relay: it settles
 * immediately on the earlier one and never opens the window, so a leak that is still on
 * the wire reads as "nothing arrived". Verified against a deliberately broadcasting build,
 * where the isolation check printed OK. This counts first and waits for the count to move.
 */
const relaysAt = (stream) => stream.events.filter((e) => e.event === 'relay');

async function relaysAfter(stream, seenAlready, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    const all = relaysAt(stream);
    if (all.length > seenAlready) return all.slice(seenAlready);
    if (Date.now() >= deadline) return [];
    await delay(40);
  }
}

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
  // An allowlist that includes the fields being objected to cannot object to them. This
  // previously permitted `rooms` and `uptimeSec`, so it passed both before and after the
  // live room gauge (an attack progress meter and a usage side channel) was removed.
  // Liveness is the entire contract: exactly one key, and it is `ok`.
  check('health returns liveness and nothing else',
    JSON.stringify(Object.keys(health.json ?? {}).sort()) === '["ok"]',
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
  const proof = makeJoinProof();
  const created = await request(PORT, 'POST', '/api/create', {
    roomId: ROOM, sessionMinutes: 10, joinProofHash: proof.hash,
  });
  check('create returns a token and role a', created.status === 200 && created.json?.role === 'a' && typeof created.json?.token === 'string', created.text);
  // The slot id is new, and it is what a relay is addressed at. It is routing information
  // rather than a secret, so it is published to the whole room; the token still is not.
  check('create also returns a slot id, which is not the token',
    typeof created.json?.slotId === 'string' && created.json.slotId.length > 0
    && created.json.slotId !== created.json.token, created.text);
  // This server sets no WG_MAX_PARTICIPANTS, so it reports the shipped default. Pinned,
  // because the number is documented in SELF-HOSTING.md and stated on the page.
  check('create reports the documented default seat count',
    created.json?.maxParticipants === 6, created.text);
  const tokenA = created.json.token;
  const slotA = created.json.slotId;

  const dup = await request(PORT, 'POST', '/api/create', {
    roomId: ROOM, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
  });
  check('create on an existing room is 409', dup.status === 409 && dup.json?.error === 'room_exists', dup.text);

  const strayProof = makeJoinProof();
  const badTtl = await request(PORT, 'POST', '/api/create', {
    roomId: 'WGTEST02', sessionMinutes: 9999, joinProofHash: strayProof.hash,
  });
  check('unsupported session TTL falls back to the default',
    badTtl.status === 200 && badTtl.json?.sessionMinutes === 30, badTtl.text);

  const noRoom = await request(PORT, 'POST', '/api/join', { roomId: 'ZZZZZZZZ', joinProof: proof.proof });
  check('join on an unknown room is 404', noRoom.status === 404, noRoom.text);

  // --- streams and pairing
  const streamA = openStream(PORT, ROOM, tokenA);
  await streamA.ready;
  const helloA = await streamA.wait('hello');
  check('creator receives hello with role a and no peer',
    helloA.data?.role === 'a' && helloA.data?.peerPresent === false, JSON.stringify(helloA.data));
  // hello now tells a participant which slot it holds and who else is in the room. Without
  // its own id it could not address a relay, and without the roster it would not know who
  // to connect to when it arrives into a gate that is already running.
  check('hello carries this participant\'s own slot id',
    helloA.data?.self === created.json.slotId, JSON.stringify(helloA.data));
  check('hello carries a roster, empty while nobody else is here',
    Array.isArray(helloA.data?.peers) && helloA.data.peers.length === 0, JSON.stringify(helloA.data));

  const joined = await request(PORT, 'POST', '/api/join', { roomId: ROOM, joinProof: proof.proof });
  check('join returns a token and role b', joined.status === 200 && joined.json?.role === 'b', joined.text);
  const tokenB = joined.json.token;
  const slotB = joined.json.slotId;
  check('the two slot ids issued for one room are different',
    distinctTokens(slotA, slotB), `a=${JSON.stringify(slotA)} b=${JSON.stringify(slotB)}`);

  // A gate is no longer two seats. A third participant is admitted, gets a seat letter of
  // its own and a slot id nobody else holds. The cap is exercised on its own server below,
  // where the limit can be set low enough to reach.
  const third = await request(PORT, 'POST', '/api/join', { roomId: ROOM, joinProof: proof.proof });
  check('a third participant is admitted now that a gate seats more than two',
    third.status === 200 && third.json?.role === 'c'
    && distinctTokens(third.json?.slotId, slotA) && distinctTokens(third.json?.slotId, slotB),
    third.text);

  // The creator starts its offer on peer-joined. If that fires on the join POST rather
  // than on the joiner's stream attaching, the offer is relayed into a room where nobody
  // is listening yet and the handshake is lost.
  //
  // The previous form of this check read streamA.events the instant the POST returned.
  // A leaked frame is still on the wire at that moment, so the list was empty either way:
  // it printed OK against a server that DOES leak (verified against a deliberately
  // patched build). It has to hold the window open, and settle early if the leak shows.
  const leaked = await streamA.arrivedWithin('peer-joined', 1200);
  check('creator is NOT told of a peer before that peer is listening',
    leaked === false,
    `peer-joined arrived while slot B had no stream; events so far: ${JSON.stringify(streamA.events.map((e) => e.event))}`);

  const streamB = openStream(PORT, ROOM, tokenB);
  await streamB.ready;
  const announced = await streamA.arrivedWithin('peer-joined', 4000);
  check('creator IS told once the joiner is actually listening', announced === true,
    `no peer-joined within 4s of slot B attaching; events: ${JSON.stringify(streamA.events.map((e) => e.event))}`);

  const helloB = await streamB.wait('hello');
  check('joiner sees the creator already present', helloB.data?.peerPresent === true, JSON.stringify(helloB.data));
  check('the joiner\'s roster names the creator, attached, and the third seat, not attached',
    helloB.data?.self === slotB
    && helloB.data.peers.length === 2
    && helloB.data.peers.some((p) => p.id === slotA && p.role === 'a' && p.present === true)
    && helloB.data.peers.some((p) => p.id === third.json.slotId && p.present === false),
    JSON.stringify(helloB.data));
  const joinAnnounce = streamA.events.filter((e) => e.event === 'peer-joined');
  check('peer-joined names the participant that arrived',
    joinAnnounce.length >= 1 && joinAnnounce[joinAnnounce.length - 1].data?.id === slotB,
    JSON.stringify(joinAnnounce.map((e) => e.data)));

  // --- token handling
  const wrongToken = await request(PORT, 'POST', '/api/relay', {
    roomId: ROOM, token: 'not-a-real-token', to: slotA, envelope: { n: 'x', c: 'y' },
  });
  check('relay with a wrong token is 403', wrongToken.status === 403, wrongToken.text);

  // An empty token must never match. A retired slot stores an empty token, and a
  // length-only comparison would otherwise let an empty supplied token equal it.
  for (const token of ['', null, undefined, 0]) {
    const r = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token, to: slotA, envelope: { n: 'x', c: 'y' } });
    check(`relay with token ${JSON.stringify(token)} is refused`, r.status === 403, `status ${r.status}`);
  }

  const streamBadToken = openStream(PORT, ROOM, 'wrong');
  const streamErr = await streamBadToken.ready.then(() => null, (e) => e);
  check('event stream with a wrong token is refused', streamErr !== null && /403/.test(String(streamErr.message)), String(streamErr?.message));

  // --- relay is verbatim and opaque
  const envelope = { n: 'BASE64URL_NONCE_x', c: 'BASE64URL_CIPHERTEXT_yyyy' };
  const relayed = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenB, to: slotA, envelope });
  check('relay reports delivered', relayed.status === 200 && relayed.json?.delivered === true, relayed.text);
  const got = await streamA.wait('relay');
  check('relayed envelope arrives byte-for-byte unmodified',
    got.data?.n === envelope.n && got.data?.c === envelope.c, JSON.stringify(got.data));
  // The server adds EXACTLY ONE field, and it is the authenticated-sender stamp. Asserted
  // as the exact key set rather than "sfrom is present", so anything else the server ever
  // starts attaching to a relay breaks this: the envelope is the one thing on this route
  // it is supposed to be unable to touch.
  check('the server adds the sender stamp and nothing else to the envelope',
    Object.keys(got.data).sort().join(',') === 'c,n,sfrom', JSON.stringify(got.data));
  check('and the stamp is the slot the token authorised, not anything else about the caller',
    got.data?.sfrom === slotB, `${got.data?.sfrom} vs sender ${slotB}`);

  const backwards = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, to: slotB, envelope: { n: 'a', c: 'b' } });
  check('relay works in the other direction too', backwards.status === 200, backwards.text);
  await streamB.wait('relay');

  // --- envelope validation
  const badEnv = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, to: slotB, envelope: { n: 1, c: 2 } });
  check('non-string envelope fields are rejected', badEnv.status === 400, badEnv.text);

  const noEnv = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, to: slotB });
  check('missing envelope is rejected', noEnv.status === 400, noEnv.text);

  const huge = await request(PORT, 'POST', '/api/relay', {
    roomId: ROOM, token: tokenA, to: slotB, envelope: { n: 'x', c: 'y'.repeat(70_000) },
  });
  check('oversized envelope is rejected', huge.status === 413 || huge.status === 400, `status ${huge.status}`);

  // --- a relay is ADDRESSED, and there is no fallback
  //
  // This is the single most important refusal in the file. A relay that fell back to
  // "send it to everyone" would hand one pair's ECDH to the whole room, and every other
  // guarantee about pairwise keys would be worth nothing.
  const beforeRefused = relaysAt(streamB).length;
  for (const [what, to] of [['no target', undefined], ['a null target', null], ['an empty target', ''],
    ['a non-string target', 7], ['itself', slotA]]) {
    const body = { roomId: ROOM, token: tokenA, envelope: { n: 'p', c: 'q' } };
    if (to !== undefined) body.to = to;
    const r = await request(PORT, 'POST', '/api/relay', body);
    check(`a relay with ${what} is refused`,
      r.status === 400 && r.json?.error === 'bad_target', `${r.status} ${r.text}`);
  }
  const unknownTarget = await request(PORT, 'POST', '/api/relay', {
    roomId: ROOM, token: tokenA, to: 'AAAAAAAA', envelope: { n: 'p', c: 'q' },
  });
  check('a relay addressed at a slot this room does not seat is refused',
    unknownTarget.status === 404 && unknownTarget.json?.error === 'no_peer',
    `${unknownTarget.status} ${unknownTarget.text}`);
  // The negative control for the six refusals above: none of them may have been delivered
  // anyway. streamB is the only other attached stream, so it is where a broadcast lands,
  // and the window is held open rather than sampled: a leaked frame is still in flight the
  // instant the POST returns.
  const refusedDelivered = await relaysAfter(streamB, beforeRefused, 1500);
  check('none of the refused relays were delivered to anybody',
    refusedDelivered.length === 0,
    `${refusedDelivered.length} refused relay(s) still arrived: ${JSON.stringify(refusedDelivered.map((e) => e.data))}`);

  // --- heartbeat, which is what keeps a proxy from idling the stream out
  await delay(900);
  check('stream emits heartbeat comments', streamA.seen('__heartbeat'), 'no heartbeat within 900ms at a 400ms interval');

  // --- severing
  const bye = await request(PORT, 'POST', '/api/bye', { roomId: ROOM, token: tokenA });
  check('bye succeeds', bye.status === 200, bye.text);
  const closed = await streamB.wait('closed');
  check('the other peer is told the room was severed', closed.data?.reason === 'severed', JSON.stringify(closed.data));

  const afterBye = await request(PORT, 'POST', '/api/relay', { roomId: ROOM, token: tokenA, to: slotB, envelope: { n: 'a', c: 'b' } });
  check('the room is gone after bye', afterBye.status === 404, afterBye.text);

  // With the correct proof in hand, the only thing that can turn this into no_room is
  // the room not being in the map. Presenting the right proof is what makes it evidence
  // of destruction rather than evidence of a rejected joiner.
  const rejoin = await roomIsGone(PORT, ROOM, proof.proof);
  check('a severed room cannot be rejoined even with the correct join proof',
    rejoin.gone, `${rejoin.status} ${rejoin.body}`);

  streamA.close();
  streamB.close();
  streamBadToken.close();

  // WGTEST02 was created by the TTL-fallback check and never paired. Severing it with
  // no stream attached also exercises bye on an unattached room.
  const strayBye = await request(PORT, 'POST', '/api/bye', {
    roomId: 'WGTEST02', token: badTtl.json.token,
  });
  check('bye works on a room that was never paired', strayBye.status === 200, strayBye.text);

  const strayGone = await roomIsGone(PORT, 'WGTEST02', strayProof.proof);
  check('an unpaired room is destroyed by bye too', strayGone.gone, `${strayGone.status} ${strayGone.body}`);

  check('server wrote nothing to stderr', srv.stderr() === '', srv.stderr());
  await srv.stop();
}

// ------------------------------------------------------- destruction, without a gauge
{
  // The old proof that rooms are really destroyed read a live room count off /api/health.
  // That gauge is gone, and it deserved to be. Occupancy is instead observed through the
  // only ceiling the server still enforces publicly: with WG_MAX_ROOMS set to 2, a third
  // create is refused with 503 capacity, and can only succeed again once the map has
  // actually released the earlier rooms.
  //
  // This is strictly stronger than the count it replaces: a stale or lying counter would
  // have satisfied `rooms === 0`, whereas nothing but a genuinely empty map lets the
  // refused create through.
  const P = PORT + 8;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_MAX_ROOMS: '2', WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
    WG_UNCLAIMED_TTL_MS: '2500', WG_SWEEP_MS: '120',
  });

  const mk = async (id) => {
    const p = makeJoinProof();
    const r = await request(P, 'POST', '/api/create', { roomId: id, sessionMinutes: 10, joinProofHash: p.hash });
    return { id, proof: p, res: r };
  };

  const one = await mk('ZAPD0001');
  const two = await mk('ZAPD0002');
  check('two rooms fill a two-room server',
    one.res.status === 200 && two.res.status === 200, `${one.res.status}/${two.res.status}`);

  // The negative control. If this does not refuse, the capacity probe below proves
  // nothing, because it would succeed whether or not the rooms were destroyed.
  const overflow = await mk('ZAPD0003');
  check('a third create is refused while both rooms are held',
    overflow.res.status === 503 && overflow.res.json?.error === 'capacity',
    `${overflow.res.status} ${overflow.res.text}`);

  // --- destruction by sever
  await request(P, 'POST', '/api/bye', { roomId: one.id, token: one.res.json.token });
  const afterOneBye = await mk('ZAPD0004');
  check('severing a room frees its slot in the map',
    afterOneBye.res.status === 200, `${afterOneBye.res.status} ${afterOneBye.res.text}`);
  const oneGone = await roomIsGone(P, one.id, one.proof.proof);
  check('the severed room id is no longer joinable', oneGone.gone, `${oneGone.status} ${oneGone.body}`);

  // --- destruction by TTL expiry
  // Both remaining rooms are unclaimed, so the 700ms unclaimed TTL reaps them. Nothing
  // is created in the meantime, so a success afterwards can only mean the sweep removed
  // them; a leak would keep the server at capacity forever.
  await delay(3200);
  const afterTtl = await mk('ZAPD0005');
  check('rooms destroyed by TTL expiry release their capacity too',
    afterTtl.res.status === 200, `${afterTtl.res.status} ${afterTtl.res.text}`);
  const twoGone = await roomIsGone(P, two.id, two.proof.proof);
  check('an expired room id is no longer joinable', twoGone.gone, `${twoGone.status} ${twoGone.body}`);

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
    const r = await request(P, 'POST', '/api/create', {
      roomId: id, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
    });
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
    const r = await request(P, 'POST', '/api/create', {
      roomId: ids[i], sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
    }, {
      'cf-connecting-ip': `203.0.113.${i + 1}`, // a distinct client each time
    });
    trusted.push(r.status);
  }
  check('with the proxy trusted, distinct clients get distinct rate-limit buckets',
    trusted.every((s) => s === 200), `statuses ${trusted.join(',')}`);

  // Same server, same trusted-proxy setting: one client sending the SAME address is
  // still capped. Without this the check above is satisfied by a limiter that is simply
  // switched off, which is the failure mode it exists to catch.
  const oneClient = [];
  for (let i = 0; i < 5; i += 1) {
    const r = await request(P, 'POST', '/api/create', {
      roomId: `SAME000${i + 1}`, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
    }, { 'cf-connecting-ip': '203.0.113.250' });
    oneClient.push(r.status);
  }
  check('a trusted proxy does not disable the limiter, it only re-keys it',
    oneClient.includes(429), `statuses ${oneClient.join(',')}`);
  await srvTrust.stop();

  const srvNoTrust = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_TRUST_PROXY: '0', WG_CREATE_PER_WINDOW: '2', WG_RATE_WINDOW_MS: '60000',
  });
  const untrusted = [];
  for (let i = 0; i < ids.length; i += 1) {
    const r = await request(P, 'POST', '/api/create', {
      roomId: ids[i], sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
    }, {
      'cf-connecting-ip': `203.0.113.${i + 1}`,
    });
    untrusted.push(r.status);
  }
  check('with the proxy untrusted, a forged header cannot buy extra quota',
    untrusted.includes(429), `statuses ${untrusted.join(',')}`);

  await srvNoTrust.stop();

  // X-Forwarded-For is the other half of the same claim and has to be refused on the
  // same grounds. A rotating value here would otherwise hand its sender a fresh
  // rate-limit key on every request, which is every limit in the process defeated.
  // Its own server, so the quota it is spending is demonstrably its own.
  const srvXff = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_TRUST_PROXY: '0', WG_CREATE_PER_WINDOW: '2', WG_RATE_WINDOW_MS: '60000',
  });
  const forgedXff = [];
  for (let i = 0; i < 5; i += 1) {
    const r = await request(P, 'POST', '/api/create', {
      roomId: `XFFF000${i + 1}`, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
    }, { 'x-forwarded-for': `198.51.100.${i + 1}, 203.0.113.9` });
    forgedXff.push(r.status);
  }
  check('a forged X-Forwarded-For from an untrusted source buys no quota either',
    forgedXff.filter((s) => s === 200).length === 2 && forgedXff.includes(429),
    `statuses ${forgedXff.join(',')}`);
  await srvXff.stop();
}

// ---------------------------------------------------------------- expiry
{
  const P = PORT + 2;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_UNCLAIMED_TTL_MS: '700', WG_SWEEP_MS: '150',
  });

  const p1 = makeJoinProof();
  const create = await request(P, 'POST', '/api/create', { roomId: 'EXPRY001', sessionMinutes: 10, joinProofHash: p1.hash });
  const stream = openStream(P, 'EXPRY001', create.json.token);
  await stream.ready;
  await stream.wait('hello');

  const closed = await stream.wait('closed', 4000).catch((e) => e);
  check('an unclaimed room expires and says so',
    closed?.data?.reason === 'ttl', closed instanceof Error ? closed.message : JSON.stringify(closed?.data));

  const after = await roomIsGone(P, 'EXPRY001', p1.proof);
  check('an expired room cannot be joined', after.gone, `${after.status} ${after.body}`);

  // Joining must extend the clock past the unclaimed window, or a paired session
  // would die mid-transfer.
  const p2 = makeJoinProof();
  const create2 = await request(P, 'POST', '/api/create', { roomId: 'EXPRY002', sessionMinutes: 10, joinProofHash: p2.hash });
  const join2 = await request(P, 'POST', '/api/join', { roomId: 'EXPRY002', joinProof: p2.proof });
  check('joining extends the room past the unclaimed TTL', join2.status === 200, join2.text);
  const s2a = openStream(P, 'EXPRY002', create2.json.token);
  const s2b = openStream(P, 'EXPRY002', join2.json.token);
  await Promise.all([s2a.ready, s2b.ready]);
  await delay(1400); // comfortably past the 700ms unclaimed TTL
  const stillThere = await request(P, 'POST', '/api/relay', {
    roomId: 'EXPRY002', token: create2.json.token, to: join2.json.slotId, envelope: { n: 'a', c: 'b' },
  });
  check('a paired room survives past the unclaimed TTL', stillThere.status === 200, stillThere.text);

  stream.close(); s2a.close(); s2b.close();
  await srv.stop();
}

// ---------------------------------------------------------------- races
{
  const P = PORT + 4;
  // Pinned to two seats, because this block is about the race for the LAST one. With the
  // default six every join below would simply succeed and the assertion would prove
  // nothing about contention.
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
    WG_MAX_PARTICIPANTS: '2',
  });

  // Two devices scanning the same QR at the same moment. Exactly one may take the
  // second slot; the loser must be told the room is full, not silently share it.
  const raceProof = makeJoinProof();
  const raceCreate = await request(P, 'POST', '/api/create', {
    roomId: 'RACE0001', sessionMinutes: 10, joinProofHash: raceProof.hash,
  });
  const joins = await Promise.all([
    request(P, 'POST', '/api/join', { roomId: 'RACE0001', joinProof: raceProof.proof }),
    request(P, 'POST', '/api/join', { roomId: 'RACE0001', joinProof: raceProof.proof }),
    request(P, 'POST', '/api/join', { roomId: 'RACE0001', joinProof: raceProof.proof }),
  ]);
  const okJoins = joins.filter((r) => r.status === 200);
  const fullJoins = joins.filter((r) => r.status === 409);
  check('exactly one of three simultaneous joins succeeds',
    okJoins.length === 1 && fullJoins.length === 2, joins.map((r) => r.status).join(','));

  // This used to assert only that the winner got *a* token, which is already covered by
  // the 200 above, so it could not fail on the thing its name claims: two slots in one
  // room holding the same token would have printed OK. Compare them.
  const tokA = raceCreate.json?.token;
  const tokB = okJoins[0]?.json?.token;
  check('the two tokens issued for one room are different',
    distinctTokens(tokA, tokB),
    `a=${JSON.stringify(tokA)} b=${JSON.stringify(tokB)}`);

  // Two browsers generating the same room id would mean the same secret, which cannot
  // happen by chance, but the server must still not merge them.
  const creates = await Promise.all([
    request(P, 'POST', '/api/create', { roomId: 'RACE0002', sessionMinutes: 10, joinProofHash: makeJoinProof().hash }),
    request(P, 'POST', '/api/create', { roomId: 'RACE0002', sessionMinutes: 10, joinProofHash: makeJoinProof().hash }),
  ]);
  check('exactly one of two simultaneous creates for one id succeeds',
    creates.filter((r) => r.status === 200).length === 1
    && creates.filter((r) => r.status === 409).length === 1,
    creates.map((r) => r.status).join(','));

  // A refresh: the stream drops and comes back with the same token. The peer must not
  // be told the device left, and the room must survive.
  const pC = makeJoinProof();
  const roomC = await request(P, 'POST', '/api/create', { roomId: 'RACE0003', sessionMinutes: 10, joinProofHash: pC.hash });
  const joinC = await request(P, 'POST', '/api/join', { roomId: 'RACE0003', joinProof: pC.proof });
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
    roomId: 'RACE0003', token: roomC.json.token, to: joinC.json.slotId, envelope: { n: 'a', c: 'b' },
  });
  check('the room survives a peer reconnecting', stillAlive.status === 200, stillAlive.text);
  const afterRefresh = await sB2.wait('relay');
  check('relay still reaches the reattached stream', afterRefresh.data?.c === 'b', JSON.stringify(afterRefresh.data));

  sA.close(); sB2.close();
  await srv.stop();
}

// ---------------------------------------------------------------- idle extension
{
  // A fixed deadline is wrong for a pair who are actively using the gate: a long file
  // transfer would be cut off mid-way. The chosen TTL is an idle timeout, so the expiry
  // is pushed forward while somebody is still attached.
  //
  // "Somebody", not "both". One party attached and waiting while the other reconnects
  // from a train is not an idle gate, and treating it as one destroyed the room out from
  // under the side that was still there. What must still stop the clock is nobody being
  // attached at all, which is what lets a gate expire.
  const P = PORT + 6;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_SWEEP_MS: '150',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
    // Long enough that the room is still there to be measured while nobody is attached.
    WG_EMPTY_GRACE_MS: '30000',
  });

  const ROOM = 'KEEP0001';
  const pk = makeJoinProof();
  const create = await request(P, 'POST', '/api/create', { roomId: ROOM, sessionMinutes: 10, joinProofHash: pk.hash });
  const join = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pk.proof });
  check('idle-extension fixture room created', create.status === 200 && join.status === 200,
    `${create.status}/${join.status}`);

  const sa = openStream(P, ROOM, create.json.token);
  const sb = openStream(P, ROOM, join.json.token);
  await Promise.all([sa.ready, sb.ready]);
  await sa.wait('peer-joined');

  const read = async () => (await request(P, 'GET', `/api/room?room=${ROOM}&token=${create.json.token}`)).json;
  const first = await read();
  await delay(700);
  const later = await read();
  check('expiry moves forward while both devices are attached',
    later.expiresAt > first.expiresAt, `${first.expiresAt} -> ${later.expiresAt}`);

  // One side gone, one side still attached and waiting. The clock keeps moving: that
  // party is present, and reaping the gate underneath it is exactly the bug this
  // behaviour exists to prevent.
  sb.close();
  await delay(900); // past the point where the server has certainly seen the close
  const oneLeft = await read();
  await delay(700);
  const oneLeft2 = await read();
  check('expiry keeps moving while one device is still attached and waiting',
    oneLeft2.expiresAt > oneLeft.expiresAt, `${oneLeft.expiresAt} -> ${oneLeft2.expiresAt}`);

  // Nobody attached at all. Now the clock has to stop, or no gate could ever expire.
  sa.close();
  await delay(900);
  const empty = await read();
  await delay(900);
  const empty2 = await read();
  check('expiry stops moving once nobody is attached at all',
    empty2.expiresAt === empty.expiresAt, `${empty.expiresAt} -> ${empty2.expiresAt}`);
  // The negative control for the pair above: a clock that never moved would satisfy
  // "stops moving", so it has to be shown to have moved earlier in the same room.
  check('the same room\'s clock demonstrably did move while it was occupied',
    empty.expiresAt > first.expiresAt, `${first.expiresAt} -> ${empty.expiresAt}`);

  await srv.stop();
}

// ---------------------------------------------------------------- hard limit
{
  // The extension must not be unbounded, or two forgotten tabs would pin a room.
  const P = PORT + 7;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_SWEEP_MS: '150',
    WG_MAX_SESSION_MS: '900',
  });
  const ph = makeJoinProof();
  const create = await request(P, 'POST', '/api/create', { roomId: 'HARD0001', sessionMinutes: 10, joinProofHash: ph.hash });
  const join = await request(P, 'POST', '/api/join', { roomId: 'HARD0001', joinProof: ph.proof });
  const sa = openStream(P, 'HARD0001', create.json.token);
  const sb = openStream(P, 'HARD0001', join.json.token);
  await Promise.all([sa.ready, sb.ready]);

  const closed = await sa.wait('closed', 6000).catch((e) => e);
  // The hard cap has its own reason code, distinct from an idle expiry. The two are
  // different things to tell a user: one means "nobody was using this", the other means
  // "this gate has been open long enough". Asserting the specific code is what keeps the
  // distinction from silently collapsing back into one.
  check('an actively used gate still dies at the hard limit',
    closed?.data?.reason === 'ttl-hard', closed instanceof Error ? closed.message : JSON.stringify(closed?.data));
  check('and the peer is told at the same moment',
    (await sb.arrivedWithin('closed', 2000)) === true,
    JSON.stringify(sb.events.map((e) => e.event)));

  sa.close(); sb.close();
  await srv.stop();
}

// ---------------------------------------------------------------- STUN
{
  const P = PORT + 3;
  const S = STUN + 3;
  // WG_STUN_ENABLED is opt-in, and without it startStun() returns no sockets at all.
  // Omitting it left every assertion below measuring a port with nothing behind it.
  const srv = await startServer({ WG_HTTP_PORT: String(P), WG_STUN_PORT: String(S), WG_STUN_ENABLED: '1' });
  check('the server reports the STUN responder actually bound',
    /warp-gate stun udp\/\d+ \([1-9]\d* socket/.test(srv.stdout()), srv.stdout());

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

  // Malformed input on the same socket. A STUN responder is reachable by anyone who can
  // send a UDP datagram, so the parser is the most exposed surface in the process and
  // had no coverage at all. Nothing that is not a well-formed Binding request may
  // produce a reply, and none of it may take the process down.
  const stunHeader = (type, declared, magic, bodyBytes = 0) => {
    const b = Buffer.alloc(20 + bodyBytes);
    b.writeUInt16BE(type, 0);
    b.writeUInt16BE(declared, 2);
    b.writeUInt32BE(magic, 4);
    crypto.randomBytes(12).copy(b, 8); // transaction id
    return b;
  };
  const MAGIC = 0x2112a442;

  // Not a Binding request. Every one of these must be dropped in silence: a responder
  // that answers arbitrary traffic is a reflector, and the source address on a UDP
  // datagram is whatever the sender wrote.
  const mustBeSilent = [
    ['empty datagram', Buffer.alloc(0)],
    ['one byte', Buffer.from([0x00])],
    ['19 bytes, one short of a header', crypto.randomBytes(19)],
    ['20 random bytes', crypto.randomBytes(20)],
    ['right shape, wrong magic cookie', stunHeader(0x0001, 0, 0xdeadbeef)],
    ['a binding SUCCESS, which is a response and not a request', stunHeader(0x0101, 0, MAGIC)],
    ['an allocate request, which this responder does not implement', stunHeader(0x0003, 0, MAGIC)],
    ['declared length far larger than the datagram', stunHeader(0x0001, 0xffff, MAGIC)],
    ['declared length smaller than the datagram', stunHeader(0x0001, 0, MAGIC, 8)],
    ['1200 random bytes', crypto.randomBytes(1200)],
  ];

  const sock = dgram.createSocket('udp4');
  await new Promise((r) => sock.bind(0, '127.0.0.1', r));
  let replies = [];
  sock.on('message', (msg) => replies.push(msg));
  for (const [, datagram] of mustBeSilent) sock.send(datagram, S, '127.0.0.1');
  await delay(700);

  check('input that is not a binding request draws no reply at all',
    replies.length === 0,
    `${replies.length} reply/replies to ${mustBeSilent.length} datagrams: ${replies.map((r) => r.toString('hex').slice(0, 24)).join(' ')}`);

  // A header-valid Binding request carrying a junk body IS answerable, and this
  // responder answers it. What must not happen is the junk coming back: a response that
  // grows with its request is an amplification primitive aimed at a forged source.
  replies = [];
  const padded = stunHeader(0x0001, 800, MAGIC, 800);
  padded.writeUInt16BE(0x0006, 20); // USERNAME
  padded.writeUInt16BE(0x7fff, 22); // ...claiming far more length than it has
  sock.send(padded, S, '127.0.0.1');
  await delay(700);
  sock.close();

  // Negative control for the whole fuzz: this datagram MUST be answered, or the silence
  // asserted above is the silence of a dead socket and proves nothing.
  check('a header-valid binding request with a junk body is still answered',
    replies.length === 1, `${replies.length} replies`);
  const reply = replies[0];
  check('the reply is a binding success and not the junk echoed back',
    reply?.length === 32
    && reply.readUInt16BE(0) === 0x0101
    && reply.readUInt32BE(4) === MAGIC
    && reply.subarray(8, 20).equals(padded.subarray(8, 20)),
    reply ? `${reply.length} bytes: ${reply.toString('hex').slice(0, 32)}` : 'no reply');
  check('the response is smaller than the request, so it cannot amplify',
    reply !== undefined && reply.length < padded.length, `${reply?.length} vs ${padded.length}`);

  // The point of the fuzz is that the process is still there afterwards. Without this
  // the silence above would also be satisfied by a responder that had crashed.
  const aliveAfter = await request(P, 'GET', '/api/health');
  check('the process survives the malformed STUN traffic',
    aliveAfter.status === 200 && aliveAfter.json?.ok === true, aliveAfter.text);

  const stillBinding = await stunBinding('127.0.0.1', S, 2000).then((v) => v, (e) => e);
  check('a well-formed binding request still works after the malformed ones',
    !(stillBinding instanceof Error) && stillBinding.ip === '127.0.0.1',
    stillBinding instanceof Error ? stillBinding.message : JSON.stringify(stillBinding));

  await srv.stop();
}

// ---------------------------------------------------------------- join proof
{
  // Possession of the room id alone must not buy slot B. The id is server-visible on
  // every request while the room secret never leaves the browser, so without a proof
  // anyone who can watch or operate this process could squat the second slot and lock
  // the real peer out.
  const P = PORT + 9;
  // Two seats, so the occupancy-oracle ordering below can actually be reached: the check
  // is that a caller who cannot prove knowledge of the secret is refused BEFORE being told
  // whether the gate is full, and a gate that is never full would never test it.
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
    WG_MAX_PARTICIPANTS: '2',
  });

  const right = makeJoinProof();
  const wrong = makeJoinProof();
  const ROOM = 'PRVE0001';
  const created = await request(P, 'POST', '/api/create', {
    roomId: ROOM, sessionMinutes: 10, joinProofHash: right.hash,
  });
  check('a room can be created with a join proof registered', created.status === 200, created.text);

  const noProof = await request(P, 'POST', '/api/join', { roomId: ROOM });
  check('knowing the room id alone does not take the second slot',
    noProof.status === 403 && noProof.json?.error === 'bad_join_proof', `${noProof.status} ${noProof.text}`);

  const wrongProof = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: wrong.proof });
  check('a join proof from a different secret is refused',
    wrongProof.status === 403 && wrongProof.json?.error === 'bad_join_proof', `${wrongProof.status} ${wrongProof.text}`);

  for (const bad of ['', 'x', right.proof.slice(0, -1), `${right.proof}A`, right.hash, null, 42, { proof: right.proof }]) {
    const r = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: bad });
    check(`a malformed join proof ${JSON.stringify(bad)} is refused`, r.status === 403, `status ${r.status}`);
  }

  // The positive control. Without it every check above is satisfied by a server that
  // refuses every join, which would be a total outage reported as a security pass.
  const good = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: right.proof });
  check('the correct join proof does take the slot',
    good.status === 200 && good.json?.role === 'b', `${good.status} ${good.text}`);

  // Ordering matters: an occupancy answer before the proof check would turn the room
  // id alone into an oracle for whether a gate has been claimed.
  const fullNoProof = await request(P, 'POST', '/api/join', { roomId: ROOM });
  check('occupancy is not disclosed to a caller who cannot prove knowledge of the secret',
    fullNoProof.status === 403 && fullNoProof.json?.error === 'bad_join_proof',
    `${fullNoProof.status} ${fullNoProof.text}`);
  const fullWithProof = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: right.proof });
  check('a caller who CAN prove it is told the room is full',
    fullWithProof.status === 409 && fullWithProof.json?.error === 'room_full',
    `${fullWithProof.status} ${fullWithProof.text}`);

  // A malformed registration is refused outright rather than stored.
  for (const bad of ['', 'short', right.proof, `${right.hash}A`, `${right.hash.slice(0, -1)}+`]) {
    const r = await request(P, 'POST', '/api/create', {
      roomId: 'PRVE0002', sessionMinutes: 10, joinProofHash: bad,
    });
    check(`create rejects a malformed join proof hash ${JSON.stringify(bad)}`,
      r.status === 400 && r.json?.error === 'bad_join_proof', `${r.status} ${r.text}`);
  }

  // A non-string is not a malformed hash, it is no hash at all: the route only forwards
  // strings, so the room is created with nothing registered. That must fail CLOSED, and
  // an absent proof must never read as "this room does not need one".
  const unregistered = await request(P, 'POST', '/api/create', {
    roomId: 'PRVE0003', sessionMinutes: 10, joinProofHash: 12,
  });
  check('a room created with no usable join proof is still created', unregistered.status === 200, unregistered.text);
  const cannotJoin = await request(P, 'POST', '/api/join', { roomId: 'PRVE0003', joinProof: right.proof });
  const cannotJoinBare = await request(P, 'POST', '/api/join', { roomId: 'PRVE0003' });
  check('a room with no registered join proof is joinable by nobody, not by everybody',
    cannotJoin.status === 403 && cannotJoinBare.status === 403,
    `with a proof ${cannotJoin.status}, without one ${cannotJoinBare.status}`);

  await srv.stop();
}

// ---------------------------------------------------------------- room password
{
  // The password never reaches the server. All it may learn is the boolean it needs in
  // order to prompt the joiner, and that flag has to survive to every reader: create,
  // join and the resume path all show it, so a page that reloads still knows to ask.
  const P = PORT + 10;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_PUBLIC_GET_PER_WINDOW: '200',
  });

  const withPw = makeJoinProof();
  const noPw = makeJoinProof();
  const guarded = await request(P, 'POST', '/api/create', {
    roomId: 'PWRD0001', sessionMinutes: 10, requiresPassword: true, joinProofHash: withPw.hash,
  });
  const open = await request(P, 'POST', '/api/create', {
    roomId: 'PWRD0002', sessionMinutes: 10, joinProofHash: noPw.hash,
  });
  check('create reports back that the gate requires a password',
    guarded.status === 200 && guarded.json?.requiresPassword === true, guarded.text);
  // The negative control: without it, a server hard-coding `true` would pass.
  check('a gate created without one reports requiresPassword false',
    open.status === 200 && open.json?.requiresPassword === false, open.text);

  const joinGuarded = await request(P, 'POST', '/api/join', { roomId: 'PWRD0001', joinProof: withPw.proof });
  check('the joiner is told to expect a password before it connects',
    joinGuarded.status === 200 && joinGuarded.json?.requiresPassword === true, joinGuarded.text);
  const joinOpen = await request(P, 'POST', '/api/join', { roomId: 'PWRD0002', joinProof: noPw.proof });
  check('the joiner of an unguarded gate is not told to expect one',
    joinOpen.status === 200 && joinOpen.json?.requiresPassword === false, joinOpen.text);

  const resumed = await request(P, 'GET', `/api/room?room=PWRD0001&token=${encodeURIComponent(joinGuarded.json.token)}`);
  check('a resumed session still knows the gate needs a password',
    resumed.status === 200 && resumed.json?.requiresPassword === true, resumed.text);

  // Only ever a boolean. Anything password-shaped in a server response would mean the
  // password had left the browser, which is the one thing this feature must not do.
  const bodies = [guarded.text, open.text, joinGuarded.text, joinOpen.text, resumed.text].join(' ');
  check('no server response carries anything but the boolean',
    !/passw(or)?d"\s*:\s*"/i.test(bodies) && !/hunter2/i.test(bodies), bodies.slice(0, 200));

  // A password is a client-side concept, so a truthy non-boolean must not smuggle one in.
  const smuggled = await request(P, 'POST', '/api/create', {
    roomId: 'PWRD0003', sessionMinutes: 10, requiresPassword: 'hunter2', joinProofHash: makeJoinProof().hash,
  });
  check('a non-boolean requiresPassword is coerced, never stored',
    smuggled.status === 200 && smuggled.json?.requiresPassword === false
    && !/hunter2/.test(smuggled.text), smuggled.text);

  await srv.stop();
}

// ---------------------------------------------------------------- the participant cap
{
  // A gate seats config.limits.maxParticipants devices. Set low here so the ceiling can
  // actually be reached, and so the refusal past it is observed rather than assumed.
  const P = PORT + 11;
  // Six, the shipped default, so this exercises the real ceiling and a full six-way roster
  // rather than a number chosen to make the test short. Fifteen links is what the cap is
  // actually there to bound.
  const CAP = 6;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_MAX_PARTICIPANTS: String(CAP),
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
    // Every stream here comes from 127.0.0.1, so they share one rate-limit key. The
    // production ceiling of four would refuse the fifth participant's stream for a reason
    // that has nothing to do with the seat cap under test.
    WG_STREAMS_PER_KEY: '30',
  });

  const ROOM = 'CAPS0001';
  const pr = makeJoinProof();
  const creator = await request(P, 'POST', '/api/create', {
    roomId: ROOM, sessionMinutes: 10, joinProofHash: pr.hash,
  });
  check('the server advertises the seat count it was configured with',
    creator.json?.maxParticipants === CAP, creator.text);

  const seated = [creator];
  for (let i = 1; i < CAP; i += 1) {
    seated.push(await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pr.proof }));
  }
  check(`${CAP} participants fill the gate`,
    seated.every((r) => r.status === 200), seated.map((r) => r.status).join(','));
  check('every seated participant holds a slot id nobody else holds',
    new Set(seated.map((r) => r.json.slotId)).size === CAP,
    JSON.stringify(seated.map((r) => r.json.slotId)));

  const overflow = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pr.proof });
  check('the participant past the cap is refused as room_full',
    overflow.status === 409 && overflow.json?.error === 'room_full',
    `${overflow.status} ${overflow.text}`);
  check('and is given no slot to use',
    overflow.json?.slotId === undefined && overflow.json?.token === undefined, overflow.text);

  // "Unaffected" is the half that is easy to skip and is the whole point: a refused joiner
  // must not cost the people already in the gate anything. Every one of them can still
  // attach, and a relay between two of them still lands.
  const streams = [];
  for (const r of seated) streams.push(openStream(P, ROOM, r.json.token));
  await Promise.all(streams.map((s) => s.ready));
  const hellos = await Promise.all(streams.map((s) => s.wait('hello')));
  check('every seated participant is still able to attach after the refusal',
    hellos.every((h, i) => h.data?.self === seated[i].json.slotId),
    JSON.stringify(hellos.map((h) => h.data?.self)));
  check('and each of them sees the other two in its roster',
    hellos.every((h) => h.data?.peers?.length === CAP - 1),
    JSON.stringify(hellos.map((h) => h.data?.peers?.length)));

  const afterRefusal = await request(P, 'POST', '/api/relay', {
    roomId: ROOM, token: seated[0].json.token, to: seated[1].json.slotId,
    envelope: { n: 'cap', c: 'ok' },
  });
  const landed = await streams[1].wait('relay');
  check('a relay between two already-seated participants still works after a refusal',
    afterRefusal.status === 200 && afterRefusal.json?.delivered === true && landed.data?.c === 'ok',
    `${afterRefusal.status} ${afterRefusal.text}`);

  for (const s of streams) s.close();
  await srv.stop();
}

// ------------------------------------------------- a relay reaches ONE peer, not the room
{
  // The most important property in the mesh. Every pair runs its own ECDH, and that is
  // only private to the pair because the server delivers a relay to the addressed slot and
  // to nothing else. A fallback broadcast here would hand one pair's handshake to everyone.
  const P = PORT + 12;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
  });

  const ROOM = 'MESH0001';
  const pr = makeJoinProof();
  const a = await request(P, 'POST', '/api/create', { roomId: ROOM, sessionMinutes: 10, joinProofHash: pr.hash });
  const b = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pr.proof });
  const c = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pr.proof });
  check('three participants are seated in one gate',
    a.status === 200 && b.status === 200 && c.status === 200,
    `${a.status}/${b.status}/${c.status}`);

  const sa = openStream(P, ROOM, a.json.token);
  const sb = openStream(P, ROOM, b.json.token);
  const sc = openStream(P, ROOM, c.json.token);
  await Promise.all([sa.ready, sb.ready, sc.ready]);
  await Promise.all([sa.wait('hello'), sb.wait('hello'), sc.wait('hello')]);

  // Positive control FIRST: prove C's stream is capable of receiving a relay at all.
  // Without this, "C did not receive it" is satisfied by a stream nothing could ever
  // reach, which is the same green output as a server that routes correctly.
  await request(P, 'POST', '/api/relay', {
    roomId: ROOM, token: a.json.token, to: c.json.slotId, envelope: { n: 'ctl', c: 'to-c' },
  });
  const control = await sc.wait('relay');
  check('a relay addressed at the third participant does reach it',
    control.data?.c === 'to-c', JSON.stringify(control.data));

  const seenAtB = relaysAt(sb).length;
  const seenAtC = relaysAt(sc).length;
  const secret = await request(P, 'POST', '/api/relay', {
    roomId: ROOM, token: a.json.token, to: b.json.slotId, envelope: { n: 'pair', c: 'a-to-b-only' },
  });
  const atB = await relaysAfter(sb, seenAtB, 4000);
  check('a relay addressed at one peer is delivered to that peer',
    secret.status === 200 && secret.json?.delivered === true && atB[0]?.data?.c === 'a-to-b-only',
    `${secret.status} ${secret.text} -> ${JSON.stringify(atB.map((e) => e.data))}`);

  // The window is held open for its whole length whatever B saw, so this cannot report
  // "nothing arrived" without having waited. Against a deliberately broadcasting build
  // this prints BAD; against the shipped one it prints OK.
  const leaked = await relaysAfter(sc, seenAtC, 1500);
  check('and is NOT delivered to the third participant',
    leaked.length === 0,
    `third participant received ${leaked.length} extra relay(s): ${JSON.stringify(leaked.map((e) => e.data))}`);

  // One participant leaving must not disturb the other two. The server holds a departure
  // for a grace period first, because a reload puts the stream straight back.
  sc.close();
  const goneAtA = await sa.wait('peer-left', 14000);
  const goneAtB = await sb.wait('peer-left', 14000);
  check('a departure is announced to the others, naming who left',
    goneAtA.data?.id === c.json.slotId && goneAtB.data?.id === c.json.slotId,
    `${JSON.stringify(goneAtA.data)} / ${JSON.stringify(goneAtB.data)}`);

  const stillWorks = await request(P, 'POST', '/api/relay', {
    roomId: ROOM, token: b.json.token, to: a.json.slotId, envelope: { n: 'after', c: 'still-here' },
  });
  const atA = await sa.wait('relay');
  check('the remaining pair keeps working after the third participant leaves',
    stillWorks.status === 200 && stillWorks.json?.delivered === true && atA.data?.c === 'still-here',
    `${stillWorks.status} ${stillWorks.text}`);

  sa.close(); sb.close();
  await srv.stop();
}

// ---------------------------------------------------------------------------
// Signalling replay control.
//
// k_sig depends on the room secret alone and the AAD is a constant, so a captured
// envelope decrypts as many times as anyone relays it. That is denial of service rather
// than compromise, since a replayed offer carries a stale public key and key confirmation
// fails closed, but it lets an observer wedge a gate repeatedly.
//
// Exercised directly against the client's Signal, which is safe to construct in Node: the
// constructor touches no EventSource and no network. What is under test is the decision,
// not the transport.
{
  const { Signal } = await import('../public/js/signal.js');
  const sig = () => new Signal({ roomId: 'ABCDEFGH', token: 't', signalKey: null });

  const E1 = 1000;
  const E2 = 2000; // a later page load

  const s = sig();
  const first = s.acceptSeq({ from: 'peerone', epoch: E1, seq: 1 });
  check('a signalling message with a fresh sequence is accepted', first === true);

  // The positive case above is what stops this whole block from being vacuous: a guard
  // that refused everything would also "pass" every replay assertion below.
  check('the same message replayed is refused',
    s.acceptSeq({ from: 'peerone', epoch: E1, seq: 1 }) === false);
  check('an older sequence from the same sender is refused',
    s.acceptSeq({ from: 'peerone', epoch: E1, seq: 0 }) === false);
  check('a later sequence from the same sender is accepted',
    s.acceptSeq({ from: 'peerone', epoch: E1, seq: 2 }) === true);

  // Per sender, not global: one participant's traffic must not raise the bar for another.
  check('each sender has an independent sequence',
    s.acceptSeq({ from: 'peertwo', epoch: E1, seq: 1 }) === true);

  // THE CASE THAT SHIPPED BROKEN. A reload keeps the slot id but starts a new page, so the
  // counter restarts at 1. Judged on the counter alone that looks exactly like a replay,
  // and refusing it failed the resume and then cleared the room secret. A newer epoch has
  // to be accepted from sequence 1.
  check('a reloaded peer restarting its counter under a newer epoch is accepted',
    s.acceptSeq({ from: 'peerone', epoch: E2, seq: 1 }) === true);
  check('and its own replay is still refused afterwards',
    s.acceptSeq({ from: 'peerone', epoch: E2, seq: 1 }) === false);
  check('an envelope from the peer\'s PREVIOUS page is refused once it has reloaded',
    s.acceptSeq({ from: 'peerone', epoch: E1, seq: 9 }) === false);

  check('a message with no sender is refused', s.acceptSeq({ epoch: E1, seq: 9 }) === false);
  check('a message with no sequence is refused',
    s.acceptSeq({ from: 'peerone', epoch: E1 }) === false);
  check('a message with no epoch is refused', s.acceptSeq({ from: 'peerone', seq: 9 }) === false);
  check('a non-integer sequence is refused',
    s.acceptSeq({ from: 'peerone', epoch: E1, seq: 1.5 }) === false);

  // A fresh session must accept what the old one already saw, or a reconnecting peer
  // would be locked out by state it cannot see.
  check('a fresh session accepts a sequence a previous one had already seen',
    sig().acceptSeq({ from: 'peerone', epoch: E1, seq: 1 }) === true);

  let refusals = 0;
  const listening = sig();
  listening.addEventListener('replay-refused', () => { refusals += 1; });
  listening.acceptSeq({ from: 'peerone', epoch: E1, seq: 5 });
  listening.acceptSeq({ from: 'peerone', epoch: E1, seq: 5 });
  check('a refused replay is reported rather than dropped in silence', refusals === 1, `${refusals} events`);
}

// ---------------------------------------------------------------------------
// A reader that stops reading.
//
// Everything in the three blocks below needs the same thing: an SSE stream whose client
// has accepted the connection and then stopped draining it. Node cannot set a zero TCP
// window directly, but it does not need to: a socket that is never read from fills its
// own receive buffer, then the server's send buffer, and after that every relayed byte is
// queued in the server process's own heap, which is exactly the resource under test.
//
// A NOTE ON WHAT CAN BE OBSERVED FROM HERE, because it is the whole reason these tests
// are shaped the way they are. A socket that is not being read cannot see its own
// closure: measured, the server destroyed a stream at about 3 MB and the paused client
// showed nothing at all after a further 21 MB. So every assertion below is made on
// something the SERVER reports over a second connection, never on the stalled socket.
function stalledStream(port, roomId, token) {
  const sock = net.connect(port, '127.0.0.1');
  const opened = new Promise((resolve, reject) => {
    // Not unref'd. A timer that lets the process exit while this is pending would report
    // an outcome without having waited for one.
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('stalled stream never got headers')); }, 8000);
    sock.on('connect', () => {
      sock.write(`GET /api/events?room=${encodeURIComponent(roomId)}&token=${encodeURIComponent(token)}`
        + ' HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    });
    sock.once('data', (d) => {
      clearTimeout(timer);
      const head = d.toString('latin1');
      // From here on nothing is ever read again.
      sock.pause();
      resolve(head);
    });
    sock.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
  return {
    opened,
    close: () => { try { sock.destroy(); } catch (err) { void err; } },
  };
}

/**
 * Relay maxRelayBytes envelopes at a stalled seat until the server stops delivering them.
 *
 * `delivered` is the observable: sendTo() reports false the moment the stream it was
 * addressed at is gone, and it is reported back over the POST's own connection, which is
 * a healthy one. Returns the count sent and the index at which delivery stopped, so the
 * number itself is part of the evidence rather than a hidden threshold.
 *
 * Measured on this machine: the kernel absorbs about 2.7 MB before any of it shows up as
 * server-side backlog at all, so a bound of a few hundred KB trips at around relay 50 of
 * 60 KB. Anything that never trips runs the full count.
 */
async function pumpRelays(port, roomId, senderToken, targetSlot, max) {
  const c = 'y'.repeat(60_000); // under the 64 KiB relay cap, with room for framing
  let sent = 0;
  let stoppedAt = -1;
  for (let i = 0; i < max; i += 1) {
    const r = await request(port, 'POST', '/api/relay', {
      roomId, token: senderToken, to: targetSlot, envelope: { n: 'nonce', c },
    });
    if (r.status !== 200) break;
    sent += 1;
    if (r.json?.delivered === false && stoppedAt === -1) stoppedAt = i;
  }
  return { sent, stoppedAt, dropped: stoppedAt !== -1 };
}

/** Can this key open another SSE stream right now? The per-key gauge, read over HTTP. */
function streamAccepted(port, roomId, token) {
  return new Promise((resolve) => {
    const req = http.get({
      host: '127.0.0.1', port, path: `/api/events?room=${roomId}&token=${encodeURIComponent(token)}`,
    }, (res) => { res.resume(); req.destroy(); resolve(res.statusCode); });
    req.on('error', () => resolve(0));
    req.setTimeout(6000, () => { req.destroy(); resolve(0); });
  });
}

/** Create a gate and seat a second participant. Returns both sides. */
async function twoSeats(port, roomId) {
  const pr = makeJoinProof();
  const a = await request(port, 'POST', '/api/create', { roomId, sessionMinutes: 10, joinProofHash: pr.hash });
  const b = await request(port, 'POST', '/api/join', { roomId, joinProof: pr.proof });
  return { a: a.json, b: b.json, ok: a.status === 200 && b.status === 200 };
}

// -------------------------------------------- the SSE backlog is bounded in AGGREGATE
{
  // The per-stream cap was 1 MiB and nothing bounded the sum. At WG_MAX_ROOMS 200 and
  // WG_MAX_PARTICIPANTS 6 that is 1,200 possible streams and about 1.2 GB of allowance
  // against a 128 MB container. The attack is two seats: open both streams, stall one,
  // and POST 64 KiB envelopes at the stalled seat.
  const P = PORT + 20;
  const ROOM = 'BACK0001';
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
    WG_RELAY_PER_MIN: '100000', WG_API_PER_WINDOW: '100000',
    // The per-stream cap is put far out of reach on purpose, so what trips below can only
    // be the aggregate. Without this the test would pass on a server that has no
    // aggregate bound at all, which is the state it exists to detect.
    WG_MAX_STREAM_BACKLOG_BYTES: '100000000',
    WG_MAX_TOTAL_BACKLOG_BYTES: '400000',
    WG_HEARTBEAT_MS: '600000',
  });

  const seats = await twoSeats(P, ROOM);
  check('CONTROL: two seats for the aggregate-backlog probe', seats.ok, JSON.stringify(seats));

  const stalled = stalledStream(P, ROOM, seats.b.token);
  const head = await stalled.opened;
  check('CONTROL: the stalled reader really did open a stream',
    /^HTTP\/1\.1 200/.test(head) && /text\/event-stream/.test(head), JSON.stringify(head.slice(0, 80)));

  const pumped = await pumpRelays(P, ROOM, seats.a.token, seats.b.slotId, 400);
  check('a stream whose reader has stopped draining is dropped once the process-wide backlog is spent',
    pumped.dropped, `all ${pumped.sent} relays of 60 KB were still delivered, so nothing bounded the sum`);
  // The per-stream cap is 100 MB on this server, so the bound that fired can only be the
  // aggregate. Reported as a number rather than asserted against a threshold: what is
  // being claimed is that a bound exists, and the figure is how far it let things go.
  process.stdout.write(`     (measured: aggregate bound of 400 KB fired at relay ${pumped.stoppedAt} of 60 KB, `
    + `about ${Math.round(((pumped.stoppedAt + 1) * 60_000) / 1024 / 1024 * 10) / 10} MB relayed)\n`);

  // The seat is freed as well as the socket, or the per-key gauge would leak an entry
  // every time this fired.
  await delay(300);
  check('and its entry in the per-key stream gauge goes back',
    await streamAccepted(P, ROOM, seats.b.token) === 200,
    'the dropped stream did not release its slot in the gauge');

  stalled.close();
  await srv.stop();
}

{
  // THE CONTROL, and it is the whole evidence that the block above measures the aggregate
  // rather than the kernel or the per-stream cap. Same room, same stalled reader, same
  // number of relays, and the ONLY difference is that the aggregate ceiling is out of
  // reach. Against the pre-fix server, which had no aggregate bound, this is what the
  // block above also did.
  const P = PORT + 21;
  const ROOM = 'BACK0002';
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
    WG_RELAY_PER_MIN: '100000', WG_API_PER_WINDOW: '100000',
    WG_MAX_STREAM_BACKLOG_BYTES: '100000000',
    WG_MAX_TOTAL_BACKLOG_BYTES: '100000000',
    WG_HEARTBEAT_MS: '600000',
  });

  const seats = await twoSeats(P, ROOM);
  const stalled = stalledStream(P, ROOM, seats.b.token);
  await stalled.opened;
  const pumped = await pumpRelays(P, ROOM, seats.a.token, seats.b.slotId, 400);
  check('CONTROL: with both ceilings out of reach the same stream survives the same load',
    !pumped.dropped && pumped.sent === 400,
    `dropped at ${pumped.stoppedAt} after ${pumped.sent} relay(s)`);
  process.stdout.write('     (that arm is the pre-fix server expressed as configuration: '
    + `${Math.round((pumped.sent * 60_000) / 1024 / 1024)} MB of unread relay held in one process)\n`);

  stalled.close();
  await srv.stop();
}

{
  // The per-stream cap still does its own job, and it is configurable now rather than a
  // hard-coded 1 MiB that was sixteen times the relay cap for no stated reason.
  const P = PORT + 22;
  const ROOM = 'BACK0003';
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
    WG_RELAY_PER_MIN: '100000', WG_API_PER_WINDOW: '100000',
    WG_MAX_STREAM_BACKLOG_BYTES: '150000',
    WG_MAX_TOTAL_BACKLOG_BYTES: '100000000',
    WG_HEARTBEAT_MS: '600000',
  });

  const seats = await twoSeats(P, ROOM);
  const stalled = stalledStream(P, ROOM, seats.b.token);
  await stalled.opened;
  const pumped = await pumpRelays(P, ROOM, seats.a.token, seats.b.slotId, 400);
  check('a single stream past its own cap is still dropped, with the aggregate out of reach',
    pumped.dropped, `all ${pumped.sent} relays were still delivered`);

  stalled.close();
  await srv.stop();
}

// -------------------------------------- a destroyed room does not leave its socket pinned
// destroyRoom wrote `closed`, called res.end() and nulled slot.res. end() only queues a
// FIN behind whatever the peer has not read, so a stalled reader held the socket, and
// its entry in the per-key stream counter, until TCP gave up: a peer sending window
// probes defers that indefinitely. After slot.res is null nothing writes to it again,
// so the backlog guard cannot fire on it and the heartbeat skips it.
//
// What is observed is the PER-KEY STREAM GAUGE, not the socket, because a socket that is
// not being read cannot see its own closure. The gauge is the resource the finding names
// alongside the socket: streamClose only runs on the response's `close`, so a response
// that was ended but never actually closed holds its entry indefinitely. With
// WG_STREAMS_PER_KEY at 1 that entry is directly readable over HTTP: a second stream is
// either accepted or refused 429, and the whole difference is whether the first one let go.
{
  const env = {
    WG_STUN_ENABLED: '0', WG_STREAMS_PER_KEY: '1',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
    WG_RELAY_PER_MIN: '100000', WG_API_PER_WINDOW: '100000',
    // Both backlog bounds out of reach: what is under test is the teardown, and a stream
    // the backlog guard had already dropped would release the gauge for the wrong reason.
    WG_MAX_STREAM_BACKLOG_BYTES: '100000000',
    WG_MAX_TOTAL_BACKLOG_BYTES: '100000000',
    WG_HEARTBEAT_MS: '600000',
  };

  // One arm per linger setting. Identical in every other respect, so the linger is the
  // only thing that can account for a difference between them.
  const arm = async (port, room, spare, lingerMs) => {
    const srv = await startServer({ ...env, WG_HTTP_PORT: String(port), WG_DESTROY_LINGER_MS: String(lingerMs) });
    const seats = await twoSeats(port, room);
    const stalled = stalledStream(port, room, seats.b.token);
    await stalled.opened;
    // Fill the buffers first. Without this the FIN from end() is delivered, the socket
    // closes on its own, and the gauge is released whether or not the fix exists.
    const pumped = await pumpRelays(port, room, seats.a.token, seats.b.slotId, 400);
    // A second room for the probe, created while the gauge is still held.
    const spareSeats = await twoSeats(port, spare);
    const bye = await request(port, 'POST', '/api/bye', { roomId: room, token: seats.a.token });
    await delay(Math.min(lingerMs, 1200) + 900);
    const probe = await streamAccepted(port, spare, spareSeats.a.token);
    const out = { seats, pumped, spareSeats, bye, probe };
    stalled.close();
    await srv.stop();
    return out;
  };

  const short = await arm(PORT + 23, 'PNND0001', 'PNND0003', 300);
  check('CONTROL: the short-linger arm seated, flooded and destroyed a room',
    short.seats.ok && short.spareSeats.ok && short.pumped.sent === 400
    && !short.pumped.dropped && short.bye.status === 200,
    `seated=${short.seats.ok} flooded=${short.pumped.sent} droppedAt=${short.pumped.stoppedAt} bye=${short.bye.status}`);
  check('a destroyed room lets go of its stalled stream rather than waiting for TCP',
    short.probe === 200, `a later stream on the same key got ${short.probe}`);

  // THE CONTROL, and it is the whole evidence. Identical, except the linger is longer than
  // the window above waits in: this IS the pre-fix server, expressed as configuration. If
  // the gauge were released here too, the assertion above would print OK against a server
  // that never let go, which is exactly the state it exists to detect.
  const long = await arm(PORT + 24, 'PNND0002', 'PNND0004', 600_000);
  check('CONTROL: the long-linger arm seated, flooded and destroyed a room too',
    long.seats.ok && long.spareSeats.ok && long.pumped.sent === 400
    && !long.pumped.dropped && long.bye.status === 200,
    `seated=${long.seats.ok} flooded=${long.pumped.sent} droppedAt=${long.pumped.stoppedAt} bye=${long.bye.status}`);
  check('CONTROL: with the linger long the stream is still pinned, so the release above was the linger',
    long.probe === 429, `a later stream on the same key got ${long.probe}, expected 429`);
}

// ------------------------------------ the relay stamps the sender the token authorised
{
  // Sender identity otherwise rides only inside the sealed envelope, where the sender
  // wrote it. That envelope is sealed under k_sig, which every participant holds, so it
  // is forgeable by anyone in the room: one seat could seal a `pk` as another peer and
  // the victim would pin it forever, or seal a `sever` and end the victim's gate. This
  // server authorised the POST with a per-seat token, so it knows who really sent it.
  const P = PORT + 25;
  const ROOM = 'STMP0001';
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
  });

  const pr = makeJoinProof();
  const a = await request(P, 'POST', '/api/create', { roomId: ROOM, sessionMinutes: 10, joinProofHash: pr.hash });
  const b = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pr.proof });
  const c = await request(P, 'POST', '/api/join', { roomId: ROOM, joinProof: pr.proof });
  check('CONTROL: three seats for the impersonation probe',
    a.status === 200 && b.status === 200 && c.status === 200, `${a.status}/${b.status}/${c.status}`);

  const sc = openStream(P, ROOM, c.json.token);
  await sc.ready;
  await sc.wait('hello');

  // A seals an envelope that CLAIMS to be from B, and addresses it at C. The claim is a
  // plaintext decoy here because the server cannot see inside a real one, which is
  // precisely why the stamp has to come from the token instead.
  const seen = relaysAt(sc).length;
  const forged = await request(P, 'POST', '/api/relay', {
    roomId: ROOM, token: a.json.token, to: c.json.slotId,
    envelope: { n: 'NONCE', c: 'CIPHERTEXT', from: b.json.slotId, sfrom: b.json.slotId },
  });
  check('the forged relay is accepted, because the server cannot read what it carries',
    forged.status === 200, `${forged.status} ${forged.text}`);

  const got = (await relaysAfter(sc, seen, 4000))[0];
  check('CONTROL: the relay arrived, so the stamp assertions below are not vacuous',
    got !== undefined, JSON.stringify(relaysAt(sc).map((e) => e.data)));
  check('the stamp names the seat whose token authorised the POST',
    got?.data?.sfrom === a.json.slotId, `sfrom ${got?.data?.sfrom}, real sender ${a.json.slotId}`);
  // THE ASSERTION THAT MAKES IT WORTH ANYTHING. The sender put a competing sfrom in the
  // envelope, and the stamp did not follow it.
  check('and it does NOT follow a claim the sender put in the envelope',
    got?.data?.sfrom !== b.json.slotId, `sfrom ${got?.data?.sfrom} followed the claim of ${b.json.slotId}`);
  check('the sender\'s own claim is still carried through untouched, for the client to compare against',
    got?.data?.from === b.json.slotId, JSON.stringify(got?.data));

  // Byte-for-byte passthrough, on content chosen to break anything that reparses: the
  // moment this process can alter an envelope it is a participant in a conversation it is
  // supposed to be unable to read.
  const awkward = {
    n: 'AAAA-_09',
    c: `{"looks":"like json"} \\ " é 中 ${'z'.repeat(500)}`,
  };
  const seenB = relaysAt(sc).length;
  await request(P, 'POST', '/api/relay', {
    roomId: ROOM, token: b.json.token, to: c.json.slotId, envelope: awkward,
  });
  const through = (await relaysAfter(sc, seenB, 4000))[0];
  check('an envelope that looks like JSON and carries quotes and astral text survives byte for byte',
    through?.data?.n === awkward.n && through?.data?.c === awkward.c,
    JSON.stringify(through?.data));
  check('and the stamp on it is the second sender, not the first',
    through?.data?.sfrom === b.json.slotId, `${through?.data?.sfrom} vs ${b.json.slotId}`);

  sc.close();
  await srv.stop();
}

// ------------------------- an ignored forwarding header is reported, once, and never per request
{
  // WG_TRUST_PROXY=1 with a proxy whose address is not on the trusted list is a silent
  // failure: the header is correctly ignored, every client is keyed by the proxy's
  // address instead, they all share one rate-limit bucket, and any single client can lock
  // out everyone else. Nothing in a response or a log distinguished that from a
  // deployment with no proxy at all. The shipped compose file is bridge-networked and
  // does not set WG_TRUSTED_PROXIES, which is the case this exists for; that topology is
  // UNVERIFIED here, which is why the server counts rather than asserts.
  //
  // 127.0.0.2 is a loopback address that is NOT 127.0.0.1, so it stands in for a hop the
  // server has no reason to trust while still being reachable from this test.
  const HOP = '127.0.0.2';
  const fromHop = (port, headers) => new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, localAddress: HOP, method: 'GET', path: '/api/config', headers,
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
    req.setTimeout(6000, () => req.destroy(new Error('request timeout')));
    req.end();
  });
  const WARN = /WG_TRUST_PROXY=1 but a forwarding header arrived from a hop that is/;

  const P = PORT + 26;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_TRUST_PROXY: '1',
    WG_PUBLIC_GET_PER_WINDOW: '500', WG_API_PER_WINDOW: '500',
  });
  const status = await fromHop(P, { 'cf-connecting-ip': '203.0.113.7' });
  check('CONTROL: the request from an untrusted hop was actually served',
    status === 200, `status ${status}`);
  await delay(150);
  check('an ignored forwarding header is reported to the operator',
    WARN.test(srv.stderr()), JSON.stringify(srv.stderr().slice(-400)));

  // Never per request. This server keeps no request log by design, and a flood must not
  // be able to turn this into one.
  for (let i = 0; i < 8; i += 1) await fromHop(P, { 'x-forwarded-for': `198.51.100.${i}` });
  await delay(150);
  const times = (srv.stderr().match(new RegExp(WARN.source, 'g')) ?? []).length;
  check('and reported exactly once however many arrive', times === 1, `${times} occurrence(s) after 9 requests`);

  // It names no address and quotes no header value: the address of the hop is the very
  // thing this process is built not to write down.
  const line = srv.stderr();
  check('the warning carries neither an address nor the header value',
    !/203\.0\.113\.7/.test(line) && !/198\.51\.100\./.test(line) && !/127\.0\.0\.2/.test(line),
    JSON.stringify(line.slice(-400)));
  await srv.stop();

  // CONTROL 1: the hop IS trusted, so the header is honoured and there is nothing to say.
  const named = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_TRUST_PROXY: '1',
    WG_TRUSTED_PROXIES: HOP, WG_PUBLIC_GET_PER_WINDOW: '500', WG_API_PER_WINDOW: '500',
  });
  await fromHop(P, { 'cf-connecting-ip': '203.0.113.7' });
  await delay(150);
  check('CONTROL: naming the hop in WG_TRUSTED_PROXIES silences it, so this is not a constant warning',
    !WARN.test(named.stderr()), JSON.stringify(named.stderr().slice(-400)));
  await named.stop();

  // CONTROL 2: no forwarding header at all from the same untrusted hop. Ordinary direct
  // traffic must not trip it, or an operator learns to ignore the line.
  const quiet = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_TRUST_PROXY: '1',
    WG_PUBLIC_GET_PER_WINDOW: '500', WG_API_PER_WINDOW: '500',
  });
  await fromHop(P, {});
  await delay(150);
  check('CONTROL: an ordinary request with no forwarding header says nothing',
    !WARN.test(quiet.stderr()), JSON.stringify(quiet.stderr().slice(-400)));
  await quiet.stop();

  // CONTROL 3: the setting is off. Ignoring a forwarding header is then the configured
  // behaviour rather than a misconfiguration, and there is nothing to report.
  const off = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_TRUST_PROXY: '0',
    WG_PUBLIC_GET_PER_WINDOW: '500', WG_API_PER_WINDOW: '500',
  });
  await fromHop(P, { 'cf-connecting-ip': '203.0.113.7' });
  await delay(150);
  check('CONTROL: with WG_TRUST_PROXY off there is nothing to warn about',
    !WARN.test(off.stderr()), JSON.stringify(off.stderr().slice(-400)));
  await off.stop();
}

ok = summary('signalling');
process.exit(ok ? 0 : 1);
