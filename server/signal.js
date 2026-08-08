// The signalling API. Six routes, and none of them can read what they carry.
//
// The one rule about `envelope` is: hand it to the other slot unmodified. The server
// does not parse it, cannot parse it, and does not know it contains SDP and ICE
// candidates (DESIGN.md 1.4).

import { config } from './config.js';
import { keyFor, allow, streamOpen, streamClose } from './limits.js';
import {
  createRoom, joinRoom, getRoom, slotFor, attach, detach,
  relayAllowed, destroyRoom, sendTo, roomCount, RoomError, validRoomId,
} from './rooms.js';

export function clientIp(req) {
  if (config.trustProxy) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.length) return cf;
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

export function sendJson(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': payload.length,
    'cache-control': 'no-store',
  });
  res.end(payload);
}

const fail = (res, status, code) => sendJson(res, status, { error: code });

function readJson(req, res) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > config.limits.maxBodyBytes) {
        finish(null);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      try {
        finish(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (err) {
        res.wgParseError = err.message;
        finish(null);
      }
    });
    req.on('error', (err) => {
      res.wgReadError = err.message;
      finish(null);
    });
  });
}

/** Resolve a room + slot from a body or query, or send the error and return null. */
function authorize(res, roomId, token) {
  if (!validRoomId(roomId)) return fail(res, 400, 'bad_room_id'), null;
  const room = getRoom(roomId);
  if (!room) return fail(res, 404, 'no_room'), null;
  const role = slotFor(room, token);
  if (!role) return fail(res, 403, 'bad_token'), null;
  return { room, role };
}

export async function handleApi(req, res, url) {
  const ip = clientIp(req);
  const key = keyFor(ip);
  const method = req.method;

  if (url.pathname === '/api/config' && method === 'GET') {
    return sendJson(res, 200, {
      iceServers: config.iceServers,
      sessionMinutes: config.ttl.allowedSessionMinutes,
      defaultSessionMinutes: config.ttl.defaultSessionMinutes,
      unclaimedTtlMs: config.ttl.unclaimedMs,
      heartbeatMs: config.heartbeatMs,
      maxRelayBytes: config.limits.maxRelayBytes,
    });
  }

  if (url.pathname === '/api/health' && method === 'GET') {
    // Deliberately contains no identifying information.
    return sendJson(res, 200, { ok: true, rooms: roomCount(), uptimeSec: Math.floor(process.uptime()) });
  }

  // Lets a reloaded page find out whether its slot is still valid before deciding
  // between resuming and starting over. Without this a refresh is fatal: re-joining
  // a room you are already in is correctly refused as full.
  if (url.pathname === '/api/room' && method === 'GET') {
    const roomId = url.searchParams.get('room');
    const token = url.searchParams.get('token');
    if (!validRoomId(roomId)) return fail(res, 400, 'bad_room_id');
    const room = getRoom(roomId);
    if (!room) return fail(res, 404, 'no_room');
    const role = slotFor(room, token);
    if (!role) return fail(res, 403, 'bad_token');
    const peer = role === 'a' ? room.b : room.a;
    return sendJson(res, 200, {
      role,
      expiresAt: room.expiresAt,
      peerPresent: Boolean(peer?.res && !peer.res.writableEnded),
    });
  }

  if (url.pathname === '/api/create' && method === 'POST') {
    if (!allow('create', key, config.limits.createPerWindow, config.limits.windowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    const body = await readJson(req, res);
    if (!body) return fail(res, 400, 'bad_body');
    try {
      const out = createRoom(body.roomId, Number(body.sessionMinutes), key);
      return sendJson(res, 200, out);
    } catch (err) {
      if (err instanceof RoomError) return fail(res, err.status, err.code);
      throw err;
    }
  }

  if (url.pathname === '/api/join' && method === 'POST') {
    if (!allow('join', key, config.limits.joinPerWindow, config.limits.windowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    const body = await readJson(req, res);
    if (!body) return fail(res, 400, 'bad_body');
    try {
      const out = joinRoom(body.roomId, key);
      return sendJson(res, 200, out);
    } catch (err) {
      if (err instanceof RoomError) return fail(res, err.status, err.code);
      throw err;
    }
  }

  if (url.pathname === '/api/relay' && method === 'POST') {
    const body = await readJson(req, res);
    if (!body) return fail(res, 400, 'bad_body');
    const found = authorize(res, body.roomId, body.token);
    if (!found) return undefined;
    const { room, role } = found;

    const env = body.envelope;
    if (!env || typeof env.n !== 'string' || typeof env.c !== 'string') {
      return fail(res, 400, 'bad_envelope');
    }
    if (env.n.length + env.c.length > config.limits.maxRelayBytes) {
      return fail(res, 413, 'envelope_too_large');
    }
    if (!relayAllowed(room)) return fail(res, 429, 'relay_rate_limited');

    const peer = role === 'a' ? 'b' : 'a';
    const delivered = sendTo(room, peer, 'relay', env);
    return sendJson(res, 200, { delivered });
  }

  if (url.pathname === '/api/bye' && method === 'POST') {
    const body = await readJson(req, res);
    if (!body) return fail(res, 400, 'bad_body');
    const found = authorize(res, body.roomId, body.token);
    if (!found) return undefined;
    // The severing peer already knows; only the other side needs telling.
    destroyRoom(found.room.id, 'severed', found.role);
    return sendJson(res, 200, { ok: true });
  }

  if (url.pathname === '/api/events' && method === 'GET') {
    const roomId = url.searchParams.get('room');
    const token = url.searchParams.get('token');
    if (!validRoomId(roomId)) return fail(res, 400, 'bad_room_id');
    const room = getRoom(roomId);
    if (!room) return fail(res, 404, 'no_room');
    const role = slotFor(room, token);
    if (!role) return fail(res, 403, 'bad_token');

    if (!streamOpen(key, config.limits.streamsPerKey)) return fail(res, 429, 'too_many_streams');

    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      // no-transform matters: it asks intermediaries not to buffer or recompress,
      // which is what would break SSE through a proxy.
      'cache-control': 'no-cache, no-store, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.flushHeaders?.();
    req.socket.setNoDelay(true);
    req.socket.setTimeout(0);

    attach(room, role, res);

    let closed = false;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      streamClose(key);
      detach(room, role, res);
    };
    res.on('close', cleanup);
    res.on('error', (err) => { res.wgStreamError = err.message; cleanup(); });
    return undefined;
  }

  return fail(res, 404, 'not_found');
}
