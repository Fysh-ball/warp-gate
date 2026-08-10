// The signalling API. Eight routes, and none of them can read what they carry.
//
// The one rule about `envelope` is: hand it to the other slot unmodified. The server
// does not parse it, cannot parse it, and does not know it contains SDP and ICE
// candidates (DESIGN.md 1.4).

import { config } from './config.js';
import { keyFor, allow, exhausted, streamOpen, streamClose } from './limits.js';
import {
  createRoom, joinRoom, getRoom, slotFor, attach, detach, hasSlot, describeSlot,
  relayAllowed, destroyRoom, sendTo, RoomError, validRoomId, maxParticipants,
} from './rooms.js';

const LOOPBACK = new Set(['127.0.0.1', '::1']);

/** Is the peer that actually opened this socket one whose forwarding headers we believe? */
function trustedHop(addr) {
  if (typeof addr !== 'string' || !addr.length) return false;
  const bare = addr.startsWith('::ffff:') ? addr.slice(7) : addr;
  return LOOPBACK.has(bare) || config.trustedProxies.includes(bare);
}

export function clientIp(req) {
  const peer = req.socket.remoteAddress ?? 'unknown';
  // Who sent the header is checked before the header is read. A forwarding header is a
  // claim, and anyone who can reach this port can make it: without this gate a rotating
  // CF-Connecting-IP hands its sender a fresh rate-limit key on every request, which is
  // every limit in the process defeated. The loopback bind in the compose file is a
  // deployment detail, not a control, so the trust boundary is asserted here instead.
  if (!config.trustProxy || !trustedHop(peer)) return peer;

  const cf = req.headers['cf-connecting-ip'];
  if (typeof cf === 'string' && cf.length) return cf.trim();
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) {
    // Rightmost hop, not leftmost: our proxy appends, so everything to the left of the
    // last entry was written by the client and can be rotated at will.
    const hops = xff.split(',').map((s) => s.trim()).filter(Boolean);
    if (hops.length) return hops[hops.length - 1];
  }
  return peer;
}

export function sendJson(res, status, body) {
  // readJson answers an oversize body itself and then hands its caller a null, which
  // would otherwise be reported a second time as 400 bad_body. First answer wins.
  if (res.headersSent) return;
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': payload.length,
    'cache-control': 'no-store',
  });
  res.end(payload);
}

const fail = (res, status, code) => {
  // Every refusal is charged to the reject budget. It is only charged here; the check
  // runs once at the top of handleApi, where a request can still be refused cheaply.
  // res.wgKey is how the per-request key reaches this helper, and it is read, not stored.
  if (res.wgKey) allow('reject', res.wgKey, config.limits.rejectPerWindow, config.limits.apiWindowMs);
  return sendJson(res, status, { error: code });
};

function readJson(req, res, maxBytes = config.limits.maxBodyBytes) {
  return new Promise((resolve) => {
    let size = 0;
    let chunks = [];
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      chunks = []; // release the buffered body as soon as the outcome is known
      resolve(value);
    };
    req.on('data', (chunk) => {
      if (done) return; // already answered or aborted: drop the rest on the floor
      size += chunk.length;
      if (size > maxBytes) {
        // Answer, then let the connection close on its own. Destroying the socket here
        // gives the caller an ECONNRESET and no status at all, so a deliberate refusal
        // is indistinguishable from a network fault; and a reset while the rest of the
        // body is still in the receive buffer makes the client discard the 413 as well.
        res.setHeader('connection', 'close');
        fail(res, 413, 'body_too_large');
        finish(null);
        req.resume(); // discard the remainder rather than buffer it
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      try {
        finish(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (err) {
        // The message is the caller's own malformed JSON described back to them. It is
        // answered with 400 and nothing here logs requests by design, so it is dropped.
        void err;
        finish(null);
      }
    });
    // 'end' and 'error' are not enough: a client that aborts mid-body emits neither, so
    // the promise never settled and the handler frame plus the buffered body stayed
    // resident for the life of the process.
    req.on('close', () => finish(null));
    req.on('error', () => finish(null)); // a broken request body has nothing to report
  });
}

/** Resolve a room + slot from a body or query, or send the error and return null. */
function authorize(res, roomId, token) {
  if (!validRoomId(roomId)) return fail(res, 400, 'bad_room_id'), null;
  const room = getRoom(roomId);
  if (!room) return fail(res, 404, 'no_room'), null;
  const slot = slotFor(room, token);
  if (!slot) return fail(res, 403, 'bad_token'), null;
  return { room, slot };
}

export async function handleApi(req, res, url) {
  const ip = clientIp(req);
  const key = keyFor(ip);
  const method = req.method;
  res.wgKey = key; // read by fail(), which has no other way to see the key

  // Applies to every route. Previously only /api/create and /api/join were limited, so
  // /api/health, /api/config and /api/room were unmetered, and /api/relay and /api/bye
  // would parse a maxBodyBytes body from an unauthenticated caller as often as asked.
  if (!allow('api', key, config.limits.apiPerWindow, config.limits.apiWindowMs)) {
    return fail(res, 429, 'rate_limited');
  }
  // Checked before the route runs so that probing costs the prober, not this process.
  if (exhausted('reject', key, config.limits.rejectPerWindow)) {
    return fail(res, 429, 'rate_limited');
  }

  if (url.pathname === '/api/config' && method === 'GET') {
    if (!allow('config', key, config.limits.publicGetPerWindow, config.limits.apiWindowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    return sendJson(res, 200, {
      iceServers: config.iceServers,
      sessionMinutes: config.ttl.allowedSessionMinutes,
      defaultSessionMinutes: config.ttl.defaultSessionMinutes,
      unclaimedTtlMs: config.ttl.unclaimedMs,
      heartbeatMs: config.heartbeatMs,
      maxRelayBytes: config.limits.maxRelayBytes,
      // How many devices one gate seats. The page needs it to say what "full" means.
      maxParticipants: maxParticipants(),
      sourceUrl: config.sourceUrl,
    });
  }

  if (url.pathname === '/api/health' && method === 'GET') {
    if (!allow('health', key, config.limits.publicGetPerWindow, config.limits.apiWindowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    // Liveness only. A live count of open gates is an attack progress meter and a
    // usage-pattern side channel on a tool whose premise is that the server learns
    // nothing; the container healthcheck only ever reads `ok`.
    return sendJson(res, 200, { ok: true });
  }

  // Lets a reloaded page find out whether its slot is still valid before deciding
  // between resuming and starting over. Without this a refresh is fatal: re-joining
  // a room you are already in is correctly refused as full.
  if (url.pathname === '/api/room' && method === 'GET') {
    // Tighter than the backstop because the 404/403 split below is a room-existence
    // oracle, and a page resuming a session asks this once, not in a loop.
    if (!allow('room', key, config.limits.publicGetPerWindow, config.limits.apiWindowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    const roomId = url.searchParams.get('room');
    const token = url.searchParams.get('token');
    if (!validRoomId(roomId)) return fail(res, 400, 'bad_room_id');
    const room = getRoom(roomId);
    if (!room) return fail(res, 404, 'no_room');
    const slot = slotFor(room, token);
    if (!slot) return fail(res, 403, 'bad_token');
    return sendJson(res, 200, {
      ...describeSlot(room, slot),
      expiresAt: room.expiresAt,
      requiresPassword: room.requiresPassword,
    });
  }

  if (url.pathname === '/api/create' && method === 'POST') {
    if (!allow('create', key, config.limits.createPerWindow, config.limits.windowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    const body = await readJson(req, res, config.limits.maxSmallBodyBytes);
    if (!body) return fail(res, 400, 'bad_body');
    try {
      // joinProofHash is H = SHA-256(J), where J = HKDF(S, "wg/v1/join") in the browser.
      // Held so that /api/join can require proof of knowledge of the room secret before
      // handing out slot B. It is a hash of a hash of S: it adds nothing this process
      // could use to read anything it relays.
      const out = createRoom(
        body.roomId, Number(body.sessionMinutes), key,
        body.requiresPassword === true,
        typeof body.joinProofHash === 'string' ? body.joinProofHash : null,
      );
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
    const body = await readJson(req, res, config.limits.maxSmallBodyBytes);
    if (!body) return fail(res, 400, 'bad_body');
    try {
      // joinProof is J itself. Hashed and compared against the stored H in constant time;
      // a room that never registered an H is not joinable, rather than open to everyone.
      const out = joinRoom(body.roomId, key, typeof body.joinProof === 'string' ? body.joinProof : null);
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
    const { room, slot } = found;

    const env = body.envelope;
    if (!env || typeof env.n !== 'string' || typeof env.c !== 'string') {
      return fail(res, 400, 'bad_envelope');
    }
    // Bytes, not UTF-16 code units: .length admits 1.5x the advertised cap on 3-byte
    // characters and 2x on astral ones, and bytes are both what /api/config advertises
    // and what actually gets written into the peer's socket.
    if (Buffer.byteLength(env.n) + Buffer.byteLength(env.c) > config.limits.maxRelayBytes) {
      return fail(res, 413, 'envelope_too_large');
    }

    // A relay is ADDRESSED. There is no fallback, no default target and no broadcast:
    // every one of those would hand one pair's handshake to the whole room, and a pair's
    // ECDH is only private to that pair because nobody else ever receives it. A missing,
    // malformed, self-addressed or unknown target is refused outright.
    const to = body.to;
    if (typeof to !== 'string' || to.length === 0 || to === slot) {
      return fail(res, 400, 'bad_target');
    }
    if (!hasSlot(room, to)) return fail(res, 404, 'no_peer');

    if (!relayAllowed(room)) return fail(res, 429, 'relay_rate_limited');

    const delivered = sendTo(room, to, 'relay', env);
    return sendJson(res, 200, { delivered });
  }

  if (url.pathname === '/api/bye' && method === 'POST') {
    const body = await readJson(req, res, config.limits.maxSmallBodyBytes);
    if (!body) return fail(res, 400, 'bad_body');
    const found = authorize(res, body.roomId, body.token);
    if (!found) return undefined;
    // The severing participant already knows; everybody else needs telling.
    destroyRoom(found.room.id, 'severed', found.slot);
    return sendJson(res, 200, { ok: true });
  }

  if (url.pathname === '/api/events' && method === 'GET') {
    const roomId = url.searchParams.get('room');
    const token = url.searchParams.get('token');
    if (!validRoomId(roomId)) return fail(res, 400, 'bad_room_id');
    const room = getRoom(roomId);
    if (!room) return fail(res, 404, 'no_room');
    const slot = slotFor(room, token);
    if (!slot) return fail(res, 403, 'bad_token');

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

    attach(room, slot, res);

    let closed = false;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      streamClose(key);
      detach(room, slot, res);
    };
    res.on('close', cleanup);
    // Nothing to report: a dead stream is indistinguishable from a closed tab, and the
    // only correct response to either is the same cleanup.
    res.on('error', () => cleanup());
    return undefined;
  }

  return fail(res, 404, 'not_found');
}
