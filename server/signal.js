// The signalling API. Eight routes, and none of them can read what they carry.
//
// The one rule about `envelope` is: hand it to the other slot unmodified. The server
// does not parse it, cannot parse it, and does not know it contains SDP and ICE
// candidates (DESIGN.md 1.4).

import { config } from './config.js';
import { keyFor, allow, exhausted, streamOpen, streamClose } from './limits.js';
import { append as appendSuggestion, enabled as suggestionsEnabled } from './suggestions.js';
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

/**
 * How many times a forwarding header arrived from a hop we do not trust.
 *
 * This is the observable for the one failure mode WG_TRUST_PROXY has that looks exactly
 * like normal operation. When the setting is on and the header is IGNORED because its
 * sender is not on the trusted list, every client shares one rate-limit bucket keyed on
 * the proxy's address, and any single client can then lock out everyone else. Nothing in
 * a response or a log distinguished that from a deployment with no proxy at all.
 *
 * A bridge-networked container is the case that motivates it: host loopback traffic
 * reaches the service from the bridge gateway, not 127.0.0.1, so the loopback default
 * does not cover it and WG_TRUSTED_PROXIES has to name the gateway. That topology is
 * UNVERIFIED here, which is exactly why this counts rather than asserts.
 *
 * It is also the signature of a spoof attempt: someone who can reach the port directly,
 * sending a forwarding header they hope will be believed. Both readings want the same
 * thing, which is for an operator to find out.
 */
let untrustedForwardCount = 0;
let untrustedForwardWarned = false;

export function untrustedForwards() {
  return untrustedForwardCount;
}

function noteUntrustedForward() {
  untrustedForwardCount += 1;
  if (untrustedForwardWarned) return;
  untrustedForwardWarned = true;
  // Once per process, never per request: a flood must not be able to turn this into the
  // request log this server deliberately does not keep. Deliberately carries NEITHER the
  // header value NOR any address: the count is the finding, and the address of the hop is
  // the very thing this process is built not to write down.
  process.stderr.write('warp-gate WARNING: WG_TRUST_PROXY=1 but a forwarding header arrived from a hop that is\n');
  process.stderr.write('warp-gate          not trusted, so it was ignored and that client was keyed by its peer\n');
  process.stderr.write('warp-gate          address. If a proxy really is in front, name its address in\n');
  process.stderr.write('warp-gate          WG_TRUSTED_PROXIES or every client will share one rate-limit bucket.\n');
  process.stderr.write('warp-gate          If one is not, somebody is trying to forge a rate-limit key.\n');
  process.stderr.write('warp-gate          Reported once per process.\n');
}

const hasForwardedHeader = (req) => (
  typeof req.headers['cf-connecting-ip'] === 'string'
  || typeof req.headers['x-forwarded-for'] === 'string'
);

export function clientIp(req) {
  const peer = req.socket.remoteAddress ?? 'unknown';
  // Who sent the header is checked before the header is read. A forwarding header is a
  // claim, and anyone who can reach this port can make it: without this gate a rotating
  // CF-Connecting-IP hands its sender a fresh rate-limit key on every request, which is
  // every limit in the process defeated. The loopback bind in the compose file is a
  // deployment detail, not a control, so the trust boundary is asserted here instead.
  if (!config.trustProxy || !trustedHop(peer)) {
    // Ignoring the header is the correct behaviour and it stays. What changes is that it
    // is no longer silent when the operator has asked for the opposite.
    if (config.trustProxy && hasForwardedHeader(req)) noteUntrustedForward();
    return peer;
  }

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

/**
 * The routes a LIVE gate runs on, and the only ones exempt from the reject budget.
 *
 * Exempt in both directions: a refusal on one is not charged to that budget, and an
 * exhausted budget does not refuse one. Each carries a per-seat capability token, so an
 * authorised caller here is not the prober the budget exists to make pay, and refusing
 * one of these does not slow an attacker down: it ends a gate that is in progress.
 *
 * The budget was a SINGLE bucket across every route, which made it a denial of service in
 * its own right. A page resuming an expired gate gets 404 no_room from /api/room through
 * nobody's fault, so thirty ordinary users holding stale links could spend the whole
 * budget for the window and take live /api/events reconnects and /api/relay down with it.
 * That compounds with a shared rate-limit key, which is what every client behind one
 * proxy has whenever WG_TRUST_PROXY is on but not effective.
 *
 * What still bounds these three: the shared api backstop (apiPerWindow, 600/min), the
 * per-key concurrent stream cap on /api/events, and the per-room relay budget. None of
 * those was ever this budget's job.
 */
const LIVE_ROUTES = new Set(['/api/events', '/api/relay', '/api/bye']);

/**
 * Which reject budget a route spends, so one route's refusals cannot refuse another.
 *
 * /api/room deliberately KEEPS a budget, because its 404/403 split is a room-existence
 * oracle and that is the thing the budget was written for. What changes is its blast
 * radius: it is now scoped to /api/room alone, so a caller who spends it probing for
 * rooms is refused on /api/room and nowhere else.
 *
 * A FIXED set of names. Deriving the bucket name from the pathname would let an
 * unauthenticated caller mint a new bucket per request by asking for /api/<random>, which
 * is unbounded memory growth keyed on attacker input: the exact shape maxBucketEntries
 * exists to bound inside one bucket.
 */
const REJECT_SCOPES = new Set([
  '/api/room', '/api/create', '/api/join', '/api/suggest', '/api/config', '/api/health',
]);

function rejectScope(pathname) {
  if (LIVE_ROUTES.has(pathname)) return null;
  return REJECT_SCOPES.has(pathname) ? `reject${pathname}` : 'reject:other';
}

const fail = (res, status, code) => {
  // Every refusal on a metered route is charged to that route's reject budget. It is only
  // charged here; the check runs once at the top of handleApi, where a request can still
  // be refused cheaply. res.wgKey and res.wgReject are how the per-request key and scope
  // reach this helper, and they are read, not stored.
  if (res.wgKey && res.wgReject) {
    allow(res.wgReject, res.wgKey, config.limits.rejectPerWindow, config.limits.apiWindowMs);
  }
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
  res.wgReject = rejectScope(url.pathname); // null on the token-bearing routes

  // Applies to every route. Previously only /api/create and /api/join were limited, so
  // /api/health, /api/config and /api/room were unmetered, and /api/relay and /api/bye
  // would parse a maxBodyBytes body from an unauthenticated caller as often as asked.
  if (!allow('api', key, config.limits.apiPerWindow, config.limits.apiWindowMs)) {
    return fail(res, 429, 'rate_limited');
  }
  // Checked before the route runs so that probing costs the prober, not this process.
  // Per route, and never on a route that authorises with a per-seat token: see
  // TOKEN_ROUTES above for why a single shared budget was itself a denial of service.
  if (res.wgReject && exhausted(res.wgReject, key, config.limits.rejectPerWindow)) {
    return fail(res, 429, 'rate_limited');
  }

  // A cross-site POST is refused before any body is read.
  //
  // Nothing here matches on Origin or on a token in the body, and readJson parses any
  // content type, so a hostile page posting text/plain is a SIMPLE request: no preflight,
  // and /api/create and /api/suggest are reachable as the visitor. Responses are not
  // readable cross-origin, since no CORS header is ever set, so the exposure is
  // write-only: burning a visitor's create budget, and posting suggestions as them.
  //
  // ABSENT means ALLOW, deliberately. Sec-Fetch-Site is sent by every current browser, so
  // absent means a non-browser client: curl, the project's own tools/, the test harness,
  // a monitoring probe. Treating absent as deny would break all of those to defend
  // against a browser that is not sending it, and this check is defence in depth rather
  // than the control that holds: per-seat capability tokens and a room secret that never
  // leaves the fragment are what actually protect a gate, and none of that depends on
  // this header. `same-site` is refused alongside `cross-site` because this application
  // is one origin: nothing it serves ever legitimately posts here from a sibling host.
  if (method === 'POST') {
    const site = req.headers['sec-fetch-site'];
    if (site === 'cross-site' || site === 'same-site') {
      return fail(res, 403, 'cross_site');
    }
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
      // Whether this deployment accepts suggestions. The page asks rather than assumes,
      // because offering a box that 404s collects nothing and says nothing.
      suggestions: suggestionsEnabled(),
    });
  }

  // The one route that deliberately keeps something. Off unless an operator set a path;
  // see server/suggestions.js for what is and is not written.
  if (url.pathname === '/api/suggest' && method === 'POST') {
    if (!suggestionsEnabled()) return fail(res, 404, 'not_found');
    // Its own bucket, and a tight one. The shared api limiter is 600/minute, which is
    // right for signalling and absurd for a box a human types into.
    if (!allow('suggest', key, config.suggestions.perWindow, config.limits.apiWindowMs)) {
      return fail(res, 429, 'rate_limited');
    }
    const body = await readJson(req, res, config.limits.maxSmallBodyBytes);
    if (!body) return fail(res, 400, 'bad_body');
    const out = await appendSuggestion(body.text);
    if (!out.ok && out.error !== 'store_full') {
      // detail carries a filesystem path and never leaves this process.
      if (out.detail) console.error(`[suggest] ${out.error}: ${out.detail}`);
      return fail(res, 400, out.error);
    }
    // A FULL store answers 204, exactly as an accepted one does.
    //
    // The 507/204 split was a fill-level oracle: anyone could poll the box and watch it
    // approach its cap, which is the same class of usage side channel the live room count
    // was removed from /api/health for. The operator still finds out, because
    // suggestions.js writes a rate-limited line to stderr when the store is full, and
    // that is somewhere they look and a stranger cannot read.
    //
    // 204 otherwise: there is nothing to say back, and an id or a count would be a way to
    // probe how many other people have written in.
    res.writeHead(204);
    return res.end();
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
    // characters and 2x on astral ones. Measured over the WHOLE serialized envelope, not
    // just n and c: every sibling key a sender adds is carried to the peer as well, so a
    // cap that skipped them bounded only the two keys an honest client sends, and the
    // real ceiling was the body cap. This serialization is for measurement alone; what is
    // delivered is still the parsed object, untouched.
    if (Buffer.byteLength(JSON.stringify(env)) > config.limits.maxRelayBytes) {
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

    // The AUTHENTICATED sender, stamped on the delivered event.
    //
    // Sender identity otherwise rides only inside the sealed envelope, where the sender
    // wrote it. That envelope is sealed under k_sig, which every participant in the room
    // holds, so it is unforgeable by the server and by anyone outside the room, and
    // forgeable by anyone inside it: one seat could seal a `pk` as another peer and the
    // victim would pin it forever, or seal a `sever` and end the victim's gate. This
    // server already knows who is really posting, because a per-seat token authorised the
    // POST, and it used to throw that knowledge away.
    //
    // `sfrom` is the slot id and nothing else: not the room, not the rate-limit key, not
    // an address, not a header. The client compares it against the `from` it decrypts and
    // drops the message on a mismatch. Neither half closes the forgery alone: the server
    // cannot forge the sealed body, and a participant cannot forge the stamp.
    //
    // The envelope is spread FIRST and the stamp written LAST, so a sender who puts an
    // `sfrom` of their own in the envelope overwrites nothing. `n` and `c` are carried
    // across byte for byte and are never parsed, re-parsed or re-serialised here: the
    // moment this process can alter an envelope it is a participant in a conversation it
    // is supposed to be unable to read.
    const delivered = sendTo(room, to, 'relay', { ...env, sfrom: slot });
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

    // Keyed by the seat the token authorised, never by address: every client behind one
    // NAT or proxy hop shares an address, and seats are bounded by maxRooms x maxParticipants.
    const streamKey = `${room.id}/${slot}`;
    if (!streamOpen(streamKey, config.limits.streamsPerKey)) return fail(res, 429, 'too_many_streams');

    // Only now, and not a moment earlier. An SSE stream is long lived by definition, so
    // its request and response timeouts have to be lifted; but index.js used to do that
    // keyed on the pathname alone, before the room or the token had been looked at, which
    // handed an unbounded timeout to an unauthenticated caller who merely named the path.
    // Here it happens after slotFor has returned a seat, so what is unbounded is an
    // authorised stream and nothing else.
    req.setTimeout(0);
    res.setTimeout(0);

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
      streamClose(streamKey);
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
