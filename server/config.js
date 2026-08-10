// Warp Gate configuration.
//
// Everything that a deployment might need to change lives here as data, so that
// changing it is a config edit and not a refactor. In particular `iceServers` is
// the hook that lets TURN be added later without touching peer.js (DESIGN.md 1.1).

import { env } from 'node:process';

/**
 * Refuse to boot, naming the variable.
 *
 * A misconfigured operator has to learn at start rather than from a user's blank page.
 * The alternative considered was falling back to the default on a bad value, and it was
 * rejected: WG_HTTP_PORT=0x1F silently binding 3095 and WG_SUGGESTIONS_MAX_BYTES=1e9
 * silently meaning "one byte" are both indistinguishable from a working deployment until
 * something breaks in a way that does not name its own cause. The value is printed
 * through JSON.stringify so a control character in it cannot repaint the operator's
 * terminal, and none of these variables ever holds a secret.
 */
const refuse = (name, value, why) => {
  process.stderr.write(`warp-gate config: ${name}=${JSON.stringify(value)} is not ${why}\n`);
  process.stderr.write('warp-gate config: refusing to start rather than running on a value that was not meant\n');
  process.exit(1);
};

// Anything that is not a plain decimal integer. Number.parseInt is deliberately not
// trusted here: it stops at the first character it does not understand, so '1e9' parses
// as 1, '0x1F' as 0 and '10x' as 10, and every one of those is a small wrong number
// rather than an error. Measured, all three, before this guard existed.
const INT_RE = /^-?\d+$/;

const int = (name, v, d) => {
  if (v === undefined || v === null || String(v).trim() === '') return d;
  const raw = String(v).trim();
  if (!INT_RE.test(raw)) refuse(name, v, 'a whole number');
  const n = Number(raw);
  if (!Number.isSafeInteger(n)) refuse(name, v, 'a number this process can represent exactly');
  return n;
};

const list = (v) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

/**
 * A CSP source expression narrow enough that it cannot become a second directive.
 *
 * Scheme, host and optional port. No path, no whitespace, no semicolon, no comma, no
 * quote and no control character, because every one of those changes the meaning of the
 * header rather than the origin in it: a CRLF makes res.setHeader throw ERR_INVALID_CHAR
 * inside an fs.stat callback (asynchronously, so nothing catches it), and a semicolon
 * injects a whole directive that was never in CSP_DIRECTIVES.
 */
const AD_ORIGIN_RE = /^https?:\/\/(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/i;

// STUN URLs advertised to browsers. Deliberately empty by default: a public STUN
// server is a third party IP disclosure on the default path (DESIGN.md 1.2), so a
// deployment must opt in explicitly rather than inherit one silently.
const stunUrls = list(env.WG_STUN_URL);

// Origins the LANDING document alone is allowed to reach, for a sponsor or ad slot.
// Empty by default, and empty means the landing gets byte-identical headers to the
// gate: opting in is an explicit act by an operator, never an inherited default.
//
// This is the entire reason index.html and app.html are separate documents. A gate
// holds a decryption key in the same heap as every script the page loaded, so no
// value of this variable may ever apply to app.html. server/index.js enforces that
// by matching the resolved filename, not the request path.
//
// Validated here and not at first request. The value is interpolated into a header that
// is only ever set inside an fs.stat callback, so a bad one used to surface as an
// asynchronous throw with no uncaughtException handler anywhere in server/: the process
// died on the first GET / and the operator's evidence was a blank page.
const adOrigins = list(env.WG_AD_ORIGINS);
for (const origin of adOrigins) {
  if (!AD_ORIGIN_RE.test(origin)) {
    refuse('WG_AD_ORIGINS', origin, 'an origin (scheme://host[:port], nothing else)');
  }
}

export const config = {
  adOrigins,

  httpHost: env.WG_HTTP_HOST || '0.0.0.0',
  httpPort: int('WG_HTTP_PORT', env.WG_HTTP_PORT, 3095),

  // In-process RFC 5389 binding responder. Port 3478 is unavailable on the target
  // host (a dead docker publish owned by another service), hence 3479.
  //
  // Opt-in. Defaulting this on gave anyone who ran the repo without the shipped compose
  // file a UDP service they never asked for. The shipped compose sets 0, which still
  // means off.
  stunEnabled: env.WG_STUN_ENABLED === '1',
  stunHost: env.WG_STUN_HOST || '0.0.0.0',
  stunPort: int('WG_STUN_PORT', env.WG_STUN_PORT, 3479),

  // Served to the client at GET /api/config.
  // TURN would be appended here as { urls, username, credential }. Not in v1.
  iceServers: stunUrls.length ? [{ urls: stunUrls }] : [],

  ttl: {
    // Short and aggressive while nobody has joined.
    unclaimedMs: int('WG_UNCLAIMED_TTL_MS', env.WG_UNCLAIMED_TTL_MS, 5 * 60 * 1000),
    // How long a room with nobody attached survives before being reaped. This must be
    // comfortably longer than a page reload takes, or refreshing either device would
    // destroy the gate; and short enough that a closed tab frees its room promptly.
    emptyGraceMs: int('WG_EMPTY_GRACE_MS', env.WG_EMPTY_GRACE_MS, 45_000),
    // Once paired, the room survives so ICE restart on a network change can be
    // signalled (DESIGN.md 1.6). The chosen value is an IDLE timeout, not an absolute
    // one: while both devices are attached the clock is pushed forward, so a long file
    // transfer or a long conversation is never cut off mid-way.
    allowedSessionMinutes: [10, 30, 60],
    // Backstop so a pair of forgotten tabs cannot hold a room forever.
    maxSessionMs: int('WG_MAX_SESSION_MS', env.WG_MAX_SESSION_MS, 24 * 60 * 60 * 1000),
    defaultSessionMinutes: int('WG_DEFAULT_SESSION_MIN', env.WG_DEFAULT_SESSION_MIN, 30),
  },

  limits: {
    maxRooms: int('WG_MAX_ROOMS', env.WG_MAX_ROOMS, 200),
    // How many participants one gate seats. Every pair runs its own peer connection, its
    // own ECDH and its own frame counters, so the connection count is O(N^2): six is
    // fifteen links, twenty would be a hundred and ninety. The cap is what makes a full
    // mesh the right shape here, so raising it is not a free knob.
    maxParticipants: int('WG_MAX_PARTICIPANTS', env.WG_MAX_PARTICIPANTS, 6),
    maxRelayBytes: int('WG_MAX_RELAY_BYTES', env.WG_MAX_RELAY_BYTES, 64 * 1024),
    maxBodyBytes: int('WG_MAX_BODY_BYTES', env.WG_MAX_BODY_BYTES, 96 * 1024),
    // Only /api/relay carries an envelope. Everything else posts a room id and a token,
    // so it gets a cap that an unauthenticated caller cannot use to force a large parse.
    maxSmallBodyBytes: int('WG_MAX_SMALL_BODY_BYTES', env.WG_MAX_SMALL_BODY_BYTES, 2 * 1024),
    createPerWindow: int('WG_CREATE_PER_WINDOW', env.WG_CREATE_PER_WINDOW, 10),
    joinPerWindow: int('WG_JOIN_PER_WINDOW', env.WG_JOIN_PER_WINDOW, 30),
    windowMs: int('WG_RATE_WINDOW_MS', env.WG_RATE_WINDOW_MS, 5 * 60 * 1000),
    relayPerMinutePerRoom: int('WG_RELAY_PER_MIN', env.WG_RELAY_PER_MIN, 200),
    streamsPerKey: int('WG_STREAMS_PER_KEY', env.WG_STREAMS_PER_KEY, 4),

    // Queued-but-unflushed SSE bytes one stream may hold before it is called a dead
    // reader. This used to be a hard-coded 1 MiB, which is 16 times the relay cap for no
    // reason: one maxRelayBytes envelope plus its framing is the most a live reader is
    // ever legitimately behind by, and 256 KiB is that with room for a second in flight.
    maxStreamBacklogBytes: int('WG_MAX_STREAM_BACKLOG_BYTES', env.WG_MAX_STREAM_BACKLOG_BYTES, 256 * 1024),
    // ...and the bound that actually matters, because the per-stream figure multiplies.
    // At maxRooms 200 and maxParticipants 6 there are 1,200 possible streams, so a
    // per-stream cap alone permits their sum, which was 1.2 GB against a 128 MB
    // container. Attack: hold two seats, stall one stream at a zero TCP window, and POST
    // maxRelayBytes envelopes at the stalled seat. This is the ceiling on the sum of
    // every stream's backlog in the process, and it is what a mem_limit is sized against.
    maxTotalBacklogBytes: int('WG_MAX_TOTAL_BACKLOG_BYTES', env.WG_MAX_TOTAL_BACKLOG_BYTES, 8 * 1024 * 1024),
    stunPerSecondPerIp: int('WG_STUN_PER_SEC', env.WG_STUN_PER_SEC, 20),
    // The per-source STUN key is a UDP source address and therefore forgeable, so a
    // global ceiling is the only limit an attacker cannot rotate around.
    stunPerSecondGlobal: int('WG_STUN_PER_SEC_GLOBAL', env.WG_STUN_PER_SEC_GLOBAL, 2000),

    // Window shared by every API limiter below. Shorter than windowMs because these
    // guard cheap reads, where a long window would strand an ordinary client.
    apiWindowMs: int('WG_API_WINDOW_MS', env.WG_API_WINDOW_MS, 60 * 1000),
    // Backstop across all routes. Generous: it exists to stop automation, not clients.
    apiPerWindow: int('WG_API_PER_WINDOW', env.WG_API_PER_WINDOW, 600),
    // The unauthenticated GETs. Nothing legitimate fetches these in a loop: the page
    // reads /api/config once and /api/room only on resume.
    publicGetPerWindow: int('WG_PUBLIC_GET_PER_WINDOW', env.WG_PUBLIC_GET_PER_WINDOW, 30),
    // Charged only when a request is refused. A client that keeps being refused is
    // probing (the 404/403 split on /api/room is a room-existence oracle); a working
    // client never touches this budget, so it can be far tighter than the others.
    rejectPerWindow: int('WG_REJECT_PER_WINDOW', env.WG_REJECT_PER_WINDOW, 30),
    // Per rate-limit bucket. Bucket entries are per-boot memory that an unauthenticated
    // caller grows one key at a time, and they live for a whole window regardless of the
    // sweeper. Measured at 116 B/entry: this cap times the number of buckets has to stay
    // small next to the 128 MiB container.
    maxBucketEntries: int('WG_MAX_BUCKET_ENTRIES', env.WG_MAX_BUCKET_ENTRIES, 10_000),
    // Entries examined per sweep call. A full pass over large maps blocks the event
    // loop (measured: 578 ms at 800k entries), so a pass is spread over several calls.
    sweepSlice: int('WG_SWEEP_SLICE', env.WG_SWEEP_SLICE, 2_000),
  },

  // How long a destroyed room's streams are given to receive their `closed` event before
  // the socket is destroyed outright. res.end() only queues a FIN behind whatever the
  // peer has not read, so a reader stalled at a zero window held the socket, and its
  // entry in the per-key stream counter, until TCP gave up: a peer sending window probes
  // can defer that indefinitely, and the 1 MiB guard cannot fire on a slot whose res has
  // already been nulled. Long enough that a healthy client always gets the event.
  destroyLingerMs: int('WG_DESTROY_LINGER_MS', env.WG_DESTROY_LINGER_MS, 1_500),

  sweepIntervalMs: int('WG_SWEEP_MS', env.WG_SWEEP_MS, 10_000),
  // Must stay well under Cloudflare's verified 100s idle timeout on Free/Pro.
  heartbeatMs: int('WG_HEARTBEAT_MS', env.WG_HEARTBEAT_MS, 25_000),

  // Only trust CF-Connecting-IP / X-Forwarded-For when actually behind a proxy we
  // control. Trusting it unconditionally would let anyone forge their rate-limit key.
  //
  // The inverse is just as bad once a proxy IS in front: every request then arrives
  // from the proxy's address, so all users share one rate-limit bucket and any single
  // client can lock out everyone else. Behind cloudflared this must be on.
  trustProxy: env.WG_TRUST_PROXY === '1',

  // Which peer addresses may set those headers. Trusting the header without checking
  // who sent it means whoever can reach the port owns the rate-limit key space: a
  // rotating CF-Connecting-IP gets a fresh budget on every request. Loopback is always
  // trusted (cloudflared reaches this process at 127.0.0.1); anything else has to be
  // named here. Comma separated, e.g. "10.0.0.4,10.0.0.5".
  trustedProxies: list(env.WG_TRUSTED_PROXIES),

  // Send HSTS. Only enable where TLS actually terminates in front of this process.
  hsts: env.WG_HSTS === '1',

  // Warp Gate is AGPL-3.0. Section 13 obliges an operator to offer the corresponding
  // source to users who interact with it over a network, which is every user here. Set
  // this to wherever your copy of the source lives, especially if you modified it.
  sourceUrl: env.WG_SOURCE_URL || '',

  // The suggestion box: one append-only text file, and the only thing on this server that
  // deliberately keeps something a user typed.
  //
  // OFF unless a path is set, and that is the point. Every other byte this process holds
  // is in memory and gone when a gate expires; a file on disk is a different promise, so
  // an operator has to make it on purpose. When it is off /api/suggest 404s and the page
  // does not offer the box at all, rather than offering it and dropping what it collects.
  suggestions: {
    // Absolute, or relative to the working directory. The directory must already exist:
    // creating it here would let a typo silently start a second, invisible store.
    path: env.WG_SUGGESTIONS_PATH || '',
    // Refuse rather than rotate once the file reaches this. Rotating would delete
    // somebody's suggestion to make room for somebody else's, and doing that quietly is
    // worse than saying "full".
    //
    // ~1 MiB is about 1,700 suggestions of ordinary ASCII, and at least ~800 even if
    // every one of them is at maxTextBytes. That second figure is the one that bounds
    // this: the character cap counts CODE POINTS and the file cap counts BYTES, so
    // before maxTextBytes existed, 600 emoji was 2,444 bytes and 429 submissions filled
    // the store rather than the ~1,700 this comment used to claim on its own.
    maxBytes: int('WG_SUGGESTIONS_MAX_BYTES', env.WG_SUGGESTIONS_MAX_BYTES, 1024 * 1024),
    // Per suggestion. Long enough for a paragraph, short enough that the file is not a
    // useful place to stash data.
    maxChars: int('WG_SUGGESTIONS_MAX_CHARS', env.WG_SUGGESTIONS_MAX_CHARS, 600),
    // The same cap measured in the unit the file is measured in, so the two agree. Two
    // bytes per allowed code point: 600 characters of ASCII, of Latin-1 or of Greek all
    // still fit, and a submission made entirely of astral characters is refused at the
    // point where it would otherwise cost four times what it claims.
    maxTextBytes: int('WG_SUGGESTIONS_MAX_TEXT_BYTES', env.WG_SUGGESTIONS_MAX_TEXT_BYTES, 1200),
    // Per rate-limit key per window (the shared api window, 60 s by default). A person
    // with an idea sends one; a script sends thousands.
    perWindow: int('WG_SUGGESTIONS_PER_WINDOW', env.WG_SUGGESTIONS_PER_WINDOW, 3),
  },
};
