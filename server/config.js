// Warp Gate configuration.
//
// Everything that a deployment might need to change lives here as data, so that
// changing it is a config edit and not a refactor. In particular `iceServers` is
// the hook that lets TURN be added later without touching peer.js (DESIGN.md 1.1).

import { env } from 'node:process';

const int = (v, d) => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : d;
};

const list = (v) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

// STUN URLs advertised to browsers. Deliberately empty by default: a public STUN
// server is a third party IP disclosure on the default path (DESIGN.md 1.2), so a
// deployment must opt in explicitly rather than inherit one silently.
const stunUrls = list(env.WG_STUN_URL);

export const config = {
  httpHost: env.WG_HTTP_HOST || '0.0.0.0',
  httpPort: int(env.WG_HTTP_PORT, 3095),

  // In-process RFC 5389 binding responder. Port 3478 is unavailable on the target
  // host (an unrelated service already publishes 3478 there), hence 3479.
  //
  // Opt-in. Defaulting this on gave anyone who ran the repo without the shipped compose
  // file a UDP service they never asked for. The shipped compose sets 0, which still
  // means off.
  stunEnabled: env.WG_STUN_ENABLED === '1',
  stunHost: env.WG_STUN_HOST || '0.0.0.0',
  stunPort: int(env.WG_STUN_PORT, 3479),

  // Served to the client at GET /api/config.
  // TURN would be appended here as { urls, username, credential }. Not in v1.
  iceServers: stunUrls.length ? [{ urls: stunUrls }] : [],

  ttl: {
    // Short and aggressive while nobody has joined.
    unclaimedMs: int(env.WG_UNCLAIMED_TTL_MS, 5 * 60 * 1000),
    // How long a room with nobody attached survives before being reaped. This must be
    // comfortably longer than a page reload takes, or refreshing either device would
    // destroy the gate; and short enough that a closed tab frees its room promptly.
    emptyGraceMs: int(env.WG_EMPTY_GRACE_MS, 45_000),
    // Once paired, the room survives so ICE restart on a network change can be
    // signalled (DESIGN.md 1.6). The chosen value is an IDLE timeout, not an absolute
    // one: while both devices are attached the clock is pushed forward, so a long file
    // transfer or a long conversation is never cut off mid-way.
    allowedSessionMinutes: [10, 30, 60],
    // Backstop so a pair of forgotten tabs cannot hold a room forever.
    maxSessionMs: int(env.WG_MAX_SESSION_MS, 24 * 60 * 60 * 1000),
    defaultSessionMinutes: int(env.WG_DEFAULT_SESSION_MIN, 30),
  },

  limits: {
    maxRooms: int(env.WG_MAX_ROOMS, 200),
    // How many participants one gate seats. Every pair runs its own peer connection, its
    // own ECDH and its own frame counters, so the connection count is O(N^2): six is
    // fifteen links, twenty would be a hundred and ninety. The cap is what makes a full
    // mesh the right shape here, so raising it is not a free knob.
    maxParticipants: int(env.WG_MAX_PARTICIPANTS, 6),
    maxRelayBytes: int(env.WG_MAX_RELAY_BYTES, 64 * 1024),
    maxBodyBytes: int(env.WG_MAX_BODY_BYTES, 96 * 1024),
    // Only /api/relay carries an envelope. Everything else posts a room id and a token,
    // so it gets a cap that an unauthenticated caller cannot use to force a large parse.
    maxSmallBodyBytes: int(env.WG_MAX_SMALL_BODY_BYTES, 2 * 1024),
    createPerWindow: int(env.WG_CREATE_PER_WINDOW, 10),
    joinPerWindow: int(env.WG_JOIN_PER_WINDOW, 30),
    windowMs: int(env.WG_RATE_WINDOW_MS, 5 * 60 * 1000),
    relayPerMinutePerRoom: int(env.WG_RELAY_PER_MIN, 200),
    streamsPerKey: int(env.WG_STREAMS_PER_KEY, 4),
    stunPerSecondPerIp: int(env.WG_STUN_PER_SEC, 20),
    // The per-source STUN key is a UDP source address and therefore forgeable, so a
    // global ceiling is the only limit an attacker cannot rotate around.
    stunPerSecondGlobal: int(env.WG_STUN_PER_SEC_GLOBAL, 2000),

    // Window shared by every API limiter below. Shorter than windowMs because these
    // guard cheap reads, where a long window would strand an ordinary client.
    apiWindowMs: int(env.WG_API_WINDOW_MS, 60 * 1000),
    // Backstop across all routes. Generous: it exists to stop automation, not clients.
    apiPerWindow: int(env.WG_API_PER_WINDOW, 600),
    // The unauthenticated GETs. Nothing legitimate fetches these in a loop: the page
    // reads /api/config once and /api/room only on resume.
    publicGetPerWindow: int(env.WG_PUBLIC_GET_PER_WINDOW, 30),
    // Charged only when a request is refused. A client that keeps being refused is
    // probing (the 404/403 split on /api/room is a room-existence oracle); a working
    // client never touches this budget, so it can be far tighter than the others.
    rejectPerWindow: int(env.WG_REJECT_PER_WINDOW, 30),
    // Per rate-limit bucket. Bucket entries are per-boot memory that an unauthenticated
    // caller grows one key at a time, and they live for a whole window regardless of the
    // sweeper. Measured at 116 B/entry: this cap times the number of buckets has to stay
    // small next to the 128 MiB container.
    maxBucketEntries: int(env.WG_MAX_BUCKET_ENTRIES, 10_000),
    // Entries examined per sweep call. A full pass over large maps blocks the event
    // loop (measured: 578 ms at 800k entries), so a pass is spread over several calls.
    sweepSlice: int(env.WG_SWEEP_SLICE, 2_000),
  },

  sweepIntervalMs: int(env.WG_SWEEP_MS, 10_000),
  // Must stay well under Cloudflare's verified 100s idle timeout on Free/Pro.
  heartbeatMs: int(env.WG_HEARTBEAT_MS, 25_000),

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
};
