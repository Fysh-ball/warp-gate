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
  // host (a dead docker publish owned by another service), hence 3479.
  stunEnabled: env.WG_STUN_ENABLED !== '0',
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
    maxRelayBytes: int(env.WG_MAX_RELAY_BYTES, 64 * 1024),
    maxBodyBytes: int(env.WG_MAX_BODY_BYTES, 96 * 1024),
    createPerWindow: int(env.WG_CREATE_PER_WINDOW, 10),
    joinPerWindow: int(env.WG_JOIN_PER_WINDOW, 30),
    windowMs: int(env.WG_RATE_WINDOW_MS, 5 * 60 * 1000),
    relayPerMinutePerRoom: int(env.WG_RELAY_PER_MIN, 200),
    streamsPerKey: int(env.WG_STREAMS_PER_KEY, 4),
    stunPerSecondPerIp: int(env.WG_STUN_PER_SEC, 20),
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

  // Send HSTS. Only enable where TLS actually terminates in front of this process.
  hsts: env.WG_HSTS === '1',

  // Warp Gate is AGPL-3.0. Section 13 obliges an operator to offer the corresponding
  // source to users who interact with it over a network, which is every user here. Set
  // this to wherever your copy of the source lives, especially if you modified it.
  sourceUrl: env.WG_SOURCE_URL || '',
};
