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
    // Once paired, the room survives so ICE restart on a network change can be
    // signalled (DESIGN.md 1.6).
    allowedSessionMinutes: [10, 30, 60],
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

  sweepIntervalMs: 10_000,
  // Must stay well under Cloudflare's verified 100s idle timeout on Free/Pro.
  heartbeatMs: int(env.WG_HEARTBEAT_MS, 25_000),

  // Only trust CF-Connecting-IP / X-Forwarded-For when actually behind a proxy we
  // control. Trusting it unconditionally would let anyone forge their rate-limit key.
  trustProxy: env.WG_TRUST_PROXY === '1',
};
