// In-memory room registry. This Map is the entirety of Warp Gate's persistent state.
// No database, no disk, no logs. A restart destroys every room, as intended.

import crypto from 'node:crypto';
import { config } from './config.js';

/**
 * room = {
 *   id, sessionMs, createdAt, expiresAt,
 *   a: slot, b: slot | null,
 *   relayCount, relayWindowStart
 * }
 * slot = { token, res: ServerResponse|null, graceTimer: Timeout|null, key: string }
 */
const rooms = new Map();

// The client derives its own room id from the room secret (room_id = HKDF(S, ...)),
// so the server accepts a client-chosen id. It must be exactly the shape we generate,
// or the id space could be polluted with long or ambiguous values.
const ROOM_ID_RE = /^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}$/;

export function validRoomId(id) {
  return typeof id === 'string' && ROOM_ID_RE.test(id);
}

const newToken = () => crypto.randomBytes(16).toString('base64url');

export function roomCount() {
  return rooms.size;
}

export class RoomError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export function createRoom(roomId, sessionMinutes, key, requiresPassword = false, now = Date.now()) {
  if (!validRoomId(roomId)) throw new RoomError(400, 'bad_room_id');
  if (rooms.size >= config.limits.maxRooms) throw new RoomError(503, 'capacity');
  if (rooms.has(roomId)) throw new RoomError(409, 'room_exists');

  const minutes = config.ttl.allowedSessionMinutes.includes(sessionMinutes)
    ? sessionMinutes
    : config.ttl.defaultSessionMinutes;

  const room = {
    id: roomId,
    // Server-visible only as a boolean, so a joiner can be prompted. It never sees
    // the password itself, which exists only in the two browsers.
    requiresPassword: Boolean(requiresPassword),
    sessionMs: minutes * 60 * 1000,
    createdAt: now,
    // Unclaimed rooms die fast. The clock is extended to the session TTL only once
    // a second participant actually joins (DESIGN.md 1.6).
    expiresAt: now + config.ttl.unclaimedMs,
    a: { token: newToken(), res: null, graceTimer: null, key },
    b: null,
    relayCount: 0,
    relayWindowStart: now,
    // A freshly created room has nobody attached yet; the creator attaches moments
    // later. Left null so the unclaimed TTL governs this window, not the grace.
    emptySince: null,
    // Hard limit regardless of activity, so a forgotten pair of tabs cannot pin a room.
    hardExpiresAt: now + config.ttl.maxSessionMs,
  };
  rooms.set(roomId, room);
  return {
    token: room.a.token, role: 'a', expiresAt: room.expiresAt,
    sessionMinutes: minutes, requiresPassword: room.requiresPassword,
  };
}

export function joinRoom(roomId, key, now = Date.now()) {
  if (!validRoomId(roomId)) throw new RoomError(400, 'bad_room_id');
  const room = rooms.get(roomId);
  if (!room) throw new RoomError(404, 'no_room');
  if (room.b) throw new RoomError(409, 'room_full');

  room.b = { token: newToken(), res: null, graceTimer: null, key };
  room.expiresAt = now + room.sessionMs;
  return {
    token: room.b.token, role: 'b', expiresAt: room.expiresAt,
    sessionMinutes: room.sessionMs / 60000, requiresPassword: room.requiresPassword,
  };
}

/** Constant-time token match. Returns 'a' | 'b' | null. */
export function slotFor(room, token) {
  if (typeof token !== 'string' || token.length === 0) return null;
  for (const role of ['a', 'b']) {
    const slot = room[role];
    // A retired slot has no token. Without this guard an empty stored token could be
    // matched by an empty supplied one, since both would be zero length.
    if (!slot || typeof slot.token !== 'string' || slot.token.length === 0) continue;
    const want = Buffer.from(slot.token);
    const got = Buffer.from(token);
    if (want.length === got.length && crypto.timingSafeEqual(want, got)) return role;
  }
  return null;
}

export function getRoom(roomId) {
  return rooms.get(roomId) ?? null;
}

const otherRole = (role) => (role === 'a' ? 'b' : 'a');

function writeEvent(res, event, data) {
  if (!res || res.writableEnded) return false;
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    return true;
  } catch (err) {
    // A dead socket is normal, not exceptional. Keep the reason, drop the stream.
    res.wgError = err.message;
    return false;
  }
}

export function sendTo(room, role, event, data) {
  return writeEvent(room[role]?.res, event, data);
}

/** Attach a live SSE response to a slot, replacing any previous one. */
export function attach(room, role, res) {
  const slot = room[role];
  if (slot.graceTimer) {
    clearTimeout(slot.graceTimer);
    slot.graceTimer = null;
  }
  if (slot.res && slot.res !== res && !slot.res.writableEnded) {
    // A second stream for the same slot: the first is stale (EventSource reconnect
    // after a network blip). Close it rather than leaking the response object.
    try { slot.res.end(); } catch (err) { void err; }
  }
  slot.res = res;
  // Somebody is here again, so the abandonment clock stops.
  room.emptySince = null;

  const peer = room[otherRole(role)];
  const peerPresent = Boolean(peer?.res && !peer.res.writableEnded);
  writeEvent(res, 'hello', { role, peerPresent, expiresAt: room.expiresAt });
  if (peerPresent) {
    // Both here now, so restart the idle clock immediately rather than waiting for the
    // next sweep.
    extendIfActive(room);
    // Tell the peer we are listening. The creator uses this to start the offer, so it
    // must fire on stream attachment and not merely on the join POST: otherwise the
    // offer can be relayed before the joiner is listening for it.
    sendTo(room, otherRole(role), 'peer-joined', {});
  }
}

/**
 * Detach a stream. A transient disconnect is not a departure: EventSource reconnects
 * on its own, so peer-left is only reported after a grace period.
 */
export function detach(room, role, res, graceMs = 8000) {
  const slot = room[role];
  if (!slot || slot.res !== res) return;
  slot.res = null;
  // Start the abandonment clock only when nobody at all is attached. A reload puts a
  // stream back within a second or so, which cancels it.
  const aGone = !room.a?.res;
  const bGone = !room.b || !room.b.res;
  if (aGone && bGone) room.emptySince = Date.now();
  if (slot.graceTimer) clearTimeout(slot.graceTimer);
  slot.graceTimer = setTimeout(() => {
    slot.graceTimer = null;
    if (!rooms.has(room.id) || room[role]?.res) return;
    sendTo(room, otherRole(role), 'peer-left', { reason: 'disconnected', expiresAt: room.expiresAt });
  }, graceMs);
  if (slot.graceTimer.unref) slot.graceTimer.unref();
}

/** Per-room relay budget. Rooms are short lived, so a fixed window is enough. */
export function relayAllowed(room, now = Date.now()) {
  if (now - room.relayWindowStart >= 60_000) {
    room.relayWindowStart = now;
    room.relayCount = 0;
  }
  if (room.relayCount >= config.limits.relayPerMinutePerRoom) return false;
  room.relayCount += 1;
  return true;
}

export function destroyRoom(roomId, reason, exceptRole = null) {
  const room = rooms.get(roomId);
  if (!room) return false;
  rooms.delete(roomId);
  for (const role of ['a', 'b']) {
    const slot = room[role];
    if (!slot) continue;
    if (slot.graceTimer) clearTimeout(slot.graceTimer);
    if (role !== exceptRole) sendTo(room, role, 'closed', { reason });
    if (slot.res && !slot.res.writableEnded) {
      try { slot.res.end(); } catch (err) { void err; }
    }
    // Drop the token so a late request cannot match a destroyed room's slot.
    slot.token = '';
    slot.res = null;
  }
  return true;
}

/** True when both participants currently have a live stream attached. */
export function bothPresent(room) {
  return Boolean(room.a?.res && !room.a.res.writableEnded
    && room.b?.res && !room.b.res.writableEnded);
}

/**
 * Push the expiry forward while both devices are still here.
 *
 * The selected TTL is an idle timeout, not a deadline. Cutting off a pair who are
 * actively using the gate, mid file transfer, is never the right behaviour: the point
 * of the timeout is to reap gates nobody is using. The hard limit still applies.
 */
export function extendIfActive(room, now = Date.now()) {
  if (!bothPresent(room)) return false;
  const wanted = Math.min(now + room.sessionMs, room.hardExpiresAt);
  if (wanted <= room.expiresAt) return false;
  room.expiresAt = wanted;
  return true;
}

/** Expiry sweep and heartbeat. Returns how many rooms were destroyed. */
export function sweep(now = Date.now()) {
  let destroyed = 0;
  for (const [id, room] of rooms) {
    // Keep an actively used gate alive before considering it for expiry.
    extendIfActive(room, now);
    if (room.hardExpiresAt <= now) {
      destroyRoom(id, 'ttl');
      destroyed += 1;
      continue;
    }
    if (room.expiresAt <= now) {
      destroyRoom(id, 'ttl');
      destroyed += 1;
      continue;
    }
    // Nobody has been attached for the grace period, so nobody is coming back.
    if (room.emptySince && now - room.emptySince > config.ttl.emptyGraceMs) {
      destroyRoom(id, 'abandoned');
      destroyed += 1;
    }
  }
  return destroyed;
}

export function heartbeat() {
  for (const room of rooms.values()) {
    for (const role of ['a', 'b']) {
      const res = room[role]?.res;
      if (res && !res.writableEnded) {
        // An SSE comment: keeps proxies from idling the connection out without
        // being delivered to the EventSource as an event.
        try { res.write(': hb\n\n'); } catch (err) { void err; }
      }
    }
  }
}

export function destroyAll(reason) {
  for (const id of [...rooms.keys()]) destroyRoom(id, reason);
}
