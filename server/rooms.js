// In-memory room registry. This Map is the entirety of Warp Gate's persistent state.
// No database, no disk, no logs. A restart destroys every room, as intended.

import crypto from 'node:crypto';
import { config } from './config.js';

/**
 * room = {
 *   id, sessionMs, createdAt, expiresAt,
 *   slots: Map<slotId, slot>,
 *   relayCount, relayWindowStart
 * }
 * slot = { id, role, token, res: ServerResponse|null, graceTimer: Timeout|null, key: string }
 *
 * A gate used to hold exactly two participants, `room.a` and `room.b`. It now holds a map
 * of slots keyed by a server-generated slot id, capped at config.limits.maxParticipants.
 * The slot id is ROUTING INFORMATION, not a secret: it is broadcast to every occupant so
 * they can address a relay at one another. The token is the secret, and it never leaves
 * the participant it was issued to.
 */
const rooms = new Map();

// A stream that cannot drain is a dead stream, not a buffer. Past this much queued but
// unflushed data the peer has stopped reading, and every relayed byte is unbounded
// server heap: at the relay cap one room grows faster than the container's memory limit.
const maxStreamBacklogBytes = 1024 * 1024;

/**
 * How far past the 24h hard cap an ACTIVELY USED gate may be pushed.
 *
 * The cap exists so a pair of forgotten tabs cannot pin a room forever, and removing it
 * would undo that. But it was an absolute deadline measured from creation, and a real
 * transfer can legitimately outlive it: 30 GB at 10 Mbps upstream is about 6.7 hours, at
 * 5 Mbps about 13, and that is before any stall, any overnight pause, or any reconnect.
 * Reaping a gate that is 90% through a 30 GB file because a clock ran out is the wrong
 * answer, and it is worse than the thing the cap protects against.
 *
 * So the 24h figure becomes the cap for a gate that is NOT being actively used, and a gate
 * with two or more devices attached may push it forward to this multiple of it. Still
 * bounded, and still tuneable through WG_MAX_SESSION_MS, so the DoS ceiling the audit
 * relies on holds: a room can never outlive createdAt + maxSessionMs * this factor.
 *
 * The server cannot see the data channel at all: a peer-to-peer transfer never touches it.
 * Two live SSE streams is therefore the strongest evidence of activity available here, and
 * this is deliberately honest about that rather than pretending to measure progress.
 */
const ACTIVE_EXTENSION_FACTOR = 3;

// How close to the absolute ceiling a room gets before its occupants are told, and how
// often they are told. A gate that is going to die mid-transfer must say so in advance
// rather than simply vanishing.
const EXPIRY_WARNING_MS = 15 * 60 * 1000;
const EXPIRY_WARNING_INTERVAL_MS = 60 * 1000;

// Rooms currently held per creator key, and the per-key ceiling. The global maxRooms cap
// alone is a denial-of-service: one client can take every room and lock everyone else out
// for the whole unclaimed TTL.
const roomsPerKey = new Map();
const maxRoomsPerKey = 5;

function releaseKey(key) {
  const held = roomsPerKey.get(key);
  if (!held) return;
  if (held > 1) roomsPerKey.set(key, held - 1);
  else roomsPerKey.delete(key);
}

// The client derives its own room id from the room secret (room_id = HKDF(S, ...)),
// so the server accepts a client-chosen id. It must be exactly the shape we generate,
// or the id space could be polluted with long or ambiguous values.
const ROOM_ID_RE = /^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}$/;

export function validRoomId(id) {
  return typeof id === 'string' && ROOM_ID_RE.test(id);
}

// The join proof. The browser derives J = HKDF(S, "wg/v1/join"); the creator registers
// H = SHA-256(J) here and a joiner must present J to take a slot. Without it the room id
// alone buys a slot, and the room id is server-visible on every request while S never
// leaves the browser: anyone who can watch or operate this process could squat a slot and
// lock a real participant out, even on a room that requires a password.
//
// It is ROOM level, not per participant: every occupant proves knowledge of the same room
// secret, which is exactly what admits them to the same gate. Nothing about widening a
// gate from two seats to six changes that.
//
// This teaches the server nothing it can decrypt with. H is a hash of a hash of S and J
// is a one-way derivation of S, so neither yields S, the signalling key or any session
// key. The server checks an equality it cannot invert.
const JOIN_PROOF_RE = /^[A-Za-z0-9_-]{22}$/; // 16 bytes, unpadded base64url
const JOIN_PROOF_HASH_RE = /^[A-Za-z0-9_-]{43}$/; // 32 bytes, unpadded base64url
const JOIN_PROOF_HASH_BYTES = 32;

/** Decode a registered H, or throw. Returns null only when none was supplied at all. */
function parseJoinProofHash(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || !JOIN_PROOF_HASH_RE.test(value)) {
    throw new RoomError(400, 'bad_join_proof');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== JOIN_PROOF_HASH_BYTES) throw new RoomError(400, 'bad_join_proof');
  return bytes;
}

/**
 * Constant-time check of a presented J against the room's registered H.
 *
 * Fails closed in every direction: a room with no H (which cannot happen through the
 * current create path) is not joinable at all, because an absent proof must never read as
 * "this room does not need one". Same comparison path as slotFor: length guard, then
 * timingSafeEqual, never a === on secret-derived bytes.
 */
function joinProofMatches(room, joinProof) {
  const want = room.joinProofHash;
  if (!Buffer.isBuffer(want) || want.length !== JOIN_PROOF_HASH_BYTES) return false;
  if (typeof joinProof !== 'string' || !JOIN_PROOF_RE.test(joinProof)) return false;
  const got = crypto.createHash('sha256').update(Buffer.from(joinProof, 'base64url')).digest();
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

const newToken = () => crypto.randomBytes(16).toString('base64url');

// 6 bytes, so 8 base64url characters. Short enough to render in a roster, wide enough
// that two slots in one room never collide by accident, and regenerated on collision
// anyway. Deliberately NOT derived from anything: it is published to the whole room.
const SLOT_ID_BYTES = 6;

function newSlotId(room) {
  for (;;) {
    const id = crypto.randomBytes(SLOT_ID_BYTES).toString('base64url');
    if (!room.slots.has(id)) return id;
  }
}

// A stable, human-readable seat label. The creator is 'a', the first joiner 'b', and so on,
// which is exactly what the two-party server reported. It is a label for people reading a
// roster or a log; it is NOT the direction constant in the key schedule any more. Each pair
// derives that from the two slot ids, because with a mesh there is no single 'a' side.
const ROLE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';

function nextRole(room) {
  const taken = new Set();
  for (const slot of room.slots.values()) taken.add(slot.role);
  for (const letter of ROLE_ALPHABET) if (!taken.has(letter)) return letter;
  return `s${room.slots.size}`;
}

/** Seat a participant. The caller has already checked the cap and the join proof. */
function seat(room, key) {
  const id = newSlotId(room);
  const slot = { id, role: nextRole(room), token: newToken(), res: null, graceTimer: null, key };
  room.slots.set(id, slot);
  return slot;
}

export class RoomError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

/** How many participants this deployment seats in one gate. */
export function maxParticipants() {
  const n = Number(config.limits.maxParticipants);
  return Number.isInteger(n) && n >= 2 ? n : 2;
}

export function createRoom(roomId, sessionMinutes, key, requiresPassword = false, joinProofHash = null, now = Date.now()) {
  if (!validRoomId(roomId)) throw new RoomError(400, 'bad_room_id');
  // Before the caps, so a malformed request is refused without spending anyone's quota.
  const proofHash = parseJoinProofHash(joinProofHash);
  // Checked before the global cap so one key exhausting its own allowance is reported as
  // its own fault, and can never present as the service being full. Its own code too:
  // "you personally hold too many gates" is a different instruction to the user than
  // "the service is throttling you", and only one of them is fixed by waiting.
  if ((roomsPerKey.get(key) ?? 0) >= maxRoomsPerKey) throw new RoomError(429, 'too_many_rooms');
  if (rooms.size >= config.limits.maxRooms) throw new RoomError(503, 'capacity');
  if (rooms.has(roomId)) throw new RoomError(409, 'room_exists');

  const minutes = config.ttl.allowedSessionMinutes.includes(sessionMinutes)
    ? sessionMinutes
    : config.ttl.defaultSessionMinutes;

  const room = {
    id: roomId,
    // Server-visible only as a boolean, so a joiner can be prompted. It never sees
    // the password itself, which exists only in the browsers.
    requiresPassword: Boolean(requiresPassword),
    // H = SHA-256(J), the only thing the server ever holds about the room secret.
    joinProofHash: proofHash,
    sessionMs: minutes * 60 * 1000,
    createdAt: now,
    // Unclaimed rooms die fast. The clock is extended to the session TTL only once
    // a second participant actually joins (DESIGN.md 1.6).
    expiresAt: now + config.ttl.unclaimedMs,
    slots: new Map(),
    relayCount: 0,
    relayWindowStart: now,
    // A freshly created room has nobody attached yet; the creator attaches moments
    // later. Left null so the unclaimed TTL governs this window, not the grace.
    emptySince: null,
    // Hard limit for a gate nobody is actively using, so a forgotten pair of tabs cannot
    // pin a room. Pushed forward by extendIfActive while two or more devices are attached,
    // but never past absoluteExpiresAt.
    hardExpiresAt: now + config.ttl.maxSessionMs,
    // The one deadline nothing can move. Everything else is an idle timeout.
    absoluteExpiresAt: now + config.ttl.maxSessionMs * ACTIVE_EXTENSION_FACTOR,
    // When the occupants were last warned that this room is about to end for good.
    warnedAt: 0,
    // Kept on the room, not read back off a slot, so the per-key ledger survives the
    // slot teardown that destroyRoom performs.
    ownerKey: key,
  };
  rooms.set(roomId, room);
  roomsPerKey.set(key, (roomsPerKey.get(key) ?? 0) + 1);
  const slot = seat(room, key);
  return {
    token: slot.token, slotId: slot.id, role: slot.role, expiresAt: room.expiresAt,
    sessionMinutes: minutes, requiresPassword: room.requiresPassword,
    maxParticipants: maxParticipants(),
  };
}

export function joinRoom(roomId, key, joinProof, now = Date.now()) {
  if (!validRoomId(roomId)) throw new RoomError(400, 'bad_room_id');
  const room = rooms.get(roomId);
  if (!room) throw new RoomError(404, 'no_room');
  // Before the fullness check, so a caller who cannot prove knowledge of the room secret
  // learns nothing about the room's occupancy either.
  if (!joinProofMatches(room, joinProof)) throw new RoomError(403, 'bad_join_proof');
  // "Full" now means at the cap rather than "there are already two of you". A slot that
  // has been seated is counted whether or not its stream is attached: it may be a device
  // reloading, and that device has a token it is entitled to come back with.
  if (room.slots.size >= maxParticipants()) throw new RoomError(409, 'room_full');

  const slot = seat(room, key);
  room.expiresAt = now + room.sessionMs;
  return {
    token: slot.token, slotId: slot.id, role: slot.role, expiresAt: room.expiresAt,
    sessionMinutes: room.sessionMs / 60000, requiresPassword: room.requiresPassword,
    maxParticipants: maxParticipants(),
  };
}

/**
 * Constant-time token match. Returns a slot id, or null.
 *
 * Every seated slot is compared, and the comparison is timingSafeEqual on equal-length
 * buffers, never a === on a secret. The empty-token guard is what stops a retired slot
 * (destroyRoom blanks the token) being matched by an empty supplied one, since both
 * would be zero length.
 */
export function slotFor(room, token) {
  if (typeof token !== 'string' || token.length === 0) return null;
  const got = Buffer.from(token);
  for (const slot of room.slots.values()) {
    if (!slot || typeof slot.token !== 'string' || slot.token.length === 0) continue;
    const want = Buffer.from(slot.token);
    if (want.length === got.length && crypto.timingSafeEqual(want, got)) return slot.id;
  }
  return null;
}

export function getRoom(roomId) {
  return rooms.get(roomId) ?? null;
}

/** Is this slot id one this room actually seats? */
export function hasSlot(room, slotId) {
  return typeof slotId === 'string' && slotId.length > 0 && room.slots.has(slotId);
}

const isLive = (slot) => Boolean(slot?.res && !slot.res.writableEnded);

/** How many participants currently have a live stream attached. */
function presentCount(room) {
  let n = 0;
  for (const slot of room.slots.values()) if (isLive(slot)) n += 1;
  return n;
}

/**
 * The roster as one participant sees it: everybody except themselves.
 *
 * `present` is what the page acts on. A seated but unattached slot is a device that has
 * taken a place and has not opened its stream yet (or is reloading), so it is listed but
 * not connected to; the `peer-joined` that follows its attach is what starts that link.
 */
function rosterFor(room, selfId) {
  const peers = [];
  for (const slot of room.slots.values()) {
    if (slot.id === selfId) continue;
    peers.push({ id: slot.id, role: slot.role, present: isLive(slot) });
  }
  return peers;
}

function writeChunk(res, chunk) {
  if (!res || res.writableEnded || res.destroyed) return false;
  if (res.writableLength > maxStreamBacklogBytes) {
    res.destroy();
    return false;
  }
  try {
    // write() returns false when the chunk had to be buffered, which is normal on a slow
    // link. It is only fatal once the backlog is past the cap: that peer is not draining
    // at all, so the stream is destroyed and its slot detached by the usual close path.
    if (!res.write(chunk) && res.writableLength > maxStreamBacklogBytes) {
      res.destroy();
      return false;
    }
    return true;
  } catch (err) {
    // A dead socket is normal, not exceptional. There is no one left to report it to, so
    // drop the stream rather than stashing a message nothing reads.
    void err;
    res.destroy();
    return false;
  }
}

function writeEvent(res, event, data) {
  return writeChunk(res, `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

/**
 * Deliver one event to ONE slot.
 *
 * There is deliberately no "send to everybody who is not the sender" helper for relay to
 * fall back on. A relay that broadcasts hands one pair's handshake to the whole room, and
 * a fallback path is exactly how that happens by accident.
 */
export function sendTo(room, slotId, event, data) {
  const slot = room.slots.get(slotId);
  if (!slot?.res) return false;
  if (writeEvent(slot.res, event, data)) return true;
  // The stream is gone. Detach it now so emptySince is set and the room is reaped on the
  // abandonment schedule rather than lingering until its TTL.
  detach(room, slotId, slot.res);
  return false;
}

/** Announce something to every attached participant except `exceptId`. */
function broadcast(room, exceptId, event, data) {
  for (const slot of [...room.slots.values()]) {
    if (slot.id === exceptId) continue;
    if (!slot.res) continue;
    sendTo(room, slot.id, event, data);
  }
}

function helloPayload(room, slotId, extra = {}) {
  const slot = room.slots.get(slotId);
  const peers = rosterFor(room, slotId);
  return {
    // The participant's own slot id. Everything the page does with the mesh hangs off
    // this: which links to open, which side of each pair offers, and where a relay goes.
    self: slotId,
    role: slot?.role ?? null,
    peers,
    maxParticipants: maxParticipants(),
    // Kept from the two-party protocol, and still exactly true: is anybody else here?
    peerPresent: peers.some((p) => p.present),
    expiresAt: room.expiresAt,
    // Both reported so the page can tell the user how long the gate has, and distinguish
    // "idle timeout you can push back by staying here" from "this is the end of it".
    hardExpiresAt: room.hardExpiresAt,
    absoluteExpiresAt: room.absoluteExpiresAt,
    ...extra,
  };
}

/** Attach a live SSE response to a slot, replacing any previous one. */
export function attach(room, slotId, res) {
  const slot = room.slots.get(slotId);
  if (!slot) return;
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

  // Somebody being here is itself the thing that keeps a claimed gate alive, so the clock
  // is pushed forward BEFORE the deadlines are reported: otherwise the first thing a
  // reconnecting device is told is the stale deadline it was about to be reaped on.
  extendIfActive(room);

  writeEvent(res, 'hello', helloPayload(room, slotId));

  if (presentCount(room) > 1) {
    // Two or more here now, so restart the idle clock immediately rather than waiting for
    // the next sweep.
    extendIfActive(room);
    // Tell everybody else we are listening. The side with the lexicographically smaller
    // slot id starts the offer, so this must fire on stream attachment and not merely on
    // the join POST: otherwise the offer can be relayed before we are listening for it.
    broadcast(room, slotId, 'peer-joined', { id: slotId, role: slot.role });
  }
}

/**
 * Detach a stream. A transient disconnect is not a departure: EventSource reconnects
 * on its own, so peer-left is only reported after a grace period.
 *
 * The slot itself SURVIVES. It still holds its token, so the device can come back to the
 * same seat after a reload, which is the whole reason a refresh is not fatal.
 */
export function detach(room, slotId, res, graceMs = 8000) {
  const slot = room.slots.get(slotId);
  if (!slot || slot.res !== res) return;
  slot.res = null;
  // Start the abandonment clock only when nobody at all is attached. A reload puts a
  // stream back within a second or so, which cancels it.
  if (presentCount(room) === 0) room.emptySince = Date.now();
  if (slot.graceTimer) clearTimeout(slot.graceTimer);
  slot.graceTimer = setTimeout(() => {
    slot.graceTimer = null;
    if (!rooms.has(room.id) || room.slots.get(slotId)?.res) return;
    broadcast(room, slotId, 'peer-left', {
      id: slotId, role: slot.role, reason: 'disconnected', expiresAt: room.expiresAt,
    });
  }, graceMs);
  if (slot.graceTimer.unref) slot.graceTimer.unref();
}

/**
 * Per-room relay budget. Rooms are short lived, so a fixed window is enough.
 *
 * Scaled by the number of LINKS a participant has, not left flat. A full mesh of six
 * runs fifteen handshakes over the same room budget, so a flat per-room ceiling tuned
 * for one pair would refuse ordinary ICE traffic on a full gate. At two participants the
 * budget is unchanged from the two-party server.
 */
export function relayAllowed(room, now = Date.now()) {
  if (now - room.relayWindowStart >= 60_000) {
    room.relayWindowStart = now;
    room.relayCount = 0;
  }
  const links = Math.max(1, room.slots.size - 1);
  if (room.relayCount >= config.limits.relayPerMinutePerRoom * links) return false;
  room.relayCount += 1;
  return true;
}

export function destroyRoom(roomId, reason, exceptSlot = null) {
  const room = rooms.get(roomId);
  if (!room) return false;
  rooms.delete(roomId);
  // Every destruction path (sever, sweep, shutdown) funnels through here, so the per-key
  // ledger cannot leak a count for a room that no longer exists.
  releaseKey(room.ownerKey);
  for (const slot of room.slots.values()) {
    if (slot.graceTimer) clearTimeout(slot.graceTimer);
    if (slot.id !== exceptSlot && slot.res) writeEvent(slot.res, 'closed', { reason });
    if (slot.res && !slot.res.writableEnded) {
      try { slot.res.end(); } catch (err) { void err; }
    }
    // Drop the token so a late request cannot match a destroyed room's slot.
    slot.token = '';
    slot.res = null;
  }
  return true;
}

/** True when two or more participants currently have a live stream attached. */
export function activelyPaired(room) {
  return presentCount(room) > 1;
}

/** True when at least one participant has a live stream attached. */
export function anyPresent(room) {
  return presentCount(room) > 0;
}

/** True once a second participant has taken a slot, whether or not it is attached now. */
export function isClaimed(room) {
  return room.slots.size >= 2;
}

/**
 * Push the expiry forward while the gate is still being used.
 *
 * The selected TTL is an idle timeout, not a deadline. Cutting off people who are actively
 * using the gate, mid file transfer, is never the right behaviour: the point of the
 * timeout is to reap gates nobody is using.
 *
 * ONE party present is enough for the idle clock. The rule once required TWO, so the exact
 * situation resuming exists for -- one device holding a half-received file while the other
 * reconnects from a train -- was also the situation in which the idle clock was allowed to
 * run out and destroy the room underneath it. A device that is sitting there attached,
 * waiting, is not an idle gate.
 *
 * Two clocks move, and they move on different evidence:
 *   expiresAt      the idle timeout. One attached party is enough.
 *   hardExpiresAt  the 24h cap. Only two or more attached parties move this, and only up
 *                  to absoluteExpiresAt, which nothing moves.
 *
 * An UNCLAIMED room is excluded from both: nobody has joined it, so its short unclaimed TTL
 * must govern, or a creator who opens a gate and walks away would hold it for a day.
 */
export function extendIfActive(room, now = Date.now()) {
  if (!isClaimed(room) || !anyPresent(room)) return false;
  let moved = false;

  // Two or more here means the gate is genuinely in use, so the 24h cap may be pushed
  // forward. Bounded by absoluteExpiresAt, stamped at creation and never recomputed.
  if (activelyPaired(room)) {
    const wantedHard = Math.min(now + config.ttl.maxSessionMs, room.absoluteExpiresAt);
    if (wantedHard > room.hardExpiresAt) {
      room.hardExpiresAt = wantedHard;
      moved = true;
    }
  }

  const wanted = Math.min(now + room.sessionMs, room.hardExpiresAt);
  if (wanted > room.expiresAt) {
    room.expiresAt = wanted;
    moved = true;
  }
  return moved;
}

/**
 * Warn a room's occupants that it is within sight of the deadline nothing can move.
 *
 * Sent as a repeat `hello`, which is the only push event the page already forwards, and
 * which it treats as idempotent. It carries the same three deadlines the first one did,
 * plus `expiring`, so the page can say how long is left and the user can decide whether to
 * start a fresh gate rather than discovering the answer when the transfer dies.
 */
export function warnIfEnding(room, now = Date.now()) {
  if (!anyPresent(room)) return false;
  if (room.absoluteExpiresAt - now > EXPIRY_WARNING_MS) return false;
  if (now - (room.warnedAt ?? 0) < EXPIRY_WARNING_INTERVAL_MS) return false;
  room.warnedAt = now;
  for (const slot of [...room.slots.values()]) {
    if (!slot.res) continue;
    sendTo(room, slot.id, 'hello', helloPayload(room, slot.id, { expiring: true }));
  }
  return true;
}

/** Expiry sweep and heartbeat. Returns how many rooms were destroyed. */
export function sweep(now = Date.now()) {
  let destroyed = 0;
  for (const [id, room] of rooms) {
    // Keep an actively used gate alive before considering it for expiry.
    extendIfActive(room, now);
    if (room.absoluteExpiresAt <= now) {
      // The one deadline that cannot be pushed. Distinct reason code so the page can say
      // what actually happened rather than "the gate expired", which for a gate that is
      // most of the way through a large file is not an adequate explanation.
      destroyRoom(id, 'ttl-hard');
      destroyed += 1;
      continue;
    }
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
    // Say so BEFORE it happens. A gate that vanishes mid-transfer with no warning is the
    // behaviour this whole change exists to remove.
    warnIfEnding(room, now);
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
    for (const slot of [...room.slots.values()]) {
      const res = slot.res;
      if (!res) continue;
      // An SSE comment: keeps proxies from idling the connection out without
      // being delivered to the EventSource as an event. A failed heartbeat is the
      // earliest proof a stream is dead, so act on it instead of discarding it.
      if (!writeChunk(res, ': hb\n\n')) detach(room, slot.id, res);
    }
  }
}

export function destroyAll(reason) {
  for (const id of [...rooms.keys()]) destroyRoom(id, reason);
}

/** Read-only view of a room's occupancy, for the resume route. */
export function describeSlot(room, slotId) {
  const slot = room.slots.get(slotId);
  const peers = rosterFor(room, slotId);
  return {
    self: slotId,
    role: slot?.role ?? null,
    peers,
    peerPresent: peers.some((p) => p.present),
    maxParticipants: maxParticipants(),
  };
}
