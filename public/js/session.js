// Session orchestration: the room, and the mesh of links inside it.
//
// A gate holds up to config.maxParticipants participants (six by default). Every PAIR of
// them runs its own RTCPeerConnection, its own ECDH, its own Channel and its own replay
// counters; link.js owns one of those pairs from key agreement to teardown. This file owns
// what is true of the ROOM: the secret, the signalling stream, the roster, and fanning
// chat, secrets and files out across every link.
//
// Full mesh with pairwise channels is O(N^2) connections, which is right for three to six
// people and wrong for twenty. The cap is what makes it acceptable, and it is the reason
// there is no group key here: each pair's keys stay private to that pair, and nobody
// forwards anybody else's traffic.
//
// The UI in app.js subscribes to events from here and never touches crypto directly.

import {
  deriveRoomId, deriveSignalKey, b64u, derivePasswordKey,
  deriveJoinProof, deriveJoinProofHash, SECRET_BYTES,
} from './crypto.js';
import { Signal } from './signal.js';
import { Link, STATE, readInboundRecord, dropInboundRecord } from './link.js';
import { formatBytes, fingerprintFile } from './transfer.js';

export { STATE };

const API_TIMEOUT_MS = 8000;

/**
 * POST to a room lifecycle route.
 *
 * /api/create and /api/join both carry a join proof derived from the room secret, which
 * the generic request helpers in signal.js do not model, so these two requests are built
 * here. Same error contract as those helpers: the server's `error` code becomes the
 * message, so app.js can map it to human copy.
 */
async function postRoom(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(API_TIMEOUT_MS),
  });
  const parsed = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(parsed.error ?? `${path} failed: http ${res.status}`);
  return parsed;
}

// Events a link raises that carry an object. They are forwarded with the originating
// peer stamped on them, so the UI can say which participant a message or a file came from.
const OBJECT_EVENTS = [
  'chat', 'secret', 'progress', 'diagnostics', 'holding', 'transfer-waiting',
  'file-offered', 'file-refused', 'file-accepted', 'file-accepted-local',
  'file-failed', 'file-stalled', 'file-resumed', 'file-reselect-needed',
  'file-reselect-refused', 'file-received', 'file-incoming', 'file-complete',
];

// Events a link raises that carry a bare string. Forwarded unchanged: app.js writes them
// into the diagnostic log, and rewriting them per peer would change every existing line.
const STRING_EVENTS = ['warning', 'auth-failed', 'frame-rejected', 'connection-state'];

// How the aggregate session state is picked from the individual links. First match wins.
// A verification failure outranks everything because it burns the whole gate; after that
// the most advanced link is what the badge reports, so one peer still negotiating never
// makes a working gate look broken.
const STATE_PRECEDENCE = [
  STATE.AUTH_FAILED,
  STATE.CONNECTED,
  STATE.CONFIRMING,
  STATE.CONNECTING,
  STATE.NEGOTIATING,
  STATE.EXCHANGING,
  STATE.RECONNECTING,
];

// ---------------------------------------------------------------- display names
//
// Every participant gets a two-word name. It is NOT typed, NOT stored and NOT sent.
//
//     name_seed = HKDF(S, "wg/v1/name" || slotId)
//
// Four properties fall out of that one line, and every one of them is load-bearing:
//
//  1. EVERYBODY AGREES. S is the room secret, which every participant holds, and the slot
//     ids are published to the whole room in the roster. So each device computes the same
//     name for a given slot, including for itself, without a single byte being exchanged.
//     The obvious alternative, hashing the peer's ephemeral public key, cannot do this: in
//     a mesh each PAIR has its own key pair, so my key toward X differs from my key toward
//     Y, and X and Y would compute two different names for me.
//  2. NOBODY PICKS THEIR OWN. The slot id is server-assigned, so a participant has no input
//     into it, and there is no field anywhere in this app to type a name into. The lazy path
//     is the private one: you cannot accidentally put your real name into a tool whose whole
//     premise is that it does not know who you are.
//  3. THE SERVER CANNOT PICK IT EITHER, and that is why S is mixed in rather than hashing
//     the slot id alone. The server chooses slot ids, so with slotId as the only input it
//     could grind ids until somebody's name came out abusive. It does not hold S, so it
//     cannot predict the mapping at all. Cheap, and worth having even though names are
//     cosmetic.
//  4. IT IS NOT A CROSS-GATE IDENTIFIER. S is fresh per gate and slot ids are fresh per
//     gate, so the same two people in a new gate are two new names. That is the property
//     that makes this feature safe to ship at all, and it is why nothing here is persisted:
//     the moment a name outlived its gate it would become a handle to correlate on.
//
// Vocabulary: 64 adjectives times 128 nouns, so 8192 pairings. Deliberately calm and
// concrete, with no proper nouns, no brands, nothing that reads as an insult next to
// somebody's message and no pair that combines into something worse than its parts.
// Assume every pairing will be read out loud, because SAS verification means some of
// them will be.

const te = new TextEncoder();

const NAME_INFO = 'wg/v1/name';
const NAME_SEED_BITS = 128;

// A ceiling on what can ever reach the DOM. The longest constructible name is
// "Tranquil Lighthouse" plus at most NAME_SUFFIX_MAX distinguishing characters, which is
// 28, so this never truncates a real name; it is here so that a future word list cannot
// quietly grow an unbounded label into the transcript.
const NAME_MAX_CHARS = 32;

const NAME_ADJECTIVES = [
  'amber', 'autumn', 'azure', 'balmy', 'breezy', 'bright', 'brisk', 'calm',
  'candid', 'careful', 'chalky', 'cheerful', 'clement', 'cobalt', 'copper', 'coral',
  'cosy', 'crisp', 'dappled', 'dawn', 'distant', 'drifting', 'early', 'easy',
  'emerald', 'evening', 'fleecy', 'floating', 'frosted', 'gentle', 'gilded', 'glassy',
  'golden', 'hazy', 'hushed', 'ivory', 'jade', 'kindly', 'lilac', 'linen',
  'mellow', 'misty', 'moonlit', 'mossy', 'olive', 'opal', 'patient', 'pearl',
  'placid', 'polished', 'quiet', 'restful', 'russet', 'sandy', 'scarlet', 'silent',
  'silver', 'slate', 'snowy', 'soft', 'steady', 'sunlit', 'tranquil', 'velvet',
];

const NAME_NOUNS = [
  'acorn', 'alcove', 'anchor', 'arbour', 'archway', 'aspen', 'atrium', 'aurora',
  'basin', 'beacon', 'bracken', 'bramble', 'breeze', 'bridge', 'brook', 'burrow',
  'canyon', 'cavern', 'cedar', 'channel', 'cliff', 'clover', 'comet', 'compass',
  'copse', 'cottage', 'cove', 'crater', 'crescent', 'crossing', 'crystal', 'current',
  'delta', 'dune', 'ember', 'estuary', 'fathom', 'feather', 'fennel', 'fern',
  'ferry', 'fjord', 'forest', 'fountain', 'garden', 'glacier', 'glade', 'granite',
  'grotto', 'grove', 'harbour', 'hazel', 'heather', 'hedgerow', 'hollow', 'horizon',
  'inlet', 'island', 'juniper', 'lagoon', 'lantern', 'lattice', 'ledge', 'lighthouse',
  'linden', 'lookout', 'lowland', 'marble', 'marsh', 'meadow', 'mesa', 'millpond',
  'mirror', 'moorland', 'mosaic', 'mountain', 'obsidian', 'orchard', 'outcrop', 'paddock',
  'pasture', 'pathway', 'pebble', 'pennant', 'pinnacle', 'plateau', 'poplar', 'prairie',
  'quarry', 'quartz', 'rainfall', 'rampart', 'ravine', 'reef', 'ridge', 'rivulet',
  'sapling', 'savanna', 'seashore', 'shallows', 'shelter', 'shoreline', 'spruce', 'summit',
  'sundial', 'sycamore', 'terrace', 'thicket', 'thistle', 'tideway', 'timber', 'trellis',
  'tundra', 'valley', 'veranda', 'viaduct', 'village', 'vineyard', 'waterfall', 'watermill',
  'wetland', 'wharf', 'wheatfield', 'wildflower', 'willow', 'windmill', 'woodland', 'yarrow',
];

/** How many distinct pairings exist. Exported so a test can assert the space did not shrink. */
export const NAME_SPACE = NAME_ADJECTIVES.length * NAME_NOUNS.length;

// Crockford base32, the same alphabet the gate code uses: no I, L, O or U, so a
// distinguishing character cannot be misheard when the pairing is read aloud.
const NAME_SUFFIX_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const NAME_SUFFIX_MAX = 8;

const titleCase = (word) => word.charAt(0).toUpperCase() + word.slice(1);

/**
 * name_seed = HKDF(S, "wg/v1/name" || slotId).
 *
 * Same shape as every other derivation in this app: S is the key material, the label is
 * the HKDF info, and the salt is empty. Slot ids are fixed-width base64url, so appending
 * one to a constant label is unambiguous.
 *
 * This is done here rather than in crypto.js because crypto.js exports no general HKDF
 * helper and is not this change's to edit. Web Crypto is a global, so nothing is
 * duplicated but the four lines below, and the guard on S is the same one crypto.js
 * applies: a caller that gets the secret wrong must fail loudly rather than derive a name
 * from nothing.
 */
export async function deriveNameSeed(secret, slotId) {
  if (!(secret instanceof Uint8Array) || secret.length !== SECRET_BYTES) {
    throw new TypeError(`name derivation needs the ${SECRET_BYTES}-byte room secret, got `
      + `${secret instanceof Uint8Array ? `${secret.length} bytes` : typeof secret}`);
  }
  if (typeof slotId !== 'string' || slotId.length === 0) {
    throw new TypeError(`name derivation needs a slot id, got ${typeof slotId}`);
  }
  const key = await globalThis.crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(NAME_INFO + slotId) },
    key,
    NAME_SEED_BITS,
  ));
}

/**
 * Two words out of one seed.
 *
 * Exact bit slices, 6 for the adjective and 7 for the noun, because both lists are powers
 * of two. A modulo over a non-power-of-two list would bias the vocabulary towards its
 * first entries, which is harmless for a cosmetic name and still not a thing to leave in
 * a file full of derivations that must not be biased.
 */
export function nameFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length < 2 + NAME_SUFFIX_MAX) {
    throw new TypeError(`a name seed must be at least ${2 + NAME_SUFFIX_MAX} bytes`);
  }
  return `${titleCase(NAME_ADJECTIVES[seed[0] & 63])} ${titleCase(NAME_NOUNS[seed[1] & 127])}`;
}

/** Distinguishing characters for a collision, taken from the same seed as the name. */
function nameSuffix(seed, length) {
  let out = '';
  for (let i = 0; i < length; i += 1) out += NAME_SUFFIX_ALPHABET[seed[2 + i] & 31];
  return out;
}

/**
 * Turn slot seeds into final names, resolving collisions.
 *
 * With 8192 pairings a collision inside a six-seat gate is under half a percent, but "it
 * probably will not happen" is not a resolution, and two participants shown the same name
 * is exactly the state that makes a roster lie. So when a pairing repeats, EVERY member of
 * that group gains a distinguishing character derived from its own seed, growing by one
 * character until the group is distinct.
 *
 * The result depends only on the SET of seeds, never on their order or on which device is
 * computing: each id's suffix comes from its own seed, and the suffix length comes from the
 * colliding group as a set. Two devices that know the same slots therefore print the same
 * names, which is the entire point. Picking a suffix at random, or handing it to whichever
 * side noticed the clash first, would break that and there would be no way to tell from one
 * device that it had.
 */
export function resolveDisplayNames(entries) {
  const seeds = new Map(entries);
  const groups = new Map();
  for (const [id, seed] of seeds) {
    const base = nameFromSeed(seed);
    if (!groups.has(base)) groups.set(base, []);
    groups.get(base).push(id);
  }
  const out = new Map();
  for (const [base, ids] of groups) {
    if (ids.length === 1) {
      out.set(ids[0], base.slice(0, NAME_MAX_CHARS));
      continue;
    }
    let labels = ids.map(() => base);
    for (let length = 1; length <= NAME_SUFFIX_MAX; length += 1) {
      labels = ids.map((id) => `${base} ${nameSuffix(seeds.get(id), length)}`);
      if (new Set(labels).size === ids.length) break;
    }
    // Past NAME_SUFFIX_MAX two seeds would have to agree on 80 bits, which cannot happen
    // for two distinct slot ids. If it somehow did, both devices still print the same
    // duplicate rather than disagreeing, which is the failure that stays diagnosable.
    for (let i = 0; i < ids.length; i += 1) out.set(ids[i], labels[i].slice(0, NAME_MAX_CHARS));
  }
  return out;
}

/** Derive the display name for one slot outright. Used by tests; the Session caches. */
export async function deriveDisplayName(secret, slotId) {
  return nameFromSeed(await deriveNameSeed(secret, slotId));
}

export class Session extends EventTarget {
  constructor({ secret, iceServers, password = null }) {
    super();
    this.secret = secret;
    this.iceServers = iceServers;
    // Optional second factor. Never leaves the browser; the server only ever learns
    // that a room has one, as a boolean, so a joiner can be prompted.
    this.password = password || null;
    this.passwordKey = null;
    this.passwordDeriving = null;
    // Resolved once we know the password situation. Every handshake waits on it, so a
    // link-joiner can be prompted before any key is derived.
    this.passwordGate = Promise.resolve();
    this.resolvePasswordGate = null;
    this.state = STATE.IDLE;
    this.roomId = null;
    this.signal = null;
    // Our own slot id, handed down by the server in `hello`. Everything about the mesh
    // hangs off it: which links to open, and which side of each pair makes the offer.
    this.selfId = null;
    // Our seat letter. Display only; it is NOT the direction constant in any key
    // schedule any more, because with a mesh there is no single 'a' side.
    this.role = null;
    this.maxParticipants = 2;
    /** @type {Map<string, Link>} peer slot id -> link */
    this.links = new Map();
    // Display names. `nameSeeds` only ever grows for the life of the gate, including for
    // slots that have left: collision resolution reads the whole set, so letting it shrink
    // would rename the people who stayed when somebody walked out. It is cleared at
    // teardown with everything else, and nothing here is ever written to storage.
    /** @type {Map<string, Uint8Array>} slot id -> name seed */
    this.nameSeeds = new Map();
    /** @type {Map<string, string>} slot id -> display name */
    this.names = new Map();
    this.severed = false;
    // Files being sent to more than one peer at once, so one transcript row can report
    // the whole fan-out rather than one row per recipient.
    this.fanouts = new Map();
    // An interrupted inbound transfer recovered from storage, waiting for the user gesture
    // that re-grants permission on the file they already chose.
    this.pendingInbound = null;
    // An interrupted inbound transfer whose data cannot come back (it was in memory and
    // the page reloaded). Held only so the sender can be told cleanly instead of waiting.
    this.lostInbound = null;
    // Set by resume(): every peer still holds a connection to the page we navigated away
    // from and has to be told to start over.
    this.needsRestart = false;
  }

  emit(name, detail) { this.dispatchEvent(new CustomEvent(name, { detail })); }

  setState(state, detail) {
    if (this.state === state) return;
    this.state = state;
    this.emit('state', { state, detail });
  }

  // ------------------------------------------------------------ lifecycle

  async create(sessionMinutes) {
    this.setState(STATE.CREATING);
    this.roomId = await deriveRoomId(this.secret);
    // H, not J. The server stores the hash and can only ever check a J presented to it.
    const room = await postRoom('/api/create', {
      roomId: this.roomId,
      sessionMinutes,
      requiresPassword: Boolean(this.password),
      joinProofHash: await deriveJoinProofHash(this.secret),
    });
    this.expiresAt = room.expiresAt;
    this.role = room.role ?? null;
    this.maxParticipants = Number(room.maxParticipants) || this.maxParticipants;
    await this.openSignal(room.token);
    this.setState(STATE.WAITING);
    return room;
  }

  async join() {
    this.setState(STATE.CREATING);
    this.roomId = await deriveRoomId(this.secret);
    // J proves we hold the room secret. Without it the room id alone would take a slot,
    // and the room id is the one part of this the server already knows. It is ROOM level:
    // every participant proves knowledge of the same secret, which is exactly what admits
    // them to the same gate.
    const room = await postRoom('/api/join', {
      roomId: this.roomId,
      joinProof: await deriveJoinProof(this.secret),
    });
    this.expiresAt = room.expiresAt;
    this.role = room.role ?? null;
    this.maxParticipants = Number(room.maxParticipants) || this.maxParticipants;
    if (room.requiresPassword && !this.password) {
      this.passwordGate = new Promise((resolve) => { this.resolvePasswordGate = resolve; });
      this.emit('password-required', null);
    }
    await this.openSignal(room.token);
    return room;
  }

  /**
   * Re-attach to a slot we already hold, after a page reload.
   *
   * Without this a refresh is fatal: re-joining a room you are already occupying is
   * correctly refused as full, so the gate could never be recovered.
   *
   * The password has to come back in with the caller. It is never persisted anywhere,
   * which is the point, so a resumed password-protected gate that is not handed the
   * password again would derive a different key and fail verification.
   *
   * A reload is exactly the case where the caller has nothing to hand over: the input the
   * user typed it into is empty again. So when the room is known to require a password and
   * none arrived, arm the same gate join() uses and ask the UI for it, rather than racing
   * ahead and deriving a key that can only fail confirmation.
   */
  async resume({ token, role = null, expiresAt, password = null, requiresPassword = false }) {
    this.role = role;
    if (password) {
      this.password = password;
      this.passwordKey = null; // re-derive: the old stretched key belongs to a dead session
      this.passwordDeriving = null;
    }
    if (requiresPassword && !this.password) {
      this.passwordGate = new Promise((resolve) => { this.resolvePasswordGate = resolve; });
      this.emit('password-required', null);
    }
    this.setState(STATE.CREATING);
    this.roomId = await deriveRoomId(this.secret);
    this.expiresAt = expiresAt;
    // Every peer still holds a connection to the page we just navigated away from, and
    // will ignore a new public key while it thinks it already has one. Tell each of them
    // to start over, otherwise resuming the slot restores the room but never a connection.
    this.needsRestart = true;
    await this.openSignal(token);
    return { token, role, expiresAt };
  }

  /** Supply a password that was asked for after joining, releasing every handshake. */
  setPassword(password) {
    this.password = password || null;
    this.passwordKey = null;
    this.passwordDeriving = null;
    if (this.resolvePasswordGate) {
      this.resolvePasswordGate();
      this.resolvePasswordGate = null;
    }
  }

  /**
   * Stretch the room password once for the whole room, not once per link.
   *
   * PBKDF2 here is 600,000 iterations by design. A six-way mesh runs five handshakes from
   * this page, and making each of them pay that separately would be five times the work
   * for exactly the same key.
   */
  async ensurePasswordKey() {
    if (!this.password) return null;
    if (this.passwordKey) return this.passwordKey;
    if (!this.passwordDeriving) {
      this.emit('deriving', 'Strengthening the room password.');
      this.passwordDeriving = derivePasswordKey(this.password, this.secret)
        .then((key) => { this.passwordKey = key; return key; })
        .finally(() => { this.passwordDeriving = null; });
    }
    return this.passwordDeriving;
  }

  // ------------------------------------------------------------ signalling

  async openSignal(token) {
    const signalKey = await deriveSignalKey(this.secret);
    this.signal = new Signal({ roomId: this.roomId, token, signalKey });

    this.signal.addEventListener('hello', (event) => {
      const detail = event.detail ?? {};
      // The server re-sends hello as a room approaches the one deadline it cannot push
      // back. Everything below is idempotent, so a repeat is harmless.
      if (detail.absoluteExpiresAt) {
        this.emit('gate-deadline', {
          expiresAt: detail.expiresAt ?? null,
          hardExpiresAt: detail.hardExpiresAt ?? null,
          absoluteExpiresAt: detail.absoluteExpiresAt,
          expiring: Boolean(detail.expiring),
        });
      }
      if (typeof detail.self === 'string' && detail.self) {
        this.selfId = detail.self;
        // The transport stamps it on every outgoing signalling message, so the receiver
        // knows which of its links a relayed offer belongs to.
        this.signal.selfId = detail.self;
      }
      if (typeof detail.role === 'string') this.role = detail.role;
      if (Number(detail.maxParticipants)) this.maxParticipants = Number(detail.maxParticipants);
      this.applyRoster(Array.isArray(detail.peers) ? detail.peers : []);
    });

    this.signal.addEventListener('peer-joined', (event) => {
      const detail = event.detail ?? {};
      const id = typeof detail.id === 'string' ? detail.id : null;
      if (!id || id === this.selfId) return;
      // hello is written before any relay or announcement on the same stream, so selfId is
      // always set by now. Guarded anyway: ensureLink throws without it, and a throw inside
      // an event listener is an uncaught error rather than a handled one.
      if (!this.selfId) return;
      const link = this.ensureLink(id, detail.role ?? null);
      link.peerGone = false;
      this.membershipChanged();
      link.connect().catch((err) => this.emit('warning', `could not start connecting to ${link.label}: ${err.message}`));
    });

    this.signal.addEventListener('peer-left', (event) => {
      if (this.state === STATE.SEVERED || this.severed) return;
      const detail = event.detail ?? {};
      const id = typeof detail.id === 'string' ? detail.id : null;
      const link = id ? this.links.get(id) : null;
      const everConnected = Boolean(link?.everConnected);
      // The idle clock restarts once a participant leaves, so hand the new deadline up.
      this.emit('peer-left', {
        message: everConnected
          ? 'The other device disconnected. This gate stays open and will reconnect if it comes back.'
          : 'The other device disconnected.',
        expiresAt: detail.expiresAt ?? null,
        peer: id,
        label: link ? this.labelFor(link) : null,
      });
      if (link) {
        link.peerGone = true;
        // A participant that walked away after connecting is exactly the case the owner's
        // rule is about: somebody is still here, so that link keeps waiting rather than
        // declaring anything failed. One that never connected has nothing to preserve, so
        // it is dropped outright: every OTHER link is untouched either way.
        if (everConnected) link.holdOpen('the other device disconnected');
        else this.dropLink(id, 'the other device left before connecting');
      }
      this.membershipChanged();
      this.recomputeState();
    });

    this.signal.addEventListener('closed', (event) => {
      const reason = event.detail?.reason ?? 'closed';
      if (reason === 'ttl-hard') {
        // The absolute ceiling. Distinct from the idle timeout because it is the one a
        // long transfer can actually hit while it is being used, and "the gate expired"
        // would be a misleading thing to tell someone 90% of the way through a file.
        this.teardown('This gate reached the longest a single gate may live, so it has ended. '
          + 'Open a new gate and send the rest.');
        return;
      }
      this.teardown(reason === 'ttl' ? 'The gate expired.' : 'The other device burned the gate.');
    });

    this.signal.addEventListener('undecryptable', (event) => {
      // Someone is in the room without the room secret. Not fatal, but the user
      // should know a device failed verification rather than see silence.
      this.emit('intruder', event.detail);
    });

    this.signal.addEventListener('message', (event) => this.onSignalMessage(event.detail));
    this.signal.addEventListener('reconnecting', () => this.emit('warning', 'Signalling connection interrupted, retrying.'));
    this.signal.connect();
  }

  /**
   * Bring the local mesh into line with the roster the server just sent.
   *
   * Connect to everyone already present, drop any link whose slot the server no longer
   * seats, and leave everything else exactly as it is: a roster refresh is not a reason to
   * disturb a working connection.
   */
  applyRoster(peers) {
    const seen = new Set();
    let opened = 0;
    for (const entry of peers) {
      const id = typeof entry?.id === 'string' ? entry.id : null;
      if (!id || id === this.selfId) continue;
      seen.add(id);
      const known = this.links.get(id);
      if (known) {
        if (entry.role) known.peerRole = entry.role;
        continue;
      }
      if (!entry.present) continue; // seated but not listening yet; peer-joined will say
      const link = this.ensureLink(id, entry.role ?? null);
      opened += 1;
      link.connect().catch((err) => this.emit('warning', `could not start connecting to ${link.label}: ${err.message}`));
    }
    // A slot the server no longer lists is genuinely gone, not merely away: peer-left
    // leaves the slot seated, so this only fires when the seat itself has been released.
    for (const id of [...this.links.keys()]) {
      if (!seen.has(id)) this.dropLink(id, 'that participant is no longer in the gate');
    }
    // Each link created above already carried the restart flag out to its peer. It is only
    // cleared once a link has actually been made: a resumed page whose peers are all
    // momentarily unattached would otherwise drop the flag on an empty roster and never
    // tell them to start over, leaving each of them holding a dead connection to the page
    // this one navigated away from until its own ICE timeout notices.
    if (opened) this.needsRestart = false;
    this.membershipChanged();
    this.recomputeState();
  }

  /** Get or create the link to one peer. Never creates one to ourselves. */
  ensureLink(peerId, peerRole) {
    const existing = this.links.get(peerId);
    if (existing) {
      if (peerRole) existing.peerRole = peerRole;
      return existing;
    }
    if (!this.selfId) throw new Error('the server has not said which slot this device holds yet');
    const link = new Link({
      session: this,
      peerId,
      peerRole,
      // THE initiator rule. The side with the lexicographically smaller slot id makes the
      // offer. Both sides compute it from the same two public strings, so there is no
      // glare and no perfect-negotiation rollback to implement; and because `role` is
      // derived from the SAME comparison, the direction constants in the nonce and the
      // ordering of the two public keys in the transcript hash cannot disagree across the
      // pair. If they could, both sides would derive different keys and the failure would
      // look like a crypto fault rather than the routing decision it actually is.
      initiator: this.selfId < peerId,
    });
    this.wireLink(link);
    this.links.set(peerId, link);
    return link;
  }

  dropLink(peerId, reason) {
    const link = this.links.get(peerId);
    if (!link) return;
    this.links.delete(peerId);
    link.close(reason);
    // A fan-out waiting on this recipient must stop waiting on it, or a file sent to
    // three people could never report itself delivered once one of them walked out.
    for (const fan of this.fanouts.values()) fan.targets.delete(peerId);
  }

  /** Route a decrypted signalling message to the link it belongs to. */
  async onSignalMessage(message) {
    if (!message || typeof message.t !== 'string') return;
    const from = typeof message.from === 'string' ? message.from : null;
    if (!from) {
      this.emit('warning', 'ignored a signalling message that did not say which device sent it');
      return;
    }
    if (from === this.selfId) return; // our own message, reflected somehow
    let link = this.links.get(from);
    if (!link) {
      if (!this.selfId) return;
      link = this.ensureLink(from, null);
      this.membershipChanged();
    }
    try {
      await link.onSignalMessage(message);
    } catch (err) {
      this.emit('warning', `could not handle a signalling message from ${this.labelFor(link)}: ${err.message}`);
    }
  }

  /**
   * A relay this link tried to send was refused because the room does not seat that slot.
   *
   * The link is dead and no amount of backoff will revive it, so it goes. Retrying instead
   * would spend the per-address REJECT budget, which is far tighter than the others and is
   * shared by every route: thirty refusals and this client is answered 429 on relay, join
   * and create alike, which presents as the whole service being broken.
   */
  onLinkTargetGone(link) {
    if (!this.links.has(link.peerId)) return;
    this.emit('warning', `${this.labelFor(link)} is no longer in this gate.`);
    this.dropLink(link.peerId, 'that participant is no longer in the gate');
    this.membershipChanged();
    this.recomputeState();
  }

  // ------------------------------------------------------------ names

  /** This slot's display name, or null if it has not been derived yet. */
  nameFor(slotId) {
    return (typeof slotId === 'string' && this.names.get(slotId)) || null;
  }

  /** Our own name. Every other participant computes the same string for us. */
  get selfName() {
    return this.nameFor(this.selfId);
  }

  /**
   * Derive a name for every slot we know about, then republish if anything changed.
   *
   * Async because HKDF is, and the callers are synchronous event listeners, so a slot is
   * briefly nameless between being seated and being named. The seat letter stands in for
   * that gap rather than a blank, and publishRoster runs again the moment the name lands.
   */
  async refreshNames() {
    if (this.severed || !this.secret) return;
    const ids = [this.selfId, ...this.links.keys()].filter((id) => typeof id === 'string' && id);
    const missing = ids.filter((id) => !this.nameSeeds.has(id));
    if (missing.length) {
      const secret = this.secret;
      const seeds = await Promise.all(missing.map((id) => deriveNameSeed(secret, id)));
      // The gate can end while the derivation is in flight, and a torn-down session must
      // not repopulate itself.
      if (this.severed || !this.secret) return;
      for (let i = 0; i < missing.length; i += 1) this.nameSeeds.set(missing[i], seeds[i]);
    }
    const resolved = resolveDisplayNames([...this.nameSeeds]);
    let changed = resolved.size !== this.names.size;
    for (const [id, name] of resolved) if (this.names.get(id) !== name) changed = true;
    if (!changed) return;
    this.names = resolved;
    this.publishRoster();
  }

  /** Fire and forget: a name that cannot be derived is a warning, never a broken gate. */
  scheduleNames() {
    this.refreshNames().catch((err) => this.emit('warning', `could not name a participant: ${err.message}`));
  }

  /** Somebody joined or left: republish now with what is known, and name the newcomers. */
  membershipChanged() {
    this.publishRoster();
    this.scheduleNames();
  }

  // ------------------------------------------------------------ link plumbing

  /**
   * How a peer is named in the transcript and in the roster.
   *
   * The derived name, which every participant in the gate computes identically for this
   * slot, so "Amber Meadow said this" means the same person on every device. It replaces
   * both the seat letter a mesh used to show and the anonymous "them" a two-party gate
   * used to show: a name is no more cluttered than "them" and it stays true when a third
   * person arrives.
   *
   * The seat letter is the fallback for the instant between a slot appearing on the roster
   * and its name being derived, and the raw slot id for the case where even that is absent.
   * Neither is reached in a settled gate.
   */
  labelFor(link) {
    return this.nameFor(link.peerId)
      ?? (link.peerRole ? `peer ${link.peerRole}` : link.peerId);
  }

  wireLink(link) {
    link.addEventListener('link-state', () => {
      this.publishRoster();
      this.recomputeState();
    });

    link.addEventListener('sas', () => {
      this.publishRoster();
      this.emit('sas', this.sasSummary());
    });

    link.addEventListener('route', (event) => {
      this.publishRoster();
      this.emit('route', event.detail);
    });

    for (const name of STRING_EVENTS) {
      link.addEventListener(name, (event) => this.emit(name, event.detail));
    }

    for (const name of OBJECT_EVENTS) {
      link.addEventListener(name, (event) => {
        const detail = event.detail;
        if (detail && typeof detail === 'object') {
          this.emit(name, { ...detail, peer: link.peerId, label: this.labelFor(link) });
        } else {
          this.emit(name, detail);
        }
      });
    }

    // Outbound progress and completion are aggregated across the fan-out, so one file
    // sent to three people is one row that only finishes when all three have it.
    link.addEventListener('file-progress', (event) => this.onLinkProgress(link, event.detail));
    link.addEventListener('file-sent', (event) => this.onLinkSent(link, event.detail));
    link.addEventListener('file-rejected', (event) => this.onLinkRejected(link, event.detail));

    link.addEventListener('unreachable', (event) => {
      // Only when there is nothing left that works. app.js treats this as fatal and drops
      // the session, and one peer on a hostile network must not end the gate for everybody
      // else. With a single peer this is exactly the old behaviour.
      const others = [...this.links.values()].filter((l) => l !== link);
      if (others.some((l) => l.state !== STATE.UNREACHABLE)) {
        this.emit('warning', `could not reach ${this.labelFor(link)}: ${event.detail}`);
        return;
      }
      this.emit('unreachable', event.detail);
    });
  }

  /** The verification code to display. One peer: theirs. Several: none is "the" code. */
  sasSummary() {
    const codes = [...this.links.values()].map((l) => l.sessionKeys?.sas).filter(Boolean);
    if (codes.length === 1) return codes[0];
    if (!codes.length) return '-----';
    return `${codes.length} codes`;
  }

  publishRoster() {
    this.emit('roster', {
      self: this.selfId,
      // Derived on this device from the room secret and our own slot id. It is the same
      // string every other participant sees for us, which is what makes it worth showing.
      selfName: this.selfName,
      role: this.role,
      maxParticipants: this.maxParticipants,
      peers: [...this.links.values()].map((link) => ({
        id: link.peerId,
        role: link.peerRole,
        name: this.nameFor(link.peerId),
        label: this.labelFor(link),
        state: link.state,
        connected: link.connected,
        sas: link.sessionKeys?.sas ?? null,
      })),
    });
  }

  /**
   * Fold every link's state into the one the badge shows.
   *
   * A gate with three people in it where one is still negotiating is a working gate, so
   * the most advanced link wins. With a single peer this reduces to that peer's state,
   * which is what a two-party gate has always reported.
   */
  recomputeState() {
    if (this.severed || this.state === STATE.SEVERED) return;
    const states = [...this.links.values()].map((l) => l.state);
    if (!states.length) {
      if (this.state !== STATE.CREATING) this.setState(STATE.WAITING);
      return;
    }
    for (const wanted of STATE_PRECEDENCE) {
      if (states.includes(wanted)) { this.setState(wanted); return; }
    }
    if (states.every((s) => s === STATE.UNREACHABLE)) { this.setState(STATE.UNREACHABLE); return; }
    this.setState(STATE.WAITING);
  }

  // ------------------------------------------------------------ sending

  connectedLinks() {
    return [...this.links.values()].filter((l) => l.connected);
  }

  requireConnected() {
    if (!this.connectedLinks().length) throw new Error('the gate is not connected');
  }

  /**
   * Fan a message out to every connected participant.
   *
   * Sent per link, under that pair's own key, and echoed locally exactly once. A failure
   * on one link is reported and does not stop the others; the send only throws when it
   * reached nobody at all.
   */
  async fanOut(what, send) {
    this.requireConnected();
    const targets = this.connectedLinks();
    const results = await Promise.allSettled(targets.map((link) => send(link)));
    const failed = results.filter((r) => r.status === 'rejected');
    if (failed.length === results.length) throw failed[0].reason;
    for (let i = 0; i < results.length; i += 1) {
      if (results[i].status === 'rejected') {
        this.emit('warning', `could not send ${what} to ${this.labelFor(targets[i])}: ${results[i].reason.message}`);
      }
    }
    return results.length - failed.length;
  }

  async sendChat(text) {
    await this.fanOut('a message', (link) => link.sendChat(text));
    this.emit('chat', { from: 'me', text });
  }

  async sendSecret(text) {
    await this.fanOut('a secret', (link) => link.sendSecret(text));
    this.emit('secret', { from: 'me', text });
  }

  /**
   * Send one file to every connected participant.
   *
   * ONE transfer id for the whole fan-out, so the sender sees one row. The fingerprint is
   * computed once from this exact File, and each link then runs its own transfer with its
   * own queue and its own resume state: one file in flight per peer, never one globally,
   * so a peer on a slow link cannot hold anybody else up.
   */
  async sendFile(file) {
    this.requireConnected();
    const targets = this.connectedLinks().filter((link) => !link.outbound?.active);
    if (!targets.length) throw new Error('another file is already being sent');
    const id = b64u.encode(globalThis.crypto.getRandomValues(new Uint8Array(8)));
    // Computed before anything goes out, so the identity every receiver records is the one
    // taken from this exact File at this exact moment.
    const fingerprint = await fingerprintFile(file);
    this.fanouts.set(id, {
      name: file.name,
      total: file.size,
      targets: new Set(targets.map((l) => l.peerId)),
      sent: new Map(),
      done: new Set(),
    });
    try {
      const results = await Promise.allSettled(targets.map((link) => link.sendFile(file, id, fingerprint)));
      const failed = results.filter((r) => r.status === 'rejected');
      if (failed.length === results.length) throw failed[0].reason;
      for (let i = 0; i < results.length; i += 1) {
        if (results[i].status === 'rejected') {
          this.emit('warning', `${file.name} did not reach ${this.labelFor(targets[i])}: ${results[i].reason.message}`);
        }
      }
      return undefined;
    } finally {
      this.fanouts.delete(id);
    }
  }

  /** Outbound progress is the SLOWEST recipient's, so the bar cannot lie about delivery. */
  onLinkProgress(link, detail) {
    if (!detail) return;
    // Inbound progress, and any outbound transfer that is not part of a live fan-out (a
    // resume after a reload, for instance), is one link's own business and goes straight up.
    const fan = detail.direction === 'out' ? this.fanouts.get(detail.id) : null;
    if (!fan) {
      this.emit('file-progress', { ...detail, peer: link.peerId, label: this.labelFor(link) });
      return;
    }
    fan.sent.set(link.peerId, Number(detail.sent) || 0);
    let slowest = Infinity;
    for (const peerId of fan.targets) slowest = Math.min(slowest, fan.sent.get(peerId) ?? 0);
    if (!Number.isFinite(slowest)) return;
    this.emit('file-progress', {
      direction: 'out', id: detail.id, name: fan.name, total: fan.total, sent: slowest,
      peers: fan.targets.size,
    });
  }

  onLinkSent(link, detail) {
    const fan = detail && this.fanouts.get(detail.id);
    if (!fan) {
      this.emit('file-sent', detail);
      return;
    }
    fan.done.add(link.peerId);
    // Only once every recipient has the whole file. Saying "sent" while one of three
    // copies is still streaming is the kind of half-truth this project does not ship.
    for (const peerId of fan.targets) if (!fan.done.has(peerId)) return;
    this.emit('file-sent', { ...detail, name: fan.name, size: fan.total, peers: fan.targets.size });
  }

  onLinkRejected(link, detail) {
    const fan = detail && this.fanouts.get(detail.id);
    if (fan) fan.targets.delete(link.peerId);
    this.emit('file-rejected', detail && typeof detail === 'object'
      ? { ...detail, peer: link.peerId, label: this.labelFor(link) }
      : detail);
  }

  // ------------------------------------------------------------ receiving

  /** Accept the file a specific participant offered. Called from a user gesture. */
  async acceptIncoming(peerId = null) {
    const link = this.linkForIncoming(peerId);
    if (!link) throw new Error('no incoming file to accept');
    return link.acceptIncoming();
  }

  linkForIncoming(peerId) {
    if (peerId && this.links.has(peerId)) return this.links.get(peerId);
    return [...this.links.values()].find((l) => l.incoming) ?? null;
  }

  /** Hand a specific participant's paused send its file back after a reload. */
  async resumeOutbound(file, peerId = null) {
    const link = (peerId && this.links.get(peerId))
      ?? [...this.links.values()].find((l) => l.outbound?.active && !l.outbound.file);
    if (!link) throw new Error('there is no paused transfer to continue');
    return link.resumeOutbound(file);
  }

  /**
   * Look for a transfer this room was receiving before the page reloaded.
   *
   * Emits `inbound-recoverable` when there is one that can be continued, which the UI must
   * turn into a button, because re-granting permission on a file handle needs a user
   * gesture. Emits `inbound-lost` when there was one that cannot be: the honest answer for
   * a browser that was holding the file in memory.
   */
  async recoverInbound() {
    if (!this.roomId) return null;
    let record = null;
    try {
      record = await readInboundRecord(this.roomId);
    } catch (err) {
      this.emit('warning', `could not check for an interrupted transfer: ${err.message}`);
      return null;
    }
    if (!record) return null;

    if (!record.handle) {
      await this.forgetInboundRecord();
      // Kept only so the sender can be told, so it stops holding a file open for a
      // receiver that can never take it.
      this.lostInbound = { id: record.id, peerId: record.peerId ?? null };
      this.emit('inbound-lost', {
        ...record.meta,
        received: record.received,
        peer: record.peerId ?? null,
        reason: 'This browser was holding the file in memory rather than writing it straight to disk, '
          + 'and reloading the page discarded it. The transfer has to start again from the beginning.',
      });
      return null;
    }

    this.pendingInbound = record;
    this.emit('inbound-recoverable', {
      ...record.meta,
      received: record.received,
      peer: record.peerId ?? null,
      human: formatBytes(record.received),
    });
    return record;
  }

  /**
   * Adopt the recovered transfer. MUST be called from a user gesture: re-granting write
   * permission on a stored handle prompts, and a prompt outside a gesture is refused.
   */
  async adoptInbound() {
    const record = this.pendingInbound;
    if (!record) throw new Error('there is no interrupted transfer to continue');
    // Back to the participant that was actually sending it. Falling back to the only link
    // there is keeps a two-party gate working on records written before slot ids existed.
    const link = (record.peerId && this.links.get(record.peerId))
      ?? (this.links.size === 1 ? [...this.links.values()][0] : null);
    if (!link) throw new Error('the device that was sending that file is not connected');
    this.pendingInbound = null;
    return link.adoptInbound(record);
  }

  async forgetInboundRecord() {
    if (!this.roomId) return;
    try { await dropInboundRecord(this.roomId); } catch (err) { this.emit('warning', `could not clear the resume record: ${err.message}`); }
  }

  // ------------------------------------------------------------ teardown

  /** Burn the gate. Every participant is told, then the room itself is deleted. */
  async sever() {
    if (this.severed) return;
    this.severed = true;
    // Tell each peer first, while their channels still exist. One failure must not stop
    // the others being told.
    const links = [...this.links.values()];
    const told = await Promise.allSettled(links.map((link) => link.sendSever()));
    for (let i = 0; i < told.length; i += 1) {
      if (told[i].status === 'rejected') {
        this.emit('warning', `could not notify ${this.labelFor(links[i])}: ${told[i].reason.message}`);
      }
    }
    try { await this.signal?.bye(); } catch (err) { this.emit('warning', `could not delete the room: ${err.message}`); }
    this.teardown('Gate burned.');
  }

  /**
   * Drop every reference to key material, on every link.
   *
   * The AES keys are non-extractable CryptoKey objects, so their bytes were never in the
   * JS heap; releasing the reference is the strongest erasure a browser offers
   * (DESIGN.md 1.11).
   */
  teardown(reason) {
    this.severed = true;
    for (const link of this.links.values()) link.close(reason);
    this.links.clear();
    this.fanouts.clear();
    // Names go with the gate. They are cheap to recompute while S is alive and must not
    // outlive it: a name that survived the gate would be exactly the linkable identifier
    // this derivation exists to avoid creating.
    this.nameSeeds.clear();
    this.names.clear();
    try { this.signal?.close(); } catch (err) { void err; }
    // The gate is gone, so nothing here can ever be continued. The stored handle goes with
    // it: leaving it would offer to resume into a dead room, and "nothing outlives the
    // gate" is a promise this makes to the user.
    this.forgetInboundRecord().catch(() => {});
    this.pendingInbound = null;
    this.lostInbound = null;
    if (this.secret) this.secret.fill(0);
    this.secret = null;
    this.passwordKey = null;
    this.passwordDeriving = null;
    this.signal = null;
    this.publishRoster();
    this.setState(STATE.SEVERED, reason);
    this.emit('severed', reason);
  }
}
