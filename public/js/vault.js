// Per-tab custody of the one thing a reload cannot re-derive on its own.
//
// A gate already survives a refresh: app.js keeps the room secret and the slot token in
// sessionStorage, the tab comes back, re-attaches to the slot it already holds, and the
// whole key schedule falls back out of S. An optional room password breaks exactly that,
// because the schedule needs S AND the stretched password (DESIGN.md 3.2a) and the
// password only ever existed in an <input> that a reload empties. So a password gate could
// not come back on its own: it stopped and asked again, and until the user answered, the
// resumed page never even told its peers to renegotiate, so they sat holding a connection
// to a document that no longer existed.
//
// WHAT IS STORED, AND WHY IT IS NOT THE PASSWORD
//
//   p_key = PBKDF2-HMAC-SHA256(password, salt = S || "wg/v1/password", 600000 iterations)
//
// That is precisely the value deriveSession() consumes, so storing it loses nothing, and it
// is the strongest thing available that is not the password itself:
//
//  - It is one-way. Recovering the password from p_key costs 600,000 PBKDF2 iterations per
//    guess, which is exactly the price DESIGN.md 3.2a already charges an attacker who holds
//    the link and is guessing the password. Keeping it therefore hands nobody a cheaper
//    attack than the threat model already concedes.
//  - It is room-bound. S is in the salt, so p_key is inert in any other gate and cannot be
//    replayed anywhere at all. The password, by contrast, is a human-chosen string that is
//    very often reused far outside this application: its exposure would not be bounded by
//    this gate, and p_key's is. That asymmetry is the entire reason this file stores a
//    derivative rather than the thing the user typed.
//  - It has the same lifetime as everything else here. It dies with the tab, and it is
//    deleted on sever, on expiry and on any authentication failure, whichever comes first.
//
// IS sessionStorage ACCEPTABLE FOR IT?
//
// Yes, and the argument has to be made rather than assumed, because THREAT-MODEL.md's data
// lifecycle table already flags that some browsers write sessionStorage to disk for crash
// recovery. Three things settle it:
//
//  1. Reading this store means reading THIS TAB's storage, which means the device, the
//     browser or an extension is compromised. THREAT-MODEL.md lists that under "Not
//     protected against" with no qualification, and nothing in a web page can change it.
//  2. The room secret S is already in the same store, under wg.secret, and has been since
//     the secret was taken out of the address bar. Anyone who can read this store already
//     holds S today, so the only marginal question is whether they should also get the
//     password. They do not: they get p_key, and the password is 600,000 iterations per
//     guess behind it.
//  3. The threat the password actually addresses is a LEAKED LINK: the link travelling
//     somewhere the password did not (DESIGN.md 3.2a). Nothing here puts either value on
//     the wire, in the address bar, in a referrer, in history or in front of the server,
//     so that threat is untouched. This is a per-tab handoff across one navigation, and
//     the navigation is the only reader.
//
// Considered and rejected: wrapping p_key under a non-extractable AES key held in
// IndexedDB, so that neither store would be useful alone. It reads as defence in depth and
// is not. Both stores sit on the same disk, under the same origin, reachable by the same
// script, so every attacker who reaches one reaches the other; the wrap would have bought a
// second failure mode (a browser with sessionStorage but no usable IndexedDB) and no change
// in who can read what. Storing a derivative instead of the password is the part that
// actually moves, so that is the part that got built.

import { b64u } from './crypto.js';

// Namespaced the way app.js namespaces wg.slot.<roomId> and wg.secret, and keyed by room
// id so a tab that has held several gates cannot hand one gate's key to another.
const PREFIX = 'wg.pkey.';

// PBKDF2 dkLen from DESIGN.md 3.2a. A record of any other length is not a p_key this
// application wrote, so it is discarded rather than fed into a key schedule.
const KEY_BYTES = 32;

/**
 * The per-tab store, or null.
 *
 * The property ACCESS is what throws in Safari's private mode and in a third-party context
 * with storage blocked, not the call on it, so the guard has to wrap the lookup itself.
 * Absent storage is never fatal here: it costs one password prompt after a reload, which is
 * exactly the behaviour this module replaced.
 */
function store() {
  try {
    return globalThis.sessionStorage ?? null;
  } catch (err) {
    void err; // the reason is reported by savePasswordKey, which is the only caller that can act on it
    return null;
  }
}

/**
 * File p_key for this room, for this tab only.
 *
 * Returns null on success, or the reason it could not be filed. A gate that cannot remember
 * is not a broken gate, it is a gate that asks again, so the caller reports the reason and
 * carries on rather than failing the session.
 */
export function savePasswordKey(roomId, passwordKey) {
  if (typeof roomId !== 'string' || !roomId) return 'there is no room id to file it under';
  if (!(passwordKey instanceof Uint8Array) || passwordKey.length !== KEY_BYTES) {
    return `a stretched password key must be ${KEY_BYTES} bytes, got `
      + `${passwordKey instanceof Uint8Array ? `${passwordKey.length} bytes` : typeof passwordKey}`;
  }
  const held = store();
  if (!held) return 'this browser is not offering per-tab storage';
  try {
    held.setItem(PREFIX + roomId, b64u.encode(passwordKey));
    return null;
  } catch (err) {
    // Quota, a disabled store, or a private mode that accepts the object and refuses the
    // write. All the same outcome, and the message is the only thing that distinguishes them.
    return err.message;
  }
}

/**
 * The p_key this tab filed for this room before it navigated away, or null.
 *
 * A record that is missing, undecodable or the wrong length is treated as absent AND
 * deleted: a resumed gate must never derive from a value it cannot vouch for, and leaving
 * the bad record would make every later reload of this room fail the same way.
 */
export function recallPasswordKey(roomId) {
  if (typeof roomId !== 'string' || !roomId) return null;
  const held = store();
  if (!held) return null;
  let raw;
  try {
    raw = held.getItem(PREFIX + roomId);
  } catch (err) {
    void err; // an unreadable store is an absent one; the reload falls through to prompting
    return null;
  }
  if (!raw) return null;
  let bytes = null;
  try {
    bytes = b64u.decode(raw);
  } catch (err) {
    void err; // corrupt record, handled identically to a wrong-length one below
  }
  if (!bytes || bytes.length !== KEY_BYTES) {
    forgetPasswordKey(roomId);
    return null;
  }
  return bytes;
}

/** Drop this room's record. Called on sever, on expiry and on any authentication failure. */
export function forgetPasswordKey(roomId) {
  if (typeof roomId !== 'string' || !roomId) return;
  const held = store();
  if (!held) return;
  try {
    held.removeItem(PREFIX + roomId);
  } catch (err) {
    void err; // nothing useful is available to a caller that is already tearing down
  }
}

/**
 * Drop every record this tab holds.
 *
 * For the paths that abandon a slot without ever building a Session to tear down: app.js
 * calls forgetSlot() when the server says the room is gone, and there is no session object
 * left at that point to route the wipe through.
 *
 * Indexed with length/key rather than Object.keys, because Storage exposes its contents
 * through that pair by specification and enumerating the object is an implementation
 * detail; and backwards, because removing an entry renumbers everything after it.
 */
export function forgetAllPasswordKeys() {
  const held = store();
  if (!held) return;
  try {
    for (let i = held.length - 1; i >= 0; i -= 1) {
      const name = held.key(i);
      if (typeof name === 'string' && name.startsWith(PREFIX)) held.removeItem(name);
    }
  } catch (err) {
    void err; // same as above: a store that will not enumerate cannot be swept
  }
}
