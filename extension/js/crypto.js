// Warp Gate cryptography.
//
// Construction: pre-shared-key-authenticated ephemeral ECDH with explicit key
// confirmation. This is the shape of TLS 1.3 psk_dhe_ke and the Noise NNpsk0 pattern.
// Nothing here is novel; every primitive is a Web Crypto primitive.
//
//   code    8 words from a fixed 7776-word list, 103 bits, the part a human handles
//   S       128-bit room secret, PBKDF2(code, 600k), lives only in the fragment and QR
//   room_id HKDF(S, "room-id")   server-visible, reveals nothing about S
//   J       HKDF(S, "join")      proof of knowledge of S, presented to take slot B
//   k_sig   HKDF(S, "signal")    encrypts SDP and ICE so the server never sees an IP
//   Z       ECDH-P256 shared secret, ephemeral, gives forward secrecy
//   T       SHA-256 transcript binding the room and both public keys
//   master  HKDF-Extract(salt = S, ikm = Z)
//
// Keys are non-extractable CryptoKey objects wherever possible, so key bytes never
// enter the JS heap and dropping the reference is a real erasure (DESIGN.md 1.11).

// words.js is 61 KB of wordlist, a fifth of the gate's eager graph, and NOT reachable from
// here as a static import. It used to be: crypto.js imported decodeGateCode and re-exported
// eleven symbols, so every visitor fetched all 7776 words before the page could decide
// whether they were creating a gate, joining one, or reading the screen. Nothing needs the
// list until somebody types a code or arrives on a link, and both of those are decisions a
// person makes after the page is up.
//
// The accessor stays HERE rather than each caller importing words.js directly, so the rule
// that everything about a gate code arrives from one module survives the split: crypto.js
// still owns "code -> S", words.js still owns "text -> words" and knows nothing about keys.
// One promise, so eight callers share one fetch, and a failed fetch is not remembered as
// the answer.
let gateCodeModule = null;

/**
 * The gate-code vocabulary, fetched on first use.
 *
 * @returns {Promise<object>} the words.js namespace: generateGateCode, decodeGateCode,
 *   tryDecodeGateCode, GateCodeError, WORDS, WORD_COUNT, WORDLIST_SHA256, CODE_WORDS,
 *   randomWordIndices, encodeWordIndices, canonicalPhrase.
 */
export function loadGateCode() {
  if (!gateCodeModule) {
    gateCodeModule = import('./words.js').catch((err) => {
      gateCodeModule = null;
      throw new Error(`the gate code word list could not be loaded: ${err.message}`);
    });
  }
  return gateCodeModule;
}

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const VERSION = 0x01;

export const TYPE = {
  CHAT: 0x01,
  SECRET: 0x02,
  FILE_START: 0x10,
  FILE_CHUNK: 0x11,
  FILE_END: 0x12,
  CONTROL: 0x20,
};

const TYPE_NAMES = new Map(Object.entries(TYPE).map(([k, v]) => [v, k]));
export const typeName = (t) => TYPE_NAMES.get(t) ?? `UNKNOWN_0x${t.toString(16)}`;

// ---------------------------------------------------------------- encodings

// Crockford base32: no I, L, O or U, so the code cannot be misread aloud.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DECODE_MAP = (() => {
  const map = new Map();
  for (let i = 0; i < ALPHABET.length; i += 1) map.set(ALPHABET[i], i);
  // Accept the ambiguous characters on input, mapping them the way a human means them.
  // This is exactly the substitution Crockford's decoder specifies and no more: U is
  // NOT accepted as V, because nobody misreads "vee" as "you" and every extra alias is
  // another distinct spelling of the same secret.
  map.set('I', 1); map.set('L', 1); map.set('O', 0);
  return map;
})();

// The only characters that may appear between symbols. The UI emits hyphens and humans
// paste with surrounding whitespace; anything else is a typo, not a separator.
const SEPARATOR = /[-\s]/;

export function base32Encode(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/**
 * Decode exactly `byteLength` bytes, or return null.
 *
 * Kept as the inverse of base32Encode now that the gate code is words: base32Encode still
 * mints every room id, and an encoder whose output nothing can read back is an encoder
 * nothing can test. tests/crypto.test.mjs exercises the pair.
 *
 * Deliberately narrow. The previous version deleted every character outside [0-9A-Z]
 * before decoding, so a stray slash, dot or emoji was silently dropped and one secret
 * had a large family of accepted spellings. Here only the canonical alphabet, the three
 * Crockford aliases and the documented separators are accepted, the symbol count must be
 * exact, and the padding bits of the last symbol must be zero the way base32Encode
 * leaves them. Anything else is rejected rather than quietly reinterpreted.
 */
export function base32Decode(text, byteLength) {
  const expected = Math.ceil((byteLength * 8) / 5);
  const out = new Uint8Array(byteLength);
  let buffer = 0;
  let bits = 0;
  let i = 0;
  let symbols = 0;
  for (const ch of String(text)) {
    if (SEPARATOR.test(ch)) continue;
    // ASCII first, before any case mapping. Unicode default case conversion folds
    // characters outside the alphabet ONTO it: U+0131 dotless i uppercases to 'I' (so it
    // was accepted as 1) and U+017F long s uppercases to 'S'. Those are extra spellings
    // of a secret that the module documents as having none, so reject non-ASCII outright
    // rather than letting toUpperCase decide.
    const code = ch.codePointAt(0);
    if (code > 0x7f) return null;
    const value = DECODE_MAP.get(ch.toUpperCase());
    if (value === undefined) return null;
    symbols += 1;
    if (symbols > expected) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      if (i >= byteLength) return null;
      out[i] = (buffer >>> (bits - 8)) & 0xff;
      i += 1;
      bits -= 8;
    }
  }
  // Non-zero padding bits mean a different symbol encodes the same bytes: reject the
  // non-canonical spelling instead of accepting both.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null;
  return symbols === expected && i === byteLength ? out : null;
}

export const b64u = {
  encode(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(text) {
    const pad = text.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  },
};

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ---------------------------------------------------------------- the secret

export const SECRET_BYTES = 16; // 128 bits wide, 103 bits of entropy: see deriveSecret
export const ROOM_ID_CHARS = 8; // 40 bits

// S is never generated directly any more, and never displayed. It is derived from the
// gate code by deriveSecret below, and the gate code is the only form a human sees. The
// three functions that used to live here (generateSecret, formatSecret, parseSecret) were
// removed rather than kept as shims: they took and returned 16 raw bytes, which is no
// longer something a caller can round-trip through a display string, and a shim that
// still ran would have failed later and further away. A missing named export breaks the
// importing module at link time, loudly, which is the right failure for this change.

// ------------------------------------------------------- gate code -> room secret

/**
 * The gate code is stretched into S with PBKDF2-HMAC-SHA256, the same primitive and the
 * same iteration count the optional room password already uses (3.2a).
 *
 *   S = PBKDF2-HMAC-SHA256(phrase, salt = "wg/v1/gate-code", c = 600000, dkLen = 16)
 *
 * S stays 16 bytes because every derivation below expects 16 bytes, but its ENTROPY is
 * the code's 103.40 bits (8 words from 7776) and no amount of hashing invents more. The
 * stretch is what makes 103 acceptable. DESIGN.md 3.2 sets the bar: S must survive an
 * OFFLINE attack, because S also encrypts the SDP and ICE candidates, so recovering it
 * later reveals both peers' IP addresses. One PBKDF2 attempt at 600,000 iterations is
 * about 1.2 million SHA-256 compressions, near 2^20.2, so a full search costs
 * 2^103.4 * 2^20.2 = 2^123.6 compressions: the same order as the 2^128 the old base32
 * code offered, and out of reach of anything short of a state actor. The ONLINE bar from
 * 3.2 is about 40 bits, because a wrong guess fails key confirmation and destroys the
 * room, and 103 bits was never close to it.
 *
 * The salt is a FIXED domain-separation label, which is unusual for PBKDF2 and is forced
 * here: both devices must derive the same S from the code alone, and the code is the only
 * thing that travels, so there is no per-gate value to salt with that the far side also
 * holds. A fixed salt permits precomputation, one table reused against every gate ever
 * made. That table would have 7776^8 = 2^103 entries at 2^20.2 compressions each, so the
 * cost is theoretical rather than real. The label still separates this derivation from
 * the room password's, which salts with S and therefore genuinely is per gate.
 */
export const CODE_STRETCH_ITERATIONS = 600_000;

const CODE_STRETCH_SALT = te.encode('wg/v1/gate-code');

// 600,000 iterations is NOT free, and the number is worth writing down rather than
// guessing at: measured at 1030 to 1210 ms in node on this machine (i5-8350U, and it is
// linear, 60,000 iterations takes 119 ms), against 0.08 ms for a cache hit. A phone is
// slower still, so assume two to four seconds, which is a visible pause on a button
// press and needs a "working" state in the UI rather than a frozen button. It
// has to be paid once per code, and only once: the join path parses the same code more
// than once (app.js checks the fragment is a code, then startJoin parses it again, then a
// reload parses the copy in sessionStorage), and session.js calls deriveRoomId on three
// separate paths. Every one of those already holds S as bytes, so the ONLY re-derivation
// risk is re-parsing the code, which is exactly what this cache removes.
//
// What the cache costs: S stays in the JS heap for the life of the tab rather than for
// the life of the caller's reference. That is not a new exposure class, because S is a
// plain Uint8Array at every call site anyway (assertSecret requires one), but it is a
// longer lifetime, so clearSecretCache() exists and the gate teardown path should call
// it. The map is capped so that a caller looping over codes cannot grow it without
// bound. Promises are cached, not values, so two concurrent calls share one derivation
// instead of running PBKDF2 twice; a rejected derivation is evicted so a transient
// failure is not remembered as the answer.
const SECRET_CACHE = new Map();
const SECRET_CACHE_MAX = 8;

/**
 * Gate code (or a whole link, or anything a human pasted) -> S.
 *
 * Throws GateCodeError with a `reason` and a message naming what is wrong with the code.
 * The returned array is a fresh copy on every call, so a caller that zeroes or mutates
 * its own secret cannot corrupt anybody else's.
 */
export async function deriveSecret(code) {
  const { decodeGateCode } = await loadGateCode();
  const { code: canonical, phrase } = decodeGateCode(code);

  const existing = SECRET_CACHE.get(canonical);
  if (existing) return (await existing).slice();

  const pending = (async () => {
    const material = await subtle.importKey('raw', te.encode(phrase), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: CODE_STRETCH_SALT, iterations: CODE_STRETCH_ITERATIONS },
      material,
      SECRET_BYTES * 8,
    ));
  })();
  // Attached before the await so a rejection is never unhandled, and so a failed
  // derivation leaves nothing behind to be served as an answer next time.
  pending.catch(() => SECRET_CACHE.delete(canonical));

  SECRET_CACHE.set(canonical, pending);
  if (SECRET_CACHE.size > SECRET_CACHE_MAX) SECRET_CACHE.delete(SECRET_CACHE.keys().next().value);

  return (await pending).slice();
}

/** Drop every stretched secret this tab is holding. Call it when a gate ends. */
export function clearSecretCache() {
  SECRET_CACHE.clear();
}

/**
 * Optional room password, stretched and bound to this specific room.
 *
 * This is not the trap DESIGN.md 1.5 warns about. There the objection was to a
 * password used as the ONLY secret, which an observer of the signalling channel can
 * attack offline. Here the 128-bit link secret is always present and always required;
 * the password is a second factor for the case where the link itself leaks, for
 * example when it is pasted into a group chat. PBKDF2 with a high iteration count
 * makes that residual offline attack expensive rather than free.
 *
 * Salted with the room secret, so a rainbow table cannot be shared across rooms.
 */
export const PBKDF2_ITERATIONS = 600_000;

export async function derivePasswordKey(password, secret) {
  if (!password) return null;
  assertSecret(secret);
  // NFC, per the RFC 8265 OpaqueString profile. "café" and "café" render
  // identically and a user types whichever their keyboard emits, but unnormalised they
  // are different byte strings and derive different keys, so the two devices fail
  // verification with no visible cause. OpaqueString normalises and deliberately does
  // NOT trim: a space inside or around a password is a character the user chose.
  const material = await subtle.importKey('raw', te.encode(String(password).normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: concat(secret, te.encode('wg/v1/password')), iterations: PBKDF2_ITERATIONS },
    material,
    256,
  ));
}

/**
 * The link secret is the PSK that authenticates the whole handshake. Every derivation
 * below feeds it in as HKDF key material or as an HKDF salt, and Web Crypto accepts
 * `undefined` and any length silently for a salt: `deriveSession` with `secret:
 * undefined` returned a perfectly usable session with NO pre-shared key in it, which is
 * unauthenticated ECDH wearing this module's interface. A caller that gets the secret
 * wrong must fail here, loudly, not derive a weaker thing that still works.
 */
function assertSecret(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== SECRET_BYTES) {
    throw new TypeError(`link secret must be ${SECRET_BYTES} bytes, got ${secret instanceof Uint8Array ? `${secret.length} bytes` : typeof secret}`);
  }
  return secret;
}

async function hkdfKey(secretBytes) {
  return subtle.importKey('raw', assertSecret(secretBytes), 'HKDF', false, ['deriveBits', 'deriveKey']);
}

async function hkdfBits(ikmKey, salt, info, bits) {
  return new Uint8Array(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) },
    ikmKey,
    bits,
  ));
}

// A data key is used in exactly one direction, so it is granted exactly one usage. Web
// Crypto then refuses the misuse outright instead of leaving it to the direction
// constant and the counter to make it harmless. The signalling key is genuinely
// bidirectional and keeps both.
async function hkdfAesKey(ikmKey, salt, info, usages = ['encrypt', 'decrypt']) {
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) },
    ikmKey,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: the bytes never reach the JS heap
    usages,
  );
}

const EMPTY = new Uint8Array(0);

export async function deriveRoomId(secret) {
  const bits = await hkdfBits(await hkdfKey(secret), EMPTY, 'wg/v1/room-id', 40);
  return base32Encode(bits);
}

/** Key that encrypts the signalling envelopes, so the server never sees an SDP. */
export async function deriveSignalKey(secret) {
  return hkdfAesKey(await hkdfKey(secret), EMPTY, 'wg/v1/signal');
}

// ---------------------------------------------------------------- join proof
//
// The room id is server-visible by design: it is sent in plaintext on every request. So
// on its own it cannot be allowed to buy a slot, or anyone who watches the signalling
// server can consume slot B and lock the real peer out of a gate they hold the link to.
//
// J = HKDF(S, "wg/v1/join") is a second derivation of the same secret. The creator
// registers H = SHA-256(J) at create time and a joiner presents J. Both are one-way
// derivations of S, so the server gains nothing it can decrypt with: the link secret,
// the signalling key and every session key remain unreachable from H and J alike.

async function joinProofBytes(secret) {
  return hkdfBits(await hkdfKey(secret), EMPTY, 'wg/v1/join', 128);
}

/** J, base64url, 22 characters. Presented by the joiner. */
export async function deriveJoinProof(secret) {
  return b64u.encode(await joinProofBytes(secret));
}

/** H = SHA-256(J), base64url, 43 characters. Registered by the creator. */
export async function deriveJoinProofHash(secret) {
  const digest = await subtle.digest('SHA-256', await joinProofBytes(secret));
  return b64u.encode(new Uint8Array(digest));
}

// ---------------------------------------------------------------- handshake

export async function generateKeyPair() {
  // extractable=false applies to the private key; the public key is always
  // exportable per the Web Crypto spec. If a engine disagrees, fall back loudly.
  try {
    const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits', 'deriveKey']);
    const raw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
    return { privateKey: pair.privateKey, publicRaw: raw, privateExtractable: false };
  } catch (err) {
    const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey']);
    const raw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
    return { privateKey: pair.privateKey, publicRaw: raw, privateExtractable: true, degradedReason: err.message };
  }
}

// ---------------------------------------------------------------- key commitment
//
// THE ATTACK THIS EXISTS TO STOP, stated plainly because a commitment with no attack
// written next to it is the first thing a later reader deletes as ceremony.
//
// Before this, both sides sent their ephemeral public key unconditionally, with nothing
// sent before it, and the SAS is SHA-256 over a transcript of BOTH keys reduced to five
// decimal digits. An attacker on the relay path who also holds the gate code (so it holds
// k_sig and can open and re-seal every envelope) could therefore hold both real public
// keys, having committed to nothing, and then GRIND: generate ~316 candidate keypairs to
// face A and ~316 to face B, compute the 100000 resulting transcript pairs, and by the
// birthday bound find one where sas(pk_A, m_i) equals sas(m'_j, pk_B). Both victims then
// derive keys against the attacker, both key confirmations pass because it holds the gate
// code, and both humans read the SAME five digits and the SAME two words. About 640 curve
// operations and 100000 hashes: well under a second.
//
// The spoken word pair adds nothing against this and must never be believed to. It is a
// bijective re-encoding of the same five digits (saswords.js), so matching digits imply
// matching words with certainty. That is deliberate, and it is why widening the SAS is not
// the fix here.
//
// The fix is order. The initiator publishes H(pk_A) BEFORE it has seen pk_B and cannot
// change pk_A afterwards, so the attacker must fix its A-facing key before it sees pk_B
// and its B-facing key before it sees pk_A. There is nothing left to grind: the birthday
// search collapses to one blind online 1-in-100000 guess, with no retry, because a wrong
// guess is a gate the humans visibly fail.
//
// The label is domain-separated from every other hash in this file for the usual reason:
// a commitment that could be confused with a transcript or a join proof is a commitment
// to something else.
const PKC_LABEL = 'wg/v1/pkc';

/**
 * H = SHA-256("wg/v1/pkc" || pk). The value the initiator publishes before pk itself.
 *
 * Binding, which is the property that matters here: finding a second 65-byte point with
 * the same digest is a SHA-256 collision. Hiding does not matter and is not claimed: pk is
 * a public key and the attacker learns it one message later anyway.
 */
export async function commitPublicKey(publicRaw) {
  if (!(publicRaw instanceof Uint8Array) || publicRaw.length !== 65) {
    throw new TypeError(`a public key commitment needs a 65-byte uncompressed point, got ${publicRaw?.length}`);
  }
  return new Uint8Array(await subtle.digest('SHA-256', concat(te.encode(PKC_LABEL), publicRaw)));
}

export async function importPeerPublic(raw) {
  if (!(raw instanceof Uint8Array) || raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error(`peer public key is not an uncompressed P-256 point (${raw?.length} bytes)`);
  }
  return subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}

/** master = HKDF-Extract(salt = S, ikm = Z), with Z kept out of the JS heap if possible. */
async function masterFrom(privateKey, peerPublicKey) {
  try {
    return await subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      privateKey,
      { name: 'HKDF' },
      false,
      ['deriveBits', 'deriveKey'],
    );
  } catch (err) {
    // Some engines refuse ECDH -> HKDF directly. Falling back means the shared secret
    // briefly exists as bytes; correctness is unaffected.
    let z;
    try {
      z = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256));
      const key = await subtle.importKey('raw', z, 'HKDF', false, ['deriveBits', 'deriveKey']);
      return key;
    } catch (fallbackErr) {
      // Both routes failed. Carry both messages: the first one is usually the real
      // diagnosis and swallowing it leaves "key agreement failed" with no cause.
      throw new Error(`ECDH key agreement failed (direct: ${err.message}; via raw bits: ${fallbackErr.message})`);
    } finally {
      z?.fill(0);
    }
  }
}

/**
 * Derive the whole session from the secret, our private key and the peer's public key.
 * `role` is 'a' for the room creator and 'b' for the joiner; it fixes the canonical
 * transcript order so both sides compute the same T.
 */
export async function deriveSession({ secret, privateKey, publicRaw, peerPublicRaw, role, roomId, passwordKey = null }) {
  assertSecret(secret);
  // Anything that is not exactly 'a' used to fall through to 'b'. Two peers that both
  // defaulted to 'b' would fail closed, so this was never a break, but a typo in a role
  // silently chose a direction constant and a transcript order rather than reporting it.
  if (role !== 'a' && role !== 'b') throw new TypeError(`role must be 'a' or 'b', got ${JSON.stringify(role)}`);
  if (typeof roomId !== 'string' || roomId.length === 0) {
    throw new TypeError(`roomId must be a non-empty string, got ${typeof roomId}`);
  }
  if (!(publicRaw instanceof Uint8Array) || publicRaw.length !== 65) {
    throw new TypeError(`our own public key must be a 65-byte uncompressed point, got ${publicRaw?.length}`);
  }
  if (passwordKey !== null && !(passwordKey instanceof Uint8Array)) {
    throw new TypeError('passwordKey must be null or a Uint8Array');
  }
  const peerKey = await importPeerPublic(peerPublicRaw);
  // A signalling server that reflects our own public key back at us as "the peer" gets a
  // valid self-ECDH out of it. That already fails at key confirmation, because conf/a and
  // conf/b are separate labels and the reflected value never matches the one we expect
  // (proved by probe), but a peer key equal to ours is never legitimate and there is no
  // reason to carry it as far as the confirmation step.
  if (equalCt(publicRaw, peerPublicRaw)) {
    throw new Error('peer public key is identical to our own: the signalling channel reflected our key back');
  }
  const master = await masterFrom(privateKey, peerKey);

  const pkA = role === 'a' ? publicRaw : peerPublicRaw;
  const pkB = role === 'a' ? peerPublicRaw : publicRaw;
  const transcript = new Uint8Array(await subtle.digest(
    'SHA-256',
    concat(te.encode('wg/v1'), te.encode(roomId), pkA, pkB),
  ));

  const label = (name) => `${name}:${b64u.encode(transcript)}`;
  // The PSK enters the schedule as the HKDF salt. When a room password is set, its
  // stretched form is appended, so both the link and the password are required to
  // derive the same data keys and the same confirmation values.
  const salt = passwordKey ? concat(secret, passwordKey) : secret;

  // Each data key is granted only the usage its owner needs: A encrypts on a2b and
  // decrypts on b2a, B the other way round.
  const a2bUsage = role === 'a' ? ['encrypt'] : ['decrypt'];
  const b2aUsage = role === 'a' ? ['decrypt'] : ['encrypt'];
  const [keyA2B, keyB2A, confA, confB, sasBits] = await Promise.all([
    hkdfAesKey(master, salt, label('wg/v1/data/a2b'), a2bUsage),
    hkdfAesKey(master, salt, label('wg/v1/data/b2a'), b2aUsage),
    hkdfBits(master, salt, label('wg/v1/conf/a'), 256),
    hkdfBits(master, salt, label('wg/v1/conf/b'), 256),
    hkdfBits(master, salt, label('wg/v1/sas'), 64),
  ]);

  const view = new DataView(sasBits.buffer, sasBits.byteOffset, sasBits.byteLength);
  const sas = String(view.getUint32(0) % 100000).padStart(5, '0');

  const roomHash = (await subtle.digest('SHA-256', te.encode(roomId))).slice(0, 8);

  return {
    sendKey: role === 'a' ? keyA2B : keyB2A,
    recvKey: role === 'a' ? keyB2A : keyA2B,
    sendDir: role === 'a' ? 1 : 2,
    recvDir: role === 'a' ? 2 : 1,
    confirmMine: role === 'a' ? confA : confB,
    confirmPeer: role === 'a' ? confB : confA,
    transcript,
    roomHash: new Uint8Array(roomHash),
    sas,
  };
}

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
}

/**
 * Constant-time comparison of two byte sequences. Never short-circuits on the first
 * differing byte.
 *
 * Byte-like input ONLY. On strings a[i] ^ b[i] is NaN, and `diff |= NaN` is 0, so a
 * character-wise version answered true for every unequal pair: equalCt('abc','abd') was
 * true. A constant-time compare that says "equal" for different input is worse than no
 * compare at all, so anything that is not a Uint8Array or an ArrayBuffer is a
 * programming error and throws rather than producing an answer.
 */
export function equalCt(a, b) {
  const va = asBytes(a);
  const vb = asBytes(b);
  if (va === null || vb === null) {
    throw new TypeError('equalCt needs byte-like input (Uint8Array or ArrayBuffer)');
  }
  if (va.length !== vb.length) return false;
  let diff = 0;
  for (let i = 0; i < va.length; i += 1) diff |= va[i] ^ vb[i];
  return diff === 0;
}

// ---------------------------------------------------------------- framing
//
// [0]     version
// [1]     type
// [2..9]  counter, uint64 big endian, per direction, strictly increasing
// [10..]  AES-256-GCM ciphertext and tag
//
// nonce = 4-byte direction constant || 8-byte counter.
// aad   = version || type || counter || roomHash, so a chunk cannot be replayed as chat.
//
// A (key, nonce) pair cannot recur, and that rests on three separate facts, none of
// which is free:
//   1. the two directions use different keys AND different direction constants, so the
//      counters may coincide across directions;
//   2. within one Channel the counter only ever increases, and seal() refuses to pass
//      COUNTER_MAX rather than letting setBigUint64 wrap it to 0;
//   3. a counter that restarts at 0 only ever accompanies a key that has never been used,
//      enforced by KEYS_IN_USE here and by the link layer dropping sessionKeys and
//      keyPair together, so every new Channel follows a new ECDH exchange.

export const HEADER_BYTES = 10;

// The counter is the entire nonce beyond the direction constant, so it may never repeat
// under one key. DataView.setBigUint64 truncates modulo 2^64 instead of throwing, so
// without an explicit ceiling a sendCounter of 2^64 writes 0 onto the wire and the very
// first nonce of the session is used a second time. Unreachable in practice at any real
// frame rate, but the failure is total and the guard is one comparison.
const COUNTER_MAX = (1n << 64n) - 1n;

// Every AES-GCM key here is used with a counter that restarts at 0 in a fresh Channel, so
// a key may belong to at most one Channel, ever. Two Channels over one derived session
// produce byte-identical frames: the same key, the same nonce, the same keystream, and
// XORing two such ciphertexts returns the XOR of the two plaintexts. That is the one
// catastrophic failure this design can have.
//
// Nothing in the app does this today. deriveSession runs once per ephemeral key pair and
// the link layer drops sessionKeys and keyPair together on every renegotiation and
// teardown, so a new Channel always follows a new ECDH exchange and therefore a new key.
// This guard exists so that a future reconnect or resume path that keeps the keys and
// rebuilds the Channel fails with an exception instead of silently publishing the
// keystream twice.
//
// It is keyed on CryptoKey object identity, so it catches a reused session object and any
// shallow copy of one. It does NOT catch calling deriveSession twice with identical
// inputs, which yields equal key bytes in fresh objects; that is prevented upstream by
// the ephemeral key pair being regenerated on every handshake.
const KEYS_IN_USE = new WeakSet();

function nonceFor(dir, counter) {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(0, dir);
  new DataView(nonce.buffer).setBigUint64(4, counter);
  return nonce;
}

function aadFor(type, counter, roomHash) {
  const aad = new Uint8Array(18);
  aad[0] = VERSION;
  aad[1] = type;
  new DataView(aad.buffer).setBigUint64(2, counter);
  aad.set(roomHash, 10);
  return aad;
}

export class Channel {
  constructor(session) {
    // Keyed on the CryptoKey objects rather than on the session object, because that is
    // what the nonce is actually paired with: a shallow copy of the session carries the
    // same keys and would be just as fatal.
    for (const [name, key] of [['send', session?.sendKey], ['recv', session?.recvKey]]) {
      if (!key) throw new TypeError(`session is missing a ${name} key`);
      if (KEYS_IN_USE.has(key)) {
        throw new Error(`this session's ${name} key already belongs to a Channel; derive a fresh session rather than reusing keys with a counter that restarts at zero`);
      }
    }
    KEYS_IN_USE.add(session.sendKey);
    KEYS_IN_USE.add(session.recvKey);

    this.session = session;
    this.sendCounter = 0n;
    this.recvCounter = 0n;
    this.authFailures = 0;
    // One decrypt in flight at a time. See open().
    this.openQueue = Promise.resolve();
  }

  async seal(type, plaintext) {
    if (this.sendCounter >= COUNTER_MAX) {
      throw new Error(`send counter exhausted at ${COUNTER_MAX}: this key can seal no further frames`);
    }
    this.sendCounter += 1n;
    const counter = this.sendCounter;
    const { sendKey, sendDir, roomHash } = this.session;
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: nonceFor(sendDir, counter), additionalData: aadFor(type, counter, roomHash), tagLength: 128 },
      sendKey,
      plaintext,
    ));
    const frame = new Uint8Array(HEADER_BYTES + ct.length);
    frame[0] = VERSION;
    frame[1] = type;
    new DataView(frame.buffer).setBigUint64(2, counter);
    frame.set(ct, HEADER_BYTES);
    return frame;
  }

  /**
   * Returns {type, plaintext} or throws. A throw means: drop the frame.
   *
   * Serialised, because the replay guard straddles an await: the counter is checked
   * before subtle.decrypt and assigned after it. Two frames decrypting at once
   * interleave, the lower counter is assigned last, recvCounter regresses, and the
   * higher frame can then be replayed and accepted a second time. Frames are delivered
   * from a DataChannel event listener, so concurrent opens are the normal path rather
   * than an edge case.
   *
   * Chaining every open through one promise makes check-decrypt-assign atomic per
   * Channel and leaves the AEAD semantics exactly as they were: a frame that fails to
   * authenticate never advances the counter, and a frame that authenticates can never
   * be accepted twice.
   */
  async open(frame) {
    const attempt = this.openQueue.then(() => this.openOne(frame));
    // The chain must survive a dropped frame, or every frame queued behind a rejected
    // one would be rejected with it.
    this.openQueue = attempt.then(() => undefined, () => undefined);
    return attempt;
  }

  /** The body of open(). Never call this directly: open() holds the lock. */
  async openOne(frame) {
    const bytes = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
    if (bytes.length < HEADER_BYTES + 16) throw new Error(`frame too short: ${bytes.length} bytes`);
    if (bytes[0] !== VERSION) throw new Error(`unsupported frame version ${bytes[0]}`);
    const type = bytes[1];
    const counter = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(2);

    // Replay and reorder both die here. The DataChannel is ordered and reliable, so
    // a counter that does not advance is an attack or a bug, never normal traffic.
    if (counter <= this.recvCounter) {
      throw new Error(`replay or reorder: counter ${counter} after ${this.recvCounter}`);
    }

    const { recvKey, recvDir, roomHash } = this.session;
    let plaintext;
    try {
      plaintext = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: nonceFor(recvDir, counter), additionalData: aadFor(type, counter, roomHash), tagLength: 128 },
        recvKey,
        bytes.subarray(HEADER_BYTES),
      ));
    } catch (err) {
      this.authFailures += 1;
      throw new Error(`authentication failed on ${typeName(type)} frame: ${err.message || 'bad tag'}`);
    }

    this.recvCounter = counter;
    return { type, plaintext };
  }

  async sealJson(type, value) {
    return this.seal(type, te.encode(JSON.stringify(value)));
  }
}

export const decodeJson = (bytes) => JSON.parse(td.decode(bytes));
export const decodeText = (bytes) => td.decode(bytes);
export const encodeText = (text) => te.encode(text);

// ---------------------------------------------------------------- signalling envelope

export async function sealEnvelope(key, value) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: te.encode('wg/v1/signal'), tagLength: 128 },
    key,
    te.encode(JSON.stringify(value)),
  ));
  return { n: b64u.encode(iv), c: b64u.encode(ct) };
}

export async function openEnvelope(key, envelope) {
  const iv = b64u.decode(envelope.n);
  const ct = b64u.decode(envelope.c);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: te.encode('wg/v1/signal'), tagLength: 128 },
    key,
    ct,
  );
  return JSON.parse(td.decode(pt));
}
