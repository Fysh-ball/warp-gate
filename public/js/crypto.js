// Warp Gate cryptography.
//
// Construction: pre-shared-key-authenticated ephemeral ECDH with explicit key
// confirmation. This is the shape of TLS 1.3 psk_dhe_ke and the Noise NNpsk0 pattern.
// Nothing here is novel; every primitive is a Web Crypto primitive.
//
//   S       128-bit room secret, lives only in the URL fragment and the QR code
//   room_id HKDF(S, "room-id")   server-visible, reveals nothing about S
//   k_sig   HKDF(S, "signal")    encrypts SDP and ICE so the server never sees an IP
//   Z       ECDH-P256 shared secret, ephemeral, gives forward secrecy
//   T       SHA-256 transcript binding the room and both public keys
//   master  HKDF-Extract(salt = S, ikm = Z)
//
// Keys are non-extractable CryptoKey objects wherever possible, so key bytes never
// enter the JS heap and dropping the reference is a real erasure (DESIGN.md 1.11).

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
  map.set('I', 1); map.set('L', 1); map.set('O', 0); map.set('U', map.get('V'));
  return map;
})();

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

export function base32Decode(text, byteLength) {
  const clean = String(text).toUpperCase().replace(/[^0-9A-Z]/g, '');
  const out = new Uint8Array(byteLength);
  let buffer = 0;
  let bits = 0;
  let i = 0;
  for (const ch of clean) {
    const value = DECODE_MAP.get(ch);
    if (value === undefined) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      if (i >= byteLength) return null;
      out[i] = (buffer >>> (bits - 8)) & 0xff;
      i += 1;
      bits -= 8;
    }
  }
  return i === byteLength ? out : null;
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

export const SECRET_BYTES = 16; // 128 bits
export const SECRET_CHARS = 26; // ceil(128 / 5)
export const ROOM_ID_CHARS = 8; // 40 bits

export function generateSecret() {
  return globalThis.crypto.getRandomValues(new Uint8Array(SECRET_BYTES));
}

/** Group a secret for display: WARP-XXXX-XXXX-XXXX-XXXX-XXXX-XX */
export function formatSecret(secret) {
  const raw = base32Encode(secret);
  return `WARP-${raw.match(/.{1,4}/g).join('-')}`;
}

/** Accept anything a human might type or paste back. */
export function parseSecret(text) {
  const stripped = String(text ?? '').toUpperCase().replace(/^.*?WARP[-\s]*/s, '').replace(/[^0-9A-Z]/g, '');
  if (stripped.length !== SECRET_CHARS) return null;
  return base32Decode(stripped, SECRET_BYTES);
}

async function hkdfKey(secretBytes) {
  return subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveBits', 'deriveKey']);
}

async function hkdfBits(ikmKey, salt, info, bits) {
  return new Uint8Array(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) },
    ikmKey,
    bits,
  ));
}

async function hkdfAesKey(ikmKey, salt, info) {
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) },
    ikmKey,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: the bytes never reach the JS heap
    ['encrypt', 'decrypt'],
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
    void err;
    const z = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256));
    const key = await subtle.importKey('raw', z, 'HKDF', false, ['deriveBits', 'deriveKey']);
    z.fill(0);
    return key;
  }
}

/**
 * Derive the whole session from the secret, our private key and the peer's public key.
 * `role` is 'a' for the room creator and 'b' for the joiner; it fixes the canonical
 * transcript order so both sides compute the same T.
 */
export async function deriveSession({ secret, privateKey, publicRaw, peerPublicRaw, role, roomId }) {
  const peerKey = await importPeerPublic(peerPublicRaw);
  const master = await masterFrom(privateKey, peerKey);

  const pkA = role === 'a' ? publicRaw : peerPublicRaw;
  const pkB = role === 'a' ? peerPublicRaw : publicRaw;
  const transcript = new Uint8Array(await subtle.digest(
    'SHA-256',
    concat(te.encode('wg/v1'), te.encode(roomId), pkA, pkB),
  ));

  const label = (name) => `${name}:${b64u.encode(transcript)}`;
  const salt = secret; // the PSK enters the schedule as the HKDF salt

  const [keyA2B, keyB2A, confA, confB, sasBits] = await Promise.all([
    hkdfAesKey(master, salt, label('wg/v1/data/a2b')),
    hkdfAesKey(master, salt, label('wg/v1/data/b2a')),
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

/** Constant-time comparison. Never short-circuit on the first differing byte. */
export function equalCt(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------- framing
//
// [0]     version
// [1]     type
// [2..9]  counter, uint64 big endian, per direction, strictly increasing
// [10..]  AES-256-GCM ciphertext and tag
//
// nonce = 4-byte direction constant || 8-byte counter. The key is per direction and
// the counter never repeats, so a (key, nonce) pair cannot recur.
// aad   = version || type || counter || roomHash, so a chunk cannot be replayed as chat.

export const HEADER_BYTES = 10;

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
    this.session = session;
    this.sendCounter = 0n;
    this.recvCounter = 0n;
    this.authFailures = 0;
  }

  async seal(type, plaintext) {
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

  /** Returns {type, plaintext} or throws. A throw means: drop the frame. */
  async open(frame) {
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
