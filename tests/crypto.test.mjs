// Cryptographic verification.
//
// The point of this file is that it does NOT trust public/js/crypto.js. The expected
// values are recomputed with node:crypto's classic APIs (createECDH, hkdfSync,
// createDecipheriv) straight from RFC 5869 and the key schedule in DESIGN.md 3.3.
// Agreement between two independent implementations is evidence; a module agreeing
// with itself is not.

import crypto from 'node:crypto';
import { check, summary } from './lib/harness.mjs';
import {
  base32Encode, base32Decode, b64u, generateSecret, formatSecret, parseSecret,
  deriveRoomId, deriveSignalKey, generateKeyPair, deriveSession, Channel,
  sealEnvelope, openEnvelope, equalCt, TYPE, VERSION, HEADER_BYTES, decodeJson,
} from '../public/js/crypto.js';
import {
  canAccept, createSink, sanitizeFilename, MEMORY_LIMIT_BYTES,
} from '../public/js/transfer.js';

const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;
const b64uNode = (buf) => Buffer.from(buf).toString('base64url');

// ---------------------------------------------------------------- encodings
{
  const vectors = [
    [[0x00], '00'],
    [[0xff], 'ZW'],
    [[0x00, 0x00, 0x00, 0x00, 0x00], '00000000'],
    [[0xff, 0xff, 0xff, 0xff, 0xff], 'ZZZZZZZZ'],
  ];
  let allOk = true;
  for (const [bytes, expected] of vectors) {
    const got = base32Encode(Uint8Array.from(bytes));
    if (got !== expected) { allOk = false; process.stdout.write(`     vector ${bytes} -> ${got}, expected ${expected}\n`); }
  }
  check('base32 matches hand-computed vectors', allOk);

  let roundTrips = true;
  for (let i = 0; i < 200; i += 1) {
    const bytes = crypto.randomBytes(16);
    const back = base32Decode(base32Encode(bytes), 16);
    if (!back || !Buffer.from(back).equals(bytes)) { roundTrips = false; break; }
  }
  check('base32 round-trips 200 random 128-bit secrets', roundTrips);

  check('base32 alphabet excludes the ambiguous letters I L O U',
    !/[ILOU]/.test(base32Encode(Uint8Array.from(Array.from({ length: 64 }, (_, i) => i * 4 % 256)))));

  const secret = generateSecret();
  check('a generated secret is 128 bits', secret.length === 16);
  const formatted = formatSecret(secret);
  check('formatted secret has the documented shape', /^WARP(-[0-9A-Z]{1,4}){7}$/.test(formatted), formatted);
  check('a formatted secret parses back to the same bytes',
    Buffer.from(parseSecret(formatted)).equals(Buffer.from(secret)));
  check('a secret parses out of a full URL',
    Buffer.from(parseSecret(`https://warpgate.fysh.site/#${formatted}`)).equals(Buffer.from(secret)));
  check('a secret parses when typed lower case with stray spaces',
    Buffer.from(parseSecret(` ${formatted.toLowerCase()} `)).equals(Buffer.from(secret)));
  check('a truncated secret is rejected', parseSecret(formatted.slice(0, -1)) === null);
  check('garbage is rejected', parseSecret('hello world') === null);

  let b64ok = true;
  for (let i = 0; i < 100; i += 1) {
    const bytes = crypto.randomBytes(1 + (i % 40));
    if (!Buffer.from(b64u.decode(b64u.encode(bytes))).equals(bytes)) { b64ok = false; break; }
  }
  check('base64url round-trips', b64ok);
}

// ---------------------------------------------------------------- HKDF vs node
{
  const secret = generateSecret();

  const roomId = await deriveRoomId(secret);
  const expectedRoomBytes = crypto.hkdfSync('sha256', secret, Buffer.alloc(0), te.encode('wg/v1/room-id'), 5);
  const expectedRoomId = base32Encode(new Uint8Array(expectedRoomBytes));
  check('room id matches an independent RFC 5869 HKDF', roomId === expectedRoomId, `${roomId} vs ${expectedRoomId}`);
  check('room id is 8 Crockford characters', /^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}$/.test(roomId), roomId);

  // The server-visible room id must not leak the secret.
  const other = generateSecret();
  check('a different secret yields a different room id', (await deriveRoomId(other)) !== roomId);

  // Signalling key: verify by decrypting a real envelope with independently derived bytes.
  const sigKey = await deriveSignalKey(secret);
  const envelope = await sealEnvelope(sigKey, { t: 'offer', sdp: 'v=0 fake' });
  const expectedSigBytes = crypto.hkdfSync('sha256', secret, Buffer.alloc(0), te.encode('wg/v1/signal'), 32);
  const iv = Buffer.from(b64u.decode(envelope.n));
  const ct = Buffer.from(b64u.decode(envelope.c));
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(expectedSigBytes), iv);
  decipher.setAAD(Buffer.from('wg/v1/signal'));
  decipher.setAuthTag(ct.subarray(ct.length - 16));
  const plain = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
  check('signalling envelope decrypts with an independently derived key',
    JSON.parse(plain.toString('utf8')).sdp === 'v=0 fake');

  const roundTrip = await openEnvelope(sigKey, envelope);
  check('envelope round-trips through our own code', roundTrip.t === 'offer');

  const wrongKey = await deriveSignalKey(other);
  const wrongResult = await openEnvelope(wrongKey, envelope).then(() => 'decrypted', (e) => e.name);
  check('an envelope will not open under the wrong secret', wrongResult !== 'decrypted', String(wrongResult));

  const tampered = { n: envelope.n, c: b64u.encode((() => { const c = b64u.decode(envelope.c); c[0] ^= 1; return c; })()) };
  const tamperResult = await openEnvelope(sigKey, tampered).then(() => 'decrypted', (e) => e.name);
  check('a tampered envelope fails authentication', tamperResult !== 'decrypted', String(tamperResult));
}

// ---------------------------------------------------------------- handshake
{
  const kp = await generateKeyPair();
  check('the ECDH private key is non-extractable', kp.privateExtractable === false, kp.degradedReason ?? '');
  check('the public key is an uncompressed P-256 point', kp.publicRaw.length === 65 && kp.publicRaw[0] === 0x04);

  const secret = generateSecret();
  const roomId = await deriveRoomId(secret);
  const a = await generateKeyPair();
  const b = await generateKeyPair();

  const sessionA = await deriveSession({ secret, privateKey: a.privateKey, publicRaw: a.publicRaw, peerPublicRaw: b.publicRaw, role: 'a', roomId });
  const sessionB = await deriveSession({ secret, privateKey: b.privateKey, publicRaw: b.publicRaw, peerPublicRaw: a.publicRaw, role: 'b', roomId });

  check('both peers compute the same transcript',
    Buffer.from(sessionA.transcript).equals(Buffer.from(sessionB.transcript)));
  check('both peers compute the same SAS', sessionA.sas === sessionB.sas, `${sessionA.sas} vs ${sessionB.sas}`);
  check('the SAS is 5 decimal digits', /^[0-9]{5}$/.test(sessionA.sas), sessionA.sas);
  check("each peer's confirmation is the other's expected value",
    equalCt(sessionA.confirmMine, sessionB.confirmPeer) && equalCt(sessionB.confirmMine, sessionA.confirmPeer));
  check('the two confirmation values differ from each other',
    !equalCt(sessionA.confirmMine, sessionA.confirmPeer));
  check('send and receive directions are opposite', sessionA.sendDir === sessionB.recvDir && sessionA.recvDir === sessionB.sendDir);

  // --- full independent recomputation of the schedule with node:crypto
  const ecdhA = crypto.createECDH('prime256v1');
  ecdhA.generateKeys();
  const ecdhB = crypto.createECDH('prime256v1');
  ecdhB.generateKeys();

  const toJwk = (ecdh) => {
    const pub = ecdh.getPublicKey();
    return {
      kty: 'EC', crv: 'P-256', ext: true,
      d: b64uNode(ecdh.getPrivateKey()),
      x: b64uNode(pub.subarray(1, 33)),
      y: b64uNode(pub.subarray(33, 65)),
    };
  };
  const importPriv = (ecdh) => subtle.importKey('jwk', toJwk(ecdh), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits', 'deriveKey']);

  const privA = await importPriv(ecdhA);
  const pubA = new Uint8Array(ecdhA.getPublicKey());
  const pubB = new Uint8Array(ecdhB.getPublicKey());
  const roomId2 = await deriveRoomId(secret);

  const sess = await deriveSession({ secret, privateKey: privA, publicRaw: pubA, peerPublicRaw: pubB, role: 'a', roomId: roomId2 });

  // Independent: Z, T and the expanded keys, computed straight from the spec.
  const z = ecdhA.computeSecret(ecdhB.getPublicKey());
  const transcript = crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from('wg/v1'), Buffer.from(roomId2), pubA, pubB]))
    .digest();
  check('transcript matches an independent SHA-256',
    Buffer.from(sess.transcript).equals(transcript));

  const label = (name) => `${name}:${transcript.toString('base64url')}`;
  const expectA2B = Buffer.from(crypto.hkdfSync('sha256', z, secret, te.encode(label('wg/v1/data/a2b')), 32));
  const expectConfA = Buffer.from(crypto.hkdfSync('sha256', z, secret, te.encode(label('wg/v1/conf/a')), 32));
  const expectSas = Buffer.from(crypto.hkdfSync('sha256', z, secret, te.encode(label('wg/v1/sas')), 8));

  check('confirmation value matches an independent HKDF',
    Buffer.from(sess.confirmMine).equals(expectConfA));
  check('SAS matches an independent HKDF',
    sess.sas === String(expectSas.readUInt32BE(0) % 100000).padStart(5, '0'));

  // The strongest check: a frame sealed by our Channel decrypts under a key that was
  // never produced by our code, with the nonce and AAD taken from DESIGN.md 3.4.
  const channel = new Channel(sess);
  const frame = await channel.seal(TYPE.CHAT, te.encode('independent verification'));
  const counter = Buffer.from(frame.subarray(2, 10));
  const nonce = Buffer.concat([Buffer.from([0, 0, 0, sess.sendDir]), counter]);
  const aad = Buffer.concat([Buffer.from([VERSION, TYPE.CHAT]), counter, Buffer.from(sess.roomHash)]);
  const body = Buffer.from(frame.subarray(HEADER_BYTES));
  const dec = crypto.createDecipheriv('aes-256-gcm', expectA2B, nonce);
  dec.setAAD(aad);
  dec.setAuthTag(body.subarray(body.length - 16));
  const out = Buffer.concat([dec.update(body.subarray(0, body.length - 16)), dec.final()]);
  check('a sealed frame decrypts under an independently derived key, nonce and AAD',
    out.toString('utf8') === 'independent verification', out.toString('utf8'));
}

// ---------------------------------------------------------------- the MITM case
{
  const roomId = await deriveRoomId(generateSecret());
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const rightSecret = generateSecret();
  const wrongSecret = generateSecret();

  const sessionA = await deriveSession({ secret: rightSecret, privateKey: a.privateKey, publicRaw: a.publicRaw, peerPublicRaw: b.publicRaw, role: 'a', roomId });
  const sessionB = await deriveSession({ secret: wrongSecret, privateKey: b.privateKey, publicRaw: b.publicRaw, peerPublicRaw: a.publicRaw, role: 'b', roomId });

  check('a peer with the wrong secret computes a different confirmation',
    !equalCt(sessionA.confirmMine, sessionB.confirmPeer),
    'key confirmation would have passed with a mismatched secret');
  check('a peer with the wrong secret computes a different SAS', sessionA.sas !== sessionB.sas);

  const chanA = new Channel(sessionA);
  const chanB = new Channel(sessionB);
  const frame = await chanA.seal(TYPE.CHAT, te.encode('secret message'));
  const result = await chanB.open(frame).then(() => 'decrypted', (e) => e.message);
  check('a peer with the wrong secret cannot decrypt: failure is explicit, not garbage',
    result !== 'decrypted' && /authentication failed/.test(result), String(result));
}

// ---------------------------------------------------------------- frame integrity
{
  const secret = generateSecret();
  const roomId = await deriveRoomId(secret);
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const sA = await deriveSession({ secret, privateKey: a.privateKey, publicRaw: a.publicRaw, peerPublicRaw: b.publicRaw, role: 'a', roomId });
  const sB = await deriveSession({ secret, privateKey: b.privateKey, publicRaw: b.publicRaw, peerPublicRaw: a.publicRaw, role: 'b', roomId });

  const send = new Channel(sA);
  const recv = new Channel(sB);

  const f1 = await send.seal(TYPE.CHAT, te.encode('one'));
  const r1 = await recv.open(f1);
  check('a chat frame decrypts across the pair',
    r1.type === TYPE.CHAT && Buffer.from(r1.plaintext).toString() === 'one');

  const f2 = await send.sealJson(TYPE.CONTROL, { kind: 'ping', n: 2 });
  const r2 = await recv.open(f2);
  check('a JSON control frame round-trips', decodeJson(r2.plaintext).kind === 'ping');

  const replay = await recv.open(f1).then(() => 'accepted', (e) => e.message);
  check('replaying an earlier frame is rejected', /replay or reorder/.test(String(replay)), String(replay));

  // Type confusion: relabel a chat frame as a file chunk. The type is inside the AAD,
  // so this must fail authentication rather than being silently accepted.
  const f3 = await send.seal(TYPE.CHAT, te.encode('three'));
  const confused = Uint8Array.from(f3);
  confused[1] = TYPE.FILE_CHUNK;
  const confusedResult = await recv.open(confused).then(() => 'accepted', (e) => e.message);
  check('a chat frame relabelled as a file chunk fails authentication',
    /authentication failed/.test(String(confusedResult)), String(confusedResult));

  const f4 = await send.seal(TYPE.CHAT, te.encode('four'));
  const flipped = Uint8Array.from(f4);
  flipped[flipped.length - 1] ^= 0x01;
  const flipResult = await recv.open(flipped).then(() => 'accepted', (e) => e.message);
  check('a single flipped ciphertext bit fails authentication',
    /authentication failed/.test(String(flipResult)), String(flipResult));

  const f5 = await send.seal(TYPE.CHAT, te.encode('five'));
  const moved = Uint8Array.from(f5);
  new DataView(moved.buffer).setBigUint64(2, 9999n);
  const movedResult = await recv.open(moved).then(() => 'accepted', (e) => e.message);
  check('rewriting the counter fails authentication',
    /authentication failed/.test(String(movedResult)), String(movedResult));

  check('failed frames did not advance the receive counter, so valid traffic still flows',
    (await recv.open(await send.seal(TYPE.CHAT, te.encode('six'))).then((r) => Buffer.from(r.plaintext).toString(), (e) => e.message)) === 'six');

  const short = await recv.open(new Uint8Array(5)).then(() => 'accepted', (e) => e.message);
  check('a truncated frame is rejected', /too short/.test(String(short)), String(short));

  const wrongVersion = Uint8Array.from(await send.seal(TYPE.CHAT, te.encode('v')));
  wrongVersion[0] = 0x99;
  const versionResult = await recv.open(wrongVersion).then(() => 'accepted', (e) => e.message);
  check('an unknown frame version is rejected', /unsupported frame version/.test(String(versionResult)), String(versionResult));

  // Exactly three of the attacks above reach the AEAD: type confusion, the flipped
  // bit and the rewritten counter. The replay, the truncated frame and the bad
  // version are all rejected before any decryption is attempted, so they must NOT be
  // counted as authentication failures: the distinction is what makes a
  // "sever after N auth failures" policy meaningful rather than trigger-happy.
  check('only frames that actually reached the AEAD count as authentication failures',
    recv.authFailures === 3, `counted ${recv.authFailures}`);
}

// ------------------------------------------------- concurrent replay (the TOCTOU)
{
  // The replay guard straddles an await: the counter is checked before subtle.decrypt
  // and assigned after it. Frames arrive from a DataChannel event listener, so two
  // decrypts running at once is the normal path, not an edge case. Interleaved, both
  // frames pass a check against the same stale counter, the lower one is assigned last,
  // recvCounter regresses, and the higher frame can then be accepted a SECOND time.
  //
  // The existing replay test delivers frames strictly in order, one await at a time. It
  // structurally cannot reach this: the window it exploits only exists while two opens
  // overlap. These deliver concurrently.
  const secret = generateSecret();
  const roomId = await deriveRoomId(secret);
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const mk = async (role, mine, theirs) => deriveSession({
    secret, privateKey: mine.privateKey, publicRaw: mine.publicRaw, peerPublicRaw: theirs.publicRaw, role, roomId,
  });

  /**
   * The same Channel with the serialisation removed: check-decrypt-assign is no longer
   * atomic. This is the pre-fix behaviour, kept here as a negative control so that every
   * assertion below is demonstrably capable of failing on every run. A guard that has
   * never been shown to reject anything is not evidence that it rejects.
   */
  class RacyChannel extends Channel {
    open(frame) { return this.openOne(frame); }
  }

  const settle = (p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e: e.message }));

  /** Deliver frames to one receiver with every open() in flight at once. */
  const deliverConcurrently = async (recv, frames) =>
    Promise.all(frames.map((f) => settle(recv.open(f))));

  const build = async () => {
    const sA = await mk('a', a, b);
    const sB = await mk('b', b, a);
    const send = new Channel(sA);
    const frames = [];
    for (let i = 1; i <= 5; i += 1) frames.push(await send.seal(TYPE.CHAT, te.encode(`f${i}`)));
    return { sB, frames };
  };

  // --- 1. the same frame delivered twice, concurrently
  {
    const { sB, frames } = await build();
    const guarded = new Channel(sB);
    const first = await guarded.open(frames[0]);
    void first;
    const dup = await deliverConcurrently(guarded, [frames[1], frames[1]]);
    check('a frame delivered twice at once is accepted exactly once',
      dup.filter((r) => r.ok).length === 1 && dup.filter((r) => !r.ok).length === 1,
      JSON.stringify(dup.map((r) => (r.ok ? 'accepted' : r.e))));

    const racy = new RacyChannel(await mk('b', b, a));
    await racy.open(frames[0]).catch(() => {});
    const racyDup = await deliverConcurrently(racy, [frames[1], frames[1]]);
    check('...and the negative control, with the serialisation removed, accepts it twice',
      racyDup.filter((r) => r.ok).length === 2,
      JSON.stringify(racyDup.map((r) => (r.ok ? 'accepted' : r.e))));
  }

  // --- 2. out-of-order concurrent delivery must not let the counter regress
  {
    const { sB, frames } = await build();
    const guarded = new Channel(sB);
    // Highest first, so a correct guard accepts one frame and rejects the other four.
    const out = await deliverConcurrently(guarded, [frames[4], frames[3], frames[2], frames[1], frames[0]]);
    check('of five frames delivered at once, only the first one seen is accepted',
      out.filter((r) => r.ok).length === 1, JSON.stringify(out.map((r) => (r.ok ? 'accepted' : r.e))));
    check('the receive counter never regressed below the frame it accepted',
      guarded.recvCounter === 5n, `recvCounter ${guarded.recvCounter}`);

    // The frame that WAS accepted must still be unreplayable afterwards. This is the
    // exact consequence of the regression: replaying it a second time is the attack.
    const replayAfter = await settle(guarded.open(frames[4]));
    check('the accepted frame cannot then be replayed',
      replayAfter.ok === false && /replay or reorder/.test(replayAfter.e), JSON.stringify(replayAfter));

    const racy = new RacyChannel(await mk('b', b, a));
    const racyOut = await deliverConcurrently(racy, [frames[4], frames[3], frames[2], frames[1], frames[0]]);
    const racyReplay = await settle(racy.open(frames[4]));
    // The counter it ends on is a race and varies run to run, so it is reported rather
    // than asserted. What is deterministic, and what actually matters, is that the
    // unserialised guard admits more than one of the five and then admits a replay.
    check('...and the negative control admits several at once and then replays one',
      racyOut.filter((r) => r.ok).length > 1 && racyReplay.ok === true,
      `accepted ${racyOut.filter((r) => r.ok).length}, counter ${racy.recvCounter}, replay ${racyReplay.ok ? 'accepted' : racyReplay.e}`);
  }

  // --- 3. a rejected frame must not stall the frames queued behind it
  {
    const { sB, frames } = await build();
    const guarded = new Channel(sB);
    await guarded.open(frames[2]); // counter 3
    const mixed = await deliverConcurrently(guarded, [frames[0], frames[3], frames[1], frames[4]]);
    check('a dropped frame does not poison the frames queued behind it',
      mixed[1].ok === true && mixed[3].ok === true && mixed[0].ok === false && mixed[2].ok === false,
      JSON.stringify(mixed.map((r) => (r.ok ? 'accepted' : r.e))));
  }
}

// ---------------------------------------------------------------- file refusal paths
{
  // A file that cannot be received has to be refused BEFORE the transfer starts, never
  // at 90 percent. showSaveFilePicker exists only in Chromium on desktop, so on every
  // other browser the receiver must hold the whole file in memory.
  const noPicker = typeof globalThis.showSaveFilePicker !== 'function';
  check('this environment has no save picker, which is the case being exercised', noPicker);

  const small = canAccept(1024);
  check('an ordinary file is accepted without needing disk', small.ok === true && small.requiresDisk === false,
    JSON.stringify(small));
  const atLimit = canAccept(MEMORY_LIMIT_BYTES);
  check('a file exactly at the memory limit is still accepted', atLimit.ok === true, JSON.stringify(atLimit));

  const tooBig = canAccept(MEMORY_LIMIT_BYTES + 1);
  check('one byte over the memory limit is refused where there is no disk sink',
    tooBig.ok === false, JSON.stringify(tooBig));
  check('the refusal says what the limit is and what would fix it',
    /limit/i.test(tooBig.reason ?? '') && /Chromium|desktop/i.test(tooBig.reason ?? ''), tooBig.reason);

  // createSink must refuse on its own account. preferMemory is a caller option with no
  // guard of its own, so it may not rely on canAccept having been consulted first.
  const refused = await createSink({ name: 'huge.bin', size: MEMORY_LIMIT_BYTES + 1 }, { preferMemory: true })
    .then(() => null, (err) => err);
  check('createSink refuses an oversized file rather than opening anything',
    refused instanceof Error && /cannot be held in memory/.test(refused.message), String(refused?.message));

  // A peer-supplied filename arrives exactly as the other side wrote it.
  const names = [
    ['../../etc/passwd', /^\.*[^/\\]*$/, 'no path separators survive'],
    ['..\\..\\windows\\system32', /^[^/\\]*$/, 'no backslashes survive'],
    ['....//....//etc/shadow', /^[^/\\]*$/, 'doubled traversal is flattened'],
    ['.hidden', /^[^.]/, 'a leading dot cannot make a hidden file'],
    ['..', /^[^.]/, 'the parent directory is not a filename'],
    ['\u202egpj.exe', /^[^\u202a-\u202e\u2066-\u2069]*$/, 'a right-to-left override cannot disguise the extension'],
    ['bad\u0000name.txt', /^[^\u0000-\u001f\u007f-\u009f]*$/, 'control characters are stripped'],
    ['report\u200e.pdf', /^[^\u200e\u200f]*$/, 'bidi marks are stripped'],
  ];
  for (const [raw, shape, why] of names) {
    const cleaned = sanitizeFilename(raw);
    check(`filename: ${why}`, shape.test(cleaned) && cleaned.length > 0, `${JSON.stringify(raw)} -> ${JSON.stringify(cleaned)}`);
  }

  check('a name that is entirely stripped falls back rather than becoming empty',
    sanitizeFilename('\u0000\u0000\u0000') === 'warp-gate-file'
    && sanitizeFilename('') === 'warp-gate-file'
    && sanitizeFilename(null) === 'warp-gate-file',
    JSON.stringify([sanitizeFilename('\u0000\u0000\u0000'), sanitizeFilename(''), sanitizeFilename(null)]));

  // The control for every assertion above: an ordinary name must survive untouched, or
  // "the dangerous parts were removed" is satisfied by a function that removes everything.
  check('an ordinary filename is passed through unchanged',
    sanitizeFilename('Holiday photo (2).jpeg') === 'Holiday photo (2).jpeg',
    sanitizeFilename('Holiday photo (2).jpeg'));

  // The extension is taken from the LAST dot, so a double extension keeps only its tail.
  // That is the right call for the save dialog: it is what the file will open with.
  const long = `${'a'.repeat(400)}.tar.gz`;
  const truncated = sanitizeFilename(long);
  check('an absurdly long name is truncated but keeps its extension',
    truncated.length <= 120 && truncated.endsWith('.gz'), `${truncated.length} chars, ends ${truncated.slice(-8)}`);
  // Control: an extension longer than the cutoff is not treated as one, so a name that
  // is all dots cannot smuggle 300 characters through as an "extension".
  const noExt = sanitizeFilename('b'.repeat(400));
  check('a long name with no extension is simply cut to the cap',
    noExt.length === 120 && !noExt.includes('.'), `${noExt.length} chars`);
}

// ---------------------------------------------------------------- large payloads
{
  const secret = generateSecret();
  const roomId = await deriveRoomId(secret);
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const sA = await deriveSession({ secret, privateKey: a.privateKey, publicRaw: a.publicRaw, peerPublicRaw: b.publicRaw, role: 'a', roomId });
  const sB = await deriveSession({ secret, privateKey: b.privateKey, publicRaw: b.publicRaw, peerPublicRaw: a.publicRaw, role: 'b', roomId });
  const send = new Channel(sA);
  const recv = new Channel(sB);

  const chunk = crypto.randomBytes(16384);
  let allMatch = true;
  for (let i = 0; i < 64; i += 1) {
    const frame = await send.seal(TYPE.FILE_CHUNK, chunk);
    if (frame.length !== HEADER_BYTES + chunk.length + 16) { allMatch = false; break; }
    const got = await recv.open(frame);
    if (!Buffer.from(got.plaintext).equals(chunk)) { allMatch = false; break; }
  }
  check('64 sequential 16 KiB chunks seal and open intact', allMatch);
  check('a 16 KiB chunk is 16410 bytes on the wire, under the 64 KiB interop floor',
    HEADER_BYTES + 16384 + 16 === 16410);
  check('counters advanced to the expected value', send.sendCounter === 64n && recv.recvCounter === 64n,
    `${send.sendCounter} / ${recv.recvCounter}`);
}

process.exit(summary('crypto') ? 0 : 1);
