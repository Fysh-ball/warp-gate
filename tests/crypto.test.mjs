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
  base32Encode, base32Decode, b64u,
  deriveRoomId, deriveSignalKey, generateKeyPair, deriveSession, Channel,
  sealEnvelope, openEnvelope, equalCt, TYPE, VERSION, HEADER_BYTES, decodeJson,
  generateGateCode, decodeGateCode, tryDecodeGateCode, GateCodeError,
  encodeWordIndices, canonicalPhrase, randomWordIndices,
  WORDS, WORD_COUNT, WORDLIST_SHA256, CODE_WORDS,
  deriveSecret, clearSecretCache, CODE_STRETCH_ITERATIONS,
} from '../public/js/crypto.js';
import {
  canAccept, createSink, sanitizeFilename, MEMORY_LIMIT_BYTES,
} from '../public/js/transfer.js';
import { Session, STATE } from '../public/js/session.js';
import { savePasswordKey, recallPasswordKey, forgetAllPasswordKeys } from '../public/js/vault.js';

const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;
const b64uNode = (buf) => Buffer.from(buf).toString('base64url');

// A raw 16-byte secret, for the sections that verify HKDF, the handshake and the framing.
// Those care that S is 16 bytes, not where it came from, and routing every one of them
// through a gate code would add a second of PBKDF2 per call for no extra coverage. The
// gate-code path is verified end to end in the section that owns it, including that what
// it produces is exactly what deriveRoomId and the handshake accept.
const randomSecret = () => new Uint8Array(crypto.randomBytes(16));

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

  let b64ok = true;
  for (let i = 0; i < 100; i += 1) {
    const bytes = crypto.randomBytes(1 + (i % 40));
    if (!Buffer.from(b64u.decode(b64u.encode(bytes))).equals(bytes)) { b64ok = false; break; }
  }
  check('base64url round-trips', b64ok);
}

// ---------------------------------------------------------------- the wordlist
//
// The list is DATA. A word moved, added or dropped is not a cosmetic change: it renames
// every index and therefore resolves every existing code to a different secret. These
// checks pin the properties the format depends on, and the digest pins the list itself.
{
  check(`the wordlist holds exactly 7776 entries`, WORD_COUNT === 7776, String(WORD_COUNT));
  check('every wordlist entry is 4 to 7 lowercase ASCII letters',
    WORDS.every((w) => /^[a-z]{4,7}$/.test(w)),
    WORDS.filter((w) => !/^[a-z]{4,7}$/.test(w)).slice(0, 5).join(' '));
  check('every wordlist entry is distinct', new Set(WORDS).size === WORD_COUNT, String(new Set(WORDS).size));

  // The whole point of the four-character rule: four characters name exactly one word, so
  // an autocomplete cannot be ambiguous and decodeGateCode can name the word a typo meant.
  const prefixes = new Set(WORDS.map((w) => w.slice(0, 4)));
  check('the first four characters are unique across the wordlist', prefixes.size === WORD_COUNT, String(prefixes.size));

  // Follows from the line above given a 4-letter minimum, and is worth asserting anyway:
  // it is the property a human relies on when they stop typing early.
  const wordSet = new Set(WORDS);
  const prefixPairs = WORDS.filter((w) => {
    for (let n = 4; n < w.length; n += 1) if (wordSet.has(w.slice(0, n))) return true;
    return false;
  });
  check('no wordlist entry is a prefix of another entry', prefixPairs.length === 0, prefixPairs.slice(0, 5).join(' '));

  check('the wordlist is sorted, so index order is reproducible',
    WORDS.every((w, i) => i === 0 || WORDS[i - 1] < w));

  // "warp" is the display prefix. If it were also a word, "WARP-WARP-..." would have two
  // readings and decodeGateCode would have to guess.
  check('the wordlist does not contain the display prefix', !wordSet.has('warp'));

  const digest = crypto.createHash('sha256').update(`${WORDS.join('\n')}\n`).digest('hex');
  check('the wordlist digest matches the one recorded in words.js',
    digest === WORDLIST_SHA256, `${digest} vs ${WORDLIST_SHA256}`);
}

// ---------------------------------------------------------------- uniform sampling
//
// 13 bits give 8192 values for 7776 words. The tempting `value % 7776` folds the 416
// leftovers onto words 0 to 415 and makes each of them twice as likely as any other. The
// first check below is not a statistical argument, it is exhaustive: feed the sampler
// every 13-bit value once and observe what comes out.
{
  // Descending, so the 416 valueless draws come FIRST and the walk cannot stop before it
  // has seen all 8192. The top three bits are forced to 1 in every draw as well: if the
  // sampler stopped masking to 13 bits every value would land above 7776 and the loop
  // would never terminate, so this walks the domain AND proves the mask.
  let cursor = 0;
  const walk = (buf) => {
    const full = 0xe000 | ((8191 - cursor) & 0x1fff);
    cursor += 1;
    buf[0] = full >>> 8;
    buf[1] = full & 0xff;
  };
  const all = randomWordIndices(WORD_COUNT, walk);
  check('walking the whole 13-bit domain consumes exactly 8192 draws for 7776 words',
    cursor === 8192, `${cursor} draws`);
  check('every one of the 7776 indices comes out exactly once, in order',
    all.length === WORD_COUNT && all.every((v, i) => v === WORD_COUNT - 1 - i));
  check('the 416 values with no word are rejected and redrawn, never folded onto a word',
    8192 - WORD_COUNT === 416 && all.every((v) => v < WORD_COUNT));

  // And a statistical pass over the real sampler, which targets the same bug from the
  // other side: under modulo the low 416 indices would appear about twice as often.
  const pool = crypto.randomBytes(4 << 20);
  let p = 0;
  const fromPool = (buf) => { buf[0] = pool[p]; buf[1] = pool[p + 1]; p += 2; };
  const N = 400_000;
  const draws = randomWordIndices(N, fromPool);
  const counts = new Uint32Array(WORD_COUNT);
  let low = 0;
  for (const v of draws) { counts[v] += 1; if (v < 416) low += 1; }
  const expectedLow = (N * 416) / WORD_COUNT;
  check('the 416 lowest indices are not over-represented (the modulo-bias signature)',
    Math.abs(low / expectedLow - 1) < 0.05, `${low} vs ${expectedLow.toFixed(0)} expected`);

  // Pearson chi-square over all 7776 buckets. df = 7775, sd = sqrt(2*df) = 124.7, so a
  // five-sigma band is roughly 7152 to 8398. Wide on purpose: this must not fail on an
  // unlucky day, it exists to catch a distribution that is wrong by construction.
  const expected = N / WORD_COUNT;
  let chi2 = 0;
  for (const c of counts) chi2 += ((c - expected) ** 2) / expected;
  check('the sampler is uniform across all 7776 words (chi-square, df 7775)',
    chi2 > 7152 && chi2 < 8398, `chi2 = ${chi2.toFixed(1)}`);
}

// ---------------------------------------------------------------- gate code encoding
{
  const code = generateGateCode();
  check('a fresh code is WARP plus eight capitalised words',
    /^WARP(-[A-Z]{4,7}){8}$/.test(code), code);
  check('a fresh code carries eight words', code.split('-').length - 1 === CODE_WORDS, code);

  // Exactness matters more than it looks: the canonical string is what gets stretched
  // into S, so any code that round-trips to a different string is a different secret.
  let roundTrips = true;
  let counterexample = '';
  for (let i = 0; i < 500; i += 1) {
    const c = generateGateCode();
    const back = encodeWordIndices(decodeGateCode(c).indices);
    if (back !== c) { roundTrips = false; counterexample = `${c} -> ${back}`; break; }
  }
  check('encode(decode(code)) === code for 500 fresh codes', roundTrips, counterexample);

  const { indices, phrase } = decodeGateCode(code);
  check('the hashed phrase is the lowercase words, single spaced, no prefix',
    phrase === [...indices].map((i) => WORDS[i]).join(' ') && phrase === canonicalPhrase(indices), phrase);

  // Everything a human or a chat client can do to a code on its way back in.
  const words = code.slice(5).split('-');
  const spellings = [
    code,
    code.toLowerCase(),
    `  ${code}  `,
    words.join(' '),
    `warp ${words.join(' ').toLowerCase()}`,
    `${words.slice(0, 4).join('-')}\n${words.slice(4).join('-')}`,
    `https://warpgate.fysh.site/app#${code}`,
    `https://warp.example.com/warp/#${code.toLowerCase()}`,
    `WARP‑${words.join('‑')}`,
    `${words.slice(0, 3).join(' ')} ${words.slice(3).join(' ')}`,
  ];
  const bad = spellings.filter((s) => tryDecodeGateCode(s)?.code !== code);
  check('the same code parses out of every spelling a human or a chat client produces',
    bad.length === 0, bad.map((s) => JSON.stringify(s)).join(' | '));

  // A random draw repeats a word about once in 280 codes. It is a legal code.
  const dup = new Uint16Array([3, 3, 9, 9, 9, 100, 7775, 0]);
  const dupCode = encodeWordIndices(dup);
  check('a code with repeated words is legal and round-trips',
    [...decodeGateCode(dupCode).indices].join(',') === [...dup].join(','), dupCode);

  const fails = (input) => {
    try { decodeGateCode(input); return null; } catch (err) {
      return err instanceof GateCodeError ? err : (() => { throw err; })();
    }
  };

  check('an empty code is rejected as empty', fails('')?.reason === 'empty', fails('')?.message);
  check('a code with the wrong number of words is rejected, saying how many it has',
    fails(words.slice(0, 6).join('-'))?.reason === 'count'
      && /\b6\b/.test(fails(words.slice(0, 6).join('-')).message),
    fails(words.slice(0, 6).join('-'))?.message);
  check('a code with too many words is rejected too',
    fails(`${code}-${words[0]}`)?.reason === 'count', fails(`${code}-${words[0]}`)?.message);

  const unknown = fails([...words.slice(0, 3), 'zzzzz', ...words.slice(4)].join('-'));
  check('an unknown word is rejected, naming the word and its position',
    unknown?.reason === 'unknown' && unknown.position === 4 && unknown.word === 'zzzzz'
      && /zzzzz/.test(unknown.message) && /\b4\b/.test(unknown.message),
    unknown?.message);

  // A word mistyped after its fourth character identifies exactly one candidate, because
  // the list guarantees a unique four-character prefix. Say which, do not silently fix it.
  const target = WORDS[decodeGateCode(code).indices[1]];
  const typoWord = `${target.slice(0, 4)}xy`;
  const typo = fails([words[0], typoWord, ...words.slice(2)].join('-'));
  check('a mistyped word is rejected with the word it was probably meant to be',
    typo?.reason === 'typo' && typo.suggestion === target && typo.position === 2
      && typo.message.includes(target.toUpperCase()),
    typo?.message);

  check('a non-ASCII lookalike is rejected rather than case-folded onto a letter',
    fails(`${words[0].replace(/i/i, 'ı')}-${words.slice(1).join('-')}`)?.reason === 'charset'
      || fails(`ſ${words.join('-')}`)?.reason === 'charset');

  check('tryDecodeGateCode returns null where decodeGateCode throws',
    tryDecodeGateCode('not a code at all') === null && tryDecodeGateCode(code)?.code === code);

  // No backward compatibility to keep, but the person holding an old link must be told
  // the format changed rather than that their code is malformed.
  // 26 Crockford symbols, exactly what formatSecret used to mint before 2026-08-09.
  const LEGACY = 'WARP-3K7M-9QX2-B4TF-8NPW-VJ5H-RD2S-Y7';
  const legacy = fails(LEGACY);
  check('an old-style base32 code is rejected with a message saying the format changed',
    legacy?.reason === 'legacy' && /old-style/i.test(legacy.message) && /\b8 words\b/.test(legacy.message),
    legacy?.message);
  check('an old-style code inside a full link is recognised as old, not as garbage',
    fails(`https://warpgate.fysh.site/#${LEGACY}`)?.reason === 'legacy');
  check('an old-style code without its WARP prefix is recognised too',
    fails('M4V604TY8XQK2BND5RTG9J1234')?.reason === 'legacy');

  // Regression: the old-format test used to be "26 characters", and six four-and-five
  // letter words strip to 26 characters too, so a truncated word code was told it was an
  // old code. A wrong cause is worse than a vague one; it sends the reader somewhere else.
  const short = [];
  for (const w of WORDS) {
    const want = [4, 4, 4, 4, 5, 5][short.length];
    if (w.length === want) short.push(w);
    if (short.length === 6) break;
  }
  check('six words that happen to strip to 26 letters are a word count, not an old code',
    short.join('').length === 26 && fails(short.join('-'))?.reason === 'count',
    `${short.join('-')} -> ${fails(short.join('-'))?.message}`);
}

// ---------------------------------------------------------------- code -> secret
{
  check('the stretch runs at the documented iteration count', CODE_STRETCH_ITERATIONS === 600_000);

  const code = generateGateCode();
  const { phrase } = decodeGateCode(code);

  clearSecretCache();
  const t0 = performance.now();
  const secret = await deriveSecret(code);
  const coldMs = performance.now() - t0;

  check('a gate code derives a 128-bit secret', secret instanceof Uint8Array && secret.length === 16, String(secret.length));

  // The cross-implementation check this file exists for: node's classic PBKDF2, over the
  // canonical phrase and the documented salt, must reproduce S byte for byte.
  const expected = crypto.pbkdf2Sync(Buffer.from(phrase, 'utf8'), Buffer.from('wg/v1/gate-code', 'utf8'), CODE_STRETCH_ITERATIONS, 16, 'sha256');
  check('the secret matches an independent PBKDF2-HMAC-SHA256 over the canonical phrase',
    Buffer.from(secret).equals(expected), `${Buffer.from(secret).toString('hex')} vs ${expected.toString('hex')}`);

  // A stretch that quietly did nothing would still return 16 bytes and still agree with
  // itself. It would not cost anything, so the cost is the evidence.
  check('stretching actually costs real work, so it cannot have been skipped',
    coldMs > 100, `${coldMs.toFixed(0)} ms`);

  const t1 = performance.now();
  const again = await deriveSecret(code);
  const warmMs = performance.now() - t1;
  check('the same code derives the same secret from the cache',
    Buffer.from(again).equals(Buffer.from(secret)));
  check('a cached derivation is at least 50 times cheaper than a cold one',
    warmMs * 50 < coldMs, `${warmMs.toFixed(3)} ms cached vs ${coldMs.toFixed(0)} ms cold`);

  // The cache hands out copies. A caller zeroing its own secret must not blank everyone
  // else's. Both return paths are exercised, the cold one and the cache-hit one, on a
  // code of their own: covering only the hit path left the cold path free to hand out the
  // cached array itself, and the mutation suite proved that hole was real.
  const copyCode = generateGateCode();
  const cold = await deriveSecret(copyCode);
  const reference = Uint8Array.from(cold);
  cold.fill(0);
  const warm = await deriveSecret(copyCode);
  warm.fill(0xff);
  const third = await deriveSecret(copyCode);
  check('both the cold and the cached path return a fresh copy, not the shared array',
    reference.some((b) => b !== 0) && Buffer.from(third).equals(Buffer.from(reference)),
    `${Buffer.from(third).toString('hex')} vs ${Buffer.from(reference).toString('hex')}`);

  clearSecretCache();
  const t2 = performance.now();
  const afterClear = await deriveSecret(code);
  check('clearing the cache forces a real re-derivation of the same secret',
    Buffer.from(afterClear).equals(expected) && performance.now() - t2 > 100);

  // Two calls that race must share one derivation, not run PBKDF2 twice: the join path
  // can start two of these before either finishes.
  clearSecretCache();
  const t3 = performance.now();
  const raced = await Promise.all([deriveSecret(code), deriveSecret(code), deriveSecret(code), deriveSecret(code)]);
  const racedMs = performance.now() - t3;
  check('four concurrent derivations of one code run PBKDF2 once, not four times',
    racedMs < coldMs * 2, `${racedMs.toFixed(0)} ms for four vs ${coldMs.toFixed(0)} ms for one`);
  check('every racing caller gets the same secret', raced.every((s) => Buffer.from(s).equals(expected)));

  const otherCode = generateGateCode();
  const otherSecret = await deriveSecret(otherCode);
  check('a different code derives a different secret', !Buffer.from(otherSecret).equals(expected));

  // The whole chain, from what a human types to what the server sees, computed twice.
  const roomId = await deriveRoomId(secret);
  const expectedRoom = base32Encode(new Uint8Array(crypto.hkdfSync('sha256', expected, Buffer.alloc(0), te.encode('wg/v1/room-id'), 5)));
  check('a code-derived secret drives deriveRoomId exactly as a raw secret does',
    roomId === expectedRoom, `${roomId} vs ${expectedRoom}`);

  // And that it is accepted by the rest of the module, which type-checks S at every entry.
  const sigKey = await deriveSignalKey(secret);
  const envelope = await sealEnvelope(sigKey, { t: 'probe' });
  check('a code-derived secret produces a working signalling key',
    (await openEnvelope(await deriveSignalKey(await deriveSecret(code)), envelope)).t === 'probe');

  clearSecretCache();
}

// ---------------------------------------------------------------- HKDF vs node
{
  const secret = randomSecret();

  const roomId = await deriveRoomId(secret);
  const expectedRoomBytes = crypto.hkdfSync('sha256', secret, Buffer.alloc(0), te.encode('wg/v1/room-id'), 5);
  const expectedRoomId = base32Encode(new Uint8Array(expectedRoomBytes));
  check('room id matches an independent RFC 5869 HKDF', roomId === expectedRoomId, `${roomId} vs ${expectedRoomId}`);
  check('room id is 8 Crockford characters', /^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}$/.test(roomId), roomId);

  // The server-visible room id must not leak the secret.
  const other = randomSecret();
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

  const secret = randomSecret();
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
  const roomId = await deriveRoomId(randomSecret());
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const rightSecret = randomSecret();
  const wrongSecret = randomSecret();

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
  const secret = randomSecret();
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
  const secret = randomSecret();
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
  const secret = randomSecret();
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

// ---------------------------------------------------------------- reload on a password gate
//
// The gap: the key schedule takes a room password (DESIGN.md 3.2a) but the reload path
// carried nothing, so a resumed tab held S and no password, could not reproduce the HKDF
// salt it had used minutes earlier, and stopped dead until the user typed the password
// again. Worse than a prompt: connect() waits on the password gate BEFORE it sends the
// restart every peer needs, so every other device in the gate went on holding a connection
// to a document that no longer existed.
//
// Everything below drives the real Session. openSignal is the only member that needs a
// network and it is the only thing stubbed; the key schedule, the vault and the teardown
// are the shipped code.
{
  class OfflineSession extends Session {
    async openSignal(token) { this.openedWith = token; }
  }

  const password = 'correct horse battery staple';
  const secret = randomSecret();
  const roomId = await deriveRoomId(secret);
  const copy = () => Uint8Array.from(secret);

  forgetAllPasswordKeys();

  // The gate as it stood before the reload: created here, with the password typed in.
  const live = new OfflineSession({ secret: copy(), iceServers: [], password });
  live.roomId = roomId;
  const pkLive = await live.ensurePasswordKey();
  check('a live gate stretches the room password to a 32-byte key',
    pkLive instanceof Uint8Array && pkLive.length === 32, `${pkLive?.length}`);

  // The reload. A fresh tab: same secret out of sessionStorage, same slot token, and no
  // password anywhere, because the input the user typed it into no longer exists.
  const reloaded = new OfflineSession({ secret: copy(), iceServers: [] });
  let prompted = false;
  reloaded.addEventListener('password-required', () => { prompted = true; });
  await reloaded.resume({
    token: 'slot-token', role: 'a', expiresAt: Date.now() + 60_000,
    password: null, requiresPassword: true,
  });
  const pkBack = await reloaded.ensurePasswordKey();

  check('a resumed gate recovers its stretched password key without being handed the password',
    pkBack instanceof Uint8Array && pkBack.length === 32, pkBack === null ? 'null: nothing was carried across the reload' : `${pkBack?.length}`);
  check('the recovered key is byte-identical to the one used before the reload',
    Boolean(pkBack) && Buffer.from(pkBack).equals(Buffer.from(pkLive)));
  check('a resumed password gate does not stop to ask for the password again', prompted === false);

  // The property that actually matters: the resumed tab must derive the SAME keys as a
  // peer that never reloaded. Both sides are run for real, and the confirmation values are
  // what each side sends the other, so equality here is exactly what key confirmation tests
  // on the wire.
  const mine = await generateKeyPair();
  const theirs = await generateKeyPair();
  const peer = await deriveSession({
    secret: copy(), passwordKey: pkLive, privateKey: theirs.privateKey,
    publicRaw: theirs.publicRaw, peerPublicRaw: mine.publicRaw, role: 'b', roomId,
  });
  const resumedSide = pkBack ? await deriveSession({
    secret: copy(), passwordKey: pkBack, privateKey: mine.privateKey,
    publicRaw: mine.publicRaw, peerPublicRaw: theirs.publicRaw, role: 'a', roomId,
  }) : null;
  check('a resumed tab and a peer that never reloaded confirm the same keys',
    Boolean(resumedSide) && equalCt(resumedSide.confirmMine, peer.confirmPeer)
      && equalCt(resumedSide.confirmPeer, peer.confirmMine));
  check('a resumed tab and that peer agree on the same SAS',
    Boolean(resumedSide) && resumedSide.sas === peer.sas, `${resumedSide?.sas} / ${peer.sas}`);

  // The control. Without the password the resumed side is deriving unauthenticated ECDH
  // wearing the same interface, and it must NOT confirm: this is what proves the checks
  // above are measuring the password rather than passing on the shared secret alone.
  const passwordless = await deriveSession({
    secret: copy(), passwordKey: null, privateKey: mine.privateKey,
    publicRaw: mine.publicRaw, peerPublicRaw: theirs.publicRaw, role: 'a', roomId,
  });
  check('a resumed tab that recovered no password fails key confirmation',
    !equalCt(passwordless.confirmMine, peer.confirmPeer));

  // What is on disk if the browser crash-recovers this tab. Never the password: the whole
  // argument in vault.js rests on this one line being true.
  const written = [];
  for (let i = 0; i < sessionStorage.length; i += 1) {
    const name = sessionStorage.key(i);
    written.push(`${name}=${sessionStorage.getItem(name)}`);
  }
  const dump = written.join('\n');
  check('the password itself is never written to per-tab storage',
    !dump.includes(password) && !dump.toLowerCase().includes('horse'), dump.slice(0, 200));
  check('what is stored is filed under the room id, so it cannot be handed to another gate',
    written.some((line) => line.startsWith(`wg.pkey.${roomId}=`)), dump.slice(0, 200));
  check('another room recalls nothing from this one', recallPasswordKey('AAAAAAAA') === null);

  // A record this application did not write is discarded rather than fed into a key
  // schedule, and discarding it clears it so the next reload is not poisoned too.
  sessionStorage.setItem('wg.pkey.CORRUPT1', 'not-base64url-of-32-bytes');
  const corrupt = recallPasswordKey('CORRUPT1');
  check('a corrupt stored record is refused and cleared, not derived from',
    corrupt === null && sessionStorage.getItem('wg.pkey.CORRUPT1') === null);
  check('a short record is refused', savePasswordKey('SHORT111', new Uint8Array(16)) !== null
    && recallPasswordKey('SHORT111') === null);

  // Wipe on failure. A stored key that keeps failing confirmation would make every later
  // reload fail the same way with no way for the user to correct it, so the failure drops it.
  const failing = new OfflineSession({ secret: copy(), iceServers: [], password });
  failing.roomId = roomId;
  await failing.ensurePasswordKey();
  // Without this the check below reports green on a store that was never written, which is
  // exactly the shape of a check that cannot fail.
  check('a gate about to fail confirmation has a stored password key to lose',
    recallPasswordKey(roomId) !== null);
  failing.setState(STATE.AUTH_FAILED, 'test');
  check('a failed key confirmation drops the stored password key',
    recallPasswordKey(roomId) === null);

  // Wipe on sever. Nothing outlives the gate.
  const ending = new OfflineSession({ secret: copy(), iceServers: [], password });
  ending.roomId = roomId;
  await ending.ensurePasswordKey();
  check('a gate about to end has a stored password key to lose',
    recallPasswordKey(roomId) !== null);
  ending.teardown('test');
  check('tearing the gate down removes the stored password key',
    recallPasswordKey(roomId) === null);
  check('tearing the gate down drops the in-memory password key too', ending.passwordKey === null);

  // A gate with no password writes nothing at all: the store exists for the password case
  // and for nothing else.
  forgetAllPasswordKeys();
  const plain = new OfflineSession({ secret: copy(), iceServers: [] });
  plain.roomId = roomId;
  const none = await plain.ensurePasswordKey();
  check('a gate with no password stretches nothing and stores nothing',
    none === null && recallPasswordKey(roomId) === null);

  forgetAllPasswordKeys();
}

process.exit(summary('crypto') ? 0 : 1);
