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
  commitPublicKey,
} from '../public/js/crypto.js';
import {
  canAccept, createSink, sanitizeFilename, MEMORY_LIMIT_BYTES,
} from '../public/js/transfer.js';
import { Session, STATE } from '../public/js/session.js';
import { savePasswordKey, recallPasswordKey, forgetAllPasswordKeys } from '../public/js/vault.js';
import { Link, STATE as LINK_STATE } from '../public/js/link.js';
import { Signal } from '../public/js/signal.js';
import {
  CHUNK_INDEX_BYTES, frameChunk, unframeChunk, createIndexedSink,
} from '../public/js/resume.js';
import { scanOnce, lastScanError, SCAN_ERR } from '../public/js/qrscan.js';

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


// ================================================================ the SAS collision
//
// THE ATTACK, SIMULATED. Before commit-then-reveal, both sides sent their ephemeral
// public key unconditionally with nothing in front of it, and the SAS is a function of a
// transcript over both keys. An attacker on the relay path who also holds the gate code
// could therefore hold both real public keys, having bound itself to nothing, and search
// for a pair of substitute keys that makes BOTH humans read the same digits.
//
// The search is cheap because each side's SAS depends on only ONE of the attacker's keys:
//
//   what A computes  = f(pk_A, pk_M_facing_A)     one value per A-facing candidate
//   what B computes  = f(pk_M_facing_B, pk_B)     one value per B-facing candidate
//
// so it is a birthday collision between two independent lists, not a search over pairs:
// n candidates each side gives n^2 chances at the modulus. At the real 100000 that is
// about 316 keypairs per side, roughly 640 curve operations, well under a second.
//
// Run here at a REDUCED modulus so the suite stays fast. The reduction is the last two
// digits of the real SAS, which is the real value modulo 100: an attacker facing a
// two-digit SAS needs exactly the collision an attacker facing five digits needs, and the
// arithmetic of the search is identical. Nothing about the derivation is stubbed.
//
// The negative control is the whole point of the section: the SAME attacker, with the
// SAME candidate pool, is measured again under the rule that it must fix each key before
// it sees the key that key will be compared against. Its advantage has to disappear.
{
  const secret = randomSecret();
  const roomId = await deriveRoomId(secret);

  // The reduced SAS: the real five digits, taken modulo 100. 100000 is divisible by 100,
  // so this is as uniform as the value it comes from.
  const SAS_MOD = 100;
  const reduce = (sas) => sas.slice(-2);

  // What ONE side ends up reading out loud, given its own key pair and the key it was
  // handed. `role` is the pair role: the initiator is 'a', the responder 'b'.
  const sasFor = async (mine, theirPublicRaw, role) => reduce((await deriveSession({
    secret, privateKey: mine.privateKey, publicRaw: mine.publicRaw,
    peerPublicRaw: theirPublicRaw, role, roomId,
  })).sas);

  const pool = (n) => Promise.all(Array.from({ length: n }, () => generateKeyPair()));

  // n^2 / SAS_MOD chances at a collision. 40 a side is 1600 chances at 100, so the search
  // failing would itself be news.
  const CANDIDATES = 40;
  const RUNS = 3;

  let grindsFound = 0;
  let grindsAgreed = 0;
  for (let run = 0; run < RUNS; run += 1) {
    const a = await generateKeyPair();   // the initiator
    const b = await generateKeyPair();   // the responder

    // PRE-FIX ORDERING: the attacker already holds pk_A and pk_B and has published
    // nothing, so it can compute what each victim WOULD read for every candidate it holds.
    const facingA = await pool(CANDIDATES);
    const facingB = await pool(CANDIDATES);
    // Facing A the attacker plays the responder, so it derives with role 'b' against pk_A.
    const seenByA = await Promise.all(facingA.map((m) => sasFor(m, a.publicRaw, 'b')));
    // Facing B it plays the initiator, so role 'a' against pk_B.
    const seenByB = await Promise.all(facingB.map((m) => sasFor(m, b.publicRaw, 'a')));

    const byValue = new Map();
    for (let i = 0; i < seenByA.length; i += 1) if (!byValue.has(seenByA[i])) byValue.set(seenByA[i], i);
    let hit = null;
    for (let j = 0; j < seenByB.length; j += 1) {
      const i = byValue.get(seenByB[j]);
      if (i !== undefined) { hit = { i, j }; break; }
    }
    if (!hit) continue;
    grindsFound += 1;

    // And now what the two humans actually read, derived by the victims themselves rather
    // than by the attacker's model of them.
    const readByA = await sasFor(a, facingA[hit.i].publicRaw, 'a');
    const readByB = await sasFor(b, facingB[hit.j].publicRaw, 'b');
    if (readByA === readByB) grindsAgreed += 1;
  }

  check(`the pre-fix grind finds a colliding key pair on every run (${CANDIDATES} candidates a side, modulus ${SAS_MOD})`,
    grindsFound === RUNS, `${grindsFound}/${RUNS} runs found one`);
  check('and both victims then read the SAME code while talking to the attacker, which is the attack',
    grindsAgreed === RUNS, `${grindsAgreed}/${RUNS} collisions actually agreed`);

  // ---------------------------------------------------------------- the negative control
  //
  // Same attacker, same modulus, under commit-then-reveal. It must fix its B-facing key
  // before pk_B exists to compare against, and its A-facing key before pk_A is revealed,
  // so neither list can be computed and neither can be searched. All that is left is one
  // blind guess per gate, which is 1 in SAS_MOD, and the count below has to look like
  // chance rather than like an attack.
  const TRIALS = 200;
  let blindAgreed = 0;
  for (let t = 0; t < TRIALS; t += 1) {
    // The attacker moves FIRST, which is exactly what the commitment costs it.
    const facingA = await generateKeyPair();
    const facingB = await generateKeyPair();
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const readByA = await sasFor(a, facingA.publicRaw, 'a');
    const readByB = await sasFor(b, facingB.publicRaw, 'b');
    if (readByA === readByB) blindAgreed += 1;
  }
  // Expected TRIALS / SAS_MOD = 2. The bound is generous by a factor of twenty so this
  // cannot flake, and it is still nowhere near the 100% the grind achieves above.
  check(`with the keys fixed first, the same attacker succeeds only by chance (${blindAgreed}/${TRIALS}, expected about ${TRIALS / SAS_MOD})`,
    blindAgreed <= TRIALS / 5, `${blindAgreed} of ${TRIALS} blind attempts agreed`);
  // CONTROL for the measurement itself, not for the fix. A count near zero is exactly what
  // a comparison that can never report "agreed" would also print, so the same sasFor and
  // the same equality are run once over a pair that MUST agree: two honest peers, each
  // holding the other's real key. If this cannot see agreement, the zero above means
  // nothing at all.
  {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const readByA = await sasFor(a, b.publicRaw, 'a');
    const readByB = await sasFor(b, a.publicRaw, 'b');
    check('CONTROL: the same comparison DOES report agreement for an honest pair, so a low count above is a result and not a broken measurement',
      readByA === readByB, `${readByA} vs ${readByB}`);
  }
}

// ---------------------------------------------------------------- the commitment itself
{
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const ha = await commitPublicKey(a.publicRaw);
  const hb = await commitPublicKey(b.publicRaw);

  check('a key commitment is a 32-byte SHA-256 digest', ha instanceof Uint8Array && ha.length === 32, String(ha?.length));
  check('the same key commits to the same value twice',
    Buffer.from(await commitPublicKey(a.publicRaw)).equals(Buffer.from(ha)));
  check('CONTROL: two different keys commit to different values, so the digest really covers the key',
    !Buffer.from(ha).equals(Buffer.from(hb)));

  // Domain separation, recomputed independently rather than taken from the module. A
  // commitment that is a bare SHA-256 of a public key could be confused with any other
  // hash of the same bytes elsewhere in the protocol.
  const expected = crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from('wg/v1/pkc', 'utf8'), Buffer.from(a.publicRaw)]))
    .digest();
  check('the commitment is SHA-256 over the label "wg/v1/pkc" and the key, computed independently',
    expected.equals(Buffer.from(ha)));
  check('CONTROL: and it is NOT a bare SHA-256 of the key, so the label is doing work',
    !crypto.createHash('sha256').update(Buffer.from(a.publicRaw)).digest().equals(Buffer.from(ha)));

  let refusedShort = false;
  try { await commitPublicKey(a.publicRaw.subarray(0, 64)); } catch (err) { refusedShort = /65-byte/.test(err.message); }
  check('a value that is not a 65-byte point cannot be committed to', refusedShort);
}

// ================================================================ commit-then-reveal
//
// The protocol half of the fix, driven through Link's real signalling handler.
//
// Link is exercised directly with a stand-in Session because the state machine is the
// thing under test, not WebRTC: connect() would build an RTCPeerConnection, which Node has
// no business having. Everything below goes through the same onSignalMessage every relayed
// message goes through in the browser.
{
  const makeLink = ({ initiator }) => {
    const sent = [];
    const events = [];
    let severed = false;
    const session = {
      severed: false,
      needsRestart: false,
      passwordGate: Promise.resolve(),
      signal: { send: async (message, to) => { sent.push({ ...message, to }); return true; } },
      labelFor: () => 'peer',
      sever: async () => { severed = true; session.severed = true; },
    };
    const link = new Link({ session, peerId: initiator ? 'zzz' : 'aaa', initiator });
    for (const name of ['warning', 'auth-failed', 'sas', 'chat', 'secret', 'game']) {
      link.addEventListener(name, (event) => events.push({ name, detail: event.detail }));
    }
    return {
      link, sent, events, session, get severed() { return severed; },
      said: (re) => events.some((e) => re.test(String(e.detail))),
    };
  };

  // ---- the responder answers a commitment and nothing else
  {
    const peer = await generateKeyPair();
    const r = makeLink({ initiator: false });
    r.link.keyPair = await generateKeyPair();

    await r.link.onSignalMessage({ t: 'pk', pk: b64u.encode(peer.publicRaw) });
    check('a responder refuses a public key that arrived with no commitment in front of it',
      r.link.peerPublicRaw === null && r.link.state === LINK_STATE.AUTH_FAILED,
      `state=${r.link.state} pinned=${Boolean(r.link.peerPublicRaw)}`);
    check('and it says so out loud rather than timing out silently',
      r.said(/without first committing/), JSON.stringify(r.events.map((e) => e.name)));
    check('and it severs, so nothing can be exchanged over the link it was refused on', r.severed);
  }

  // ---- the honest exchange, in order
  {
    const peer = await generateKeyPair();
    const r = makeLink({ initiator: false });
    r.link.keyPair = await generateKeyPair();

    check('a responder sends nothing before the commitment arrives', r.sent.length === 0);
    await r.link.onSignalMessage({ t: 'pkc', h: b64u.encode(await commitPublicKey(peer.publicRaw)) });
    check('once committed to, the responder answers with exactly its own public key',
      r.sent.length === 1 && r.sent[0].t === 'pk' && r.sent[0].pk === b64u.encode(r.link.keyPair.publicRaw),
      JSON.stringify(r.sent.map((m) => m.t)));
    check('and it does not reveal anything about the initiator it has not been told yet',
      r.link.peerPublicRaw === null);

    await r.link.onSignalMessage({ t: 'pk', pk: b64u.encode(peer.publicRaw) });
    check('a reveal that matches the commitment is accepted',
      r.link.peerPublicRaw !== null
      && Buffer.from(r.link.peerPublicRaw).equals(Buffer.from(peer.publicRaw)),
      `state=${r.link.state}`);
    check('CONTROL: the honest path does not sever, so the refusals above mean something', !r.severed);
  }

  // ---- THE CHECK: a reveal that is not what was committed to
  {
    const promised = await generateKeyPair();
    const substituted = await generateKeyPair();
    const r = makeLink({ initiator: false });
    r.link.keyPair = await generateKeyPair();

    await r.link.onSignalMessage({ t: 'pkc', h: b64u.encode(await commitPublicKey(promised.publicRaw)) });
    await r.link.onSignalMessage({ t: 'pk', pk: b64u.encode(substituted.publicRaw) });

    check('a key that is not the one committed to is refused, which is the whole fix',
      r.link.peerPublicRaw === null && r.link.state === LINK_STATE.AUTH_FAILED,
      `state=${r.link.state} pinned=${Boolean(r.link.peerPublicRaw)}`);
    check('the refusal names what happened rather than reporting a generic failure',
      r.said(/revealed a different key from the one it committed to/),
      JSON.stringify(r.events.filter((e) => e.name === 'auth-failed').map((e) => e.detail)));
    check('and the gate is severed rather than left half-open', r.severed);
    check('no session keys were derived from a substituted key', r.link.sessionKeys === null);
  }

  // ---- a malformed commitment is a refusal, not a shrug
  {
    for (const [what, h] of [['not base64url', '!!!!'], ['the wrong length', b64u.encode(new Uint8Array(16))]]) {
      const r = makeLink({ initiator: false });
      r.link.keyPair = await generateKeyPair();
      await r.link.onSignalMessage({ t: 'pkc', h });
      check(`a commitment that is ${what} ends the exchange`,
        r.link.state === LINK_STATE.AUTH_FAILED && r.severed, `state=${r.link.state}`);
    }
  }

  // ---- the initiator does not reveal first
  {
    const peer = await generateKeyPair();
    const i = makeLink({ initiator: true });
    i.link.keyPair = await generateKeyPair();

    await i.link.maybeSendPublicKey();
    check('an initiator holding no peer key sends nothing, so its key cannot be ground against',
      i.sent.length === 0, JSON.stringify(i.sent.map((m) => m.t)));

    await i.link.onSignalMessage({ t: 'pk', pk: b64u.encode(peer.publicRaw) });
    check('the initiator reveals only after the responder has committed itself by answering',
      i.sent.length === 1 && i.sent[0].t === 'pk', JSON.stringify(i.sent.map((m) => m.t)));
  }

  // ---- an initiator refuses to play responder
  {
    const other = await generateKeyPair();
    const i = makeLink({ initiator: true });
    i.link.keyPair = await generateKeyPair();
    await i.link.onSignalMessage({ t: 'pkc', h: b64u.encode(await commitPublicKey(other.publicRaw)) });
    check('an initiator refuses a commitment, which is the roles being inverted under it',
      i.link.peerCommitment === null && i.sent.length === 0 && i.said(/ignored a key commitment/),
      `sent=${i.sent.length}`);
  }

  // ---- the wait cannot deadlock
  {
    const peer = await generateKeyPair();
    const r = makeLink({ initiator: false });
    r.link.keyPair = await generateKeyPair();

    // The timer's callback is captured rather than waited for: eight seconds of real time
    // in a unit suite is eight seconds nobody gets back, and what is under test is what
    // the callback DOES, not that setTimeout counts.
    const realSetTimeout = globalThis.setTimeout;
    let fire = null;
    globalThis.setTimeout = (fn, ms) => {
      if (ms === 8000 && fire === null) { fire = fn; return 0; }
      return realSetTimeout(fn, ms);
    };
    try {
      await r.link.onSignalMessage({ t: 'pkc', h: b64u.encode(await commitPublicKey(peer.publicRaw)) });
    } finally {
      globalThis.setTimeout = realSetTimeout;
    }
    check('the responder arms a clock on the reveal it is now owed', typeof fire === 'function');
    fire?.();
    check('a commitment that is never opened ends the exchange instead of hanging for ever',
      r.link.state === LINK_STATE.AUTH_FAILED, `state=${r.link.state}`);
    check('and it says the key was promised and never sent',
      r.said(/promised a key and never sent it/),
      JSON.stringify(r.events.filter((e) => e.name === 'auth-failed').map((e) => e.detail)));
  }

  // ---- renegotiation carries neither the commitment nor the latch
  {
    const first = await generateKeyPair();
    const second = await generateKeyPair();
    const r = makeLink({ initiator: false });
    r.link.keyPair = await generateKeyPair();
    await r.link.onSignalMessage({ t: 'pkc', h: b64u.encode(await commitPublicKey(first.publicRaw)) });
    await r.link.onSignalMessage({ t: 'pk', pk: b64u.encode(first.publicRaw) });
    check('the first handshake completed its exchange', r.link.peerPublicRaw !== null && r.link.pkSent === true);

    r.link.resetForRenegotiation();
    check('renegotiation drops the commitment, the reveal and the sent latch together',
      r.link.peerCommitment === null && r.link.peerPublicRaw === null && r.link.pkSent === false
      && r.link.keyPair === null && r.link.sessionKeys === null);

    // And the fresh handshake is checked against the FRESH commitment, not the stale one.
    r.link.keyPair = await generateKeyPair();
    const before = r.sent.length;
    await r.link.onSignalMessage({ t: 'pkc', h: b64u.encode(await commitPublicKey(second.publicRaw)) });
    await r.link.onSignalMessage({ t: 'pk', pk: b64u.encode(second.publicRaw) });
    check('a renegotiated link accepts the new key against the new commitment',
      r.link.peerPublicRaw !== null
      && Buffer.from(r.link.peerPublicRaw).equals(Buffer.from(second.publicRaw))
      && r.sent.length === before + 1 && !r.severed,
      `state=${r.link.state} severed=${r.severed}`);
  }

  // ---- the restart path now settles, exactly as restartConnection does
  {
    const r = makeLink({ initiator: false });
    r.link.lastRenegotiationAt = Date.now();
    // Stubbed so that a build WITHOUT the guard is observable rather than merely fatal:
    // the unguarded path calls connect(), which builds an RTCPeerConnection and throws in
    // Node, and a check that can only ever crash on the broken build has not been shown to
    // fail, it has been shown to explode. This makes the wrong behaviour reportable.
    r.link.connect = async () => { r.link.connectCalled = true; };
    await r.link.onSignalMessage({ t: 'restart' });
    check('a peer-sent restart landing on a handshake that just started is deferred, not obeyed',
      r.link.restartTimer !== null && r.said(/handshake is already in progress/),
      `timer=${Boolean(r.link.restartTimer)}`);
    check('and the handshake under way is left alone rather than torn down and restarted',
      r.link.connectCalled === undefined, `connect called: ${Boolean(r.link.connectCalled)}`);
    r.link.clearRestartTimer();

    // CONTROL: the guard is a guard and not a blanket refusal.
    const s = makeLink({ initiator: false });
    s.link.lastRenegotiationAt = Date.now() - 60_000;
    s.link.connect = async () => { s.link.connected_called = true; };
    await s.link.onSignalMessage({ t: 'restart' });
    check('CONTROL: a restart arriving on a settled link is still obeyed',
      s.link.connected_called === true && s.said(/Renegotiating/));
  }
}

// ================================================================ who sent it
//
// `from` rides inside the sealed envelope under k_sig, and every seated participant holds
// k_sig, so any one seat could put any other seat's name on a message. The server now
// attaches the token-authenticated sender as a sibling field `sfrom`, outside the sealed
// bytes, and the page drops anything where the two disagree.
//
// Driven through the real relay listener with a stand-in EventSource, so what is measured
// is the code path a relayed message actually takes: parse, open, check sender, check
// sequence, dispatch.
{
  const secret = randomSecret();
  const signalKey = await deriveSignalKey(secret);

  class FakeEventSource {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 2;
    constructor(url) {
      this.url = url;
      this.readyState = 1;
      this.listeners = new Map();
      FakeEventSource.last = this;
    }
    addEventListener(name, fn) {
      if (!this.listeners.has(name)) this.listeners.set(name, []);
      this.listeners.get(name).push(fn);
    }
    close() { this.readyState = 2; }
    emit(name, data) { for (const fn of this.listeners.get(name) ?? []) fn({ data }); }
  }

  const settle = () => new Promise((resolve) => { setTimeout(resolve, 25); });

  const wire = () => {
    const previous = globalThis.EventSource;
    globalThis.EventSource = FakeEventSource;
    const signal = new Signal({ roomId: 'ROOM', token: 'tok', signalKey });
    signal.selfId = 'me';
    signal.connect();
    globalThis.EventSource = previous;
    const seen = [];
    const refused = [];
    const undecryptable = [];
    signal.addEventListener('message', (e) => seen.push(e.detail));
    signal.addEventListener('impersonation-refused', (e) => refused.push(e.detail));
    signal.addEventListener('undecryptable', (e) => undecryptable.push(e.detail));
    return { signal, source: FakeEventSource.last, seen, refused, undecryptable };
  };

  const relay = async (w, message, sfrom) => {
    const envelope = await sealEnvelope(signalKey, message);
    w.source.emit('relay', JSON.stringify(sfrom === undefined ? envelope : { ...envelope, sfrom }));
    await settle();
  };

  // ---- the honest case
  {
    const w = wire();
    await relay(w, { t: 'pk', from: 'peer-1', seq: 1, epoch: 1000 }, 'peer-1');
    check('a message whose sealed sender matches the seat the server authenticated is delivered',
      w.seen.length === 1 && w.seen[0].from === 'peer-1',
      `${w.seen.length} delivered, ${w.refused.length} refused`);
  }

  // ---- the forgery
  {
    const w = wire();
    await relay(w, { t: 'sever', from: 'victim', seq: 1, epoch: 1000 }, 'attacker');
    check('a message sealed under another participant\'s name is dropped',
      w.seen.length === 0 && w.refused.length === 1,
      `${w.seen.length} delivered, ${w.refused.length} refused`);
    check('and the refusal names both the claim and the truth',
      /claims to come from victim/.test(w.refused[0]) && /sent by attacker/.test(w.refused[0]),
      w.refused[0]);
  }

  // ---- absent is a drop, and it says why
  {
    const w = wire();
    await relay(w, { t: 'pk', from: 'peer-1', seq: 1, epoch: 1000 }, undefined);
    check('a relay with no server attestation at all is dropped rather than trusted',
      w.seen.length === 0, `${w.seen.length} delivered`);
    check('and the diagnosis names the cause: a server older than this page',
      w.undecryptable.length === 1 && /older than this page/.test(w.undecryptable[0]),
      JSON.stringify(w.undecryptable));
  }

  // ---- ORDERING. The check has to run before the replay counter remembers anything.
  {
    const w = wire();
    // A forgery claiming to be peer-1, at a high sequence. If this reached acceptSeq it
    // would set peer-1's watermark to (1000, 500).
    await relay(w, { t: 'pk', from: 'peer-1', seq: 500, epoch: 1000 }, 'attacker');
    check('the forged message did not get through', w.seen.length === 0);
    // The real peer-1 now speaks for the first time, at sequence 1 as it always would.
    await relay(w, { t: 'pk', from: 'peer-1', seq: 1, epoch: 1000 }, 'peer-1');
    check('one seat cannot burn another seat\'s sequence space, so the real peer is still heard',
      w.seen.length === 1 && w.seen[0].seq === 1,
      `${w.seen.length} delivered after the forgery`);
    check('CONTROL: the sequence guard itself still refuses a genuine replay',
      await (async () => {
        await relay(w, { t: 'pk', from: 'peer-1', seq: 1, epoch: 1000 }, 'peer-1');
        return w.seen.length === 1;
      })(), `${w.seen.length} delivered after the replay`);
  }
}

// ================================================================ the receive path
//
// handleFrame used to dispatch CHAT, SECRET, FILE_START, FILE_CHUNK, FILE_END and every
// CONTROL message the moment a channel existed. The SEND side was gated on the link being
// connected; the receive side was not, so a peer that had agreed a session but had not
// completed key confirmation could push chat, secrets, file offers and game invites into a
// session that had not accepted it.
{
  const secret = randomSecret();
  const roomId = await deriveRoomId(secret);

  // A fresh pair per victim, rather than one pair reused three times. Reusing it would trip
  // the KEYS_IN_USE guard in Channel, which exists to stop a second Channel restarting a
  // nonce counter at zero over keys that have already sealed something, and that guard is
  // one of the defences this work is not allowed to weaken. So each victim gets its own
  // derivation and its own sender, and the frames are sealed once per victim. Nothing about
  // what is measured changes: the ONLY difference between the blocks below is
  // confirmedByPeer.
  const makePair = async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const keysA = await deriveSession({ secret, privateKey: a.privateKey, publicRaw: a.publicRaw, peerPublicRaw: b.publicRaw, role: 'a', roomId });
    const keysB = await deriveSession({ secret, privateKey: b.privateKey, publicRaw: b.publicRaw, peerPublicRaw: a.publicRaw, role: 'b', roomId });
    const events = [];
    let torn = false;
    const session = {
      severed: false,
      needsRestart: false,
      signal: { send: async () => true },
      labelFor: () => 'peer',
      sever: async () => { session.severed = true; },
      teardown: () => { torn = true; },
    };
    // B is the victim whose receive path is under test; A is the peer doing the sending.
    const link = new Link({ session, peerId: 'zzz', initiator: true });
    link.sessionKeys = keysB;
    link.channel = new Channel(keysB);
    for (const name of ['chat', 'secret', 'game', 'warning', 'file-incoming', 'file-offered']) {
      link.addEventListener(name, (event) => events.push({ name, detail: event.detail }));
    }
    const sender = new Channel(keysA);
    return {
      link, events, sender, keysA,
      get torn() { return torn; },
      saw: (n) => events.some((e) => e.name === n),
      chat: () => sender.seal(TYPE.CHAT, te.encode('hello')),
      secret: () => sender.seal(TYPE.SECRET, te.encode('shh')),
      game: () => sender.sealJson(TYPE.CONTROL, { kind: 'game', payload: { t: 'invite' } }),
      sever: () => sender.sealJson(TYPE.CONTROL, { kind: 'sever' }),
      confirm: () => sender.sealJson(TYPE.CONTROL, { kind: 'confirm', value: b64u.encode(keysA.confirmMine) }),
    };
  };

  {
    const v = await makePair();
    for (const frame of [await v.chat(), await v.secret(), await v.game(), await v.sever()]) {
      await v.link.handleFrame(frame);
    }
    check('an unconfirmed peer cannot put a chat message into the session', !v.saw('chat'));
    check('an unconfirmed peer cannot put a secret into the session', !v.saw('secret'));
    check('an unconfirmed peer cannot start a game', !v.saw('game'));
    check('an unconfirmed peer cannot burn the gate', v.torn === false);
    check('and every one of those is reported rather than silently dropped',
      v.events.filter((e) => e.name === 'warning').length === 4,
      JSON.stringify(v.events.map((e) => e.name)));
  }

  {
    // CONTROL: the same frames, on a link whose peer HAS confirmed. Without this the checks
    // above would pass on a build that dropped every frame it was ever handed.
    const v = await makePair();
    v.link.confirmedByPeer = true;
    for (const frame of [await v.chat(), await v.secret(), await v.game()]) {
      await v.link.handleFrame(frame);
    }
    check('CONTROL: a confirmed peer\'s chat still arrives', v.saw('chat'));
    check('CONTROL: a confirmed peer\'s secret still arrives', v.saw('secret'));
    check('CONTROL: a confirmed peer\'s game message still arrives', v.saw('game'));
    await v.link.handleFrame(await v.sever());
    check('CONTROL: and a confirmed peer can still burn the gate', v.torn === true);
  }

  {
    // The confirmation frame itself must never be caught by the gate, which is why the
    // check sits per branch rather than at the top of handleFrame.
    const v = await makePair();
    await v.link.handleFrame(await v.confirm());
    check('the key confirmation itself is exempt, or nothing could ever be confirmed',
      v.link.confirmedByPeer === true, `state=${v.link.state}`);
  }
}

// ================================================================ chunk framing bounds
{
  // R4: a chunk frame carrying an index and no bytes.
  const empty = new Uint8Array(CHUNK_INDEX_BYTES);
  let refusedEmpty = null;
  try { unframeChunk(empty); } catch (err) { refusedEmpty = err.message; }
  check('a chunk frame with an index and no bytes is refused',
    refusedEmpty !== null && /no bytes/.test(refusedEmpty), String(refusedEmpty));
  check('CONTROL: and its refusal is a different message from the too-short-to-parse one',
    await (async () => {
      let shortMsg = null;
      try { unframeChunk(new Uint8Array(3)); } catch (err) { shortMsg = err.message; }
      return shortMsg !== null && shortMsg !== refusedEmpty && /too short/.test(shortMsg);
    })());
  check('CONTROL: a one-byte body is still accepted, so the bound is exact rather than blunt',
    unframeChunk(frameChunk(7, Uint8Array.of(0x41))).bytes.byteLength === 1);

  // W7: a declared size whose chunks cannot all be named by a 32-bit index.
  const sink = { kind: 'memory', async write() {}, async finish() {}, async abort() {} };
  const MAX_INDEX_SPACE = 0x1_0000_0000;
  let refusedHuge = null;
  try {
    createIndexedSink(sink, { chunkSize: 1, size: MAX_INDEX_SPACE + 1 });
  } catch (err) { refusedHuge = err.message; }
  check('a file needing more chunks than a 32-bit index can name is refused before a sink is opened',
    refusedHuge !== null && /32-bit chunk index/.test(refusedHuge), String(refusedHuge));
  check('CONTROL: a file that fits the index space exactly is still accepted',
    typeof createIndexedSink(sink, { chunkSize: 1, size: MAX_INDEX_SPACE }).write === 'function');
}

// ================================================================ the pre-accept buffer
//
// Chunks that arrive while the accept dialog is on screen are held. The hold was bounded in
// BYTES only, and a zero-length chunk contributed zero bytes while still costing an array
// entry, so the buffer grew without limit for 30 bytes a frame on the wire. Zero length is
// refused at the framing layer now; this is the second bound, on entries.
{
  const events = [];
  const session = {
    severed: false, needsRestart: false, roomId: 'ROOM',
    signal: { send: async () => true }, labelFor: () => 'peer',
    sever: async () => {}, teardown: () => {},
  };
  const link = new Link({ session, peerId: 'zzz', initiator: true });
  for (const name of ['warning', 'file-failed']) {
    link.addEventListener(name, (event) => events.push({ name, detail: event.detail }));
  }
  // No channel, so control() is a no-op: the peer cannot be told, which is not what is
  // under test here and would need a whole second link to observe.
  link.channel = null;
  link.incoming = {
    meta: { id: 'f1', name: 'big.bin', size: 1 << 30, chunkSize: 16384 },
    received: 0, chunks: 0, sink: null, stalled: false, resumes: 0, token: null,
  };

  // One byte each: the cheapest entry that survives the zero-length refusal.
  const one = Uint8Array.of(0x41);
  for (let i = 0; i < 4000 && link.incoming; i += 1) {
    await link.onFileChunk(frameChunk(i, one));
  }
  check('the pre-accept buffer stops growing on an entry count, not only on a byte count',
    link.incoming === null, `still holding ${link.incoming?.early?.length ?? 0} entries`);
  check('and the transfer is failed with a reason rather than dropped in silence',
    events.some((e) => e.name === 'file-failed'), JSON.stringify(events.map((e) => e.name)));

  // CONTROL: the same buffer takes an ordinary run-ahead without complaining, so the cap
  // above is a cap on abuse rather than on use.
  const ok = new Link({ session, peerId: 'yyy', initiator: true });
  ok.channel = null;
  ok.incoming = {
    meta: { id: 'f2', name: 'ok.bin', size: 1 << 30, chunkSize: 16384 },
    received: 0, chunks: 0, sink: null, stalled: false, resumes: 0, token: null,
  };
  for (let i = 0; i < 200; i += 1) await ok.onFileChunk(frameChunk(i, one));
  check('CONTROL: 200 held chunks is still an ordinary sender running ahead',
    ok.incoming !== null && ok.incoming.early.length === 200,
    `held ${ok.incoming?.early?.length}`);
}

// ================================================================ peer-chosen filenames
//
// The name arrives exactly as the other side wrote it and ends up as a header value on the
// streaming download route, where the service worker encodes it. A lone surrogate cannot
// be encoded as UTF-8, so encodeURIComponent throws, the route answers 500, the start
// handshake never fires, and the page blames a stalled connection ten seconds later. That
// route is the only way Firefox and Safari receive a large file.
{
  const encodes = (s) => { try { encodeURIComponent(s); return true; } catch (err) { return false; } };

  check('CONTROL: a lone surrogate really does break encodeURIComponent, which is the bug',
    !encodes('a\ud800b.txt'));

  check('a lone high surrogate is stripped', encodes(sanitizeFilename('a\ud800b.txt')));
  check('a lone low surrogate is stripped', encodes(sanitizeFilename('a\udc00b.txt')));
  check('a name that is nothing but lone surrogates falls back rather than becoming empty',
    sanitizeFilename('\ud800\ud801') === 'warp-gate-file', sanitizeFilename('\ud800\ud801'));

  // Pairs are kept: an emoji in a filename is a name a person picked, not an attack.
  const emoji = 'holiday \u{1F600}.jpg';
  check('a well-formed surrogate PAIR survives, so emoji filenames are not silently deleted',
    sanitizeFilename(emoji) === emoji, sanitizeFilename(emoji));

  // Truncation at a UTF-16 index used to cut through a pair and produce a lone surrogate
  // out of a name that was individually well-formed.
  const split = `${'A'.repeat(119)}\u{1F600}${'B'.repeat(50)}`;
  check('CONTROL: the truncation point really does land inside the emoji in this name',
    split.length > 120 && split.charCodeAt(119) >= 0xd800 && split.charCodeAt(119) <= 0xdbff);
  const truncated = sanitizeFilename(split);
  check('truncating never cuts between the halves of a surrogate pair',
    encodes(truncated) && truncated.length <= 120, `${truncated.length} chars, encodes=${encodes(truncated)}`);

  // R6: the leading-dot strip used to run before .trim(), so one leading space defeated it.
  check('a leading space no longer smuggles ".." past the leading-dot strip',
    sanitizeFilename(' ..') === 'warp-gate-file', sanitizeFilename(' ..'));
  check('nor a hidden file', sanitizeFilename(' .bashrc') === 'bashrc', sanitizeFilename(' .bashrc'));
  check('nor a traversal spelling: the leading dots are gone and the separators are already replaced',
    sanitizeFilename('  ../../etc/passwd') === '_.._etc_passwd',
    sanitizeFilename('  ../../etc/passwd'));
  check('CONTROL: the guard still worked without the leading space, so the space was the whole bug',
    sanitizeFilename('..') === 'warp-gate-file' && sanitizeFilename('.bashrc') === 'bashrc');
  check('an ordinary name is untouched', sanitizeFilename('report.pdf') === 'report.pdf');
}

// ================================================================ the camera's only voice
//
// qrscan's per-frame decode must not throw: the next frame is a fresh attempt and very
// often the one that works. The reason used to be discarded outright, which left the whole
// camera path with no diagnostic at all: a decoder failing on every single frame looked
// exactly like a camera pointed at a wall.
{
  const realNavigator = globalThis.navigator;
  const realDocument = globalThis.document;

  const track = { stop() {} };
  const stream = { getTracks: () => [track] };
  const canvas = {
    width: 0,
    height: 0,
    getContext: () => ({
      drawImage() {},
      getImageData() { throw new Error('the frame could not be read'); },
    }),
  };
  const video = {
    srcObject: null, muted: false, videoWidth: 640, videoHeight: 480,
    setAttribute() {}, play: async () => {},
  };

  Object.defineProperty(globalThis, 'navigator', {
    value: { mediaDevices: { getUserMedia: async () => stream } },
    configurable: true, writable: true,
  });
  globalThis.document = { createElement: () => canvas };

  const abort = new AbortController();
  const scan = scanOnce(video, { signal: abort.signal }).then(() => null, (err) => err);
  // Long enough for at least one 260 ms decode attempt, then cancel.
  await new Promise((resolve) => { setTimeout(resolve, 700); });
  abort.abort();
  const outcome = await scan;

  if (realNavigator === undefined) delete globalThis.navigator;
  else Object.defineProperty(globalThis, 'navigator', { value: realNavigator, configurable: true, writable: true });
  if (realDocument === undefined) delete globalThis.document;
  else globalThis.document = realDocument;

  check('CONTROL: the scan really ran and was cancelled, so the frames really were attempted',
    outcome?.code === SCAN_ERR.CANCELLED, String(outcome?.code ?? outcome));
  check('a decode that throws is survivable: the scanner keeps going rather than falling over',
    outcome instanceof Error && outcome.code === SCAN_ERR.CANCELLED);
  check('and the reason is KEPT rather than discarded, which is the camera path\'s only diagnostic',
    lastScanError() === 'the frame could not be read', String(lastScanError()));
}

process.exit(summary('crypto') ? 0 : 1);
