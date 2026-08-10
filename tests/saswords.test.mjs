// Spoken SAS verification.
//
// The claim under test is narrow and strong: the two words a user reads out are the five
// digit SAS from DESIGN.md 3.3 in another alphabet, nothing else. So the interesting
// checks are not "does it return two strings", they are:
//
//   - the number the module reads is the number crypto.js produced, from real ECDH
//   - the same key material gives the same words on BOTH sides of a real handshake
//   - different key material NEVER gives the same words, proved over the whole 100000
//     code space rather than sampled, because a collision is a false "we are safe"
//   - the mapping is not skewed, because a skewed map quietly costs bits
//
// Every check that could pass vacuously has a negative control below it that feeds the
// same predicate a case it must reject.

import { webcrypto } from 'node:crypto';
import { check, summary } from './lib/harness.mjs';
import { b64u, deriveSession, generateKeyPair, WORDS } from '../public/js/crypto.js';
import {
  SAS_BITS,
  SAS_DIGITS,
  SAS_LIST_SIZE,
  SAS_MODULUS,
  SAS_WORD_CAPACITY_BITS,
  SAS_WORD_COUNT,
  SAS_WORD_LIST,
  formatSasWords,
  sasNumeric,
  sasPhrase,
  sasWords,
  soundKey,
} from '../public/js/saswords.js';

const te = new TextEncoder();

// ---------------------------------------------------------------- environment
{
  // public/js runs unbundled in a browser and unbundled in Node, so "the same code" is
  // only true if the same API is really there. Assert it rather than assume it: if
  // globalThis.crypto.subtle were a Node-only shim the browser behaviour would be
  // untested and this suite would still be green.
  const subtle = globalThis.crypto?.subtle;
  check('globalThis.crypto.subtle exists in Node without an import',
    typeof subtle?.digest === 'function' && typeof subtle?.deriveBits === 'function',
    `node ${process.version}`);
  check('it is the same WebCrypto object node:crypto exposes, so browser and Node agree',
    globalThis.crypto === webcrypto, `${globalThis.crypto?.constructor?.name}`);
  const digest = new Uint8Array(await subtle.digest('SHA-256', te.encode('abc')));
  check('SHA-256("abc") matches the published vector',
    Buffer.from(digest).toString('hex') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    Buffer.from(digest).toString('hex'));
}

// ---------------------------------------------------------------- the spoken word list
{
  check('the spoken list is a strict subset of the gate code wordlist',
    SAS_WORD_LIST.every((w) => WORDS.includes(w)) && SAS_LIST_SIZE < WORDS.length,
    `${SAS_LIST_SIZE} of ${WORDS.length}`);
  check('it is the documented size, so a wordlist edit cannot silently change the words',
    SAS_LIST_SIZE === 4022, `size ${SAS_LIST_SIZE}`);
  check('every word is 5 to 7 letters and lowercase a-z',
    SAS_WORD_LIST.every((w) => /^[a-z]{5,7}$/.test(w)),
    SAS_WORD_LIST.filter((w) => !/^[a-z]{5,7}$/.test(w)).slice(0, 5).join(','));
  check('the list is sorted and free of duplicates, so index order is pinned',
    SAS_WORD_LIST.every((w, i) => i === 0 || SAS_WORD_LIST[i - 1] < w), 'strictly ascending');

  const keys = new Map();
  const clashes = [];
  for (const word of SAS_WORD_LIST) {
    const k = soundKey(word);
    if (keys.has(k)) clashes.push(`${keys.get(k)}/${word}`);
    else keys.set(k, word);
  }
  check('no two words on the spoken list share a sound-alike key',
    clashes.length === 0, clashes.slice(0, 5).join(' '));

  // The filter has to actually remove something, or the "no two sound alike" check above
  // is passing on a list that was never narrowed.
  const droppedShort = WORDS.filter((w) => w.length < 5).length;
  check('the narrowing removed real candidates rather than passing the list through',
    WORDS.length - SAS_LIST_SIZE > 1000,
    `dropped ${WORDS.length - SAS_LIST_SIZE}, of which ${droppedShort} were under 5 letters`);
  check('a known confusable pair cannot both survive',
    !(SAS_WORD_LIST.includes('abbot') && SAS_WORD_LIST.includes('about')),
    `abbot=${SAS_WORD_LIST.includes('abbot')} about=${SAS_WORD_LIST.includes('about')}`);
}

// ---------------------------------------------------------------- bit accounting
{
  check('the numeric SAS space is the one crypto.js uses',
    SAS_MODULUS === 100000 && SAS_DIGITS === 5, `${SAS_DIGITS} digits mod ${SAS_MODULUS}`);
  check('the word pair carries at least as many bits as the numeric code',
    SAS_WORD_CAPACITY_BITS >= SAS_BITS,
    `${SAS_WORD_COUNT} words hold ${SAS_WORD_CAPACITY_BITS.toFixed(2)} bits, the code asserts ${SAS_BITS.toFixed(2)}`);
  check('and the honest figure is the source, not the capacity',
    Math.abs(SAS_BITS - 16.6096) < 0.001, `${SAS_BITS.toFixed(4)} bits of content`);
}

// ---------------------------------------------------------------- real handshakes
//
// An independent re-implementation of the sas branch of DESIGN.md 3.3, so the raw byte
// path is checked against the specification and not against crypto.js reading itself.
async function independentSasBits({ secret, roomId, priv, peerPubRaw, pkA, pkB }) {
  // Imported here rather than through crypto.js importPeerPublic, so this path shares no
  // code with the implementation it is checking.
  const peerPub = await webcrypto.subtle.importKey(
    'raw', peerPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const z = new Uint8Array(await webcrypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPub }, priv, 256,
  ));
  const master = await webcrypto.subtle.importKey('raw', z, 'HKDF', false, ['deriveBits']);
  const parts = [te.encode('wg/v1'), te.encode(roomId), pkA, pkB];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  const transcript = new Uint8Array(await webcrypto.subtle.digest('SHA-256', buf));
  return new Uint8Array(await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: secret, info: te.encode(`wg/v1/sas:${b64u.encode(transcript)}`) },
    master,
    64,
  ));
}

async function handshake(seed) {
  // A fixed secret per seed keeps a failure reproducible; the ECDH keys are fresh, which
  // is what makes each handshake different key material.
  const secret = new Uint8Array(16);
  new DataView(secret.buffer).setUint32(0, seed);
  const roomId = `ROOM${String(seed).padStart(4, '0')}`;
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const common = { secret, roomId };
  const sessionA = await deriveSession({
    ...common, privateKey: a.privateKey, publicRaw: a.publicRaw, peerPublicRaw: b.publicRaw, role: 'a',
  });
  const sessionB = await deriveSession({
    ...common, privateKey: b.privateKey, publicRaw: b.publicRaw, peerPublicRaw: a.publicRaw, role: 'b',
  });
  const raw = await independentSasBits({
    secret, roomId, priv: a.privateKey, peerPubRaw: b.publicRaw, pkA: a.publicRaw, pkB: b.publicRaw,
  });
  return { sessionA, sessionB, raw };
}

// Both sides of the SAME handshake must land on the same words. Kept as a predicate so
// the negative control below runs the identical comparison on material that must differ.
async function sameWordsBothSides(left, right) {
  const [wl, wr] = await Promise.all([sasWords(left), sasWords(right)]);
  return wl.length === SAS_WORD_COUNT && wr.length === SAS_WORD_COUNT
    && wl.every((w, i) => w === wr[i]);
}

const HANDSHAKES = 48;
const runs = [];
for (let i = 0; i < HANDSHAKES; i += 1) runs.push(await handshake(i));

{
  let agreed = 0;
  let numericMatched = 0;
  let rawMatched = 0;
  const detail = [];
  for (const { sessionA, sessionB, raw } of runs) {
    if (await sameWordsBothSides(sessionA, sessionB)) agreed += 1;
    if (sasNumeric(sessionA) === sessionA.sas) numericMatched += 1;
    // The independent HKDF output, reduced by the module, must reproduce the number
    // crypto.js computed AND the same words as the five digit string does.
    const fromRaw = await sasWords(raw);
    const fromDigits = await sasWords(sessionA.sas);
    if (sasNumeric(raw) === sessionA.sas && fromRaw.join(' ') === fromDigits.join(' ')) rawMatched += 1;
    else detail.push(`${sessionA.sas} vs ${sasNumeric(raw)}`);
  }
  check(`both ends of ${HANDSHAKES} real ECDH handshakes read the same two words`,
    agreed === HANDSHAKES, `${agreed}/${HANDSHAKES}`);
  check('the module reads the number deriveSession returned, not one of its own',
    numericMatched === HANDSHAKES, `${numericMatched}/${HANDSHAKES}`);
  check('the raw HKDF wg/v1/sas block and the 5 digit string give one number and one word pair',
    rawMatched === HANDSHAKES, detail.slice(0, 3).join(' | ') || `${rawMatched}/${HANDSHAKES}`);
}

// Different key material must give different words. Predicate, again, so the negative
// control can feed it a set it must reject.
function allPairsDistinct(pairs) {
  return new Set(pairs.map((p) => p.join(' '))).size === pairs.length;
}

{
  const distinctCodes = [...new Set(runs.map((r) => r.sessionA.sas))];
  const pairs = await Promise.all(distinctCodes.map((code) => sasWords(code)));
  check(`${HANDSHAKES} independent handshakes produced ${distinctCodes.length} distinct codes, and as many distinct word pairs`,
    allPairsDistinct(pairs), `${new Set(pairs.map((p) => p.join(' '))).size} pairs`);
}

// ---------------------------------------------------------------- determinism
{
  const sample = ['00000', '00001', '12345', '54321', '99999', '42424'];
  const first = await Promise.all(sample.map(sasWords));
  const second = await Promise.all(sample.map(sasWords));
  check('repeating a call returns the identical words', first.every((w, i) => w.join(' ') === second[i].join(' ')),
    first.map((w) => w.join('-')).join(' '));

  // A second, separately evaluated copy of the module. The round tables are built once
  // and cached, so calling twice inside one instance only proves memoisation works. This
  // proves the tables themselves are fixed by the label and not by evaluation order.
  const fresh = await import('../public/js/saswords.js?instance=2');
  const other = await Promise.all(sample.map((s) => fresh.sasWords(s)));
  check('a freshly evaluated copy of the module builds identical tables',
    first.every((w, i) => w.join(' ') === other[i].join(' ')), 'two module instances agree');
  check('and the two instances built the same spoken list',
    fresh.SAS_WORD_LIST.join(' ') === SAS_WORD_LIST.join(' '), `${fresh.SAS_LIST_SIZE} vs ${SAS_LIST_SIZE}`);
}

// ---------------------------------------------------------------- the whole code space
//
// 100000 codes is small enough to enumerate, so nothing here is sampled. This is the
// check that the pairing can never contradict the digits.
const everyPair = [];
{
  const t0 = Date.now();
  for (let n = 0; n < SAS_MODULUS; n += 1) {
    everyPair.push(await sasWords(String(n).padStart(SAS_DIGITS, '0')));
  }
  const seen = new Set(everyPair.map((p) => p.join(' ')));
  check(`all ${SAS_MODULUS} SAS codes map to ${SAS_MODULUS} distinct word pairs, so the words can never say "safe" while the digits say "attack"`,
    seen.size === SAS_MODULUS, `${seen.size} distinct pairs in ${Date.now() - t0} ms`);
  const onList = new Set(SAS_WORD_LIST);
  check('every word emitted is on the spoken list',
    everyPair.every((p) => p.length === SAS_WORD_COUNT && p.every((w) => onList.has(w))),
    'no word came from outside the list');
}

// ---------------------------------------------------------------- distribution
//
// Modulo bias on a 7776 entry list is the standard way to lose bits here without any
// visible symptom, so this measures the finished mapping over the entire code space
// rather than trusting the rejection sampling in buildTables.
function chiSquare(counts, samples) {
  const expected = samples / counts.length;
  let chi2 = 0;
  for (const c of counts) chi2 += ((c - expected) ** 2) / expected;
  return chi2;
}

function positionCounts(pairs, position) {
  const index = new Map(SAS_WORD_LIST.map((w, i) => [w, i]));
  const counts = new Array(SAS_LIST_SIZE).fill(0);
  for (const p of pairs) counts[index.get(p[position])] += 1;
  return counts;
}

{
  const df = SAS_LIST_SIZE - 1;
  // Five standard deviations either side of the mean of a chi-square with df degrees of
  // freedom. Wide enough that a correct mapping will not trip it by chance, narrow enough
  // that the deliberately skewed control below is rejected.
  const spread = 5 * Math.sqrt(2 * df);
  for (let position = 0; position < SAS_WORD_COUNT; position += 1) {
    const counts = positionCounts(everyPair, position);
    const chi2 = chiSquare(counts, SAS_MODULUS);
    const min = Math.min(...counts);
    const max = Math.max(...counts);
    check(`word ${position + 1} is uniform across all ${SAS_MODULUS} codes (chi-square within 5 sd of ${df} df)`,
      Math.abs(chi2 - df) <= spread,
      `chi2 ${chi2.toFixed(1)}, expected ${df} +/- ${spread.toFixed(0)}, counts ${min}..${max} against an expected ${(SAS_MODULUS / SAS_LIST_SIZE).toFixed(1)}`);
    check(`word ${position + 1} reaches every word on the list, so no entry is unreachable`,
      min > 0, `least used word appears ${min} times`);
  }
}

// ---------------------------------------------------------------- input handling
{
  const bytes = new Uint8Array([0x00, 0x01, 0x86, 0xa1, 0xde, 0xad, 0xbe, 0xef]);
  // 0x000186a1 = 100001, and 100001 mod 100000 = 1.
  check('raw bytes are reduced exactly the way crypto.js reduces them',
    sasNumeric(bytes) === '00001', sasNumeric(bytes));
  // crypto.js reduces getUint32(0), so bytes 4 to 7 of the HKDF block are not part of
  // the numeric SAS. The words must ignore exactly the same bytes: if they read wider,
  // two sessions could show matching digits and differing words, which is the same
  // contradiction as a collision, arriving from the other direction.
  const wider = Uint8Array.from(bytes);
  wider[7] ^= 0xff;
  const narrower = Uint8Array.from(bytes);
  narrower[0] ^= 0xff;
  check('the words read exactly the bits the numeric SAS reads, no wider and no narrower',
    (await sasWords(wider)).join(' ') === (await sasWords(bytes)).join(' ')
      && (await sasWords(narrower)).join(' ') !== (await sasWords(bytes)).join(' '),
    `${sasNumeric(bytes)} / ${sasNumeric(wider)} / ${sasNumeric(narrower)}`);

  check('a session-shaped object is read through its sas field',
    sasNumeric({ sas: '04217' }) === '04217' && (await sasWords({ sas: '04217' })).join(' ') === (await sasWords('04217')).join(' '),
    'object and string agree');

  const rejects = ['1234', '123456', 'abcde', '1234a', '', null, undefined, 42, {}, { sas: 7 }, new Uint8Array(3)];
  const accepted = [];
  for (const bad of rejects) {
    try { sasNumeric(bad); accepted.push(JSON.stringify(bad) ?? String(bad)); } catch (err) {
      if (!(err instanceof TypeError)) accepted.push(`${bad}: ${err.message}`);
    }
  }
  check('anything that is not a SAS is refused rather than turned into words',
    accepted.length === 0, `accepted ${accepted.join(', ')}`);
}

// ---------------------------------------------------------------- display
{
  const words = await sasWords('13579');
  const phrase = await sasPhrase('13579');
  check('the display form is capitals separated by one space, so it reads out cleanly',
    phrase === formatSasWords(words) && /^[A-Z]{5,7} [A-Z]{5,7}$/.test(phrase), phrase);
  check('the formatter refuses the wrong number of words',
    (() => { try { formatSasWords(['only']); return false; } catch (err) { return err instanceof TypeError; } })(),
    'one word must throw');
}

// ---------------------------------------------------------------- negative controls
//
// Each control runs the SAME predicate the real check above used, on input it must
// reject. Without these, a predicate that returned true unconditionally would leave the
// suite green.
{
  // Control 1: "the same key material gives the same words" must be able to report a
  // mismatch. Two DIFFERENT handshakes are fed to sameWordsBothSides, which passed on 48
  // matched pairs above. Distinct codes are picked so the comparison is genuinely
  // between different key material and not an accidental 1-in-100000 collision.
  const different = runs.filter((r, i) => i === 0 || r.sessionA.sas !== runs[0].sessionA.sas);
  const agreedWrongly = await sameWordsBothSides(different[0].sessionA, different[1].sessionB);
  check('NEGATIVE CONTROL: the same-words check reports a mismatch when the key material differs',
    agreedWrongly === false,
    `${different[0].sessionA.sas} vs ${different[1].sessionB.sas}`);

  // Control 2: "different inputs give different words" must be able to report a
  // collision. allPairsDistinct is handed a list containing the same word pair twice.
  const one = await sasWords('24680');
  const two = await sasWords('13579');
  check('NEGATIVE CONTROL: the distinctness check reports a collision when one is planted',
    allPairsDistinct([one, two, one]) === false && allPairsDistinct([one, two]) === true,
    'a duplicated pair must be caught, an honest pair must not');

  // Control 3: the uniformity check must be able to reject a skewed mapping. This one
  // uses only 16 of the 4022 words, which is exactly the shape a modulo bias produces,
  // in an exaggerated form.
  const skewed = everyPair.map((p, i) => [SAS_WORD_LIST[i % 16], p[1]]);
  const skewChi = chiSquare(positionCounts(skewed, 0), SAS_MODULUS);
  const df = SAS_LIST_SIZE - 1;
  check('NEGATIVE CONTROL: the uniformity check rejects a deliberately skewed mapping',
    Math.abs(skewChi - df) > 5 * Math.sqrt(2 * df), `skewed chi2 ${skewChi.toExponential(2)} against ${df} df`);
}

process.exit(summary('sas words') ? 0 : 1);
