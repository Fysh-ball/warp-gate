// Warp Gate spoken SAS: the five digit short authentication string, said as TWO words.
//
// DESIGN.md 3.3 derives sas = HKDF-Expand(master, "wg/v1/sas:"||b64u(T), 8) and reduces
// it to five decimal digits, which both ends display so a person can confirm aloud that
// nobody substituted a key. Five digits read out over a phone is accurate and horrible.
// This module says the SAME value as two words.
//
// ---------------------------------------------------------------- one derivation only
//
// There is no second key schedule here. This module takes the number crypto.js already
// produced and re-encodes it. That is deliberate: two independent derivations of "the
// SAS" are two assertions, and the day they disagree one of them is wrong and nobody
// knows which. Every input form this module accepts is funnelled through sasNumeric()
// into the identical five digit value first, so the words are always a function of the
// number and the number alone.
//
// The map from number to word pair is a BIJECTION (a four round Feistel network over
// the 4022 x 4022 grid of word pairs), not a hash. A hash-and-reduce would have been two
// lines shorter and would have collided: 100000 codes thrown into 7776^2 pairs collide
// about 83 times by the birthday bound, and a collision is exactly the failure this
// pairing exists to prevent. It would mean two sessions whose numbers differ showing the
// same words, so the words would say "safe" while the numbers say "attack". Being a
// bijection, this map cannot do that: different numbers ALWAYS give different words.
// The test proves it exhaustively over all 100000 codes rather than by argument.
//
// ---------------------------------------------------------------- what it is worth
//
// The word pair carries exactly log2(100000) = 16.61 bits, because that is everything
// the numeric SAS has. Two words drawn from the 4022 word list below could hold
// 2*log2(4022) = 23.95 bits, so the pair is not the limit: the five digit source is.
// A third word would add display, not security, so there are two. An attacker who wants
// a session whose spoken words match still has to hit 1 in 100000, the same odds as the
// digits, no better and no worse.
//
// Anyone tempted to widen this: the bits must come from crypto.js, by widening the SAS
// there. Widening it here would only spread the same 16.61 bits over more syllables.
//
// ---------------------------------------------------------------- the word list
//
// words.js ships 7776 words for gate codes, chosen to be TYPED. These are SPOKEN over a
// bad line, which is a different filter, so the list is narrowed here, deterministically
// and at load time, by two rules:
//
//   1. Five letters minimum. words.js already guarantees four (its regex is
//      /^[a-z]{4,7}$/), so nothing shorter exists to remove, but a longer word carries
//      more redundancy through noise: "abalone" survives a dropout that eats "abed".
//   2. No two survivors may sound alike. Words are grouped by the phonetic key below
//      and one member per group is kept, the longest, ties broken alphabetically. This
//      is what stops "abbot" and "about", or "sauna" and "senna", both being on the
//      list, because the listener compares what they HEAR against what their own screen
//      shows and a homophone on that screen reads as a match.
//
// Keeping one member per group is enough, and dropping whole groups would be the wrong
// fix: a word that sounds like a list word but is NOT on the list can never appear on
// the other screen, so it cannot cause a false match. The narrowing only has to make the
// list internally unambiguous.
//
// 4022 words survive. That is 23.95 bits of capacity against 16.61 bits of content, so
// the narrowing is free: it spends headroom nobody was using.

import { WORDS, WORDLIST_SHA256 } from './words.js';

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

/** Mirrors crypto.js deriveSession: `getUint32(0) % 100000`, padded to five digits. */
export const SAS_MODULUS = 100000;
export const SAS_DIGITS = 5;

/** Two words. See the bit accounting above for why not three. */
export const SAS_WORD_COUNT = 2;

/** Shortest word the spoken list accepts. */
export const MIN_WORD_LENGTH = 5;

/**
 * The wordlist this module was built against. A different list is not a bug and not a
 * break: the number is the authority and both ends still agree on it. But the words
 * would differ across a version skew, so the test pins this and fails loudly rather than
 * letting the displayed pair change under a wordlist edit nobody connected to the SAS.
 */
export const SOURCE_WORDLIST_SHA256 = WORDLIST_SHA256;

/**
 * A deterministic sound-alike key. Aggressive on purpose: merging two words that a good
 * line would have kept apart costs list size, which there is plenty of, while missing a
 * pair costs a false "the words match" on a bad line, which is the whole failure mode.
 *
 * Not Soundex. Soundex throws away every vowel after the first letter, which merges
 * words a human hears apart even through noise, and it is fixed at four characters so
 * long words collapse into each other by their prefix.
 *
 * Exported so the test can assert the property this list is built on, that no two
 * survivors share a key, rather than trusting the loop below to have done it.
 */
export function soundKey(word) {
  let s = word;
  // A trailing s is the first thing a phone drops, so "beacon" and "beacons" are one.
  if (s.length > 4 && s.endsWith('s')) s = s.slice(0, -1);
  return s
    // Silent leading consonants: knee/nee, wren/ren, gnome/nome, psalm/salm.
    .replace(/^kn/, 'n').replace(/^wr/, 'r').replace(/^gn/, 'n').replace(/^ps/, 's')
    .replace(/ck/g, 'k')
    .replace(/ph/g, 'f')
    .replace(/gh/g, '') // night, though, weigh: silent far more often than not
    .replace(/wh/g, 'w')
    .replace(/mb$/, 'm') // lamb, comb
    // Soft c before e, i or y; hard everywhere else. Both land on an existing letter so
    // "cell"/"sell" and "cat"/"kat" cannot survive as separate entries.
    .replace(/([aeiou])c([eiy])/g, '$1s$2')
    .replace(/c([eiy])/g, 's$1')
    .replace(/c/g, 'k')
    .replace(/q/g, 'k')
    .replace(/x/g, 'ks')
    .replace(/z/g, 's')
    .replace(/y/g, 'i')
    // Every vowel run becomes one marker. Vowel quality is the first thing a compressed
    // phone codec destroys, so "abbot"/"about" and "ablate"/"oblate" are one word here.
    .replace(/[aeiou]+/g, 'a')
    .replace(/(.)\1+/g, '$1');
}

function buildSpokenList() {
  const groups = new Map();
  for (const word of WORDS) {
    if (word.length < MIN_WORD_LENGTH) continue;
    const key = soundKey(word);
    const existing = groups.get(key);
    // Longest wins because length is redundancy; alphabetical breaks the tie so the
    // survivor never depends on the order words.js happens to store its list in.
    if (existing === undefined
      || word.length > existing.length
      || (word.length === existing.length && word < existing)) {
      groups.set(key, word);
    }
  }
  // Sorted, because index order is what pins number -> word and it must not inherit
  // insertion order from the source list.
  return Object.freeze([...groups.values()].sort());
}

/** The spoken list: 4022 words, all 5 to 7 letters, no two sound alike. */
export const SAS_WORD_LIST = buildSpokenList();
export const SAS_LIST_SIZE = SAS_WORD_LIST.length;

/** What the pair actually asserts, and what it could hold if the source were wider. */
export const SAS_BITS = Math.log2(SAS_MODULUS);
export const SAS_WORD_CAPACITY_BITS = SAS_WORD_COUNT * Math.log2(SAS_LIST_SIZE);

// ---------------------------------------------------------------- number in

function bytesOf(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return null;
}

/**
 * The five digit SAS as a string, from whatever the caller has to hand:
 *
 *   '04217'                     the value deriveSession already returned
 *   { sas: '04217' }            a sessionKeys or peer summary object
 *   Uint8Array(8)               the raw HKDF "wg/v1/sas" block
 *
 * The byte path repeats crypto.js exactly (`getUint32(0) % 100000`, padded), so all
 * three forms of the same session produce one number and therefore one word pair.
 *
 * Anything else throws. A SAS is compared to decide whether a stranger is on the wire,
 * so a caller that hands this the wrong object has to hear about it, not receive words
 * derived from something that was never the SAS.
 */
const SAS_STRING = new RegExp(`^[0-9]{${SAS_DIGITS}}$`);

export function sasNumeric(input) {
  if (typeof input === 'string') {
    if (!SAS_STRING.test(input)) {
      throw new TypeError(`a SAS string must be exactly ${SAS_DIGITS} digits, got ${JSON.stringify(input)}`);
    }
    return input;
  }
  const bytes = bytesOf(input);
  if (bytes) {
    if (bytes.length < 4) {
      throw new TypeError(`SAS bytes must be at least 4 long, got ${bytes.length}`);
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return String(view.getUint32(0) % SAS_MODULUS).padStart(SAS_DIGITS, '0');
  }
  if (input && typeof input === 'object' && typeof input.sas === 'string') {
    return sasNumeric(input.sas);
  }
  throw new TypeError(`cannot read a SAS from ${input === null ? 'null' : typeof input}`);
}

// ---------------------------------------------------------------- number to words

const ROUNDS = 4;

// Fixed label, so the tables are the same in every browser and every session. They are
// not secret and nothing rests on them: they only decide WHICH pair of words a number
// maps to. The bijection holds whatever they contain, because that is a property of the
// Feistel structure and not of the round function.
const TABLE_LABEL = 'wg/v1/sas/words/table:';

let tablesPromise = null;

/**
 * ROUNDS tables of SAS_LIST_SIZE values in [0, SAS_LIST_SIZE), read off a SHA-256
 * stream. Rejection sampling rather than a bare modulo: a uint32 folded into 4022 with
 * `%` favours the low 1738 entries by about one part in a million, and a lopsided round
 * function makes the word distribution lopsided too. The rejection is deterministic
 * because the stream is, so every engine builds identical tables.
 */
async function buildTables() {
  const n = SAS_LIST_SIZE;
  const limit = Math.floor(0x100000000 / n) * n;
  const tables = [];
  let counter = 0;
  let pool = new DataView(new ArrayBuffer(0));
  let offset = 0;
  const nextWord = async () => {
    for (;;) {
      if (offset >= pool.byteLength) {
        const digest = await subtle.digest('SHA-256', te.encode(`${TABLE_LABEL}${counter}`));
        counter += 1;
        pool = new DataView(digest);
        offset = 0;
      }
      const v = pool.getUint32(offset);
      offset += 4;
      if (v < limit) return v % n;
    }
  };
  for (let r = 0; r < ROUNDS; r += 1) {
    const table = new Uint16Array(n); // n is 4022, so 16 bits per entry is enough
    for (let i = 0; i < n; i += 1) table[i] = await nextWord();
    tables.push(table);
  }
  return tables;
}

/** Built once, then reused. Same tables every call, so sasWords stays a pure function. */
function tables() {
  if (tablesPromise === null) tablesPromise = buildTables();
  return tablesPromise;
}

/**
 * The two words for a session. Async only because the round tables come off SHA-256;
 * the answer is fixed by the input, never by when or where it is called.
 *
 * The number is split into two base-4022 halves and run through a Feistel network. Each
 * round is invertible (L' = R, R' = L + F(R) mod n, so L = R' - F(L') mod n), which makes
 * the whole map invertible, which is what guarantees two different SAS numbers can never
 * land on the same pair of words.
 */
export async function sasWords(input) {
  const n = Number(sasNumeric(input));
  const size = SAS_LIST_SIZE;
  const t = await tables();
  // Both halves are below size because size^2 (16176484) is far above SAS_MODULUS.
  let left = Math.floor(n / size);
  let right = n % size;
  for (let r = 0; r < ROUNDS; r += 1) {
    const mixed = (left + t[r][right]) % size;
    left = right;
    right = mixed;
  }
  return [SAS_WORD_LIST[left], SAS_WORD_LIST[right]];
}

/**
 * The displayed form. Capitals like the gate code, but separated by a space and not a
 * hyphen: this string exists to be read out, and a hyphen gets read out as "dash".
 */
export function formatSasWords(words) {
  if (!Array.isArray(words) || words.length !== SAS_WORD_COUNT) {
    throw new TypeError(`expected ${SAS_WORD_COUNT} words, got ${Array.isArray(words) ? words.length : typeof words}`);
  }
  return words.map((w) => w.toUpperCase()).join(' ');
}

/** sasWords plus formatSasWords, for callers that only want the string to show. */
export async function sasPhrase(input) {
  return formatSasWords(await sasWords(input));
}
