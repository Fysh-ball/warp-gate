// Chunk-level resume: the difference between a dropped connection costing the missing
// chunks and costing the whole file.
//
// WHY A BYTE OFFSET IS NOT ENOUGH
//
// A single "I have N bytes" scalar is only correct while the receiver's writes are a strict
// prefix of the sender's reads. That holds on a healthy SCTP association and stops holding
// at exactly the moment resume exists for: the channel dies, both sides restart, and chunks
// that were already in flight land after the receiver has reported its offset, or land in a
// different order once a second attempt overlaps the first. A scalar cannot express "I hold
// 0 to 4 and also 6", so either the sender re-sends 6 and the receiver appends it a second
// time (a corrupt file that still passes a length check on the sender's own count), or the
// work is thrown away. The unit of accounting here is the CHUNK, and the answer to "where
// were we" is a set of ranges rather than a number.
//
// WHAT AUTHENTICATES A RESUME
//
// The data channel is already authenticated per pair: every frame is AEAD sealed under keys
// only these two peers hold, so nothing in this file is defending against an outsider. What
// it defends against is a resume for a transfer THIS side never agreed to receive. The
// receiver mints a random token at the moment it creates a sink, and that token is what
// names the transfer INSTANCE, as opposed to the id, which names the file and is reused
// across every peer in a fan-out. Stated exactly, so nothing here is over-claimed:
//
//   - the receiver leaves its stalled state and starts writing chunks only for a resume
//     that echoes the token it minted itself, so a peer cannot restart a transfer that was
//     refused, failed, or already finished by reusing its id, and cannot make this side
//     accept chunks for a file it never accepted in the first place;
//   - the receiver's held-chunk ranges are only ever disclosed in a message the receiver
//     sent FIRST. There is no sender-initiated query that returns them, so a resume offer
//     cannot be turned into a probe for what the other side already holds;
//   - every refusal that could otherwise distinguish "no such transfer" from "wrong token"
//     from "that one already finished" returns one frozen, identical message. The peer
//     learns that the resume was refused and learns nothing else from which one it got.

import { b64u } from './crypto.js';
// The frame layout and the chunk arithmetic live in chunkwire.js, which is a fifth the size
// of this file and is the only part of chunk-level resume that link.js needs before a
// transfer exists. Splitting them is what lets everything below be fetched on demand. See
// the header of chunkwire.js for the reasoning; there is one definition of the frame and
// this file is downstream of it.
import {
  CHUNK_INDEX_BYTES, MAX_CHUNK_INDEX, chunkCount, expectedChunkBytes,
} from './chunkwire.js';
// The fingerprint pair, for serveResume at the bottom of this file. transfer.js is eager
// anyway (link.js cannot take a file without it), so importing it here adds nothing to the
// boot path, and it imports only crypto.js and streamable.js so there is no cycle back.
import { compareFingerprints, fingerprintFile, createSink, CHUNK_BYTES } from './transfer.js';

// Re-exported so a caller that already holds this module does not need a second import for
// the two primitives that pair with the ledger. Nothing here redefines them.
export { CHUNK_INDEX_BYTES, chunkCount, expectedChunkBytes, frameChunk, unframeChunk } from './chunkwire.js';

// How many ranges a resume message may carry. A ledger with more holes than this reports
// only its first ranges, which under-reports what is held: the sender then re-sends chunks
// this side already has and the duplicate guard drops them. Over-reporting would skip a
// hole and produce a corrupt file, so the truncation direction is the safe one and is the
// only one this cap is ever allowed to take.
export const MAX_WIRE_RANGES = 64;

// A chunk that arrives ahead of the write frontier is held until the gap in front of it
// fills. Bounded, because the sink underneath may be a pipe that can only be written in
// order and the holder is this page's heap. Past the bound a forward chunk is DROPPED and
// deliberately not recorded, so the ledger never claims a chunk that does not exist
// anywhere; it is simply re-requested by the next resume.
export const MAX_AHEAD_CHUNKS = 64;
export const MAX_AHEAD_BYTES = 8 * 1024 * 1024;

/** One frozen refusal for every state a peer must not be able to tell apart. */
export const RESUME_REFUSED = Object.freeze({
  ok: false,
  code: 'unknown_transfer',
  reason: 'this device is not waiting to continue that transfer',
});

// ---------------------------------------------------------------- chunk arithmetic

/** Byte range [from, to) covered by a chunk range [fromIndex, toIndex). */
export function bytesInRanges(ranges, chunkSize, size) {
  let bytes = 0;
  for (const [from, to] of ranges) {
    const start = Math.min(from * chunkSize, size);
    const end = Math.min(to * chunkSize, size);
    bytes += Math.max(0, end - start);
  }
  return bytes;
}

/**
 * How much of a file on disk can be trusted as whole chunks.
 *
 * FLOOR, not ceil. A committed file can end mid-chunk (the sink checkpoints on a byte
 * count, and a reload keeps whatever the last close landed), and rounding that up claims a
 * chunk this side holds only part of. The sender would then skip it and the hole is
 * permanent and silent. Rounding down costs at most one chunk of re-sent data.
 */
export function chunksOnDisk(position, chunkSize, size) {
  const at = Math.max(0, Math.min(Number(position) || 0, Number(size)));
  if (at >= Number(size)) return chunkCount(size, chunkSize);
  return Math.floor(at / Number(chunkSize));
}

// ---------------------------------------------------------------- the ledger

/**
 * Which chunks this side holds, as a sorted list of half-open [from, to) ranges.
 *
 * Ranges rather than a bitmap: a 30 GiB file at 16 KiB is about two million chunks, and a
 * bitmap of that is 240 KiB of heap per transfer to describe a set that is nearly always
 * one range long. Holes only appear around a drop, and there are a handful of them.
 */
export class ChunkLedger {
  constructor(total = Infinity) {
    this.total = Number.isFinite(total) ? Number(total) : Infinity;
    /** @type {Array<[number, number]>} sorted, non-overlapping, non-adjacent */
    this.parts = [];
    this.held = 0;
  }

  /** Index of the first chunk NOT held, counting from zero. */
  get frontier() {
    return this.parts.length && this.parts[0][0] === 0 ? this.parts[0][1] : 0;
  }

  get complete() {
    return Number.isFinite(this.total) && this.frontier >= this.total;
  }

  has(index) {
    const at = this.seek(index);
    const range = this.parts[at];
    return Boolean(range && range[0] <= index);
  }

  /** First range whose end is past `index`. The insertion point for a new one. */
  seek(index) {
    let lo = 0;
    let hi = this.parts.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.parts[mid][1] <= index) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** Record a chunk. Returns false if it was already held, which is not an error. */
  mark(index) {
    if (!Number.isSafeInteger(index) || index < 0 || index > MAX_CHUNK_INDEX) {
      throw new Error(`chunk index ${index} is not a chunk index`);
    }
    if (index >= this.total) {
      throw new Error(`chunk index ${index} is past the ${this.total} chunks this file has`);
    }
    const at = this.seek(index);
    const next = this.parts[at];
    if (next && next[0] <= index) return false;
    const prev = this.parts[at - 1];
    const joinsPrev = Boolean(prev) && prev[1] === index;
    const joinsNext = Boolean(next) && next[0] === index + 1;
    if (joinsPrev && joinsNext) {
      prev[1] = next[1];
      this.parts.splice(at, 1);
    } else if (joinsPrev) {
      prev[1] = index + 1;
    } else if (joinsNext) {
      next[0] = index;
    } else {
      this.parts.splice(at, 0, [index, index + 1]);
    }
    this.held += 1;
    return true;
  }

  /** The complement: what a sender still has to deliver, in ascending order. */
  missing(upTo = this.total) {
    const end = Number.isFinite(upTo) ? upTo : this.total;
    if (!Number.isFinite(end)) throw new Error('cannot list missing chunks without knowing how many there are');
    const gaps = [];
    let at = 0;
    for (const [from, to] of this.parts) {
      if (from > at) gaps.push([at, Math.min(from, end)]);
      at = to;
      if (at >= end) break;
    }
    if (at < end) gaps.push([at, end]);
    return gaps.filter(([from, to]) => to > from);
  }

  /** Plain arrays, safe to put in a control message. Truncates rather than over-reports. */
  toWire(max = MAX_WIRE_RANGES) {
    return this.parts.slice(0, max).map(([from, to]) => [from, to]);
  }

  /**
   * Rebuild a ledger from a peer's message.
   *
   * Everything here is untrusted and every field is checked rather than clamped, because a
   * clamp turns a malformed claim into a plausible one. A ledger that cannot be read means
   * the resume is refused and the transfer starts again, which is slow; a ledger read wrong
   * means a hole in the file that nothing later detects.
   */
  static fromWire(value, total) {
    const ledger = new ChunkLedger(total);
    if (value === undefined || value === null) return ledger;
    if (!Array.isArray(value)) throw new Error('the list of held chunks was not a list');
    if (value.length > MAX_WIRE_RANGES) {
      throw new Error(`the list of held chunks has ${value.length} ranges, more than the ${MAX_WIRE_RANGES} allowed`);
    }
    let previousEnd = 0;
    for (const entry of value) {
      if (!Array.isArray(entry) || entry.length !== 2) throw new Error('a held-chunk range was not a pair of numbers');
      const [from, to] = entry.map(Number);
      if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to)) throw new Error('a held-chunk range was not whole numbers');
      if (from < 0 || to <= from) throw new Error(`a held-chunk range ${from}..${to} is empty or runs backwards`);
      if (Number.isFinite(total) && to > total) throw new Error(`a held-chunk range ends at ${to}, past the ${total} chunks this file has`);
      if (from < previousEnd) throw new Error('the held-chunk ranges are not in ascending order');
      ledger.parts.push([from, to]);
      ledger.held += to - from;
      previousEnd = to;
    }
    // Adjacent ranges are legal on the wire and must be merged, or `frontier` reads the
    // first range's end and stops short of what the peer actually said it holds.
    for (let i = ledger.parts.length - 1; i > 0; i -= 1) {
      if (ledger.parts[i - 1][1] === ledger.parts[i][0]) {
        ledger.parts[i - 1][1] = ledger.parts[i][1];
        ledger.parts.splice(i, 1);
      }
    }
    return ledger;
  }
}

// ---------------------------------------------------------------- wire framing

/**
 * Put a chunk's index in front of its bytes.
 *
 * This costs one copy of the chunk on the send path. It is not avoidable without the file
 * reader writing into a buffer with the header already reserved, and a chunk is at most a
 * few hundred kilobytes: the copy is memory bandwidth on data that was just read off disk,
 * not another read. The index goes INSIDE the sealed plaintext, never in the cleartext
 * frame header, so it is covered by the AEAD tag and the server never sees it.
 */
// ---------------------------------------------------------------- the indexed sink

/**
 * Wrap a sink so that writes are addressed by chunk index and are idempotent.
 *
 * Three things this adds, and all three are what "chunk-level" means:
 *
 *   1. A duplicate index is dropped, not appended. Every sink underneath is append-only in
 *      practice (a FileSystemWritableFileStream is positional but is driven sequentially
 *      here, and the service worker route is a pipe), so an appended duplicate is silent
 *      corruption that only the final length check catches, and only if the length happens
 *      to be wrong.
 *   2. A chunk that arrives ahead of the write frontier is held in a bounded buffer and
 *      written when the gap in front of it fills. That is what makes reordering survivable
 *      rather than fatal on a sink that cannot seek.
 *   3. A ledger of what is held, so the next resume can ask for exactly the gaps.
 *
 * `position` stays the CONTIGUOUS written byte count, never the total held. It is the
 * number the sink underneath has actually taken, it is the number a checkpoint commits, and
 * it is the only number a byte-offset seek on the sender is allowed to be given.
 */
export function createIndexedSink(sink, { chunkSize, size, ledger = null, written = 0 } = {}) {
  const each = Number(chunkSize);
  const total = Number(size);
  if (!Number.isSafeInteger(each) || each <= 0) throw new Error(`a chunk size of ${chunkSize} is not usable`);
  if (!Number.isSafeInteger(total) || total < 0) throw new Error(`a file size of ${size} is not a byte count`);
  const totalChunks = chunkCount(total, each);
  // A declared size that needs more chunks than a 32-bit index can name. The index on the
  // wire is four bytes (CHUNK_INDEX_BYTES), and that ceiling was enforced only at the two
  // ends, in ChunkLedger.mark and frameChunk, so a transfer whose upper chunks are simply
  // unaddressable used to be set up happily and then fail somewhere in the middle of the
  // file with a message about one chunk index. Refused here instead, before a sink is
  // opened and before the user is asked where to save it, and naming the real limit.
  if (totalChunks > MAX_CHUNK_INDEX + 1) {
    throw new Error(
      `a ${total}-byte file at ${each} bytes per chunk needs ${totalChunks} chunks, more than the `
      + `${MAX_CHUNK_INDEX + 1} a 32-bit chunk index can name`,
    );
  }
  const book = ledger ?? new ChunkLedger(totalChunks);
  if (book.total !== totalChunks) {
    throw new Error(`the ledger counts ${book.total} chunks but the file is ${totalChunks}`);
  }

  // Chunks held ahead of the frontier, keyed by index. A Map, not an array: the indices are
  // sparse and can start anywhere in a multi-million chunk file.
  const ahead = new Map();
  let aheadBytes = 0;
  let position = Number(written) || 0;
  let next = book.frontier;

  const drainAhead = async () => {
    for (;;) {
      const chunk = ahead.get(next);
      if (!chunk) return;
      // Write BEFORE dropping it. The ledger already records this chunk, so if the write
      // rejects the buffer has to keep holding it, or the ledger would claim a chunk that
      // exists nowhere and the next resume would skip it. aheadBytes moves with the buffer,
      // in the same step, so it stays accurate whether the write succeeds or throws.
      await sink.write(chunk);
      ahead.delete(next);
      aheadBytes -= chunk.byteLength;
      position += chunk.byteLength;
      next += 1;
    }
  };

  return {
    get kind() { return sink.kind; },
    get note() { return sink.note ?? null; },
    // Explicit rather than absent. A sink route with no durable handle must SAY so: an
    // absent key reads as an unstated value to whatever consumes the resume record, and
    // "no handle" and "handle not mentioned" have to be the same answer everywhere.
    get handle() { return sink.handle ?? null; },
    get ledger() { return book; },
    get totalChunks() { return totalChunks; },
    /** Contiguous bytes actually handed to the sink underneath. */
    get position() { return position; },
    /** Chunks held, including ones buffered ahead of the frontier. */
    get held() { return book.held; },
    get wantsCheckpoint() { return Boolean(sink.wantsCheckpoint); },

    /**
     * Take one chunk. Returns what happened rather than throwing on a duplicate, because a
     * duplicate is an ordinary event on a resumed transfer, not an error to report.
     */
    async write(index, chunk) {
      if (!Number.isSafeInteger(index) || index < 0 || index >= totalChunks) {
        throw new Error(`chunk ${index} is not one of the ${totalChunks} chunks this file has`);
      }
      const want = expectedChunkBytes(index, each, total);
      if (chunk.byteLength !== want) {
        throw new Error(`chunk ${index} arrived with ${chunk.byteLength} bytes, expected ${want}`);
      }
      if (book.has(index)) return { written: false, duplicate: true, dropped: false };
      if (index < next) {
        // Below the frontier but not in the ledger is a contradiction: the frontier is
        // derived from the ledger. Fail loudly rather than write into the middle of a file
        // that is already past this point.
        throw new Error(`chunk ${index} is behind the write position with no record of it`);
      }
      if (index === next) {
        await sink.write(chunk);
        position += chunk.byteLength;
        next += 1;
        book.mark(index);
        // Whatever was waiting on this chunk can go now. Buffered chunks were recorded when
        // they were buffered, so the drain moves bytes and never touches the ledger, and it
        // drops each chunk from the buffer only once that chunk's write has resolved. A
        // failure part way through therefore leaves the ledger describing chunks this side
        // still holds, in the buffer, rather than chunks it has lost.
        await drainAhead();
        return { written: true, duplicate: false, dropped: false };
      }
      if (ahead.size >= MAX_AHEAD_CHUNKS || aheadBytes + chunk.byteLength > MAX_AHEAD_BYTES) {
        // Deliberately NOT recorded. A ledger entry for a chunk that exists nowhere would
        // make the next resume skip it and leave a hole nothing later detects.
        return { written: false, duplicate: false, dropped: true };
      }
      // Copy: the caller's view may be over a buffer that gets reused or transferred, and
      // this one is kept until the gap in front of it fills.
      ahead.set(index, chunk.slice());
      aheadBytes += chunk.byteLength;
      book.mark(index);
      return { written: false, duplicate: false, dropped: false };
    },

    /** Flush anything the frontier has caught up with. Safe to call at any time. */
    drain() { return drainAhead(); },

    async checkpoint() {
      if (typeof sink.checkpoint !== 'function') return position;
      return sink.checkpoint();
    },

    async finish() {
      await drainAhead();
      if (next < totalChunks) {
        throw new Error(`the file is missing ${totalChunks - next} of its ${totalChunks} chunks, so it cannot be closed`);
      }
      if (position !== total) {
        throw new Error(`the file was announced as ${total} bytes but ${position} were written`);
      }
      return sink.finish();
    },

    async abort(reason) {
      ahead.clear();
      aheadBytes = 0;
      return sink.abort(reason);
    },
  };
}

// ---------------------------------------------------------------- the resume protocol

/**
 * Name this transfer instance. Random, not derived: it must not be predictable from the
 * file's id, name or size, or a peer could produce one for a transfer it was never given.
 */
export function mintResumeToken() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return b64u.encode(bytes);
}

/**
 * Compare two tokens without letting the comparison time say how much of one was right.
 *
 * Not paranoia about a remote timing attack over a data channel, which is not a realistic
 * measurement: it is that the alternative costs nothing, and a token compared with === is
 * the kind of thing that gets copied into somewhere it does matter.
 */
export function sameToken(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0) return false;
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  return diff === 0;
}

/**
 * RECEIVER side. Build the message that says where this side got to.
 *
 * `received` is the contiguous byte count and nothing else, because the sender uses it to
 * seek. `have` carries the full picture including chunks held past a hole. The two are
 * consistent by construction: `have`'s first range starts at zero exactly when `received`
 * is non-zero.
 */
export function buildResumeRequest({ id, token, indexed, fingerprint = null, crossedReload = false }) {
  if (!id) throw new Error('a resume request needs the transfer it belongs to');
  if (!token) throw new Error('a resume request needs the token this side minted when it accepted');
  return {
    kind: 'file-resume',
    id,
    token,
    received: indexed.position,
    chunks: indexed.ledger.frontier,
    have: indexed.ledger.toWire(),
    crossedReload: Boolean(crossedReload),
    fingerprint,
  };
}

/**
 * SENDER side. Read a resume request and work out exactly which chunks to send.
 *
 * Returns `{ ok: true, ranges, bytes, ... }` or a refusal. Nothing about the local transfer
 * is looked at except its size and chunk size: the fingerprint check that decides whether
 * these bytes may be spliced onto the receiver's partial file is the caller's, and it stays
 * the caller's because it needs a live File this module has no business holding.
 */
export function planResumeResponse(control, { id, size, chunkSize, token = null }) {
  if (!control || typeof control !== 'object') return { ...RESUME_REFUSED };
  if (typeof control.id !== 'string' || control.id !== id) return { ...RESUME_REFUSED };
  // A transfer this side never got an accept for has no token, so there is nothing a peer
  // could echo and the answer is the same frozen refusal as an unknown id.
  if (!token || !sameToken(control.token, token)) return { ...RESUME_REFUSED };

  // The size and chunk size are this side's own, but on a sender that reloaded they came
  // back out of sessionStorage, so they are parsed rather than trusted. A throw here would
  // leave the receiver waiting on a sender that answered nothing at all.
  let totalChunks;
  let ledger;
  try {
    totalChunks = chunkCount(size, chunkSize);
    ledger = ChunkLedger.fromWire(control.have, totalChunks);
  } catch (err) {
    return { ok: false, code: 'bad_request', reason: `the request to continue the transfer was malformed: ${err.message}` };
  }

  const received = Number(control.received);
  if (!Number.isSafeInteger(received) || received < 0 || received > Number(size)) {
    return {
      ok: false,
      code: 'bad_offset',
      reason: `the other device claims ${control.received} bytes of a ${size} byte file`,
    };
  }
  // The two halves of the request have to agree, or one of them is a lie and there is no
  // way to tell which. The contiguous prefix implied by `have` must be exactly the byte
  // count `received` claims, to within the last chunk being short.
  const impliedBytes = bytesInRanges([[0, ledger.frontier]], chunkSize, Number(size));
  if (impliedBytes !== received) {
    return {
      ok: false,
      code: 'bad_offset',
      reason: `the other device says it holds ${received} bytes but the chunks it listed come to ${impliedBytes}`,
    };
  }

  const ranges = ledger.missing(totalChunks);
  return {
    ok: true,
    ranges,
    totalChunks,
    offset: received,
    bytes: bytesInRanges(ranges, chunkSize, Number(size)),
    have: ledger,
  };
}

/**
 * RECEIVER side. Decide whether a sender's offer to continue may be acted on.
 *
 * Order matters. Everything that could tell a peer WHICH transfer state this side is in is
 * answered with the one frozen refusal; only once the transfer is established as ours does
 * a refusal start explaining itself, because from that point the explanation is for the
 * user of a transfer the peer legitimately knows about.
 */
export function judgeResumeResponse(inbound, control) {
  if (!control || typeof control !== 'object') return { ...RESUME_REFUSED };
  if (!inbound || !inbound.sink || !inbound.token) return { ...RESUME_REFUSED };
  if (typeof control.id !== 'string' || control.id !== inbound.meta?.id) return { ...RESUME_REFUSED };
  if (!sameToken(control.token, inbound.token)) return { ...RESUME_REFUSED };

  const offset = Number(control.offset);
  const at = inbound.sink.position;
  // BEHIND is normal, and refusing it killed real transfers. The offer echoes the offset
  // THIS side asked from, and the request and the answer are separated by a round trip:
  // bytes already in the sender's SCTP buffer keep landing here in the meantime, so by the
  // time the answer arrives the sink is routinely further on than the number in it. Measured
  // at 3.4 to 4.4 MB behind after a sender's page was frozen for a minute, which is exactly
  // the buffer draining while the sender could not count it. The old strict equality turned
  // that into a permanent, unretryable failure. Re-sent chunks are dropped by index in
  // createIndexedSink, so the cost of tolerating it is bandwidth, not correctness.
  //
  // AHEAD stays refused. An offset past the contiguous frontier means the sender intends to
  // skip bytes nothing has written, which leaves a hole no length check on either side can
  // see. Negative is refused with it: it is not a position in a file.
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > at) {
    return {
      ok: false,
      code: 'bad_offset',
      reason: `the other device offered to continue from ${control.offset} bytes but only ${at} have been written here`,
    };
  }
  // `at`, not `offset`: what gets reported and displayed is what this side actually holds.
  return { ok: true, offset: at };
}

/**
 * SENDER side. Prove the file is still the same file, then continue from `offset`.
 *
 * Moved here from link.js on 2026-08-10 with nothing else changed: `this` became the `link`
 * argument and that is the whole diff. It sat on the boot path of every gate while being
 * unreachable until a peer asked to continue an interrupted transfer, which is the same
 * gate everything else in this file is behind.
 *
 * The fingerprint is recomputed from the live File EVERY time, not read from our own cached
 * copy, and it is checked against what the RECEIVER recorded at FILE_START rather than only
 * against our own record. A sender comparing its cache to its cache proves nothing; a sender
 * that reloaded and was handed the wrong file has a cache that agrees with itself perfectly.
 * Recomputing is one 64 KiB read, so there is no reason to skip it on the cheap resumes.
 *
 * @param {object} link the Link serving the resume. Called through link.serveResume(), which
 *   is kept as a method because tests/outbound.test.mjs drives it by that name.
 * @returns {Promise<boolean>} whether the transfer was resumed. False means this has already
 *   denied, told the peer and settled the send: the caller must not also report it.
 */
export async function serveResume(link, out, offset, ranges, remaining) {
  let fresh;
  try {
    fresh = await fingerprintFile(out.file);
  } catch (err) {
    await link.control({
      kind: 'file-resume-deny', id: out.id, code: 'unreadable',
      reason: `the file could not be read to check it is the same one: ${err.message}`,
    });
    link.abandonOutbound(out, `could not re-read ${out.name}: ${err.message}`);
    return false;
  }

  const against = out.peerFingerprint ?? out.fingerprint;
  const verdict = compareFingerprints(against, fresh);
  if (!verdict.ok) {
    // Never splice. Resuming a different file at an offset produces a corrupt result that
    // passes every length check on both sides, so this refuses rather than repairs.
    await link.control({
      kind: 'file-resume-deny', id: out.id, code: 'fingerprint_mismatch',
      reason: `${verdict.reason}. The transfer has to start again from the beginning rather than `
        + 'joining two different files together.',
    });
    link.emit('file-reselect-refused', { id: out.id, name: out.name, reason: verdict.reason });
    link.abandonOutbound(out, verdict.reason);
    return false;
  }

  // What the receiver already holds, so the running total still ends at the file's size.
  // Nothing is adopted from the peer's own counter: `remaining` came from ranges the sending
  // side validated, and FILE_END's chunk count is derived from the size and chunk size fixed
  // at FILE_START. Be honest about what the seeded slots are: for a chunk this run never
  // reads, the length written here comes from the declared size, not from the disk. It is the
  // only figure available, the receiver's own size check is the independent guard, and the
  // receiver's indexed sink refuses a wrong-length chunk on arrival, so it can never report
  // holding one that is short.
  //
  // Seeded into the coverage map rather than assigned to the total. The old line set
  // `out.sent` directly, which was correct only if nothing was still sending: this runs
  // BEFORE driveOutbound consults its `streaming` latch, so a resume arriving while the
  // previous run was still unwinding rebased the figure and then let that run keep adding to
  // it. Marking the chunks the receiver already has as covered gets the same starting total
  // and stays right no matter how the two runs overlap, because every chunk can only ever
  // contribute its own length once.
  //
  // Seeding ADDS what the receiver reports it already holds. It never takes coverage away,
  // and that distinction cost a test: replacing the map wholesale also erased the chunks the
  // still-running send had already pushed, so a resume asking for a range the old loop had
  // passed under-declared by exactly those chunks. Coverage is a record of what was actually
  // read and sent; only a read can write it, and only upwards.
  const total = chunkCount(out.size, out.chunkSize);
  if (!out.coverage || out.coverage.length !== total) out.coverage = new Uint32Array(total);
  const wanted = new Uint8Array(total);
  for (const [from, to] of ranges) {
    for (let i = from; i < to && i < total; i += 1) wanted[i] = 1;
  }
  let covered = 0;
  for (let i = 0; i < total; i += 1) {
    // Outside the requested ranges the receiver has the chunk, so it counts at its full
    // length. Inside them it counts only for what this side has actually read, which is how
    // a truncating read still shows up as a shortfall at FILE_END.
    if (!wanted[i]) out.coverage[i] = expectedChunkBytes(i, out.chunkSize, out.size);
    covered += out.coverage[i];
  }
  out.sent = covered;
  // A per-run counter now, used only to throttle progress events. The count that goes on the
  // wire at FILE_END is derived from the file, not counted from this run.
  out.chunks = 0;
  out.stalled = false;
  out.fingerprint = fresh;
  await link.control({
    kind: 'file-resume-ok', id: out.id, token: out.resumeToken ?? null, offset, ranges, fingerprint: fresh,
  });
  link.emit('file-resumed', {
    direction: 'out', id: out.id, name: out.name, offset, total: out.size,
  });
  link.driveOutbound(ranges);
  return true;
}

/**
 * RECEIVER side. Adopt a transfer recovered from storage into a live link.
 *
 * The body lives here rather than in link.js for the reason serveResume's does: none of it
 * can be reached until a page reload interrupted a transfer, and a gate that never lost a
 * connection was carrying the chunk-boundary arithmetic and the ledger replay on its boot
 * path for nothing. Split out on 2026-08-10 to buy the eager graph back under its ceiling,
 * which is the rule this project applies instead of raising the ceiling for a feature.
 *
 * `link.adoptInbound` stays as the method: session.js calls it by that name and so do the
 * tests, and a split that renames the surface it is verified through is a split nobody can
 * check. The caller keeps two things that cannot move: `primeSink()` must be awaited in the
 * same user gesture as this (re-granting write permission on a stored handle PROMPTS, and a
 * prompt outside a live activation is refused outright), and the requestResume at the end
 * needs STATE, which lives in link.js and would make this module import its own importer.
 *
 * @param {object} link the Link adopting the record.
 * @param {object} record what readInboundRecord returned: meta, handle and byte count.
 * @returns {Promise<number>} the offset the sink is positioned at, in bytes.
 */
export async function adoptInbound(link, record) {
  // startOffset is a request; the sink clamps it to what the file actually contains,
  // because everything written and not committed before the reload was discarded.
  const chunkSize = Number(record.meta.chunkSize) || CHUNK_BYTES;
  const size = Number(record.meta.size);
  const raw = await createSink(record.meta, { handle: record.handle, startOffset: record.received });
  // Re-granting write permission on a stored handle prompts, and that prompt can stand
  // open while a FILE_START arrives: anything under AUTO_ACCEPT_BYTES accepts itself,
  // builds a sink and arms a quiet timer. Overwriting link.incoming below would strand
  // that sink open and that timer armed, with the sender never told. The recovered
  // transfer is the one that gives way, because it can still be continued later.
  if (link.incoming) {
    const clash = 'another transfer started while this file was being re-opened';
    try {
      await raw.abort(clash);
    } catch (err) {
      link.emit('warning', `could not close the recovered file: ${err.message}`);
    }
    throw new Error(`${clash}, so it was not continued`);
  }
  // FLOOR, not the ceil this used to do. A committed file can end part way through a
  // chunk, and rounding that up claims a chunk this side holds only part of: the sender
  // skips it and the hole is permanent, silent, and invisible to every length check,
  // because the missing tail is never counted by either side. Rewinding to the last whole
  // chunk costs at most one chunk of re-sent data.
  const whole = chunksOnDisk(raw.position, chunkSize, size);
  // Clamped, because a complete file reports every chunk including the short last one:
  // whole * chunkSize then overshoots the file by the length of that chunk's padding.
  // Unclamped it was handed to the sink as `written`, and requestResume went on to claim
  // more bytes than the file has, which the sender refuses outright: a transfer that
  // could never be continued, explained by a number that cannot exist.
  const wholeBytes = Math.min(whole * chunkSize, size);
  if (raw.position !== wholeBytes) {
    if (typeof raw.seekTo !== 'function') {
      // Nothing may be appended onto a partial chunk that cannot be rewound: the next
      // chunk would be spliced into the middle of the file and every length check on both
      // sides would still come out right. Only the disk sink can seek, and only the disk
      // sink stores a handle, so this is unreachable today and says so loudly if that
      // stops being true rather than quietly writing at the wrong offset.
      await raw.abort('the recovered file cannot be rewound to a chunk boundary');
      throw new Error(
        `${record.meta.name} was recovered part way through a chunk and this browser cannot rewind it, `
        + 'so the transfer has to start again from the beginning',
      );
    }
    await raw.seekTo(wholeBytes);
  }
  const ledger = new ChunkLedger(chunkCount(size, chunkSize));
  for (let i = 0; i < whole; i += 1) ledger.mark(i);
  link.incoming = {
    meta: record.meta,
    received: 0,
    chunks: 0,
    sink: null,
    stalled: true,
    crossedReload: true,
    resumes: 0,
    token: null,
  };
  // adoptSink takes the resume module as its first argument because link.js reaches it
  // through a lazy import and has no other handle on it. Called from INSIDE that module the
  // namespace object is not in scope, so it gets the two functions it actually uses. Naming
  // them is better than a self-import: a third one added to adoptSink fails here loudly
  // instead of arriving as undefined.
  link.adoptSink({ createIndexedSink, mintResumeToken }, link.incoming, raw,
    { written: wholeBytes, ledger });
  const at = link.incoming.sink.position;
  await link.rememberInboundRecord(link.incoming);
  link.emit('file-incoming', record.meta);
  link.emit('file-progress', {
    direction: 'in', id: record.meta.id, sent: at, total: record.meta.size, name: record.meta.name,
  });
  return at;
}

/**
 * RECEIVER side. The sender is about to continue; check it before accepting a byte.
 *
 * Split out of link.js on 2026-08-10 alongside adoptInbound, and reachable only after a
 * resume request this side sent first. `link.onResumeAccepted` stays as the method: onControl
 * dispatches to it by name and tests/disconnect.test.mjs drives it by name.
 *
 * @param {object} link the Link whose inbound transfer is being resumed.
 * @param {object} control the `file-resume-ok` frame the sender answered with.
 */
export async function onResumeAccepted(link, control) {
  const inbound = link.incoming;
  // Everything that could distinguish "no such transfer" from "wrong token" answers with
  // one frozen refusal, and this side sends NOTHING back for it: a reply is itself a
  // signal, and a resume offer must not be usable to probe what this device holds.
  const verdict = judgeResumeResponse(inbound, control);
  if (!verdict.ok) {
    if (verdict.code === RESUME_REFUSED.code) return;
    await link.control({ kind: 'file-resume-deny', id: control.id, code: verdict.code, reason: verdict.reason });
    await link.failInbound(inbound, verdict.reason);
    return;
  }
  const offset = verdict.offset;

  // The second half of the splice guard: the sender proved the file to itself, and now
  // it has to prove it to the side that holds the partial copy.
  const sameFile = compareFingerprints(inbound.meta.fingerprint ?? null, control.fingerprint ?? null);
  if (!sameFile.ok) {
    await link.control({
      kind: 'file-resume-deny', id: control.id, code: 'fingerprint_mismatch', reason: sameFile.reason,
    });
    await link.failInbound(inbound, `refused to continue: ${sameFile.reason}`);
    return;
  }

  inbound.stalled = false;
  inbound.crossedReload = false;
  inbound.resumes = (inbound.resumes ?? 0) + 1;
  // `inbound.quietRounds = 0` used to sit here and was removed in review on 2026-08-10.
  // This handler runs on the ACK, not on bytes: the sender has said it will continue, which
  // is a promise and not progress. A sender that acks and then parks its ranges (the exact
  // overlap tests/outbound.test.mjs exists for) left the receiver looping request, ack,
  // 45 seconds of silence, request, for ever, with every message saying "attempt 1" because
  // this line reset the count each time round. The reset belongs where bytes land and it
  // already lives there, in onFileChunk: a chunk arriving IS the retry having worked.
  //
  // Chunks are about to start again, so the quiet clock starts again with them. Without the
  // re-arm a resumed transfer runs with no watchdog at all: the timer was cleared when the
  // link dropped and only an arriving chunk re-arms it, which is the one thing a sender that
  // goes quiet immediately after resuming never does.
  inbound.quietWarned = false;
  link.armInboundQuiet(inbound);
  link.emit('file-resumed', {
    direction: 'in', id: inbound.meta.id, name: inbound.meta.name, offset, total: inbound.meta.size,
  });
}
