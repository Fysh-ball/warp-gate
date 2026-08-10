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
  if (!Number.isSafeInteger(offset) || offset !== at) {
    return {
      ok: false,
      code: 'bad_offset',
      reason: `the other device offered to continue from ${control.offset} bytes but ${at} have been written here`,
    };
  }
  return { ok: true, offset };
}
