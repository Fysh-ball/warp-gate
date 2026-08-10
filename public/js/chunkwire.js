// The chunk frame itself: the four bytes of index in front of a chunk's plaintext, and the
// arithmetic that turns a file size into a chunk count.
//
// WHY THIS IS SEPARATE FROM resume.js
//
// It is not a design boundary, it is a loading one, and it is worth being honest about
// that. resume.js is 27 KB of resume NEGOTIATION: the ledger, the indexed sink, the token,
// and the four control messages that agree where to continue from. None of it is reachable
// until a file has been offered, which is a decision nobody has made when the gate opens,
// so tests/size.test.mjs's rule says it must not be among the files a browser fetches
// before the page is usable.
//
// The obstacle to loading it lazily was entirely in this file's four exports. link.js needs
// CHUNK_INDEX_BYTES at module evaluation time to size FRAME_OVERHEAD_BYTES, chunkCount in a
// synchronous helper, and frameChunk and unframeChunk once per chunk in the hot path. An
// await in front of any of those either changes a constant into a promise or puts a
// suspension point inside the send loop.
//
// So the four primitives that are needed EARLY and SYNCHRONOUSLY live here, at 4.7 KB, and
// the 22 KB behind them is fetched when a transfer actually starts. resume.js imports from
// this file rather than the other way round, so there is exactly one definition of the
// frame layout and no possibility of the two drifting.
//
// Nothing here touches a key, a peer or a sink. Keep it that way: the whole point is that
// it is small enough to be unconditional.

// Chunk index on the wire, big endian, in front of the chunk's plaintext and therefore
// inside the AEAD ciphertext and covered by its tag. 32 bits is 4.29e9 chunks: 64 TiB at
// the 16 KiB floor and far more at the sizes a real connection negotiates.
export const CHUNK_INDEX_BYTES = 4;
export const MAX_CHUNK_INDEX = 0xffffffff;

/** How many chunks a file of `size` bytes is cut into at `chunkSize`. */
export function chunkCount(size, chunkSize) {
  const total = Number(size);
  const each = Number(chunkSize);
  if (!Number.isSafeInteger(total) || total < 0) throw new Error(`a file size of ${size} is not a byte count`);
  if (!Number.isSafeInteger(each) || each <= 0) throw new Error(`a chunk size of ${chunkSize} is not usable`);
  return Math.ceil(total / each);
}

/**
 * How long the chunk at `index` must be.
 *
 * Checked on arrival rather than assumed. A peer that sends a SHORT chunk at index k would
 * otherwise shift every byte after it while both sides still agree on the chunk count, and
 * the per-chunk AEAD cannot catch that: the chunk is perfectly authentic, it is just the
 * wrong length. This is the check that keeps index arithmetic and byte arithmetic in step.
 */
export function expectedChunkBytes(index, chunkSize, size) {
  const total = Number(size);
  const each = Number(chunkSize);
  const start = index * each;
  if (start >= total) return 0;
  return Math.min(each, total - start);
}

/**
 * Put the chunk index in front of the chunk's bytes, as one buffer to seal.
 *
 * A copy rather than a scatter/gather write, because the alternative is a file reader
 * writing into a buffer with the header already reserved, and a chunk is at most a few
 * hundred kilobytes: the copy is memory bandwidth on data that was just read off disk, not
 * another read. The index goes INSIDE the sealed plaintext, never in the cleartext frame
 * header, so it is covered by the AEAD tag and the server never sees it.
 */
export function frameChunk(index, bytes) {
  if (!Number.isSafeInteger(index) || index < 0 || index > MAX_CHUNK_INDEX) {
    throw new Error(`chunk index ${index} cannot be sent`);
  }
  const out = new Uint8Array(CHUNK_INDEX_BYTES + bytes.byteLength);
  new DataView(out.buffer).setUint32(0, index, false);
  out.set(bytes, CHUNK_INDEX_BYTES);
  return out;
}

/** Split a received chunk frame back into its index and its bytes. */
export function unframeChunk(plaintext) {
  if (!(plaintext instanceof Uint8Array)) throw new Error('a file chunk arrived that was not bytes');
  if (plaintext.byteLength < CHUNK_INDEX_BYTES) {
    throw new Error(`a file chunk arrived with only ${plaintext.byteLength} bytes, too short to carry its index`);
  }
  // A chunk with an index and NO BODY is never legitimate, and saying so here is what
  // bounds the receiver's pre-accept buffer. expectedChunkBytes returns 0 only at or past
  // the end of the file, which createIndexedSink.write already refuses, and a zero-byte
  // file has no chunks at all, so no index can name an empty one. Left allowed, it was a
  // remote out-of-memory: 30 bytes on the wire bought an entry in the buffer that held
  // chunks while the accept dialog was open, and because that buffer accounted PAYLOAD
  // bytes its 4 MiB limit never moved off zero. Separate message from the one above
  // because it is a separate cause: too short to parse, and parsed but empty.
  if (plaintext.byteLength === CHUNK_INDEX_BYTES) {
    throw new Error('a file chunk arrived carrying an index and no bytes, which no transfer ever sends');
  }
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  return {
    index: view.getUint32(0, false),
    // subarray, not slice: a view over the same buffer, so nothing is copied on the way in.
    bytes: plaintext.subarray(CHUNK_INDEX_BYTES),
  };
}
