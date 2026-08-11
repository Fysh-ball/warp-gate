// File transfer: chunking on the way out, sink selection on the way in.
//
// The sink question is not a detail. showSaveFilePicker exists only in Chromium on
// desktop: Firefox declines to implement it and no Safari supports it (verified in
// DESIGN.md section 0). Everywhere else the receiver must hold the whole file in
// memory, which iOS will not tolerate at size. So the limit is checked and refused
// BEFORE the transfer starts, never at 90 percent (DESIGN.md 1.9).

import { b64u } from './crypto.js';
import { supportsStreamDownload } from './streamable.js';

export const CHUNK_BYTES = 16 * 1024;
export const MEMORY_LIMIT_BYTES = 500 * 1024 * 1024;

// How much of a file's head goes into its content fingerprint. Enough that two different
// files of the same size are not plausibly going to agree on it, small enough that
// recomputing it on every resume is free.
export const FINGERPRINT_PREFIX_BYTES = 64 * 1024;

/**
 * How often a disk sink commits what it has written so that a page reload can find it.
 *
 * This is not a tuning knob, it is a correctness one. A FileSystemWritableFileStream does
 * NOT write through to the file the user chose: Chromium writes to a swap file and only
 * renames it over the real file when close() resolves. So bytes written and never closed
 * are discarded by a reload, and the only durable offset is whatever the last close()
 * committed. Checkpointing = close() then re-open with keepExistingData and seek().
 *
 * The cost is that re-opening copies the existing data into a fresh swap file, so a small
 * interval turns one transfer into quadratic disk writes. Measured amplification is in the
 * report; set this to Infinity to disable checkpointing entirely, in which case a reload
 * resumes from whatever the file actually contains (usually zero) rather than from a
 * committed offset. Either way the offset is re-derived from the file on disk and is never
 * trusted from storage alone, so disabling this is safe, just slower to recover.
 */
export const CHECKPOINT_BYTES = 32 * 1024 * 1024;

export const canStreamToDisk = () => typeof globalThis.showSaveFilePicker === 'function';

/**
 * What this browser can RECEIVE, as a lede and a detail.
 *
 * Returns two strings rather than one, changed on 2026-08-10. It used to return a single
 * paragraph, and both places that show it (#receive-note above the home screen, #compose-hint
 * inside the composer) were the largest object on a 390x844 phone: 183px and 160px. The
 * layout pass folded both into a <details> whose summary is line-clamped to three lines,
 * which fixed the pixels and created an accessibility defect in doing so: A LINE CLAMP HIDES
 * PIXELS, NOT TEXT. The disclosure's body was empty, so the whole paragraph was in the
 * summary, so a screen reader read every word of it at all times no matter what state the
 * control was in, and pressing the control changed only what was painted.
 *
 * A seam is the only thing that fixes that, and the seam has to be here because this is the
 * only place that knows which of the three branches applies. `lede` answers the question
 * ("can this browser receive a big file, yes or no") and goes in the summary; `detail` is
 * everything a person only needs once the answer is yes or no, and goes in the body, where
 * `details` genuinely removes it from the accessibility tree while it is closed.
 *
 * @returns {{lede: string, detail: string}}
 */
export function describeLimit() {
  if (canStreamToDisk()) {
    return {
      lede: 'This browser writes received files straight to disk, so there is no practical size limit.',
      detail: 'An interrupted transfer can carry on into the same file.',
    };
  }
  // showSaveFilePicker is Chromium-only: Firefox has declined to implement it and no
  // Safari has it. That used to mean a large RECEIVE here was impossible rather than
  // slow. It no longer does: the service worker hands the file to the browser's own
  // download manager, which writes to disk with no ceiling.
  if (supportsStreamDownload()) {
    return {
      lede: `Files over ${formatBytes(MEMORY_LIMIT_BYTES)} are saved by this browser's own download `
        + 'manager as they arrive, so there is no size limit.',
      detail: 'They go to your usual downloads folder rather than a location you pick. A dropped '
        + 'connection carries on where it left off, but RELOADING the page loses it, because the '
        + 'browser owns the partial file and will not hand it back. A Chromium desktop browser '
        + 'survives both.',
    };
  }
  return {
    lede: 'This browser cannot write received files straight to disk, so it holds them in memory '
      + `and refuses anything over ${formatBytes(MEMORY_LIMIT_BYTES)}.`,
    detail: 'Sending any size is fine. To RECEIVE a large file, use a Chromium desktop browser '
      + '(Chrome, Edge, Brave, Opera) at the receiving end. A dropped connection carries on where '
      + 'it left off, but RELOADING the page loses it, because the partial file was only ever in '
      + 'this page\'s memory.',
  };
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

/**
 * Decide up front whether an incoming file can be received at all.
 *
 * `requiresDisk` matters: a file over the memory limit can only be taken by writing it
 * straight to disk, so the save dialog is not an optional convenience there. Returning a
 * bare `{ok:true}` accepted such a file and left createSink to refuse it after the user
 * was already committed.
 */
export function canAccept(size) {
  if (size > MEMORY_LIMIT_BYTES) {
    if (!canStreamToDisk()) {
      if (supportsStreamDownload()) {
        return {
          ok: true,
          requiresDisk: false,
          note: `${formatBytes(size)} is more than this browser can hold in memory, so it will be `
            + 'saved by the browser\'s own download manager as it arrives. It goes to your usual '
            + 'downloads folder. If this page is reloaded the transfer cannot be continued, because '
            + 'the browser owns the partial file.',
        };
      }
      return {
        ok: false,
        reason: `${formatBytes(size)} exceeds this browser's ${formatBytes(MEMORY_LIMIT_BYTES)} in-memory limit. `
          + 'Use a Chromium desktop browser, which can stream straight to disk.',
      };
    }
    return {
      ok: true,
      requiresDisk: true,
      note: `${formatBytes(size)} is more than this browser can hold in memory `
        + `(${formatBytes(MEMORY_LIMIT_BYTES)}), so it has to be written straight to disk. `
        + 'You will be asked where to save it, and dismissing that dialog cancels the transfer.',
    };
  }
  return { ok: true, requiresDisk: false };
}

/**
 * Fetch the sink builder the first time a file is actually taken.
 *
 * openDiskSink and createSink moved to filesink.js on 2026-08-10 because they are 18 KB
 * that no gate can reach: a sink exists only after a peer has offered a file and this side
 * has accepted it, or after a reload has found a stored handle and the user has clicked to
 * re-adopt it. Fetching it at load put the whole save-dialog, granted-folder, streaming
 * download and memory-blob apparatus in front of a key exchange that never touches any of
 * it. tests/size.test.mjs asserts it stays off the eager graph.
 *
 * The promise is cached, not the module, so N files in a batch share one fetch. The cache is
 * CLEARED on failure: a transient network miss during the one second a receiver was offline
 * must not become a tab that can never receive a file again, which is what latching a
 * rejected promise here would do.
 */
let sinkMod = null;
function loadSink() {
  if (!sinkMod) {
    sinkMod = import('./filesink.js').catch((err) => {
      sinkMod = null;
      // Preserve the reason and say what it cost. Every caller of createSink already turns a
      // throw here into a warning on screen and a file-reject to the peer, so this message
      // is what the user reads and what the sender is told: both should say that the file
      // was not saved, not merely that something failed.
      throw new Error(`the file-saving code could not be loaded (${err.message}), so this file cannot be received; check your connection and ask for it again`);
    });
  }
  return sinkMod;
}

/**
 * Start that fetch now, without needing the sink yet.
 *
 * The two paths that open a save dialog or ask to re-grant a file permission run inside a
 * user gesture, and every await before the prompt spends part of the transient activation
 * the browser allows. Both of those paths already await loadResume() first, so link.js
 * requests the two together and the second fetch costs no extra wall clock. Rejects with the
 * same message loadSink() throws, so a caller that Promise.all's it reports the real reason
 * rather than a bare "failed".
 */
export function primeSink() {
  return loadSink();
}

/**
 * Build a sink for an incoming file. Must be called from a user gesture when
 * streaming to disk, because showSaveFilePicker requires one.
 *
 * The options are documented on the implementation in filesink.js, which this fetches on
 * first use. Kept exported from here under the same name and the same async signature it
 * always had: every caller already awaited it, so the split is invisible to all of them.
 */
export async function createSink(meta, options = {}) {
  const mod = await loadSink();
  return mod.createSink(meta, options);
}

/**
 * Read a File in chunks without ever holding more than one chunk in memory, so a
 * multi-gigabyte file never becomes a multi-gigabyte allocation on the sending side.
 */
export async function* readChunks(file, chunkSize = CHUNK_BYTES, startOffset = 0) {
  // Snapshot the size once. Re-reading file.size every iteration measures the loop
  // against a bound that can move under it.
  const total = file.size;
  const from = Number(startOffset) || 0;
  // A resume offset is peer-supplied, so it is checked rather than sliced with. A negative
  // one would re-send data; one past the end would silently yield nothing and let the
  // sender declare a file complete that it never finished reading.
  if (!Number.isSafeInteger(from) || from < 0 || from > total) {
    throw new Error(`cannot resume "${file.name ?? 'file'}" at ${startOffset}: it is ${total} bytes`);
  }
  let offset = from;
  while (offset < total) {
    const end = Math.min(offset + chunkSize, total);
    const buffer = await file.slice(offset, end).arrayBuffer();
    const read = buffer.byteLength;
    // Advance by what was actually read, and refuse a short one. The integrity check
    // cannot catch this: it compares the receiver's count against the sender's own
    // already-short count, so both sides agree on the truncated number and call it a
    // success. A file that shrank or became unreadable after selection has to fail here.
    if (read < end - offset) {
      throw new Error(
        `"${file.name ?? 'file'}" could not be read in full: expected ${end - offset} bytes `
        + `at offset ${offset}, got ${read}`,
      );
    }
    yield new Uint8Array(buffer);
    offset += read;
  }
}

/**
 * Read only the chunk ranges a resuming receiver asked for, each with its own index.
 *
 * This is what "only the missing chunks" is made of. `readChunks` above can express one
 * suffix and nothing else, so a receiver that holds 0 to 4 and also 6 could only be served
 * by re-sending 6, and a sender with no index to put on the wire had no way to let the
 * receiver notice. Ranges are half-open [from, to) in CHUNK indices, ascending.
 *
 * The ranges arrive from the peer, so they are checked rather than sliced with, on exactly
 * the same reasoning readChunks gives for a bare offset: a range past the end would yield
 * nothing and let the sender declare a file complete it never read.
 */
export async function* readChunkRanges(file, chunkSize, ranges) {
  const total = file.size;
  const each = Number(chunkSize);
  if (!Number.isSafeInteger(each) || each <= 0) {
    throw new Error(`cannot read "${file.name ?? 'file'}" in chunks of ${chunkSize}`);
  }
  const chunks = Math.ceil(total / each);
  let previousEnd = 0;
  for (const range of ranges) {
    if (!Array.isArray(range) || range.length !== 2) {
      throw new Error(`cannot resume "${file.name ?? 'file'}": a requested chunk range was not a pair`);
    }
    const [from, to] = range.map(Number);
    if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to <= from || to > chunks) {
      throw new Error(
        `cannot resume "${file.name ?? 'file'}": chunks ${from}..${to} are not inside its ${chunks} chunks`,
      );
    }
    if (from < previousEnd) {
      throw new Error(`cannot resume "${file.name ?? 'file'}": the requested chunk ranges are not in order`);
    }
    previousEnd = to;
    for (let index = from; index < to; index += 1) {
      const start = index * each;
      const end = Math.min(start + each, total);
      const buffer = await file.slice(start, end).arrayBuffer();
      // Same short-read trap readChunks guards, and it matters more here: a short chunk in
      // the middle of a resumed file is spliced between bytes the receiver already holds,
      // so nothing downstream is positioned to notice it.
      if (buffer.byteLength < end - start) {
        throw new Error(
          `"${file.name ?? 'file'}" could not be read in full: expected ${end - start} bytes `
          + `at offset ${start}, got ${buffer.byteLength}`,
        );
      }
      yield { index, bytes: new Uint8Array(buffer) };
    }
  }
}

// ---------------------------------------------------------------- content fingerprint

/**
 * Identify the CONTENT a transfer is carrying, not just its length.
 *
 * This exists for one failure and it is the worst one available here. A sender that
 * reloads has lost its File object and must pick a file again; if it picks a DIFFERENT
 * file and the receiver resumes at an offset, the two are spliced into a file that is
 * corrupt and yet passes every length check on both sides, because the byte count is
 * exactly right. Per-chunk AEAD does not catch it either: every chunk is authentic, they
 * just came from two different files. So identity has to be pinned before the transfer
 * starts and re-proved before a single byte is written at a non-zero offset.
 *
 * SHA-256 of the first 64 KiB, plus the exact size, plus the name. All three are compared.
 */
export async function fingerprintFile(file) {
  const size = file.size;
  const prefixBytes = Math.min(FINGERPRINT_PREFIX_BYTES, size);
  const head = await file.slice(0, prefixBytes).arrayBuffer();
  // The same short-read trap readChunks guards: a file that became unreadable after it was
  // chosen must fail here rather than produce a fingerprint of whatever was returned.
  if (head.byteLength !== prefixBytes) {
    throw new Error(
      `"${file.name ?? 'file'}" could not be read: expected ${prefixBytes} bytes of header, got ${head.byteLength}`,
    );
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', head);
  return {
    algo: 'SHA-256',
    prefixBytes,
    hash: b64u.encode(new Uint8Array(digest)),
    size,
    name: String(file.name ?? ''),
  };
}

/**
 * Compare two fingerprints. Returns { ok } or { ok:false, reason } in plain language.
 *
 * Fails closed on a missing fingerprint on either side: an absent one must never read as
 * "this transfer does not need identity checking", or a peer could opt out of the guard by
 * simply not sending one.
 */
export function compareFingerprints(want, got) {
  if (!want || !got) {
    return { ok: false, reason: 'no content fingerprint was exchanged for this transfer, so it cannot be continued part-way' };
  }
  if (want.algo !== got.algo || Number(want.prefixBytes) !== Number(got.prefixBytes)) {
    return { ok: false, reason: 'the two devices fingerprinted the file differently' };
  }
  if (Number(want.size) !== Number(got.size)) {
    return {
      ok: false,
      reason: `this file is ${formatBytes(Number(got.size))} but the transfer began with a `
        + `${formatBytes(Number(want.size))} file`,
    };
  }
  if (String(want.name) !== String(got.name)) {
    return {
      ok: false,
      reason: `this file is named "${sanitizeFilename(got.name)}" but the transfer began with `
        + `"${sanitizeFilename(want.name)}"`,
    };
  }
  if (String(want.hash) !== String(got.hash)) {
    return { ok: false, reason: 'this is a different file: its contents do not match the one the transfer began with' };
  }
  return { ok: true };
}

// ------------------------------------------------- interrupted-transfer bookkeeping

// What is stored here, and what is deliberately NOT.
//
// STORED: the transfer's name, size, MIME type, chunk size, content fingerprint, how many
// bytes have been committed, and a FileSystemFileHandle pointing at the file the user
// themselves chose a save location for. A handle is a reference, not content.
//
// NOT STORED, ever: file bytes. The received data lives in the user's own file on their
// own disk, put there by a picker they drove. Writing partial blobs into IndexedDB would
// mean this app persisting the user's content on their device, which is precisely what it
// promises not to do, so the memory-sink case is failed rather than persisted.
//
// WHAT IS AT REST HERE IS MORE THAN "a handle is a reference". The stored meta is the
// peer's FILE_START meta whole, and that includes the content fingerprint: a SHA-256 over
// the file's first 64 KiB. Anyone who can read this origin's IndexedDB can therefore
// CONFIRM a guess about which file was received, and can read the save location the user
// chose, on a tool whose entire premise is that nothing outlives the session. That is why
// the deletion rules below are not housekeeping.
//
// The record is deleted when the transfer completes, fails, is refused, or the gate ends
// cleanly. None of those cover a crash or a closed tab, which used to leave the record
// indefinitely with nothing anywhere that would ever sweep it: `clearAllResume` was
// written for that job and, verified by full enumeration, had no caller at all. It has one
// now, `sweepResume`, run at the start of every gate. So the honest statement of the rule
// is: deleted on any orderly end, and otherwise no later than RESUME_MAX_AGE_MS after it
// was last written, on the next gate this browser opens.
const IDB_NAME = 'warp-gate';
const IDB_STORE = 'inbound-resume';
const IDB_VERSION = 1;
const IDB_TIMEOUT_MS = 5000;

// How long a record may sit unattended before the sweep takes it.
//
// Pinned to the room's own absolute ceiling rather than chosen: a gate cannot live longer
// than 24 hours, so a record older than that can no longer belong to any gate that could
// still be resumed, and deleting it can never destroy a transfer anybody is waiting on.
const RESUME_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * The key one inbound transfer is stored under: room AND peer, never room alone.
 *
 * Keyed by room alone, every Link in a mesh wrote to the same key, so B's record silently
 * overwrote A's and, after a reload, A's partial file was orphaned with the handle to it
 * gone. Worse in the other direction: A completing its transfer called clearResume on the
 * room key and destroyed B's record while B's transfer was still in flight.
 */
const resumeKey = (roomId, peerId) => `${roomId}:${peerId ?? ''}`;

function idbOpen() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error('this browser has no IndexedDB, so an interrupted transfer cannot survive a reload'));
      return;
    }
    let request;
    try {
      request = globalThis.indexedDB.open(IDB_NAME, IDB_VERSION);
    } catch (err) {
      reject(new Error(`could not open the resume index: ${err.message}`));
      return;
    }
    // Storage can simply never answer (private mode, a blocked upgrade, a wedged origin),
    // and an IDB request that never fires an event parks its caller forever.
    const timer = setTimeout(() => reject(new Error(`the resume index did not respond within ${IDB_TIMEOUT_MS}ms`)), IDB_TIMEOUT_MS);
    const settle = (fn, value) => { clearTimeout(timer); fn(value); };
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE);
    };
    request.onsuccess = () => settle(resolve, request.result);
    request.onerror = () => settle(reject, new Error(`could not open the resume index: ${request.error?.message ?? 'unknown error'}`));
    request.onblocked = () => settle(reject, new Error('the resume index is held open by another tab'));
  });
}

function idbRun(mode, work) {
  return new Promise((resolve, reject) => {
    idbOpen().then((db) => {
      let tx;
      try {
        tx = db.transaction(IDB_STORE, mode);
      } catch (err) {
        db.close();
        reject(new Error(`could not read the resume index: ${err.message}`));
        return;
      }
      let result;
      let request;
      try {
        request = work(tx.objectStore(IDB_STORE));
      } catch (err) {
        // A structured-clone failure lands here: a FileSystemFileHandle is cloneable but a
        // sink, a stream or a File is not, so a record that grew a live object by accident
        // must say so rather than abort the transaction with no explanation.
        try { tx.abort(); } catch (abortErr) { void abortErr; }
        db.close();
        reject(new Error(`could not write the resume index: ${err.message}`));
        return;
      }
      if (request) request.onsuccess = () => { result = request.result; };
      tx.oncomplete = () => { db.close(); resolve(result); };
      tx.onabort = () => { db.close(); reject(new Error(`the resume index transaction was aborted: ${tx.error?.message ?? 'unknown error'}`)); };
      tx.onerror = () => { db.close(); reject(new Error(`the resume index transaction failed: ${tx.error?.message ?? 'unknown error'}`)); };
    }, reject);
  });
}

/**
 * Walk every record in the store, letting `visit` delete the ones it does not want.
 *
 * A cursor rather than getAll(): the sweep has to be able to delete what it is looking at,
 * and the room-wide reads have to see records written by builds that keyed them
 * differently, neither of which a single keyed get can do.
 */
function idbScan(mode, visit) {
  return new Promise((resolve, reject) => {
    idbOpen().then((db) => {
      let tx;
      try {
        tx = db.transaction(IDB_STORE, mode);
      } catch (err) {
        db.close();
        reject(new Error(`could not read the resume index: ${err.message}`));
        return;
      }
      const kept = [];
      let request;
      try {
        request = tx.objectStore(IDB_STORE).openCursor();
      } catch (err) {
        try { tx.abort(); } catch (abortErr) { void abortErr; }
        db.close();
        reject(new Error(`could not scan the resume index: ${err.message}`));
        return;
      }
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;
        // The visitor decides, may call cursor.delete(), and never throws, so there is no
        // half-swept transaction to reason about. Records it returns true for are collected
        // in arrival order and handed back, which is how the callers below report both what
        // they found and what they removed.
        if (visit(cursor, cursor.value ?? null)) kept.push(cursor.value);
        cursor.continue();
      };
      tx.oncomplete = () => { db.close(); resolve(kept); };
      tx.onabort = () => { db.close(); reject(new Error(`the resume index transaction was aborted: ${tx.error?.message ?? 'unknown error'}`)); };
      tx.onerror = () => { db.close(); reject(new Error(`the resume index transaction failed: ${tx.error?.message ?? 'unknown error'}`)); };
    }, reject);
  });
}

/** Record where an interrupted incoming transfer had got to. Keyed by room AND peer. */
export function saveResume(roomId, peerId, record) {
  if (!roomId) return Promise.reject(new Error('a resume record needs a room to belong to'));
  if (!peerId) return Promise.reject(new Error('a resume record needs the participant it came from'));
  return idbRun('readwrite', (store) => store.put(record, resumeKey(roomId, peerId)));
}

export function loadResume(roomId, peerId) {
  if (!roomId || !peerId) return Promise.resolve(null);
  return idbRun('readonly', (store) => store.get(resumeKey(roomId, peerId))).then((v) => v ?? null);
}

export function clearResume(roomId, peerId) {
  if (!roomId || !peerId) return Promise.resolve();
  return idbRun('readwrite', (store) => store.delete(resumeKey(roomId, peerId)));
}

/**
 * Every record belonging to one room, newest first.
 *
 * Matched on the record's OWN roomId field rather than on the key, so a record written by
 * a build that keyed by room alone is still found and still offered back rather than
 * orphaned by a deploy that happened mid-transfer.
 */
export function listResume(roomId) {
  if (!roomId) return Promise.resolve([]);
  return idbScan('readonly', (cursor, value) => value?.roomId === roomId)
    .then((records) => records.sort((a, b) => (Number(b.savedAt) || 0) - (Number(a.savedAt) || 0)));
}

/** Drop every record belonging to one room. What burning a gate has to leave behind. */
export function clearRoomResume(roomId) {
  if (!roomId) return Promise.resolve(0);
  return idbScan('readwrite', (cursor, value) => {
    if (value?.roomId !== roomId) return false;
    cursor.delete();
    return true;
  }).then((gone) => gone.length);
}

/** Drop every stored record, whatever room it belongs to. */
export function clearAllResume() {
  return idbRun('readwrite', (store) => store.clear());
}

/**
 * Delete records nothing can ever resume, and return how many went.
 *
 * The one thing this is NOT allowed to do is take a record for a transfer that is still
 * live. The age bound is what guarantees that: a record is rewritten on every checkpoint
 * of the transfer it describes, so a live one is seconds old, and RESUME_MAX_AGE_MS is the
 * room's own absolute ceiling, past which no gate exists to resume into.
 *
 * An UNDATED record is swept too. savedAt has been written on every record this code has
 * ever stored, so an undated one cannot be dated and therefore cannot ever be shown to be
 * fresh; keeping it would mean keeping a fingerprint and a save-location handle for ever
 * on the strength of a field that is missing. Absent has to mean something explicit here,
 * not "assume the friendly value".
 *
 * Best effort and never fatal: a browser with no IndexedDB has nothing to sweep, and a
 * failure to sweep must not stop a gate opening.
 */
export function sweepResume(maxAgeMs = RESUME_MAX_AGE_MS) {
  const cutoff = Date.now() - maxAgeMs;
  return idbScan('readwrite', (cursor, value) => {
    const savedAt = Number(value?.savedAt);
    if (Number.isFinite(savedAt) && savedAt > cutoff) return false;
    cursor.delete();
    return true;
  }).then((gone) => gone.length);
}

// Object URLs handed out by saveBlob and not yet revoked. Each one keeps its blob (up to
// the in-memory limit) alive, and app.js wires saveBlob to an undebounced click handler,
// so without tracking them a few clicks pin several copies until their timers expire.
const pendingObjectUrls = new Set();

const MAX_FILENAME_CHARS = 120;

/**
 * Strip UNPAIRED surrogate code units, leaving well-formed pairs alone.
 *
 * WHY THIS IS HERE AT ALL. A lone surrogate is not a character: it cannot be encoded as
 * UTF-8, so encodeURIComponent throws a URIError on it. The peer chooses the filename, the
 * name reaches the service worker on the streaming download route, and the service worker
 * encodes it there. One lone surrogate therefore made that request answer 500, the
 * `wg-started` handshake never fired, and the page blamed a stalled connection ten seconds
 * later. That route is the ONLY way Firefox and Safari receive a large file, so a
 * peer-chosen name was a remote kill switch for large transfers on two of the three
 * engines. Measured survivor before this: "a\ud800b.txt".
 *
 * PAIRS ARE KEPT. Deleting the whole \ud800-\udfff range would be shorter and would also
 * silently delete every emoji and every astral-plane character from every filename, which
 * is a real name a real person picked. The string iterator makes the distinction free: it
 * yields one entry per CODE POINT, so a well-formed pair arrives as a single two-unit
 * string and only an unpaired surrogate can arrive as a one-unit string in that range. No
 * lookbehind, which Safari did not have before 16.4 and which would have made this module
 * fail to PARSE there rather than fail to sanitise.
 */
function dropLoneSurrogates(text) {
  if (!/[\ud800-\udfff]/.test(text)) return text; // the overwhelmingly common case
  let out = '';
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (ch.length === 1 && code >= 0xd800 && code <= 0xdfff) continue;
    out += ch;
  }
  return out;
}

/**
 * Make a peer-supplied filename safe to show and to save under.
 *
 * Path traversal is NOT the risk here: Chromium and Firefox both strip separators when
 * writing a download. What is real is that the name arrives exactly as the other side
 * wrote it, so a right-to-left override can disguise the extension, a double extension
 * can hide behind it, and control characters can blank most of it out. The same function
 * is exported so the row title and the save dialog show the one name that gets used.
 */
export function sanitizeFilename(name, fallback = 'warp-gate-file') {
  const cleaned = dropLoneSurrogates(String(name ?? ''))
    // C0 and C1 controls, plus the bidi marks and overrides that reorder what is drawn.
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\\/]+/g, '_')
    // TRIM FIRST, THEN THE DOTS. The other order was defeated by a single leading space:
    // /^\.+/ saw the space, matched nothing, and .trim() afterwards handed back exactly the
    // leading dots the next line claims to have removed. Measured before the swap: " .."
    // came out as "..", " .bashrc" as ".bashrc", "  ../../etc/passwd" as
    // ".._.._etc_passwd". Separators are already replaced above and the download manager
    // sanitises again, so nothing traversed a path, but ".." reached showSaveFilePicker as
    // a suggestedName and the invariant stated on the next line was simply false.
    .trim()
    .replace(/^\.+/, '') // no leading dots: neither ".." nor a hidden file
    // Trimmed again AFTER the strip, because the strip can uncover new edge whitespace,
    // and re-tested for empty below: "..", "..." and " .. " all reduce to nothing here,
    // which is exactly what the fallback exists for.
    .trim();
  if (!cleaned) return fallback;
  if (cleaned.length <= MAX_FILENAME_CHARS) return cleaned;
  // Keep the extension when truncating, so the saved file still opens with the right app.
  const dot = cleaned.lastIndexOf('.');
  const ext = dot > 0 && cleaned.length - dot <= 12 ? cleaned.slice(dot) : '';
  let cut = MAX_FILENAME_CHARS - ext.length;
  // Never cut BETWEEN the two halves of a surrogate pair. MAX_FILENAME_CHARS counts UTF-16
  // code units, so a name whose last kept unit is the high half of an emoji used to be
  // sliced through the middle of it, and the result carried a lone surrogate that nothing
  // after this point strips: the same URIError as above, from a name that was individually
  // well-formed. Measured: 119 'A's, one emoji, then 50 'B's.
  const last = cleaned.charCodeAt(cut - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut -= 1;
  return cleaned.slice(0, cut) + ext;
}

/** Offer a received blob to the user. Revokes the object URL so nothing lingers. */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  pendingObjectUrls.add(url);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = sanitizeFilename(filename);
  document.body.appendChild(anchor);
  try {
    anchor.click();
  } finally {
    // The anchor goes even if click() throws, or a detached-but-attached node keeps the
    // blob referenced for the life of the page.
    anchor.remove();
  }
  setTimeout(() => {
    if (pendingObjectUrls.delete(url)) URL.revokeObjectURL(url);
  }, 60_000);
  return url;
}

/** Release every object URL saveBlob is still holding. Call this when severing. */
export function revokeAllObjectUrls() {
  for (const url of pendingObjectUrls) URL.revokeObjectURL(url);
  pendingObjectUrls.clear();
}
