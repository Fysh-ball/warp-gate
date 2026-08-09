// File transfer: chunking on the way out, sink selection on the way in.
//
// The sink question is not a detail. showSaveFilePicker exists only in Chromium on
// desktop: Firefox declines to implement it and no Safari supports it (verified in
// DESIGN.md section 0). Everywhere else the receiver must hold the whole file in
// memory, which iOS will not tolerate at size. So the limit is checked and refused
// BEFORE the transfer starts, never at 90 percent (DESIGN.md 1.9).

import { b64u } from './crypto.js';
import { supportsStreamDownload, openStreamDownload } from './download.js';

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

export function describeLimit() {
  if (canStreamToDisk()) {
    return 'This browser writes received files straight to disk, so there is no practical size '
      + 'limit and an interrupted transfer can carry on into the same file.';
  }
  // showSaveFilePicker is Chromium-only: Firefox has declined to implement it and no
  // Safari has it. That used to mean a large RECEIVE here was impossible rather than
  // slow. It no longer does: the service worker hands the file to the browser's own
  // download manager, which writes to disk with no ceiling.
  if (supportsStreamDownload()) {
    return `Files over ${formatBytes(MEMORY_LIMIT_BYTES)} are saved by this browser's own download `
      + 'manager as they arrive, so there is no size limit. They go to your usual downloads folder '
      + 'rather than a location you pick, and an interrupted transfer cannot be continued after a '
      + 'reload, because the browser owns the partial file. A Chromium desktop browser can do both.';
  }
  return `This browser cannot write received files straight to disk, so it holds them in memory `
    + `and refuses anything over ${formatBytes(MEMORY_LIMIT_BYTES)}. Sending any size is fine. `
    + 'To RECEIVE a large file, use a Chromium desktop browser (Chrome, Edge, Brave, Opera) at '
    + 'the receiving end. A transfer interrupted here also cannot be continued, because the '
    + 'partial file is only in this page\'s memory.';
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
 * Wrap a FileSystemFileHandle as a resumable disk sink.
 *
 * `startOffset` is a REQUEST, not an instruction. The authority on how many bytes exist is
 * the file itself, because everything written since the last close() lives in a swap file
 * that a reload throws away. So the position is clamped to the file's actual size and
 * reported back as `position`; the caller tells the sender that number, never the one it
 * had in storage. That is what makes a resume unable to skip a hole.
 */
async function openDiskSink(handle, meta, startOffset = 0) {
  const onDisk = (await handle.getFile()).size;
  const at = Math.max(0, Math.min(Number(startOffset) || 0, onDisk));
  let writable = await handle.createWritable({ keepExistingData: at > 0 });
  if (at > 0) await writable.seek(at);

  let position = at;
  let sinceCheckpoint = 0;
  // One failed write kills the whole stream: every later write on it throws too. The
  // caller catches per chunk and carries on, so without a latch a disk-full error
  // became tens of thousands of re-entries into a dead stream, and the browser's swap
  // file was never released because nothing ever aborted it.
  let failure = null;
  const fail = async (err) => {
    if (!failure) {
      failure = err;
      try { await writable.abort(err.message); } catch (abortErr) { void abortErr; }
    }
    throw failure;
  };

  return {
    kind: 'disk',
    note: null,
    handle,
    get position() { return position; },
    // True once enough has been written that committing it is worth the copy.
    get wantsCheckpoint() { return sinceCheckpoint >= CHECKPOINT_BYTES; },
    async write(chunk) {
      if (failure) throw failure;
      try {
        await writable.write(chunk);
        position += chunk.byteLength;
        sinceCheckpoint += chunk.byteLength;
      } catch (err) { await fail(err); }
    },
    /**
     * Commit what has been written so a reload can find it, and reopen at the same place.
     * Returns the offset that is now durable. Never call this on a dead stream.
     */
    async checkpoint() {
      if (failure) throw failure;
      try {
        await writable.close();
        writable = await handle.createWritable({ keepExistingData: true });
        await writable.seek(position);
        sinceCheckpoint = 0;
      } catch (err) { await fail(err); }
      return position;
    },
    async finish() {
      if (failure) throw failure;
      try { await writable.close(); } catch (err) { await fail(err); }
      return null;
    },
    async abort(reason) {
      if (failure) return;
      failure = reason instanceof Error ? reason : new Error(String(reason ?? 'transfer aborted'));
      try { await writable.abort(reason); } catch (err) { void err; }
    },
  };
}

/**
 * Build a sink for an incoming file. Must be called from a user gesture when
 * streaming to disk, because showSaveFilePicker requires one.
 *
 * Pass `handle` to re-adopt a file the user already chose before a reload, in which case
 * no picker is opened (re-acquiring an existing handle needs a permission grant, not a new
 * choice) and `startOffset` says where the transfer had got to.
 */
export async function createSink(meta, { preferMemory = false, handle = null, startOffset = 0 } = {}) {
  let pickerNote = null;
  const size = Number(meta.size ?? 0);

  // Re-adopting a handle from before a reload. Permission does not survive the navigation,
  // so it has to be asked for again, and requestPermission needs a user gesture.
  if (handle) {
    // Not every FileSystemFileHandle carries a permission API. Handles from the origin's
    // own private file system have no permission to ask for, and the methods are simply
    // absent there, so their absence must read as "nothing to grant" and not as a failure.
    // A handle that DOES have them and refuses is a hard stop.
    if (typeof handle.queryPermission === 'function') {
      let state = 'prompt';
      try {
        state = await handle.queryPermission({ mode: 'readwrite' });
      } catch (err) {
        throw new Error(`could not check permission on the file you chose: ${err.message}`);
      }
      if (state !== 'granted' && typeof handle.requestPermission === 'function') {
        try {
          state = await handle.requestPermission({ mode: 'readwrite' });
        } catch (err) {
          throw new Error(`could not ask for permission to write to the file you chose: ${err.message}`);
        }
      }
      if (state !== 'granted') {
        throw new Error('permission to keep writing to the file you chose was not granted, so the transfer cannot continue');
      }
    }
    return openDiskSink(handle, meta, startOffset);
  }

  // Refuse a file that cannot fit before opening anything. preferMemory is a caller
  // option with no guard of its own, and a browser without the picker has no other path,
  // so neither may rely on canAccept having been consulted first.
  if ((preferMemory || !canStreamToDisk()) && size > MEMORY_LIMIT_BYTES) {
    throw new Error(
      `${formatBytes(size)} cannot be held in memory (limit ${formatBytes(MEMORY_LIMIT_BYTES)}); `
      + 'this file has to be streamed to disk',
    );
  }

  if (canStreamToDisk() && !preferMemory) {
    try {
      const picked = await globalThis.showSaveFilePicker({
        suggestedName: sanitizeFilename(meta.name),
        types: meta.mime ? [{ description: meta.mime, accept: { [meta.mime]: [] } }] : undefined,
      });
      return await openDiskSink(picked, meta, 0);
    } catch (err) {
      // Any picker failure falls back to memory: the user dismissing the dialog, a
      // missing user activation, or a sandboxed context. But falling back silently
      // for a huge file would trade a clear error for an out-of-memory crash, so the
      // in-memory limit is re-checked here rather than assumed.
      if (meta.size > MEMORY_LIMIT_BYTES) {
        throw new Error(
          `could not open a save location (${err.name}: ${err.message}), and ${formatBytes(meta.size)} `
          + `is too large to hold in memory (limit ${formatBytes(MEMORY_LIMIT_BYTES)})`,
        );
      }
      pickerNote = `save dialog unavailable (${err.name}), holding the file in memory instead`;
    }
  }

  // No save picker, but the file is too big to hold. Hand it to the browser's own
  // download machinery through the service worker: it writes straight to disk with no
  // ceiling, which is what makes a large receive possible on Firefox and Safari at all.
  //
  // Deliberately AFTER the picker: the picker gives a handle, and a handle is what lets
  // an interrupted transfer carry on into the same file after a reload. This route
  // cannot do that, because the browser owns the partial file and will not give it back.
  if (!preferMemory && size > MEMORY_LIMIT_BYTES && supportsStreamDownload()) {
    try {
      return await openStreamDownload({ name: sanitizeFilename(meta.name), size, mime: meta.mime });
    } catch (err) {
      throw new Error(
        `${formatBytes(size)} is too large to hold in memory (limit ${formatBytes(MEMORY_LIMIT_BYTES)}), `
        + `and the streaming download could not start: ${err.message}`,
      );
    }
  }

  const parts = [];
  let held = 0;
  let failure = null;
  return {
    kind: 'memory',
    note: pickerNote,
    // No handle, so nothing about this sink survives a reload. Stated as data rather than
    // inferred from `kind`, because the reload path has to fail loudly on exactly this.
    handle: null,
    get position() { return held; },
    // Never. There is nowhere durable to check point TO: the only copy is this array, and
    // writing it to storage would mean persisting the user's file content on their device,
    // which is the one thing this product promises not to do.
    get wantsCheckpoint() { return false; },
    async checkpoint() { return 0; },
    async write(chunk) {
      if (failure) throw failure;
      held += chunk.byteLength;
      if (held > MEMORY_LIMIT_BYTES) {
        // Latch and let go of what was held. Retrying a sink that has already overflowed
        // just repeats the same failure while pinning the memory that caused it.
        failure = new Error(`in-memory limit of ${formatBytes(MEMORY_LIMIT_BYTES)} exceeded`);
        parts.length = 0;
        throw failure;
      }
      parts.push(chunk);
    },
    async finish() {
      if (failure) throw failure;
      const blob = new Blob(parts, meta.mime ? { type: meta.mime } : undefined);
      parts.length = 0;
      return blob;
    },
    async abort(reason) {
      parts.length = 0;
      held = 0;
      if (!failure) failure = reason instanceof Error ? reason : new Error(String(reason ?? 'transfer aborted'));
    },
  };
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
// The record is deleted when the transfer completes, fails, is refused, or the gate ends.
const IDB_NAME = 'warp-gate';
const IDB_STORE = 'inbound-resume';
const IDB_VERSION = 1;
const IDB_TIMEOUT_MS = 5000;

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

/** Record where an interrupted incoming transfer had got to. Keyed by room. */
export function saveResume(roomId, record) {
  if (!roomId) return Promise.reject(new Error('a resume record needs a room to belong to'));
  return idbRun('readwrite', (store) => store.put(record, roomId));
}

export function loadResume(roomId) {
  if (!roomId) return Promise.resolve(null);
  return idbRun('readonly', (store) => store.get(roomId)).then((v) => v ?? null);
}

export function clearResume(roomId) {
  if (!roomId) return Promise.resolve();
  return idbRun('readwrite', (store) => store.delete(roomId));
}

/** Drop every stored record. Used when the user burns a gate from a clean page. */
export function clearAllResume() {
  return idbRun('readwrite', (store) => store.clear());
}

// Object URLs handed out by saveBlob and not yet revoked. Each one keeps its blob (up to
// the in-memory limit) alive, and app.js wires saveBlob to an undebounced click handler,
// so without tracking them a few clicks pin several copies until their timers expire.
const pendingObjectUrls = new Set();

const MAX_FILENAME_CHARS = 120;

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
  const cleaned = String(name ?? '')
    // C0 and C1 controls, plus the bidi marks and overrides that reorder what is drawn.
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\\/]+/g, '_')
    .replace(/^\.+/, '') // no leading dots: neither ".." nor a hidden file
    .trim();
  if (!cleaned) return fallback;
  if (cleaned.length <= MAX_FILENAME_CHARS) return cleaned;
  // Keep the extension when truncating, so the saved file still opens with the right app.
  const dot = cleaned.lastIndexOf('.');
  const ext = dot > 0 && cleaned.length - dot <= 12 ? cleaned.slice(dot) : '';
  return cleaned.slice(0, MAX_FILENAME_CHARS - ext.length) + ext;
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
