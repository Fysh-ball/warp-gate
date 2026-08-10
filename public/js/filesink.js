// Where a received file actually goes: the save dialog, the granted folder, the browser's
// own download manager, or this tab's heap.
//
// Split out of transfer.js on 2026-08-10, when three features in one day took the gate over
// its raw byte ceiling. The rule tests/size.test.mjs states is that the ceiling does not
// move for a feature, so something had to leave the load path, and this is the largest piece
// of transfer.js that provably cannot run until a decision nobody has made when a gate
// opens: a sink is built only once a file has been OFFERED by a peer and ACCEPTED on this
// side (link.js acceptIncoming, acceptFromGrant, the auto-accept branch of onFileStart) or
// once a reload has found a stored handle and the user has clicked to re-adopt it
// (link.js adoptInbound). None of those exist at load, so none of these bytes do either.
//
// What stayed behind in transfer.js is the half the gate genuinely needs before any of that:
// canAccept() decides whether a file may be taken AT ALL and runs on every FILE_START,
// formatBytes/describeLimit render the capability text on the connected screen, and
// readChunks feeds the sending side. Those are the boot path; this is not.
//
// The import direction is deliberately back the way it came: this module imports the
// constants and helpers from transfer.js rather than transfer.js re-exporting them here.
// transfer.js is always fully evaluated before this file is ever fetched (the only route in
// is transfer.js's own import() of it), so the cycle is inert, and keeping MEMORY_LIMIT_BYTES
// and sanitizeFilename in one place is what stops the gate's refusal and the sink's refusal
// drifting apart. They disagreeing once already cost a receiver an accepted-then-refused
// transfer: see the comment on the memory-limit guard below.

import { supportsStreamDownload } from './streamable.js';
import {
  CHECKPOINT_BYTES, MEMORY_LIMIT_BYTES, canStreamToDisk, formatBytes, sanitizeFilename,
} from './transfer.js';

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
     * Move the write position back to `offset`, discarding anything after it.
     *
     * Needed by exactly one caller and it is not an optimisation. A checkpoint commits a
     * BYTE count, so a file recovered after a reload can end in the middle of a chunk.
     * Appending the next chunk onto that partial one splices it into the middle of the
     * file: every later byte is shifted, the total length still comes out right because
     * the missing tail of the partial chunk is never noticed, and no length check on
     * either side can see it. Rewinding to the last whole chunk costs one chunk of
     * re-sent data and makes that impossible.
     *
     * truncate() then seek(), in that order: seeking alone leaves the bytes past the
     * offset in place, and a file that is longer than its write position is exactly the
     * ambiguity this exists to remove.
     */
    async seekTo(offset) {
      if (failure) throw failure;
      const at = Math.max(0, Math.min(Number(offset) || 0, position));
      try {
        await writable.truncate(at);
        await writable.seek(at);
        position = at;
      } catch (err) { await fail(err); }
      return position;
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
 *
 * Pass `directory` to write into a folder the user chose ONCE for a whole batch: that is
 * what turns N save dialogs into one gesture. Pass `noPicker` to skip the save dialog even
 * where one exists, which is what a batch accepted on a browser with no directory picker
 * needs: the one click already happened, and a per-file dialog after it would put back the
 * prompt the batch removed.
 *
 * Reached through transfer.js's createSink(), which is the name every caller still uses.
 * The wrapper there is what fetches this file; nothing calls in here directly.
 */
export async function createSink(meta, {
  preferMemory = false, handle = null, startOffset = 0, directory = null, noPicker = false,
} = {}) {
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

  // A folder the user picked once, for a batch. ABOVE the memory-limit guard below on
  // purpose: a directory handle is a real, unbounded path to disk and exists in browsers
  // whose canStreamToDisk() is false, so that guard would refuse a large file for want of a
  // save dialog this route never uses. No picker opens here; the gesture already happened.
  if (directory) {
    // Fetched here rather than imported at the top: naming a file inside a granted
    // folder cannot happen until a folder has been granted, so it is not weight every
    // gate pays to open. The branch is already async, so nothing else changes.
    const { childHandle } = await import('./dirsink.js');
    return openDiskSink(await childHandle(directory, meta.name), meta, 0);
  }

  // Refuse a file that cannot fit before opening anything, but only when there is genuinely
  // nowhere for it to go. "No picker" stopped meaning "no path to disk" when the streaming
  // download landed, and this guard was never updated. That made the block at the bottom of
  // this function unreachable: its condition is a strict subset of this one, so every file
  // it was written for was thrown out here first. canAccept() promises exactly that route
  // for exactly these files, so the gate and the sink disagreed and the receiver was refused
  // after having already clicked Accept.
  //
  // preferMemory is different and stays absolute: the caller asked for a memory sink by
  // name, and there is no route out of that but the limit.
  const streamable = !preferMemory && supportsStreamDownload();
  if ((preferMemory || !canStreamToDisk()) && size > MEMORY_LIMIT_BYTES && !streamable) {
    throw new Error(
      `${formatBytes(size)} cannot be held in memory (limit ${formatBytes(MEMORY_LIMIT_BYTES)}); `
      + 'this file has to be streamed to disk',
    );
  }

  // noPicker joins the two conditions that already meant "no dialog" rather than
  // short-circuiting earlier: everything past this branch is exactly the route a browser
  // without showSaveFilePicker takes today, which is the route a batch with no directory is
  // asking for by name.
  if (canStreamToDisk() && !preferMemory && !noPicker) {
    try {
      const picked = await globalThis.showSaveFilePicker({
        suggestedName: sanitizeFilename(meta.name),
        types: meta.mime ? [{ description: meta.mime, accept: { [meta.mime]: [] } }] : undefined,
      });
      return await openDiskSink(picked, meta, 0);
    } catch (err) {
      // A dismissed dialog and a broken dialog are not the same answer and must not get the
      // same handling.
      //
      // AbortError is the user saying no, and it means the same thing at every size.
      // canAccept() promises that dismissing the dialog cancels the transfer, with no size
      // attached to the promise, so this cancels before any route is chosen. It used to be
      // consulted only above the memory limit, which meant a smaller file fell through to a
      // memory sink: the transfer the user had just declined completed anyway, and the note
      // blamed a dialog that was working perfectly.
      //
      // Anything else, a TypeError from the options, a missing user activation, a sandboxed
      // context, is a dialog the user never got to answer, and that is no reason to give up.
      // Every browser that HAS the picker also has the streaming download, so throwing here
      // jumped over a working route and left a Chromium desktop with FEWER ways to receive a
      // large file than the Firefox and Safari the fallback was written for.
      if (err.name === 'AbortError') {
        throw new Error('you dismissed the save dialog, so the transfer was cancelled and nothing was saved');
      }
      if (meta.size > MEMORY_LIMIT_BYTES && !supportsStreamDownload()) {
        throw new Error(
          `could not open a save location (${err.name}: ${err.message}), and ${formatBytes(meta.size)} `
          + `is too large to hold in memory (limit ${formatBytes(MEMORY_LIMIT_BYTES)})`,
        );
      }
      pickerNote = meta.size > MEMORY_LIMIT_BYTES
        ? `The save dialog could not be opened (${err.name}), so this is being saved by the `
          + 'browser\'s own download manager instead. It goes to your usual downloads folder.'
        : `save dialog unavailable (${err.name}), holding the file in memory instead`;
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
      // pickerNote is set only when a picker existed and failed to open. Carried through so
      // the explanation reaches the UI: without it this route fixes the failure and leaves
      // the user with no account of why the save dialog they were promised never appeared.
      // download.js is fetched here, at the one point a stream is actually opened, rather
      // than statically: 8.5 KB of service worker plumbing that a gate does not need to
      // open and that most sessions never reach at all.
      const { openStreamDownload } = await import('./download.js');
      return await openStreamDownload({
        name: sanitizeFilename(meta.name), size, mime: meta.mime, note: pickerNote,
      });
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
