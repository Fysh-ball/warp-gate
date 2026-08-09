// File transfer: chunking on the way out, sink selection on the way in.
//
// The sink question is not a detail. showSaveFilePicker exists only in Chromium on
// desktop: Firefox declines to implement it and no Safari supports it (verified in
// DESIGN.md section 0). Everywhere else the receiver must hold the whole file in
// memory, which iOS will not tolerate at size. So the limit is checked and refused
// BEFORE the transfer starts, never at 90 percent (DESIGN.md 1.9).

export const CHUNK_BYTES = 16 * 1024;
export const MEMORY_LIMIT_BYTES = 500 * 1024 * 1024;

export const canStreamToDisk = () => typeof globalThis.showSaveFilePicker === 'function';

export function describeLimit() {
  return canStreamToDisk()
    ? 'This browser can stream directly to disk, so there is no practical size limit.'
    : `This browser cannot stream to disk, so files are held in memory and capped at ${formatBytes(MEMORY_LIMIT_BYTES)}.`;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

/** Decide up front whether an incoming file can be received at all. */
export function canAccept(size) {
  if (canStreamToDisk()) return { ok: true };
  if (size > MEMORY_LIMIT_BYTES) {
    return {
      ok: false,
      reason: `${formatBytes(size)} exceeds this browser's ${formatBytes(MEMORY_LIMIT_BYTES)} in-memory limit. `
        + 'Use a Chromium desktop browser, which can stream straight to disk.',
    };
  }
  return { ok: true };
}

/**
 * Build a sink for an incoming file. Must be called from a user gesture when
 * streaming to disk, because showSaveFilePicker requires one.
 */
export async function createSink(meta, { preferMemory = false } = {}) {
  let pickerNote = null;

  if (canStreamToDisk() && !preferMemory) {
    try {
      const handle = await globalThis.showSaveFilePicker({
        suggestedName: meta.name,
        types: meta.mime ? [{ description: meta.mime, accept: { [meta.mime]: [] } }] : undefined,
      });
      const writable = await handle.createWritable();
      return {
        kind: 'disk',
        note: null,
        async write(chunk) { await writable.write(chunk); },
        async finish() { await writable.close(); return null; },
        async abort(reason) {
          try { await writable.abort(reason); } catch (err) { void err; }
        },
      };
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

  const parts = [];
  let held = 0;
  return {
    kind: 'memory',
    note: pickerNote,
    async write(chunk) {
      held += chunk.byteLength;
      if (held > MEMORY_LIMIT_BYTES) throw new Error(`in-memory limit of ${formatBytes(MEMORY_LIMIT_BYTES)} exceeded`);
      parts.push(chunk);
    },
    async finish() {
      const blob = new Blob(parts, meta.mime ? { type: meta.mime } : undefined);
      parts.length = 0;
      return blob;
    },
    async abort() { parts.length = 0; held = 0; },
  };
}

/**
 * Read a File in chunks without ever holding more than one chunk in memory, so a
 * multi-gigabyte file never becomes a multi-gigabyte allocation on the sending side.
 */
export async function* readChunks(file, chunkSize = CHUNK_BYTES) {
  let offset = 0;
  while (offset < file.size) {
    const end = Math.min(offset + chunkSize, file.size);
    const buffer = await file.slice(offset, end).arrayBuffer();
    yield new Uint8Array(buffer);
    offset = end;
  }
}

/** Offer a received blob to the user. Revokes the object URL so nothing lingers. */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename || 'warp-gate-file';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
