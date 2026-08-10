// Page side of the OS share target.
//
// The other half is in public/sw.js. The OS posts a file to /app/share, the service
// worker answers that POST itself and puts the file in Cache Storage, then redirects to
// /app. This module is what the gate calls on load to pick it back up.
//
// Nothing here touches the network, and nothing here can: it reads Cache Storage, which
// is origin-private browser storage on the device. There is no fetch() in this file. See
// the long comment in public/sw.js for the whole argument, including why the server has
// no upload route to fall back to.
//
// Every path is optional by construction. A browser with no service worker, no Cache
// Storage, or simply no share to hand over gets an empty array and the gate behaves
// exactly as it did before. Nothing in this module runs at import time, so importing it
// in an environment without `caches` is safe.

// These three must match public/sw.js. tests/pwa.test.mjs asserts they do, because a
// mismatch fails silently: the worker stores the file and the page looks elsewhere.
export const SHARE_CACHE = 'wg-share-v1';
export const SHARE_PREFIX = '/wg-share/';
export const SHARE_ACTION = '/app/share';
// Must match SHARE_TTL_MS in the worker. Enforced on this side too: the worker sweeps
// when a new share arrives, so a device that shares once and never again would otherwise
// keep that file until the next share.
const SHARE_TTL_MS = 10 * 60 * 1000;

function available() {
  return typeof globalThis.caches === 'object' && globalThis.caches !== null
    && typeof globalThis.caches.open === 'function';
}

/**
 * Register the worker at load, and hand back whatever was shared in.
 *
 * One call, because the two halves are the same feature. Registering is not optional
 * here: public/js/download.js registers the same worker, but only when a received file
 * needs streaming, so a browser that has never taken a download has no worker, is not
 * installable, and has no share target to be shared into. This puts it there on load.
 *
 * The registration is deliberately NOT awaited. It is slow on a cold start and nothing
 * below depends on it: the file that is being claimed right now was stashed by a worker
 * that was already running when the OS posted to it. Awaiting would delay the gate for a
 * benefit that lands on the NEXT launch.
 */
export function initShare() {
  try {
    if (typeof navigator === 'object' && navigator && 'serviceWorker' in navigator
      && globalThis.isSecureContext === true) {
      // Same script and same scope as download.js, so this is the same registration and
      // not a second worker. Errors are swallowed on purpose: a browser that refuses to
      // register one is a browser that does not get the install prompt, which is a
      // missing convenience and not a broken gate.
      navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch((err) => { void err; });
    }
  } catch (err) {
    void err;
  }
  return claimSharedFiles();
}

/**
 * Take whatever the OS shared into this gate, and remove it from storage.
 *
 * Returns an array of File objects, oldest entry first, or an empty array when there is
 * nothing waiting. Never throws: a share that cannot be read must not stop the gate from
 * loading, because the gate is the whole product and the share is a convenience on top.
 *
 * Take, not read: every entry it looks at is deleted, claimed or not. A file the user
 * shared in has already been handed over; leaving a copy behind would mean a transfer app
 * that keeps your files, which is exactly what this one promises not to be.
 */
export async function claimSharedFiles() {
  if (!available()) return [];
  let cache;
  try {
    cache = await globalThis.caches.open(SHARE_CACHE);
  } catch (err) {
    void err;
    return [];
  }

  const files = [];
  try {
    const keys = await cache.keys();
    // Sorted by the URL the worker minted, which ends in the index it stashed the file
    // under. Cache.keys() is insertion-ordered in practice, but "in practice" is not an
    // ordering guarantee and a multi-file share must arrive in the order it was sent.
    const wanted = keys
      .filter((request) => new URL(request.url).pathname.startsWith(SHARE_PREFIX))
      .sort((a, b) => (a.url < b.url ? -1 : 1));
    const now = Date.now();
    for (const request of wanted) {
      const stored = await cache.match(request);
      // Delete first, use second. If constructing the File throws, the entry is still
      // gone: a stash that cannot be read must not be retried on every later load.
      await cache.delete(request);
      if (!stored) continue;
      const at = Number(stored.headers.get('x-wg-share-time'));
      // Stale enough that it belongs to some earlier session the user has forgotten
      // about. Attaching it now would be a surprise, so it is dropped, not offered.
      if (!Number.isFinite(at) || now - at > SHARE_TTL_MS) continue;
      const type = stored.headers.get('content-type') || 'application/octet-stream';
      let name = 'shared-file';
      try {
        name = decodeURIComponent(stored.headers.get('x-wg-share-name') || '') || name;
      } catch (err) {
        // A malformed escape in the stored name is not a reason to lose the file.
        void err;
      }
      const blob = await stored.blob();
      files.push(new File([blob], name, { type, lastModified: at }));
    }
  } catch (err) {
    void err;
    return files;
  }

  // An empty cache is not free: it is a named cache sitting in storage. Drop it once it
  // has nothing left in it.
  try {
    const left = await cache.keys();
    if (!left.length) await globalThis.caches.delete(SHARE_CACHE);
  } catch (err) {
    void err;
  }

  return files;
}
