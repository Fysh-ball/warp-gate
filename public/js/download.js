// Page side of the streaming download.
//
// Hands received bytes to public/sw.js, which answers a request the server never sees
// with a body this file feeds in. The browser then treats it as an ordinary download:
// straight to disk, its own progress UI, no ceiling on size.
//
// The reason this exists: showSaveFilePicker is Chromium only, so on Firefox and Safari
// a received file had to be held in memory and was capped at 500 MB. That was not a
// slow path, it was a wall.

const PREFIX = '/wg-download/';
const START_TIMEOUT_MS = 10_000;
// Enough credit to keep bytes moving before the browser's first pull arrives, small
// enough that a download nobody is consuming cannot pile up in the worker.
const INITIAL_CREDITS = 8;

let registration = null;

export function supportsStreamDownload() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true;
}

/**
 * Register the worker and wait until it is actually controlling this page.
 *
 * `ready` resolving is not enough: on the very first load nothing controls the page yet,
 * so a fetch would go to the network and 404. The worker calls clients.claim(), and this
 * waits for that to land.
 */
async function ensureWorker() {
  if (!supportsStreamDownload()) throw new Error('this browser cannot stream downloads');
  if (!registration) {
    registration = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  }
  await navigator.serviceWorker.ready;
  if (navigator.serviceWorker.controller) return;

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      navigator.serviceWorker.removeEventListener('controllerchange', onChange);
      reject(new Error('the download worker did not take control in time'));
    }, START_TIMEOUT_MS);
    function onChange() {
      clearTimeout(timer);
      navigator.serviceWorker.removeEventListener('controllerchange', onChange);
      resolve();
    }
    navigator.serviceWorker.addEventListener('controllerchange', onChange);
  });
}

let counter = 0;
const nextId = () => `${Date.now().toString(36)}-${(counter += 1).toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

/**
 * Open a download the browser writes to disk itself.
 *
 * Returns a sink with the same shape the memory and disk sinks use, so the transfer code
 * does not care which one it got.
 */
export async function openStreamDownload({ name, size, mime, note = null }) {
  await ensureWorker();

  const id = nextId();
  const worker = navigator.serviceWorker.controller;
  if (!worker) throw new Error('no download worker is controlling this page');

  let credits = INITIAL_CREDITS;
  let waiter = null;
  let started = false;
  let dead = null;

  // Mark the transfer dead AND wake a write() parked waiting for credit. A parked waiter
  // is otherwise only ever settled by wg-pull/wg-cancel, so any other terminal condition
  // (the browser never requested the download, an explicit abort) would set `dead` and
  // still leave the sender blocked forever. Every death path must go through here.
  const fail = (err) => {
    dead = dead || err;
    if (waiter) { const w = waiter; waiter = null; w.reject(dead); }
  };

  const onMessage = (event) => {
    const msg = event.data;
    if (!msg || msg.id !== id) return;
    if (msg.type === 'wg-started') {
      started = true;
    } else if (msg.type === 'wg-pull') {
      credits += 1;
      if (waiter) { const w = waiter; waiter = null; w.resolve(); }
    } else if (msg.type === 'wg-cancel') {
      // The user cancelled it in the browser's own download UI. That is a real answer,
      // not a failure to hide: stop asking the peer for bytes.
      fail(new Error('the download was cancelled in the browser'));
    }
  };
  navigator.serviceWorker.addEventListener('message', onMessage);

  const cleanup = () => navigator.serviceWorker.removeEventListener('message', onMessage);

  // Tell the worker what the response should be, and wait for it to acknowledge, before
  // triggering the request. Otherwise the fetch can win the race and get a 404.
  try {
    await new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timer = setTimeout(() => reject(new Error('the download worker did not answer')), START_TIMEOUT_MS);
      channel.port1.onmessage = () => { clearTimeout(timer); resolve(); };
      try {
        worker.postMessage({ type: 'wg-open', id, name, size, mime }, [channel.port2]);
      } catch (err) {
        // A worker that went away between the controller check and this call rejects here.
        // Without clearing the timer the rejection would be followed by a second, later
        // one that nothing is listening for.
        clearTimeout(timer);
        reject(err);
      }
    });
  } catch (err) {
    // The listener above is attached to the service worker container, which outlives this
    // page's transfers. Nothing downstream exists yet to remove it, so a handshake that
    // never completes used to leave one dead listener per attempt for the life of the tab.
    cleanup();
    throw err;
  }

  // An iframe, and it has to be an iframe.
  //
  // A link with the download attribute looks like the tidier option and does not work:
  // Chromium fetches it OUTSIDE the service worker, so the request goes to the real
  // server, gets a 404, and the download is cancelled at zero bytes with no error
  // anywhere. Measured: downloadWillBegin fired, then state "canceled", and the worker's
  // fetch handler never ran at all.
  //
  // An iframe navigation IS dispatched to the worker, which is why this is the shape
  // every version of this technique uses. It needs frame-src 'self' in the CSP, which
  // otherwise inherits default-src 'none' and blocks the frame before it requests
  // anything.
  const frame = document.createElement('iframe');
  frame.setAttribute('aria-hidden', 'true');
  frame.style.display = 'none';
  frame.src = PREFIX + encodeURIComponent(id);
  document.body.appendChild(frame);

  const removeFrame = () => { try { frame.remove(); } catch (err) { void err; } };

  const startedCheck = setTimeout(() => {
    if (!started) fail(new Error('the browser never requested the download'));
  }, START_TIMEOUT_MS);

  let handed = 0;

  return {
    kind: 'stream',
    // Passed through from the caller rather than invented here. This sink is reached by two
    // different routes (no picker at all, or a picker that failed to open), and only the
    // caller knows which one the user is on. A sink that wrote its own note would say the
    // same thing on both, and one of the two would be wrong.
    note,
    // Stated, not omitted. The other two sinks expose these, and a consumer that reads a
    // missing key gets `undefined`, which reads as an unstated value rather than as "this
    // route has no durable handle and never wants a checkpoint". Both of those are facts
    // about this sink, so it says them.
    handle: null,
    wantsCheckpoint: false,
    /**
     * Bytes handed to the worker, which is the only count this side can honestly report.
     *
     * The worker is a pipe with no acknowledgement: once a chunk is posted, what the
     * browser's download manager has committed to disk is not observable from here. So this
     * is an upper bound on what is on disk, and it is only safe to resume from because the
     * stream stays open across a data channel drop. A reload closes it, and that is the
     * case `describeLimit` and `canAccept` already refuse to promise.
     */
    get position() { return handed; },
    async checkpoint() { return handed; },
    async write(chunk) {
      if (dead) throw dead;
      if (credits <= 0) {
        // Wait for the browser to ask for more. This is the whole flow control story:
        // a slow disk slows the sender, with nothing in between guessing a rate.
        await new Promise((resolve, reject) => { waiter = { resolve, reject }; });
        if (dead) throw dead;
      }
      credits -= 1;
      const copy = chunk instanceof Uint8Array ? chunk.slice() : new Uint8Array(chunk);
      const length = copy.byteLength;
      worker.postMessage({ type: 'wg-chunk', id, chunk: copy.buffer }, [copy.buffer]);
      // After the transfer, so `copy.byteLength` is zero by now: read it before posting.
      handed += length;
    },
    async finish() {
      clearTimeout(startedCheck);
      worker.postMessage({ type: 'wg-close', id });
      cleanup();
      // Leave the frame briefly: removing it the instant the body closes can cancel the
      // download in some browsers before it has committed the last bytes.
      setTimeout(removeFrame, 2000);
      return null;
    },
    async abort(reason) {
      clearTimeout(startedCheck);
      fail(new Error(reason || 'aborted'));
      worker.postMessage({ type: 'wg-abort', id, reason: String(reason || 'aborted') });
      cleanup();
      removeFrame();
    },
  };
}
