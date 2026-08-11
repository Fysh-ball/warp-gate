/* Warp Gate download worker.
 *
 * WHAT THIS IS FOR
 *
 * A received file has to end up on disk. The obvious route, holding it in memory and
 * handing over a Blob, has a hard ceiling: anything past a few hundred megabytes either
 * fails or takes the tab down with it. The other route, showSaveFilePicker, streams
 * properly but exists only in Chromium, so on Firefox and Safari a large file was not
 * slow, it was impossible.
 *
 * This worker gives every browser the third option. It intercepts a request for a URL
 * that does not exist on the server and answers it itself, with a body the page feeds in
 * piece by piece as bytes arrive from the peer. The browser cannot tell the difference
 * between that and an ordinary download, so it uses its ordinary download machinery:
 * writes straight to disk, shows its own progress, and never holds the file in memory.
 *
 * WHAT IT IS NOT
 *
 * It never sees a key and never decrypts anything. The page decrypts and hands over
 * finished plaintext. This worker is a pipe. Keeping it that way is deliberate: a worker
 * that could decrypt would outlive the tab holding the ability to read your files.
 *
 * BACKPRESSURE
 *
 * The stream's pull() is the whole flow-control mechanism. The browser calls it when it
 * is ready for more, the worker asks the page, and the page only then asks the peer for
 * the next range. So a slow disk slows the sender, end to end, with nothing guessing.
 */

const PREFIX = '/wg-download/';
// A stream that is opened but never fetched (the iframe navigation never reaches this
// worker: blocked frame, page navigated away, a forged wg-open with no matching request)
// would otherwise sit in the map for the worker's whole lifetime. Evict it after this.
const OPEN_TTL_MS = 30_000;

/** id -> { controller, wantMore, closed } */
const streams = new Map();

// content-disposition filename is an RFC 5987 ext-value: charset "'" [lang] "'" value,
// and the value may contain only attr-char. encodeURIComponent is close but leaves
// ' ( ) * unescaped, and those are NOT attr-char, so a filename with a quote lands an
// unescaped ' inside UTF-8''<value> and a strict parser mis-reads it. Escape them too.
function encodeRFC5987(str) {
  return encodeURIComponent(str).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

// content-type comes from the untrusted peer. A value containing CR or LF makes the
// Headers constructor throw, which takes the whole fetch handler down with it (the
// request then falls through to the network and 404s, and the sender's write() hangs);
// arbitrary junk is otherwise reflected verbatim as a response header. Accept only a
// conservative media-type token, and fall back to octet-stream for anything else.
function safeMime(raw) {
  const t = typeof raw === 'string' ? raw.trim() : '';
  const TOKEN = '[A-Za-z0-9!#$&^_.+-]+';
  const re = new RegExp(`^${TOKEN}/${TOKEN}(?:\\s*;\\s*${TOKEN}=(?:"[^"\\r\\n]*"|${TOKEN}))*$`);
  return t.length <= 255 && re.test(t) ? t : 'application/octet-stream';
}

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  // Take over pages that were already open, so a transfer started on the load that
  // registered the worker does not have to wait for a reload. Sweep stale shares here
  // too: stashShare used to be the only sweeper, so a share whose gate never opened
  // sat in Cache Storage until the NEXT share arrived.
  event.waitUntil(Promise.all([
    self.clients.claim(),
    self.caches.open(SHARE_CACHE).then(sweepShares).catch((err) => { void err; }),
  ]));
});

self.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg || typeof msg !== 'object') return;

  if (msg.type === 'wg-open') {
    // Ids never legitimately collide (they are minted monotonically per page), so an
    // open for an id that already has a live record is a same-origin tab trying to
    // re-seed the stream under a clientId it controls. Refuse to overwrite it; that would
    // otherwise reopen the injection vector the clientId binding below closes.
    const existing = streams.get(msg.id);
    if (existing && !existing.closed) {
      if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: false, reason: 'in use' });
      return;
    }
    // The page is about to trigger a navigation to PREFIX + id. Record what the response
    // should look like before that request can arrive.
    const entry = {
      name: typeof msg.name === 'string' ? msg.name : '',
      size: Number.isFinite(msg.size) ? msg.size : null,
      mime: safeMime(msg.mime),
      clientId: event.source && event.source.id,
      controller: null,
      wantMore: null,
      closed: false,
      pending: [],
      evictTimer: null,
    };
    // If the fetch never arrives, drop the record rather than leak it for the worker's
    // whole lifetime. The timer is cleared the moment the real fetch's start() runs.
    entry.evictTimer = setTimeout(() => {
      const cur = streams.get(msg.id);
      if (cur && !cur.controller && !cur.closed) streams.delete(msg.id);
    }, OPEN_TTL_MS);
    streams.set(msg.id, entry);
    if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
    return;
  }

  const s = streams.get(msg && msg.id);
  if (!s) return;

  // Bind a stream to the client that opened it. The worker is at root scope and shared by
  // every same-origin tab, so without this any other tab that guesses or learns an id
  // could inject bytes into, close, or abort a download it does not own. Legit chunk/
  // close/abort messages always come from the opening client, whose id we stored above.
  if (s.clientId && (!event.source || event.source.id !== s.clientId)) return;

  if (msg.type === 'wg-chunk') {
    if (s.closed) return;
    if (s.controller) {
      try { s.controller.enqueue(new Uint8Array(msg.chunk)); } catch (err) { void err; }
    } else {
      // The fetch has not arrived yet. Hold the first pieces rather than dropping them.
      s.pending.push(new Uint8Array(msg.chunk));
    }
    return;
  }

  if (msg.type === 'wg-close') {
    s.closed = true;
    if (s.controller) {
      try { s.controller.close(); } catch (err) { void err; }
    }
    streams.delete(msg.id);
    // The reply is what lets the page's finish() declare completion: it proves every
    // prior chunk was taken and end-of-stream was committed to the browser's download.
    if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
    return;
  }

  if (msg.type === 'wg-abort') {
    s.closed = true;
    if (s.controller) {
      try { s.controller.error(new Error(msg.reason || 'transfer aborted')); } catch (err) { void err; }
    }
    streams.delete(msg.id);
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(PREFIX)) return;

  let id;
  try {
    id = decodeURIComponent(url.pathname.slice(PREFIX.length));
  } catch (err) {
    // A malformed percent-escape in a forged link would otherwise throw here and leave
    // respondWith uncalled, which surfaces as an opaque network error.
    void err;
    event.respondWith(new Response('bad transfer id', { status: 400 }));
    return;
  }
  const s = streams.get(id);
  // An unknown id means a stale or forged link. Say so rather than hanging the tab.
  if (!s) {
    event.respondWith(new Response('no such transfer', { status: 404 }));
    return;
  }

  const body = new ReadableStream({
    start(controller) {
      s.controller = controller;
      // The fetch arrived, so the opened-but-never-fetched evictor must not fire.
      if (s.evictTimer) { clearTimeout(s.evictTimer); s.evictTimer = null; }
      for (const piece of s.pending) {
        try { controller.enqueue(piece); } catch (err) { void err; }
      }
      s.pending = [];
      if (s.closed) {
        try { controller.close(); } catch (err) { void err; }
      }
      // Tell the page the browser really did come and ask. Without this the page cannot
      // distinguish "the download is going slowly" from "the request never arrived",
      // and the second one would look like a stall forever.
      self.clients.get(s.clientId).then((client) => {
        if (client) client.postMessage({ type: 'wg-started', id });
      }).catch(() => {});
    },
    pull() {
      // The browser has room. Ask the page for more, which asks the peer for more.
      if (s.closed) return;
      self.clients.get(s.clientId).then((client) => {
        if (client) client.postMessage({ type: 'wg-pull', id });
      }).catch(() => {});
    },
    cancel(reason) {
      // The user cancelled the download in the browser's own UI.
      s.closed = true;
      streams.delete(id);
      self.clients.get(s.clientId).then((client) => {
        if (client) client.postMessage({ type: 'wg-cancel', id, reason: String(reason || '') });
      }).catch(() => {});
    },
  });

  try {
    const headers = new Headers({
      // Sanitised at wg-open time: a CR/LF or junk mime cannot reach here.
      'content-type': s.mime,
      // The filename the browser saves under, percent-encoded as an RFC 5987 ext-value
      // so a quote, comma, semicolon or newline in the name cannot break the header.
      'content-disposition': `attachment; filename*=UTF-8''${encodeRFC5987(s.name || 'warp-gate-file')}`,
      'cache-control': 'no-store',
    });
    // A known length gives the browser a real progress bar instead of a spinner.
    if (s.size !== null) headers.set('content-length', String(s.size));
    event.respondWith(new Response(body, { status: 200, headers }));
  } catch (err) {
    // Belt and braces: never leave respondWith uncalled on a matched request, or the
    // request escapes to the network and 404s while the sender waits on a dead stream.
    void err;
    event.respondWith(new Response('bad transfer headers', { status: 500 }));
  }
});

/* ------------------------------------------------------------------ share target
 *
 * "Hold a photo in the gallery, share to Warp Gate, the gate opens with it attached."
 *
 * WHY A POST TARGET, AND WHY THE WORKER ANSWERS IT
 *
 * A GET share target can only carry title, text and url as query parameters. A FILE
 * needs method POST with multipart/form-data, and a POST goes somewhere. Left alone it
 * would go to this origin's server, which would mean the one thing this whole product
 * exists to avoid: the file on the wire, in a request body, at a server.
 *
 * So it never leaves the browser. The guarantee has two halves and both are load-bearing:
 *
 *   1. This handler calls event.respondWith() SYNCHRONOUSLY, inside the dispatch, before
 *      anything touches the body. Once respondWith is called the request is handled by
 *      the worker and is never dispatched to the network: that is what respondWith means.
 *      Everything after it runs on the Request object the browser already holds in this
 *      process. There is no fetch() on this path, and there is nothing in this file that
 *      could add one, so the bytes have nowhere to go but Cache Storage, which is
 *      origin-private browser storage on the device.
 *   2. The server has no counterpart. server/index.js answers every non-GET, non-HEAD
 *      request with 405 before it reads a single byte of the body. There is no upload
 *      route to reach even if the worker were missing, so the failure mode when the
 *      worker is not installed is "the share is refused", never "the file is uploaded".
 *
 * WHY CACHE STORAGE AND NOT AN IN-MEMORY MAP
 *
 * The handoff spans a navigation: this handler answers the POST with a redirect, and the
 * page that then loads is the one that wants the file. A worker may be terminated at any
 * point in between, which would take an in-memory Map with it and lose the share. Cache
 * Storage survives that. It is deleted the moment the page claims it (public/js/share.js)
 * and swept by age here, so a share that is never claimed does not sit on the device.
 */

// Must match SHARE_ACTION in the manifest's share_target.action, and SHARE_CACHE and
// SHARE_PREFIX must match public/js/share.js. A mismatch is silent: the OS posts here
// and the page looks somewhere else, so tests/pwa.test.mjs asserts all three agree.
const SHARE_ACTION = '/app/share';
const SHARE_CACHE = 'wg-share-v1';
const SHARE_PREFIX = '/wg-share/';
// An unclaimed share is a file sitting in browser storage. Ten minutes is long enough to
// cover a slow cold start of the gate and short enough that nothing lingers.
const SHARE_TTL_MS = 10 * 60 * 1000;

function shareToken() {
  if (self.crypto && typeof self.crypto.randomUUID === 'function') return self.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  self.crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Drop anything older than the TTL, so an abandoned share does not outlive its purpose. */
async function sweepShares(cache) {
  const now = Date.now();
  for (const request of await cache.keys()) {
    const stored = await cache.match(request);
    const at = Number(stored && stored.headers.get('x-wg-share-time'));
    if (!Number.isFinite(at) || now - at > SHARE_TTL_MS) await cache.delete(request);
  }
}

async function stashShare(files) {
  const cache = await self.caches.open(SHARE_CACHE);
  await sweepShares(cache);
  const token = shareToken();
  const at = String(Date.now());
  for (let i = 0; i < files.length; i += 1) {
    const file = files[i];
    // The name and the type travel as headers rather than in the URL: a filename is
    // arbitrary text, and a URL is the one place it would have to be escaped twice.
    const headers = new Headers({
      'content-type': file.type || 'application/octet-stream',
      'x-wg-share-name': encodeURIComponent(file.name || 'shared-file'),
      'x-wg-share-time': at,
    });
    // Zero-padded, because the page restores the order by sorting these keys as strings
    // and an unpadded "10" sorts before "2".
    await cache.put(
      new Request(new URL(`${SHARE_PREFIX}${token}/${String(i).padStart(3, '0')}`, self.location.origin).href),
      new Response(file, { headers }),
    );
  }
  return files.length;
}

self.addEventListener('fetch', (event) => {
  // A SECOND fetch listener, registered after the download one on purpose. Listeners run
  // in registration order, so the download path is still the first thing consulted for
  // every request and its behaviour is untouched. The two never overlap: that one answers
  // only GETs under /wg-download/, this one only a POST to the share action. Neither can
  // shadow the other, and this file must keep it that way.
  const request = event.request;
  if (request.method !== 'POST') return;
  let url;
  try {
    url = new URL(request.url);
  } catch (err) {
    void err;
    return;
  }
  if (url.origin !== self.location.origin || url.pathname !== SHARE_ACTION) return;

  // Synchronous, before the body is read. This is the line that keeps the file off the
  // network: from here the request is the worker's and the browser will not send it.
  event.respondWith(handleShare(request));
});

async function handleShare(request) {
  // Where the browser goes next. The gate itself, with nothing appended: a share leaves
  // no trace in the address bar, for the same reason the room secret does not live there.
  // The page picks the file up from Cache Storage on load (public/js/share.js).
  const landing = new URL('/app', self.location.origin).href;
  try {
    const form = await request.formData();
    // Duck-typed rather than `instanceof File`: a File from another realm is still a file
    // to everything this does with it, and an instanceof check would silently drop it.
    const files = form.getAll('file').filter((v) => v && typeof v === 'object' && typeof v.arrayBuffer === 'function');
    if (files.length) await stashShare(files);
  } catch (err) {
    // A share that cannot be parsed still has to land the user somewhere. Failing here
    // must not leave respondWith with a rejected promise, which surfaces as a browser
    // error page after the user has already left their gallery.
    void err;
  }
  // 303 rather than 302: it forces the follow-up to be a GET. A 302 lets the browser
  // repeat the POST at /app, which would put the file back on the wire.
  return Response.redirect(landing, 303);
}
