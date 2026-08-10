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
  // registered the worker does not have to wait for a reload.
  event.waitUntil(self.clients.claim());
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
