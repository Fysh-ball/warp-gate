// Warp Gate signalling process.
//
// One process: an HTTP endpoint, a static file server, an in-memory room map and a
// STUN binding responder. No database, no disk writes, no request logging.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { handleApi, sendJson } from './signal.js';
import { sweep as sweepRooms, heartbeat, destroyAll } from './rooms.js';
import { sweep as sweepLimits } from './limits.js';
import { storeProblem as suggestionStoreProblem } from './suggestions.js';
import { startStun } from './stun.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(here, '..', 'public');

const TYPES = new Map(Object.entries({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
}));

// Strict by design. No external origins at all: a page that can reach a third party
// is a page that can leak. 'wasm-unsafe-eval' is absent because nothing here uses WASM.
const CSP_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  // blob: is needed to preview a received image inline. It is same-origin data the
  // page created itself, not a remote fetch.
  "img-src 'self' blob:",
  // The same exception as img-src, for the same reason and with the same bound: a received
  // video or audio file is previewed from bytes this page assembled itself, and a media
  // element loads through media-src rather than img-src. Without this the directive falls
  // back to default-src 'none' and every <video>/<audio> fails with
  // "Media load rejected by URL safety check", which reads to a user as a corrupt file
  // rather than as a policy decision. Measured in a real browser before it was added.
  //
  // 'self' and blob: only. No data:, because a data: URL is a document the peer could have
  // authored in full, and no external origin, because the whole premise is that nothing
  // leaves the two browsers. blob: here is no wider than blob: on img-src: a blob URL is
  // opaque, unguessable, same-origin, and only ever names bytes this document created.
  "media-src 'self' blob:",
  "connect-src 'self'",
  "font-src 'self'",
  // The web app manifest, so the gate can be installed to a home screen. Without this it
  // inherits default-src 'none' and the browser refuses to fetch it, which reads as "this
  // app is not installable" with nothing in the UI to say why. 'self' only: a manifest
  // names the start URL, the scope and the share target, so a manifest from somewhere
  // else could redirect an installed launcher at an origin the user never chose.
  "manifest-src 'self'",
  // The service worker that streams a received file into the browser's own download
  // machinery. Without this it inherits default-src 'none' and is blocked outright.
  // 'self' only: the worker is served from this origin, and a worker from anywhere
  // else would be able to see every response the page makes.
  "worker-src 'self'",
  // The hidden frame that triggers a streamed download. A frame is the only shape the
  // browser dispatches to a service worker: a link with the download attribute is
  // fetched outside it, hits the real server, 404s, and cancels at zero bytes. Same
  // origin only, so this admits nothing external.
  "frame-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
];

const CSP = CSP_DIRECTIVES.join('; ');

// The landing document, and only the landing document, may be widened to reach a
// sponsor's origins. It is a separate FILE from the gate for exactly this reason:
// the widening is keyed on the resolved filename, so no request path, redirect or
// traversal can carry it onto app.html, where a decryption key lives in the heap.
//
// With WG_AD_ORIGINS unset this is the same string as CSP, so the default deployment
// has one policy and nothing to reason about.
const LANDING_CSP = (() => {
  const origins = config.adOrigins;
  if (!origins.length) return CSP;
  const extra = origins.join(' ');
  // Widened deliberately narrowly. No connect-src: a sponsor slot that can phone home
  // with what it saw is the thing this whole split exists to prevent, and a static
  // creative does not need it. No worker-src, no base-uri, no form-action.
  return CSP_DIRECTIVES.map((d) => {
    if (d.startsWith('script-src ') || d.startsWith('img-src ') || d.startsWith('frame-src ')) {
      return `${d} ${extra}`;
    }
    return d;
  }).join('; ');
})();

// The gate lives at its own path so that an invite link never lands on the document
// that may carry someone else's script. Extensionless, because it is a page people
// see in an address bar and paste into a chat.
//
// /app/share is the manifest's share_target action. The OS sends a POST there and the
// service worker answers it without the request ever reaching this process: see the share
// target comment in public/sw.js. Nothing is added here for that POST, deliberately. The
// method guard below refuses every non-GET, non-HEAD request with 405 before a byte of
// the body is read, so there is no upload route on this server to reach. What this entry
// does is make a GET of that URL land on the gate rather than a 404, for the person who
// pastes the address out of the manifest, and for a browser that follows the action by
// navigation when no worker is installed. app.html references every asset by absolute
// path, so it renders identically one directory down.
const ROUTES = new Map([
  ['/app', 'app.html'],
  ['/app/', 'app.html'],
  ['/app/share', 'app.html'],
]);

// The gate can ask for the camera, to read a QR code off the other device's screen. The
// landing, the legal pages and every static asset cannot, and neither can anything the
// gate embeds: `camera=(self)` grants this origin's own top-level document and no frame
// inside it, and `frame-ancestors 'none'` already stops the gate being the frame.
//
// Deliberately a per-document allowance rather than a site-wide one. The default stays
// `camera=()`, so the only page that can reach a camera is the one with a scan button on
// it, and a bug anywhere else cannot turn one on.
const PERMISSIONS_DEFAULT = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()';
const PERMISSIONS_GATE = 'camera=(self), microphone=(), geolocation=(), payment=(), usb=()';

function securityHeaders(res) {
  // The default. serveStatic() swaps in PERMISSIONS_GATE for app.html alone, the same way
  // it swaps in LANDING_CSP for index.html alone.
  res.setHeader('permissions-policy', PERMISSIONS_DEFAULT);
  res.setHeader('content-security-policy', CSP);
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-content-type-options', 'nosniff');
  // Only meaningful when actually served over TLS, and harmless otherwise: browsers
  // ignore it on plain HTTP. Deliberately without includeSubDomains or preload, both
  // of which are far harder to walk back than they are to switch on.
  if (config.hsts) res.setHeader('strict-transport-security', 'max-age=31536000');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  res.setHeader('cross-origin-resource-policy', 'same-origin');
}

// ---------------------------------------------------------------- compression
//
// The gate ships around 450 KB of hand-written, comment-heavy JavaScript, and every byte
// of it crosses the wire on a first visit. Behind Cloudflare that is invisible, because
// the edge compresses it. Self-hosting is a promise this project makes on its own front
// page, and a self-hosted instance was serving all of it raw: on a phone on a slow link
// that is the difference between a gate that opens and one that looks broken.
//
// zlib ships with Node, so this stays a zero-dependency server. Compression happens once
// per file and is held in memory: the tree is a few hundred kilobytes, it never changes
// while the process runs, and re-gzipping the same bytes for every visitor would trade
// bandwidth for CPU on the smallest box someone might run this on.
const COMPRESSIBLE = /^(text\/|application\/(javascript|manifest\+json|json)|image\/svg)/;
// Below this the framing and the CPU cost outweigh what is saved.
const COMPRESS_MIN_BYTES = 1024;
const gzipCache = new Map();

function gzipFor(target, stat, type) {
  if (!COMPRESSIBLE.test(type) || stat.size < COMPRESS_MIN_BYTES) return null;
  const cached = gzipCache.get(target);
  // Keyed on mtime AND size, so a file replaced by a deploy is recompressed rather than
  // served from a cache of the previous build. rsync preserves neither by default, but
  // relying on only one of the two makes an in-place edit of identical length invisible.
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached.body;
  let body;
  try {
    body = zlib.gzipSync(fs.readFileSync(target), { level: 9 });
  } catch (err) {
    // A file that cannot be read here will fail the same way on the identity path, which
    // reports it properly. Never let compression turn a servable file into an error.
    void err;
    return null;
  }
  // A compressed copy that is not smaller is not worth serving: it costs the client a
  // decompression pass to receive more bytes than the original.
  if (body.length >= stat.size) return null;
  gzipCache.set(target, { mtimeMs: stat.mtimeMs, size: stat.size, body });
  return body;
}

/** Does this client actually want gzip? Never guessed: q=0 is a refusal, not a preference. */
function acceptsGzip(req) {
  const header = req.headers['accept-encoding'];
  if (typeof header !== 'string') return false;
  return header.split(',').some((part) => {
    const [name, ...params] = part.trim().split(';');
    if (name.toLowerCase() !== 'gzip' && name !== '*') return false;
    const q = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
    return !q || parseFloat(q.slice(2)) > 0;
  });
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : (ROUTES.get(pathname) ?? pathname.replace(/^\/+/, ''));
  const target = path.resolve(PUBLIC_DIR, rel);

  // Containment check. path.resolve collapses ".." before we look, so this catches
  // traversal rather than trusting the request shape.
  if (target !== PUBLIC_DIR && !target.startsWith(PUBLIC_DIR + path.sep)) {
    return sendJson(res, 403, { error: 'forbidden' });
  }

  // lstat, not stat, and it is the SAME syscall this path already made: no request pays
  // anything for the difference. path.resolve collapses "..", but it does not resolve
  // symbolic links, and stat() follows them, so a link inside public/ pointing anywhere
  // on the host would have been served through a containment check that never saw the
  // real target. Worse, a link named public/index.html would carry LANDING_CSP, and with
  // it WG_AD_ORIGINS, onto whatever it pointed at: the single route by which an operator
  // knob could reach non-landing content. There is no symlink in public/ today, so this
  // closes a latent gap rather than a live hole.
  fs.lstat(target, (err, stat) => {
    if (err) return sendJson(res, 404, { error: 'not_found' });
    // Refused explicitly rather than left to isFile(). lstat already reports a link as
    // "not a file" so the 404 would happen anyway, but a rule nothing states is a rule
    // the next refactor deletes by accident.
    if (stat.isSymbolicLink()) return sendJson(res, 404, { error: 'not_found' });
    if (!stat.isFile()) return sendJson(res, 404, { error: 'not_found' });
    const type = TYPES.get(path.extname(target).toLowerCase()) ?? 'application/octet-stream';
    // Keyed on the resolved path, so this can only ever be the landing file itself.
    // securityHeaders() already set the strict policy; this replaces it for that one
    // document, and is a no-op string-wise unless WG_AD_ORIGINS is set.
    if (target === path.join(PUBLIC_DIR, 'index.html')) {
      res.setHeader('content-security-policy', LANDING_CSP);
    }
    // Likewise keyed on the resolved path, so the camera allowance follows the gate
    // DOCUMENT and not the URL that reached it: /app, /app/ and /app/share all resolve
    // here, and nothing else can.
    if (target === path.join(PUBLIC_DIR, 'app.html')) {
      res.setHeader('permissions-policy', PERMISSIONS_GATE);
    }
    // Vary is set whether or not this response is compressed. A shared cache that stored
    // the identity copy of app.js without it would then hand that copy to a client that
    // asked for gzip, or the other way round.
    if (COMPRESSIBLE.test(type)) res.setHeader('vary', 'accept-encoding');
    const packed = acceptsGzip(req) ? gzipFor(target, stat, type) : null;
    res.writeHead(200, {
      'content-type': type,
      'content-length': packed ? packed.length : stat.size,
      // The app is small and ephemeral; never let a stale build linger in a cache.
      'cache-control': 'no-store',
      ...(packed ? { 'content-encoding': 'gzip' } : {}),
    });
    // A HEAD answer is the headers and nothing else. Opening a stream Node will only
    // discard is wasted IO and one more descriptor with nothing to close it. The length
    // above is the compressed one when this client asked for gzip, so a HEAD and a GET
    // describe the same response rather than two different ones.
    if (req.method === 'HEAD') return res.end();
    if (packed) {
      if (res.destroyed || res.writableEnded) return undefined;
      return res.end(packed);
    }
    // The client can vanish while the stat is in flight. pipeline() throws rather than
    // reporting when its destination is already gone, so never open the file at all.
    if (res.destroyed || res.writableEnded) return undefined;
    const stream = fs.createReadStream(target);
    // pipeline, not pipe: it tears the read stream down when the destination dies, and it
    // destroys the response on a read fault. With a bare pipe every aborted GET leaks its
    // file descriptor for the life of the process.
    pipeline(stream, res, (pipeErr) => {
      // An aborted download is the normal case here and says nothing about the server.
      // Only a genuine read fault is worth a line on stderr.
      if (pipeErr && pipeErr.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
        process.stderr.write(`static read error: ${pipeErr.message}\n`);
      }
    });
  });
  return undefined;
}

const server = http.createServer((req, res) => {
  securityHeaders(res);
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch (err) {
    // The only way here is a malformed request target, which the 400 already says in
    // full. There is nothing in the message a client or an operator could act on.
    void err;
    return sendJson(res, 400, { error: 'bad_request' });
  }

  if (url.pathname.startsWith('/api/')) {
    // The request and response timeouts used to be lifted HERE, keyed on the pathname
    // alone and therefore before handleApi had validated the room or the token: an
    // unauthenticated caller naming the right path got an unbounded timeout. Not
    // exploitable on this route as it stands (headersTimeout still applies and the route
    // carries no body), but any future body on it would inherit that, so the lift now
    // happens in the /api/events branch of signal.js, after slotFor succeeds.
    return handleApi(req, res, url).catch((err) => {
      // Never leak an internal error to the client, but never swallow it either.
      process.stderr.write(`api error ${url.pathname}: ${err.message}\n`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal' });
    });
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return sendJson(res, 405, { error: 'method_not_allowed' });
  }
  return serveStatic(req, res, url.pathname);
});

// No access logging anywhere: that is a design requirement, not an oversight.
server.headersTimeout = 20_000;
// Bounded for every route. headersTimeout does not cover this: a slowloris sends complete
// headers and then dribbles the body forever. /api/events lifts it per request instead.
server.requestTimeout = 30_000;
server.keepAliveTimeout = 72_000;
// A pipelined flood answered on one socket is unmetered work. Well past what a browser
// will ever put on a single connection, and it only asks the client to reconnect.
server.maxRequestsPerSocket = 200;

const timers = [
  setInterval(() => { sweepRooms(); sweepLimits(); }, config.sweepIntervalMs),
  setInterval(heartbeat, config.heartbeatMs),
];
for (const t of timers) t.unref?.();

const stunSockets = startStun();

// Without this, a port clash surfaces as an unhandled 'error' event and a stack trace.
server.on('error', (err) => {
  process.stderr.write(`warp-gate listen failed on ${config.httpHost}:${config.httpPort}: ${err.message}\n`);
  process.exit(1);
});

server.listen(config.httpPort, config.httpHost, () => {
  process.stdout.write(`warp-gate http ${config.httpHost}:${config.httpPort}\n`);
  if (config.stunEnabled) process.stdout.write(`warp-gate stun udp/${config.stunPort} (${stunSockets.length} socket(s))\n`);
  if (!config.iceServers.length) {
    process.stdout.write('warp-gate WARNING: no WG_STUN_URL configured, clients will gather host candidates only\n');
  }
  if (!config.sourceUrl) {
    process.stdout.write('warp-gate WARNING: no WG_SOURCE_URL set. Warp Gate is AGPL-3.0 and section 13\n');
    process.stdout.write('warp-gate          requires offering the corresponding source to network users.\n');
  }
  // Said at boot, once, loudly. A box that is on and cannot write looks identical from
  // outside to a box nobody has written to: see storeProblem() in suggestions.js for the
  // deployment that spent a release in exactly that state. Not fatal, because refusing to
  // start would take the whole gate down over the one feature that touches disk.
  const storeIssue = suggestionStoreProblem();
  if (storeIssue) {
    process.stdout.write(`warp-gate WARNING: the suggestion box is ON but its store is unusable: ${storeIssue}\n`);
    process.stdout.write('warp-gate          Every submission will be refused and the file will stay empty.\n');
    process.stdout.write('warp-gate          The directory must be writable by the uid this process runs as.\n');
  }
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`warp-gate shutting down (${signal})\n`);
  const notified = destroyAll('shutdown');
  for (const t of timers) clearInterval(t);
  for (const sock of stunSockets) {
    try { sock.close(); } catch (err) { void err; }
  }
  // When anyone was just told 'closed', NOTHING is cut in this tick, server.close()
  // included: a stream whose response destroyAll just ended but has not flushed carries
  // no active request, so closeIdleConnections, closeAllConnections AND close() (which
  // closes idle connections itself since Node 19) all count it idle and cut it, and the
  // frame a backpressured reader has not taken yet dies in this process's write queue.
  // The user is then told nothing, which is the flush window destroyLingerMs exists to
  // give: destroyRoom destroys each stream itself after that window, so the cut here is
  // the backstop for everything else. Capped below the harness/deploy SIGKILL horizon
  // and the force-exit stays the absolute ceiling; with nobody to tell, shutdown is as
  // immediate as it always was.
  const graceMs = notified > 0 ? Math.min(config.destroyLingerMs, 1500) : 0;
  setTimeout(() => {
    server.closeIdleConnections();
    server.closeAllConnections();
    server.close(() => process.exit(0));
  }, graceMs).unref();
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export { server };
