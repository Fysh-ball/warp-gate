// Warp Gate signalling process.
//
// One process: an HTTP endpoint, a static file server, an in-memory room map and a
// STUN binding responder. No database, no disk writes, no request logging.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { handleApi, sendJson } from './signal.js';
import { sweep as sweepRooms, heartbeat, destroyAll } from './rooms.js';
import { sweep as sweepLimits } from './limits.js';
import { startStun } from './stun.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(here, '..', 'public');

const TYPES = new Map(Object.entries({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.ico': 'image/x-icon',
}));

// Strict by design. No external origins at all: a page that can reach a third party
// is a page that can leak. 'wasm-unsafe-eval' is absent because nothing here uses WASM.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  // blob: is needed to preview a received image inline. It is same-origin data the
  // page created itself, not a remote fetch.
  "img-src 'self' blob:",
  "connect-src 'self'",
  "font-src 'self'",
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
].join('; ');

function securityHeaders(res) {
  res.setHeader('content-security-policy', CSP);
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-content-type-options', 'nosniff');
  // Only meaningful when actually served over TLS, and harmless otherwise: browsers
  // ignore it on plain HTTP. Deliberately without includeSubDomains or preload, both
  // of which are far harder to walk back than they are to switch on.
  if (config.hsts) res.setHeader('strict-transport-security', 'max-age=31536000');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  res.setHeader('cross-origin-resource-policy', 'same-origin');
  res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const target = path.resolve(PUBLIC_DIR, rel);

  // Containment check. path.resolve collapses ".." before we look, so this catches
  // traversal rather than trusting the request shape.
  if (target !== PUBLIC_DIR && !target.startsWith(PUBLIC_DIR + path.sep)) {
    return sendJson(res, 403, { error: 'forbidden' });
  }

  fs.stat(target, (err, stat) => {
    if (err || !stat.isFile()) return sendJson(res, 404, { error: 'not_found' });
    const type = TYPES.get(path.extname(target).toLowerCase()) ?? 'application/octet-stream';
    res.writeHead(200, {
      'content-type': type,
      'content-length': stat.size,
      // The app is small and ephemeral; never let a stale build linger in a cache.
      'cache-control': 'no-store',
    });
    // A HEAD answer is the headers and nothing else. Opening a stream Node will only
    // discard is wasted IO and one more descriptor with nothing to close it.
    if (req.method === 'HEAD') return res.end();
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
    // SSE streams are long lived by definition, so the request timeout has to be lifted
    // for them. Only for them: every other route must stay bounded.
    if (url.pathname === '/api/events') {
      req.setTimeout(0);
      res.setTimeout(0);
    }
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
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`warp-gate shutting down (${signal})\n`);
  destroyAll('shutdown');
  for (const t of timers) clearInterval(t);
  for (const sock of stunSockets) {
    try { sock.close(); } catch (err) { void err; }
  }
  // server.close() waits for every open connection, so an idle keep-alive socket alone
  // would hold the process until the force-exit timer. The rooms are already gone.
  server.closeIdleConnections();
  server.closeAllConnections();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export { server };
