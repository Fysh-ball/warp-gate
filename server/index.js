// Warp Gate signalling process.
//
// One process: an HTTP endpoint, a static file server, an in-memory room map and a
// STUN binding responder. No database, no disk writes, no request logging.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
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
  "img-src 'self'",
  "connect-src 'self'",
  "font-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

function securityHeaders(res) {
  res.setHeader('content-security-policy', CSP);
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-content-type-options', 'nosniff');
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
    const stream = fs.createReadStream(target);
    stream.on('error', (streamErr) => {
      res.wgStaticError = streamErr.message;
      res.destroy();
    });
    stream.pipe(res);
  });
  return undefined;
}

const server = http.createServer((req, res) => {
  securityHeaders(res);
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch (err) {
    res.wgUrlError = err.message;
    return sendJson(res, 400, { error: 'bad_request' });
  }

  if (url.pathname.startsWith('/api/')) {
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
server.requestTimeout = 0; // SSE streams are long lived by definition.
server.keepAliveTimeout = 72_000;

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
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export { server };
