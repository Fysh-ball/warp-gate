// The HTTP surface itself: security headers, static file containment, rate limiting on
// every route, and resource behaviour under abuse.
//
// None of this had any coverage. The signalling suite tests what the API *says*; this
// one tests the transport it says it over, which is where the traversal, header and
// limiter defects live.
//
// Run: node tests/http.test.mjs

import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, summary, startServer, request, delay, makeJoinProof } from './lib/harness.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = 3781;

/**
 * Send a request line exactly as written, with no client-side normalisation.
 *
 * http.request() rewrites the path (it collapses "..", among other things), so driving
 * traversal probes through it tests Node's URL parser and not the server. These go out
 * on a raw socket so the server sees the bytes the attacker sent.
 */
function rawGet(port, target, { method = 'GET', headers = [] } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1');
    let buf = '';
    const timer = setTimeout(() => { sock.destroy(); reject(new Error(`raw ${method} ${target} timed out`)); }, 6000);
    sock.on('connect', () => {
      sock.write(`${method} ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n`
        + headers.map((h) => `${h}\r\n`).join('') + '\r\n');
    });
    sock.setEncoding('utf8');
    sock.on('data', (d) => { buf += d; });
    sock.on('error', (err) => { clearTimeout(timer); reject(err); });
    sock.on('close', () => {
      clearTimeout(timer);
      const split = buf.indexOf('\r\n\r\n');
      const head = split === -1 ? buf : buf.slice(0, split);
      const body = split === -1 ? '' : buf.slice(split + 4);
      const status = Number((/^HTTP\/1\.1 (\d+)/.exec(head) ?? [])[1]);
      resolve({ status, head, body, raw: buf });
    });
  });
}

// ---------------------------------------------------------------- security headers
{
  const srv = await startServer({ WG_HTTP_PORT: String(PORT), WG_STUN_ENABLED: '0' });

  // Headers must be on every answer, not just the happy path. A page served without a
  // CSP because it happened to 404 is a page without a CSP.
  const surfaces = [
    ['the app itself', await request(PORT, 'GET', '/')],
    ['a static asset', await request(PORT, 'GET', '/js/app.js')],
    ['an API response', await request(PORT, 'GET', '/api/config')],
    ['a 404', await request(PORT, 'GET', '/nothing-here.html')],
    ['a refused API route', await request(PORT, 'POST', '/api/create', { roomId: 'nope' })],
  ];

  for (const [what, res] of surfaces) {
    check(`${what} carries a content security policy`,
      typeof res.headers['content-security-policy'] === 'string'
      && res.headers['content-security-policy'].length > 0,
      JSON.stringify(res.headers['content-security-policy']));
    check(`${what} is sent with nosniff`,
      res.headers['x-content-type-options'] === 'nosniff', res.headers['x-content-type-options']);
    check(`${what} sends no referrer`,
      res.headers['referrer-policy'] === 'no-referrer', res.headers['referrer-policy']);
  }

  const csp = surfaces[0][1].headers['content-security-policy'] ?? '';
  const directive = (name) => (new RegExp(`(?:^|;)\\s*${name} ([^;]*)`).exec(csp) ?? [])[1]?.trim();

  check('the policy denies everything by default', directive('default-src') === "'none'", csp);
  check('scripts may only come from this origin', directive('script-src') === "'self'", directive('script-src'));
  check('styles may only come from this origin', directive('style-src') === "'self'", directive('style-src'));
  check('the page may not be framed', directive('frame-ancestors') === "'none'", directive('frame-ancestors'));
  check('no base tag may redirect relative URLs', directive('base-uri') === "'none'", directive('base-uri'));
  check('no form may post anywhere', directive('form-action') === "'none'", directive('form-action'));
  check('the page may only connect back to its own origin',
    directive('connect-src') === "'self'", directive('connect-src'));
  // The whole premise is that nothing leaves the two browsers. A policy that permits any
  // third-party origin is a policy that permits exfiltration.
  check('no external origin appears anywhere in the policy',
    !/https?:\/\//.test(csp) && !/\*/.test(csp), csp);
  check("the policy allows neither 'unsafe-inline' nor 'unsafe-eval'",
    !/unsafe-inline|unsafe-eval/.test(csp), csp);
  // blob: is the one exception and it is same-origin data the page made itself, needed
  // to preview a received image. It must be confined to images.
  check('blob: is permitted for images only',
    /img-src[^;]*blob:/.test(csp) && !/(script|connect|style|font|default)-src[^;]*blob:/.test(csp), csp);

  const isolation = surfaces[0][1].headers;
  check('the page opens in its own browsing context group',
    isolation['cross-origin-opener-policy'] === 'same-origin', isolation['cross-origin-opener-policy']);
  check('other origins cannot read the response',
    isolation['cross-origin-resource-policy'] === 'same-origin', isolation['cross-origin-resource-policy']);
  check('camera, microphone and geolocation are switched off',
    /camera=\(\)/.test(isolation['permissions-policy'] ?? '')
    && /microphone=\(\)/.test(isolation['permissions-policy'] ?? '')
    && /geolocation=\(\)/.test(isolation['permissions-policy'] ?? ''),
    isolation['permissions-policy']);

  // HSTS is only correct where TLS actually terminates in front of this process, so it
  // is off by default. Both halves are asserted: an always-on or always-off
  // implementation fails one of them.
  check('HSTS is NOT sent by default, because this process may be plain HTTP',
    surfaces[0][1].headers['strict-transport-security'] === undefined,
    surfaces[0][1].headers['strict-transport-security']);

  check('nothing identifies the server software',
    surfaces[0][1].headers.server === undefined && surfaces[0][1].headers['x-powered-by'] === undefined,
    JSON.stringify({ server: surfaces[0][1].headers.server, xpb: surfaces[0][1].headers['x-powered-by'] }));

  check('the app is never cached', surfaces[0][1].headers['cache-control'] === 'no-store',
    surfaces[0][1].headers['cache-control']);

  await srv.stop();
}

{
  const P = PORT + 1;
  const srv = await startServer({ WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_HSTS: '1' });
  const res = await request(P, 'GET', '/');
  check('HSTS IS sent once the deployment says TLS terminates in front',
    /max-age=\d+/.test(res.headers['strict-transport-security'] ?? ''),
    res.headers['strict-transport-security']);
  // Both of those are far harder to walk back than they are to switch on.
  check('HSTS is sent without includeSubDomains or preload',
    !/includeSubDomains|preload/i.test(res.headers['strict-transport-security'] ?? ''),
    res.headers['strict-transport-security']);
  await srv.stop();
}

// ---------------------------------------------------------------- static containment
{
  const P = PORT + 2;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_REJECT_PER_WINDOW: '2000', WG_API_PER_WINDOW: '5000',
  });

  // Positive control, and it has to come first. Every assertion below is "the response
  // did not contain server source". That is trivially satisfied by a server that serves
  // nothing at all, so first prove this transport really does fetch files and that the
  // body inspection really does find things in them.
  const good = await rawGet(P, '/js/transfer.js');
  check('the raw-socket client really does fetch a static file',
    good.status === 200 && good.body.includes('sanitizeFilename'),
    `status ${good.status}, ${good.body.length} bytes`);

  // ...and that a known marker in a server file is a thing this test could detect if it
  // ever came back over the wire. Without this, "no marker in the body" is a claim about
  // a marker that might simply not exist.
  const markers = [
    ['server/config.js', 'WG_TRUST_PROXY'],
    ['server/limits.js', 'bootSalt'],
    ['server/rooms.js', 'joinProofHash'],
  ];
  const markersPresent = markers.every(([file, marker]) =>
    fs.readFileSync(path.join(ROOT, file), 'utf8').includes(marker));
  check('the leak markers this test greps for actually exist in the server source',
    markersPresent, JSON.stringify(markers));

  // Two different defences have to hold for any of these to be contained: the WHATWG
  // URL parser collapses real ".." segments before the handler sees them, and the
  // handler re-resolves the path and refuses anything that lands outside public/.
  // These probes test the composition, which is what a user actually gets. Encoded
  // separators are in the list on purpose: "%2f" is NOT a path separator to the URL
  // parser, so it survives normalisation and only the containment check stops it.
  const traversals = [
    '/../server/config.js',
    '/../../server/config.js',
    '/js/../../server/config.js',
    '/%2e%2e/server/config.js',
    '/%2e%2e%2fserver%2fconfig.js',
    '/..%2fserver%2fconfig.js',
    '/..%2f..%2fserver%2fconfig.js',
    '/js%2f..%2f..%2fserver%2fconfig.js',
    '/..%252fserver%252fconfig.js',
    '/....//server/config.js',
    '/%2e%2e/%2e%2e/etc/passwd',
    '/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
    '/../.git/config',
    '/..%2f.git%2fconfig',
    '//etc/passwd',
    '/js/%00../../server/config.js',
    '/js/app.js/../../../server/config.js',
    '/.%2e/server/config.js',
    '/%252e%252e/server/config.js',
    '/\\..\\..\\server\\config.js',
  ];

  let served = null;
  for (const target of traversals) {
    const res = await rawGet(P, target);
    const leaked = markers.some(([, marker]) => res.body.includes(marker)) || res.body.includes('root:x:');
    if (leaked) served = `${target} -> ${res.status}`;
    check(`traversal ${target} is contained`,
      !leaked && (res.status === 403 || res.status === 404 || res.status === 400),
      `status ${res.status}, ${res.body.length} bytes`);
  }
  check('no traversal target returned anything from outside the public directory',
    served === null, String(served));

  // A directory is not a file, and neither is a symlink target outside the tree.
  const dir = await rawGet(P, '/js');
  check('a directory is not served as a file', dir.status === 404, `status ${dir.status}`);
  const dirSlash = await rawGet(P, '/js/');
  check('a directory with a trailing slash is not served either', dirSlash.status === 404, `status ${dirSlash.status}`);

  // Everything under public/ that the app actually ships must still be reachable, or
  // "contained" would be indistinguishable from "broken".
  const shipped = fs.readdirSync(PUBLIC_DIR).filter((f) => f.endsWith('.html'));
  check('the public directory has html pages to check', shipped.length > 0, String(shipped.length));
  let allServed = true;
  const missing = [];
  for (const page of shipped) {
    const res = await rawGet(P, `/${page}`);
    if (res.status !== 200) { allServed = false; missing.push(`${page}:${res.status}`); }
  }
  check('every shipped page is still served after the containment check',
    allServed, missing.join(','));

  // Writes to the static tree are refused before anything is opened.
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
    const res = await rawGet(P, '/index.html', { method });
    check(`${method} on a static path is refused`, res.status === 405, `status ${res.status}`);
  }
  const head = await rawGet(P, '/index.html', { method: 'HEAD' });
  check('HEAD returns headers and no body', head.status === 200 && head.body === '', `${head.status}, ${head.body.length} bytes`);

  await srv.stop();
}

// ---------------------------------------------------------------- rate limits
{
  // Five routes used to be entirely unmetered: /api/health, /api/config and /api/room
  // were free reads, and /api/relay and /api/bye would parse a full body from an
  // unauthenticated caller as often as asked.
  const P = PORT + 3;
  const LIMIT = 4;

  const publicGets = [
    ['/api/health', '/api/health'],
    ['/api/config', '/api/config'],
    ['/api/room', '/api/room?room=RMQM0001&token=x'],
  ];

  // Each of the three has its own bucket, so each gets its own server: sharing one would
  // let the first route's traffic close the others and prove nothing about them.
  for (const [label, target] of publicGets) {
    const srv = await startServer({
      WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
      WG_PUBLIC_GET_PER_WINDOW: String(LIMIT), WG_API_WINDOW_MS: '60000',
      WG_API_PER_WINDOW: '5000', WG_REJECT_PER_WINDOW: '5000',
    });
    const statuses = [];
    for (let i = 0; i < LIMIT + 6; i += 1) statuses.push((await request(P, 'GET', target)).status);
    const limited = statuses.filter((s) => s === 429).length;
    check(`${label} is rate limited`, limited > 0, `statuses ${statuses.join(',')}`);
    check(`${label} serves the first requests before limiting`,
      statuses[0] !== 429, `statuses ${statuses.join(',')}`);
    await srv.stop();
  }

  // The control for the three above. With a generous limit the same loop must NOT be
  // refused: otherwise a server that 429s everything would satisfy every check above.
  {
    const srv = await startServer({
      WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
      WG_PUBLIC_GET_PER_WINDOW: '500', WG_API_PER_WINDOW: '5000', WG_REJECT_PER_WINDOW: '5000',
    });
    const statuses = [];
    for (let i = 0; i < LIMIT + 6; i += 1) statuses.push((await request(P, 'GET', '/api/health')).status);
    check('with a generous limit the same loop is not refused at all',
      statuses.every((s) => s === 200), `statuses ${statuses.join(',')}`);
    await srv.stop();
  }
}

{
  // /api/relay and /api/bye sit behind the all-routes backstop rather than a limiter of
  // their own. Spend the backstop on cheap reads, then show that the two body-parsing
  // routes are refused as well.
  const P = PORT + 4;
  const spend = async (port, n) => {
    for (let i = 0; i < n; i += 1) await request(port, 'GET', '/api/config');
  };

  const tight = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_API_PER_WINDOW: '18', WG_API_WINDOW_MS: '60000',
    WG_PUBLIC_GET_PER_WINDOW: '5000', WG_REJECT_PER_WINDOW: '5000',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
  });
  await spend(P, 30);
  const relayLimited = await request(P, 'POST', '/api/relay', {
    roomId: 'RMTX0001', token: 'x', envelope: { n: 'a', c: 'b' },
  });
  const byeLimited = await request(P, 'POST', '/api/bye', { roomId: 'RMTX0001', token: 'x' });
  check('/api/relay is refused once the all-routes backstop is spent',
    relayLimited.status === 429 && relayLimited.json?.error === 'rate_limited',
    `${relayLimited.status} ${relayLimited.text}`);
  check('/api/bye is refused once the all-routes backstop is spent',
    byeLimited.status === 429 && byeLimited.json?.error === 'rate_limited',
    `${byeLimited.status} ${byeLimited.text}`);
  await tight.stop();

  // Control: with the backstop generous, the identical calls reach the route and are
  // answered on their own merits. Without this, "429" above could just be the server's
  // only answer to anything.
  const loose = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_API_PER_WINDOW: '5000', WG_PUBLIC_GET_PER_WINDOW: '5000', WG_REJECT_PER_WINDOW: '5000',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
  });
  await spend(P, 30);
  const relayOpen = await request(P, 'POST', '/api/relay', {
    roomId: 'RMTX0001', token: 'x', envelope: { n: 'a', c: 'b' },
  });
  const byeOpen = await request(P, 'POST', '/api/bye', { roomId: 'RMTX0001', token: 'x' });
  check('the same relay call is NOT refused when the backstop is generous',
    relayOpen.status === 404, `${relayOpen.status} ${relayOpen.text}`);
  check('the same bye call is NOT refused when the backstop is generous',
    byeOpen.status === 404, `${byeOpen.status} ${byeOpen.text}`);

  await loose.stop();
}

{
  // A caller that keeps being refused is probing. That budget is separate and far
  // tighter than the others, and it is what stops the 404/403 split on /api/room being
  // a free room-existence oracle.
  const P = PORT + 8;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_REJECT_PER_WINDOW: '5', WG_API_WINDOW_MS: '60000',
    WG_API_PER_WINDOW: '5000', WG_PUBLIC_GET_PER_WINDOW: '5000',
  });
  const rejects = [];
  for (let i = 0; i < 14; i += 1) {
    rejects.push((await request(P, 'GET', `/api/room?room=RJCT000${i % 10}&token=x`)).status);
  }
  check('repeated refusals exhaust a budget of their own',
    rejects.includes(429), `statuses ${rejects.join(',')}`);
  check('the first few refusals are answered honestly before the budget bites',
    rejects[0] === 404, `statuses ${rejects.join(',')}`);
  await srv.stop();

  // Control, on its own server because the budget above is now spent for this address:
  // a caller who is never refused does not touch that budget at all, so the tight limit
  // cannot lock out an ordinary client.
  const clean = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_REJECT_PER_WINDOW: '5', WG_API_WINDOW_MS: '60000',
    WG_API_PER_WINDOW: '5000', WG_PUBLIC_GET_PER_WINDOW: '5000',
  });
  const cleanStatuses = [];
  for (let i = 0; i < 14; i += 1) cleanStatuses.push((await request(P, 'GET', '/api/config')).status);
  check('a caller that is never refused does not spend the reject budget',
    cleanStatuses.every((s) => s === 200), `statuses ${cleanStatuses.join(',')}`);
  await clean.stop();
}

{
  // Concurrent SSE streams are a gauge, not a counter: four per key, and a fifth must
  // be refused rather than quietly accepted.
  const P = PORT + 5;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_STREAMS_PER_KEY: '2',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
  });
  // One stream per room, four rooms, all from the same address. Re-opening a stream for
  // the same slot would not do: attaching a second one ends the first, so the gauge
  // oscillates between one and two and never reaches the ceiling.
  const rooms = ['STRM0001', 'STRM0002', 'STRM0003', 'STRM0004'];
  const opened = [];
  const statuses = [];
  for (const id of rooms) {
    const created = await request(P, 'POST', '/api/create', {
      roomId: id, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
    });
    const res = await new Promise((resolve) => {
      const req = http.get({ host: '127.0.0.1', port: P, path: `/api/events?room=${id}&token=${created.json.token}` }, resolve);
      req.on('error', () => resolve({ statusCode: 0 }));
      opened.push(req);
    });
    statuses.push(res.statusCode);
  }
  check('the first streams up to the per-key ceiling are accepted',
    statuses[0] === 200 && statuses[1] === 200, `statuses ${statuses.join(',')}`);
  check('concurrent streams past the per-key ceiling are refused',
    statuses.filter((s) => s === 200).length === 2 && statuses.filter((s) => s === 429).length === 2,
    `statuses ${statuses.join(',')}`);

  // The gauge must come back down, or a client that reloads twice is locked out for good.
  opened[0].destroy();
  await delay(400);
  const reopened = await new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: P, path: `/api/events?room=${rooms[2]}&token=x` }, resolve);
    req.on('error', () => resolve({ statusCode: 0 }));
    opened.push(req);
  });
  // 403 is the right answer here (the token is wrong); what matters is that it is not
  // 429, which would mean the closed stream never gave its slot back.
  check('closing a stream returns its slot to the per-key gauge',
    reopened.statusCode !== 429, `status ${reopened.statusCode}`);

  for (const req of opened) { try { req.destroy(); } catch (err) { void err; } }
  await srv.stop();
}

// ---------------------------------------------------------------- descriptor leaks
{
  // With a bare pipe, every aborted download leaks its file descriptor for the life of
  // the process: a few thousand cancelled loads and the server can no longer open a
  // file or accept a connection. The fix is pipeline(), which tears the read stream
  // down when its destination dies.
  const P = PORT + 6;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_PUBLIC_GET_PER_WINDOW: '50000', WG_API_PER_WINDOW: '50000',
  });
  const pid = srv.child.pid;

  const classify = (procPid) => {
    const out = { file: 0, socket: 0, total: 0 };
    let entries;
    try { entries = fs.readdirSync(`/proc/${procPid}/fd`); } catch (err) { return { ...out, unreadable: err.message }; }
    for (const fd of entries) {
      let target;
      try { target = fs.readlinkSync(`/proc/${procPid}/fd/${fd}`); } catch (err) { void err; continue; }
      out.total += 1;
      if (target.startsWith(PUBLIC_DIR + path.sep)) out.file += 1;
      else if (target.startsWith('socket:')) out.socket += 1;
    }
    return out;
  };

  // Soundness control for the classifier itself. A counter that never matches anything
  // reports "no leaked file descriptors" forever, whether or not there are any. Point it
  // at a descriptor this process is holding open on a file in public/ and require it to
  // see exactly that one.
  const ownFd = fs.openSync(path.join(PUBLIC_DIR, 'js', 'app.js'), 'r');
  const ownBefore = classify(process.pid).file;
  fs.closeSync(ownFd);
  const ownAfter = classify(process.pid).file;
  check('the descriptor classifier can see a file descriptor on a public/ file',
    ownBefore >= 1 && ownAfter === ownBefore - 1, `${ownBefore} held, ${ownAfter} after closing`);

  const baseline = classify(pid);
  check('the server process descriptor table is readable',
    baseline.unreadable === undefined && baseline.total > 0, JSON.stringify(baseline));

  // Second control: the counter must respond to real server-side growth, or "no growth"
  // below is the answer it would give even if it were measuring nothing.
  const held = [];
  for (let i = 0; i < 30; i += 1) {
    const s = net.connect(P, '127.0.0.1');
    s.on('error', () => {});
    await new Promise((r) => s.once('connect', r));
    s.pause();
    s.write('GET /js/session.js HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n');
    held.push(s);
  }
  await delay(500);
  const whileHeld = classify(pid);
  check('the descriptor count rises while 30 downloads are in flight',
    whileHeld.total >= baseline.total + 25, `${baseline.total} -> ${whileHeld.total}`);

  for (const s of held) s.destroy();
  await delay(900);
  const afterHeld = classify(pid);
  check('and falls back once those connections close',
    afterHeld.total <= baseline.total + 2, `${baseline.total} -> ${whileHeld.total} -> ${afterHeld.total}`);

  // The actual test: abort mid-download, many times over.
  const ABORTS = 600;
  for (let round = 0; round < 6; round += 1) {
    const reqs = [];
    for (let i = 0; i < ABORTS / 6; i += 1) {
      const req = http.get({ host: '127.0.0.1', port: P, path: '/js/session.js' }, (res) => res.destroy());
      req.on('error', () => {});
      reqs.push(req);
    }
    await delay(40);
    for (const req of reqs) { try { req.destroy(); } catch (err) { void err; } }
    await delay(80);
  }
  // Drain, with a deadline. A descriptor still closing a moment after the last abort is
  // a transient, not a leak; a leak never drains. This waits for the transients and
  // still fails on anything that stays, so it neither flakes nor forgives: the
  // bare-pipe build leaves hundreds here and none of them ever go away.
  let after = classify(pid);
  const drainDeadline = Date.now() + 8000;
  while (Date.now() < drainDeadline && (after.file > 0 || after.total > baseline.total + 4)) {
    await delay(250);
    after = classify(pid);
  }

  check(`${ABORTS} aborted downloads leak no file descriptors`,
    after.file === 0, `${after.file} descriptors still open on public/ files after an 8s drain window`);
  check(`${ABORTS} aborted downloads leak no descriptors of any kind`,
    after.total <= baseline.total + 4, `${baseline.total} -> ${after.total}`);

  // A leaked descriptor eventually stops the server working at all, so prove it still does.
  const stillAlive = await request(P, 'GET', '/js/session.js');
  check('the server still serves files after the abort storm',
    stillAlive.status === 200 && stillAlive.text.length > 0, `status ${stillAlive.status}`);
  check('the abort storm produced no stderr noise',
    srv.stderr() === '', srv.stderr().slice(0, 300));

  await srv.stop();
}

// ---------------------------------------------------------------- malformed requests
{
  const P = PORT + 7;
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_REJECT_PER_WINDOW: '2000', WG_API_PER_WINDOW: '5000', WG_PUBLIC_GET_PER_WINDOW: '2000',
  });

  const badTarget = await rawGet(P, 'http://[::1');
  check('a malformed request target is answered, not crashed on',
    badTarget.status === 400 || badTarget.status === 404, `status ${badTarget.status}`);

  const unknownApi = await request(P, 'GET', '/api/does-not-exist');
  check('an unknown API route is 404 not_found',
    unknownApi.status === 404 && unknownApi.json?.error === 'not_found', unknownApi.text);

  const wrongMethod = await request(P, 'GET', '/api/create');
  check('the right route with the wrong method is not silently accepted',
    wrongMethod.status === 404, `${wrongMethod.status} ${wrongMethod.text}`);

  const notJson = await new Promise((resolve, reject) => {
    const payload = Buffer.from('{this is not json');
    const req = http.request({ host: '127.0.0.1', port: P, method: 'POST', path: '/api/create',
      headers: { 'content-type': 'application/json', 'content-length': payload.length } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(payload);
  });
  check('a body that is not JSON is refused with bad_body',
    notJson.status === 400 && /bad_body/.test(notJson.text), `${notJson.status} ${notJson.text}`);

  // The small-body cap exists so an unauthenticated caller cannot force a large parse on
  // the routes that only ever carry a room id and a token.
  const oversized = await request(P, 'POST', '/api/create', {
    roomId: 'QVER0001', sessionMinutes: 10, pad: 'x'.repeat(8000),
  });
  check('an oversized create body is refused rather than parsed',
    oversized.status === 413 || oversized.status === 400, `${oversized.status} ${oversized.text}`);

  check('none of the malformed input reached stderr', srv.stderr() === '', srv.stderr().slice(0, 300));
  await srv.stop();
}

process.exit(summary('http surface') ? 0 : 1);
