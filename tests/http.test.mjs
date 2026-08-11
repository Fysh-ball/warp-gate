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
import { spawn } from 'node:child_process';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, summary, startServer, request, delay, makeJoinProof, freePort } from './lib/harness.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = await freePort(3781);
// Every server this suite spawns beyond the first sits in a private band well clear of the
// other suites. The offsets used to land on 3785 to 3793, which other suites in this repo
// also use: a run could fail with EADDRINUSE for a reason that had nothing to do with the
// code under test, and an EADDRINUSE reads exactly like a server that refused to boot.
const BAND = 100;

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
    ['the landing', await request(PORT, 'GET', '/')],
    ['the gate document', await request(PORT, 'GET', '/app')],
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
  // blob: is the one exception and it is same-origin data the page made itself, needed to
  // preview a received image and, since inline players landed, a received video or audio
  // file. It must be confined to those two directives: enumerated positively rather than
  // by listing the directives it must NOT appear in, because that form passes for any
  // directive nobody thought to add to the deny list, which is how media-src would have
  // slipped in unreviewed.
  const blobDirectives = csp.split(';').map((d) => d.trim())
    .filter((d) => /(^|\s)blob:/.test(d)).map((d) => d.split(/\s+/)[0]).sort();
  check('blob: is permitted for inline images and media only',
    JSON.stringify(blobDirectives) === JSON.stringify(['img-src', 'media-src']),
    `${blobDirectives.join(' ')} || ${csp}`);

  const isolation = surfaces[0][1].headers;
  check('the page opens in its own browsing context group',
    isolation['cross-origin-opener-policy'] === 'same-origin', isolation['cross-origin-opener-policy']);
  check('other origins cannot read the response',
    isolation['cross-origin-resource-policy'] === 'same-origin', isolation['cross-origin-resource-policy']);
  check('camera, microphone and geolocation are switched off on the landing',
    /camera=\(\)/.test(isolation['permissions-policy'] ?? '')
    && /microphone=\(\)/.test(isolation['permissions-policy'] ?? '')
    && /geolocation=\(\)/.test(isolation['permissions-policy'] ?? ''),
    isolation['permissions-policy']);

  // The gate, and ONLY the gate, may reach a camera: it reads a QR code off the other
  // device's screen. Asserted as a difference rather than as one page's header, because
  // the risk here is not "the gate cannot scan", it is "everything can".
  {
    const gatePP = surfaces[1][1].headers['permissions-policy'] ?? '';
    check('the gate document may use this origin\'s camera',
      /camera=\(self\)/.test(gatePP), gatePP);
    check('and nothing else on the site may: not the landing, not an asset, not a 404',
      [0, 2, 4, 5].every((i) => /camera=\(\)/.test(surfaces[i][1].headers['permissions-policy'] ?? '')),
      surfaces.map(([w, r]) => `${w}: ${r.headers['permissions-policy']}`).join(' | '));
    check('the camera allowance does not drag microphone or geolocation along with it',
      /microphone=\(\)/.test(gatePP) && /geolocation=\(\)/.test(gatePP), gatePP);
    // A frame inside the gate must not inherit the grant. `(self)` is the origin's own
    // documents only, and frame-ancestors already stops the gate being framed; this
    // asserts the half that is this header's job.
    check('and it is not granted to any other origin',
      !/camera=\([^)]*(\*|https?:)/.test(gatePP), gatePP);
  }

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

  // The gate is reachable at its own path, and it is the gate document rather than a
  // redirect back to the landing or a 404 that a test could mistake for either.
  const gate = await request(PORT, 'GET', '/app');
  check('the gate is served at /app', gate.status === 200, `http ${gate.status}`);
  check('and /app is the gate document, not the landing',
    /id="screen-connected"/.test(gate.text) && !/class="lp-hero"/.test(gate.text),
    `${gate.text.length} bytes`);
  const front = await request(PORT, 'GET', '/');
  check('while / is the landing, and carries no gate machinery',
    /class="lp-hero"/.test(front.text)
    && !/id="screen-connected"/.test(front.text) && !/id="create-btn"/.test(front.text),
    `${front.text.length} bytes`);
  // With no sponsor configured the two documents get the SAME policy. If these ever
  // differ by default, something has widened the landing without being asked to.
  check('with no sponsor configured both documents get an identical policy',
    front.headers['content-security-policy'] === gate.headers['content-security-policy'],
    `${front.headers['content-security-policy']}\nvs\n${gate.headers['content-security-policy']}`);

  await srv.stop();
}

// ---------------------------------------------------------------- the sponsor knob
//
// WG_AD_ORIGINS may widen the landing's policy and MUST NOT widen the gate's. That is
// the entire security argument for serving them as two documents, so it is asserted
// against a server that actually has the variable set: a check run only with it unset
// would pass on a build where the two documents share one policy again.
{
  const P = await freePort(PORT + BAND + 2);
  const ADS = 'https://ads.example.net';
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_AD_ORIGINS: ADS,
  });

  const landingCsp = (await request(P, 'GET', '/')).headers['content-security-policy'] ?? '';
  const gateCsp = (await request(P, 'GET', '/app')).headers['content-security-policy'] ?? '';
  const fileCsp = (await request(P, 'GET', '/app.html')).headers['content-security-policy'] ?? '';
  const assetCsp = (await request(P, 'GET', '/js/app.js')).headers['content-security-policy'] ?? '';

  // The positive arm. Without this the three negatives below would all pass on a build
  // where the variable does nothing at all.
  check('a configured sponsor origin reaches the landing',
    landingCsp.includes(ADS), landingCsp);
  check('and it never reaches the gate at /app', !gateCsp.includes(ADS), gateCsp);
  check('nor the same file requested by name, so no path trick carries it over',
    !fileCsp.includes(ADS), fileCsp);
  check('nor any other asset on the origin', !assetCsp.includes(ADS), assetCsp);

  // Widened narrowly and deliberately. A sponsor that can open its own connections is
  // a sponsor that can report what it saw, which is the thing the split exists to stop.
  const dir = (name, csp) => (new RegExp(`(?:^|;)\\s*${name} ([^;]*)`).exec(csp) ?? [])[1]?.trim();
  check('the widening covers scripts, images and frames only',
    dir('script-src', landingCsp).includes(ADS)
    && dir('img-src', landingCsp).includes(ADS)
    && dir('frame-src', landingCsp).includes(ADS),
    landingCsp);
  check('and never connect-src, so a sponsor cannot phone home from the landing',
    dir('connect-src', landingCsp) === "'self'", dir('connect-src', landingCsp));
  check('the landing still denies everything by default',
    dir('default-src', landingCsp) === "'none'", landingCsp);
  check("and still allows neither 'unsafe-inline' nor 'unsafe-eval'",
    !/unsafe-inline|unsafe-eval/.test(landingCsp), landingCsp);

  await srv.stop();
}

{
  const P = await freePort(PORT + BAND + 1);
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
  const P = await freePort(PORT + BAND + 2);
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
  const P = await freePort(PORT + BAND + 3);
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
  const P = await freePort(PORT + BAND + 4);
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
  const P = await freePort(PORT + BAND + 8);
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
  const P = await freePort(PORT + BAND + 5);
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0', WG_STREAMS_PER_KEY: '1',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
  });
  // The gauge is keyed on the authenticated SEAT (room/slot), never on the address:
  // behind one NAT hop every client shares an address, and the old per-address key let
  // four strangers' streams lock out a fifth. Everything below runs from one address,
  // ceiling 1, so: a second concurrent stream on the SAME seat is refused, and a stream
  // on a DIFFERENT seat is untouched by it. That second half is the collapse the audit
  // measured live, so it is the assertion that matters.
  const opened = [];
  const openRaw = (roomId, token) => new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: P, path: `/api/events?room=${roomId}&token=${token}` }, resolve);
    req.on('error', () => resolve({ statusCode: 0 }));
    opened.push(req);
  });
  const seatA = await request(P, 'POST', '/api/create', {
    roomId: 'STRM0001', sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
  });
  const seatB = await request(P, 'POST', '/api/create', {
    roomId: 'STRM0002', sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
  });
  const first = await openRaw('STRM0001', seatA.json.token);
  const second = await openRaw('STRM0001', seatA.json.token);
  const bystander = await openRaw('STRM0002', seatB.json.token);
  check('the first stream on a seat is accepted',
    first.statusCode === 200, `status ${first.statusCode}`);
  check('a second concurrent stream on the SAME seat is past the per-seat ceiling and refused',
    second.statusCode === 429, `status ${second.statusCode}`);
  check('a stream on a DIFFERENT seat from the same address is untouched by that ceiling',
    bystander.statusCode === 200, `status ${bystander.statusCode}`);

  // The gauge must come back down, or a client that reloads twice is locked out for good.
  // Proven with the seat's own valid token: a 200 here can only mean the closed stream
  // gave its slot back, where the old wrong-token probe was answered 403 before the
  // gauge was ever consulted.
  opened[0].destroy();
  await delay(400);
  const reopened = await openRaw('STRM0001', seatA.json.token);
  check('closing a stream returns its slot to the per-seat gauge',
    reopened.statusCode === 200, `status ${reopened.statusCode}`);

  for (const req of opened) { try { req.destroy(); } catch (err) { void err; } }
  await srv.stop();
}

// ---------------------------------------------------------------- descriptor leaks
{
  // With a bare pipe, every aborted download leaks its file descriptor for the life of
  // the process: a few thousand cancelled loads and the server can no longer open a
  // file or accept a connection. The fix is pipeline(), which tears the read stream
  // down when its destination dies.
  const P = await freePort(PORT + BAND + 6);
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
  const P = await freePort(PORT + BAND + 7);
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

// ---------------------------------------------------------------- compression
//
// Behind Cloudflare the edge compresses everything and this is invisible. The project
// tells people to run their own instance, and a self-hosted one was shipping the whole
// hand-written, comment-heavy front end raw. These checks are about the server, so they
// are made against the server, not against the deployment in front of it.
{
  const P = await freePort(PORT + BAND + 8);
  const srv = await startServer({ WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0' });

  // The shared helper decodes the body as utf8, which turns a gzip stream into mojibake.
  // Raw bytes, so the answer can actually be decompressed and compared.
  const raw = (pathname, headers = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: P, method: 'GET', path: pathname, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.setTimeout(6000, () => req.destroy(new Error('request timeout')));
    req.end();
  });

  const plain = await raw('/js/app.js');
  const packed = await raw('/js/app.js', { 'accept-encoding': 'gzip' });
  check('a client that does not ask for gzip is not sent gzip',
    plain.headers['content-encoding'] === undefined, String(plain.headers['content-encoding']));
  check('a client that asks for gzip gets it', packed.headers['content-encoding'] === 'gzip',
    String(packed.headers['content-encoding']));
  check('the compressed answer is substantially smaller', packed.body.length * 2 < plain.body.length,
    `${plain.body.length} raw, ${packed.body.length} gzipped`);
  check('and it decompresses to exactly the same bytes',
    zlib.gunzipSync(packed.body).equals(plain.body),
    `${zlib.gunzipSync(packed.body).length} vs ${plain.body.length}`);
  check('content-length describes the body that was actually sent',
    Number(packed.headers['content-length']) === packed.body.length,
    `${packed.headers['content-length']} declared, ${packed.body.length} received`);
  check('a compressible answer carries vary: accept-encoding, so a shared cache cannot mix the two',
    /accept-encoding/i.test(String(packed.headers.vary)) && /accept-encoding/i.test(String(plain.headers.vary)),
    `${plain.headers.vary} / ${packed.headers.vary}`);

  const refused = await raw('/js/app.js', { 'accept-encoding': 'gzip;q=0' });
  check('q=0 is read as a refusal, not as a preference',
    refused.headers['content-encoding'] === undefined, String(refused.headers['content-encoding']));

  const png = await raw('/icons/icon-192.png', { 'accept-encoding': 'gzip' });
  check('an already-compressed image is not gzipped again',
    png.headers['content-encoding'] === undefined && png.body.length > 0,
    `${png.headers['content-encoding']} ${png.body.length} bytes`);

  const head = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: P, method: 'HEAD', path: '/js/app.js', headers: { 'accept-encoding': 'gzip' } },
      (res) => { res.resume(); res.on('end', () => resolve({ headers: res.headers })); });
    req.on('error', reject);
    req.end();
  });
  check('HEAD describes the same response a GET would return',
    head.headers['content-encoding'] === 'gzip'
    && Number(head.headers['content-length']) === packed.body.length,
    `${head.headers['content-encoding']} ${head.headers['content-length']} vs ${packed.body.length}`);

  // CONTROL. Every check above compares two answers from the same server, so it would
  // still pass if the comparison itself were vacuous. This asks the same questions of a
  // pair that is known to differ, and of a body that is known not to be gzip.
  check('CONTROL: the byte-for-byte comparison can fail',
    !zlib.gunzipSync(packed.body).equals(Buffer.concat([plain.body, Buffer.from('x')])),
    'a body with one extra byte was not accepted as identical');
  let sawThrow = false;
  try { zlib.gunzipSync(plain.body); } catch (err) { sawThrow = true; void err; }
  check('CONTROL: the identity answer really is not gzip', sawThrow,
    'gunzip of the uncompressed body threw, as it must');

  await srv.stop();
}

// --------------------------------------------------- a bad config refuses to boot
//
// The failure these replace was asynchronous and unattributable. WG_AD_ORIGINS is
// interpolated into a header that is only ever set inside an fs.stat callback, so a CRLF
// in it made res.setHeader throw ERR_INVALID_CHAR with nothing on the stack to catch it
// (there is no process.on('uncaughtException') anywhere in server/), and the process died
// on the first GET /. The operator's evidence was a blank page.
//
// startServer() is deliberately not used here: it waits for a listening banner, and the
// whole point is that there is never going to be one.
function bootOutcome(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'server', 'index.js')], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => { err += d.toString(); });
    // Not unref'd: a timer that lets the process exit while this is still open would
    // report "it exited" without having waited, which is the same green output either way.
    const kill = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) { void e; } }, 6000);
    child.on('exit', (code) => { clearTimeout(kill); resolve({ code, out, err }); });
    child.on('error', (e) => { clearTimeout(kill); resolve({ code: null, out, err: `${err}${e.message}` }); });
  });
}

{
  const P = await freePort(PORT + BAND + 9);
  const base = { WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0' };

  // CONTROL FIRST. Every assertion below is "the process exited 1", which a server that
  // cannot start for any reason at all satisfies. Prove the same environment minus the
  // bad value starts and listens.
  const okBoot = await startServer(base);
  check('CONTROL: this environment starts a server when nothing in it is malformed',
    /warp-gate http/.test(okBoot.stdout()), JSON.stringify(okBoot.stdout().slice(0, 200)));
  await okBoot.stop();

  // Each of these produced a working-looking boot and a wrong number. Measured, all of
  // them, against the parseInt this replaced: '1e9' parsed as 1, '0x1F' as 0, '10x' as 10.
  const badInts = [
    ['WG_SUGGESTIONS_MAX_BYTES', '1e9', 'a one BYTE cap, so the store 507s from the first write'],
    ['WG_SUGGESTIONS_MAX_BYTES', '0x1F', 'zero'],
    ['WG_MAX_ROOMS', '10x', 'ten'],
    ['WG_MAX_ROOMS', '2,000', 'two'],
    ['WG_HEARTBEAT_MS', ' ', 'silently the default'],
  ];
  for (const [name, value, wasInterpretedAs] of badInts) {
    // A blank value is the one case that is legitimately the default rather than an
    // error: an operator who writes FOO= in a compose file means "leave it alone".
    const wantExit = value.trim() === '' ? 0 : 1;
    if (wantExit === 1) {
      const outcome = await bootOutcome({ ...base, [name]: value });
      check(`${name}=${value} refuses to boot rather than becoming ${wasInterpretedAs}`,
        outcome.code === 1 && outcome.err.includes(name),
        `exit ${outcome.code}: ${JSON.stringify(outcome.err.slice(0, 200))}`);
      check(`...and says so before listening, not at first request`,
        !/warp-gate http/.test(outcome.out), JSON.stringify(outcome.out.slice(0, 200)));
    } else {
      // This row used to emit ZERO checks: it walked the whole boot and asserted
      // nothing, so a server that started refusing whitespace would never be seen here.
      const srv = await startServer({ ...base, [name]: value });
      check(`${name}=${JSON.stringify(value)} boots as ${wasInterpretedAs} rather than refusing`,
        /warp-gate http/.test(srv.stdout()), JSON.stringify(srv.stdout().slice(0, 200)));
      await srv.stop();
    }
  }

  // Blank is not malformed. Without this the guard could be "refuse everything", which
  // would also pass every check above.
  const blank = await startServer({ ...base, WG_HEARTBEAT_MS: '' });
  check('CONTROL: an empty value is the default, not an error',
    /warp-gate http/.test(blank.stdout()), JSON.stringify(blank.stdout().slice(0, 200)));
  await blank.stop();

  // WG_AD_ORIGINS. A CRLF kills the process asynchronously; a semicolon injects a whole
  // directive. Built with String.fromCharCode so no raw control byte enters this file:
  // one of those makes grep treat the whole file as binary and return nothing.
  const CR = String.fromCharCode(13);
  const LF = String.fromCharCode(10);
  const badOrigins = [
    [`https://x.example${CR}${LF}x-evil: 1`, 'a CRLF, which throws inside an fs.stat callback'],
    ['https://x.example; script-src-elem *', 'a second CSP directive that was never in the policy'],
    ['javascript:alert(1)', 'a scheme that is not http or https'],
    ['https://x.example/path', 'a path, which is not an origin'],
    ["https://x.example 'unsafe-inline'", 'a second source expression'],
    ['not-an-origin-at-all', 'a bare word'],
  ];
  for (const [value, why] of badOrigins) {
    const outcome = await bootOutcome({ ...base, WG_AD_ORIGINS: value });
    check(`WG_AD_ORIGINS carrying ${why} refuses to boot`,
      outcome.code === 1 && outcome.err.includes('WG_AD_ORIGINS'),
      `exit ${outcome.code}: ${JSON.stringify(outcome.err.slice(0, 200))}`);
  }

  // ...and the values an operator legitimately wants still work, or the validation would
  // be indistinguishable from removing the feature.
  const goodOrigins = 'https://ads.example.net,http://localhost:8080,https://*.cdn.example.com:443';
  const good = await startServer({ ...base, WG_AD_ORIGINS: goodOrigins });
  const landing = (await request(P, 'GET', '/')).headers['content-security-policy'] ?? '';
  check('CONTROL: ordinary sponsor origins still boot and still reach the landing',
    landing.includes('https://ads.example.net')
    && landing.includes('http://localhost:8080')
    && landing.includes('https://*.cdn.example.com:443'),
    landing);
  await good.stop();
}

// --------------------------------------------------- a symlink is not a served file
{
  // index.js resolved the path and checked containment on the RESULT of path.resolve,
  // which does not resolve symbolic links, and then called fs.stat, which follows them.
  // A link inside public/ was therefore served from wherever it pointed, and a link named
  // index.html would have carried LANDING_CSP, and with it WG_AD_ORIGINS, onto it: the
  // single route by which an operator knob could reach non-landing content.
  //
  // There is no symlink in public/ today. This plants one, so the check is measured
  // against the state it exists for rather than against its absence, and removes it in a
  // finally plus an exit hook so a crash cannot leave it behind.
  const P = await freePort(PORT + BAND + 10);
  const secret = path.join(ROOT, `.wg-symlink-target-${process.pid}`);
  // No .html suffix: the containment block above enumerates public/*.html and expects
  // every one of them to serve 200, and a probe file has no business appearing in that.
  const link = path.join(PUBLIC_DIR, `.wg-symlink-probe-${process.pid}`);
  const MARKER = 'OUTSIDE_THE_PUBLIC_TREE_MARKER';
  const cleanup = () => {
    for (const f of [link, secret]) {
      try { fs.rmSync(f, { force: true }); } catch (err) { void err; }
    }
  };
  process.on('exit', cleanup);

  let srv = null;
  try {
    fs.writeFileSync(secret, `${MARKER}\n`);
    fs.symlinkSync(secret, link);
    check('CONTROL: the planted symlink exists and really does point outside public/',
      fs.lstatSync(link).isSymbolicLink()
      && fs.readFileSync(link, 'utf8').includes(MARKER)
      && !path.resolve(fs.realpathSync(link)).startsWith(PUBLIC_DIR + path.sep),
      fs.realpathSync(link));

    srv = await startServer({ WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0' });
    const res = await rawGet(P, `/${path.basename(link)}`);
    check('a symlink inside the public tree is not served',
      res.status === 404, `status ${res.status}, ${res.body.length} bytes`);
    check('and nothing from its target came back',
      !res.body.includes(MARKER), res.body.slice(0, 120));

    // The refusal must be about the link, not about the server having stopped serving.
    const real = await rawGet(P, '/index.html');
    check('CONTROL: an ordinary file on the same server is still served',
      real.status === 200 && real.body.length > 0, `status ${real.status}`);
  } finally {
    if (srv) await srv.stop();
    cleanup();
  }
  check('the planted symlink was removed',
    !fs.existsSync(link) && !fs.existsSync(secret),
    `${fs.existsSync(link)} / ${fs.existsSync(secret)}`);
}

// --------------------------------------------------- a cross-site POST is refused
{
  // Nothing here matches on Origin, and readJson parses any content type, so a hostile
  // page posting text/plain is a SIMPLE request: no preflight, and /api/create and
  // /api/suggest are reachable as the visitor. Write-only, since no CORS header is ever
  // set and the response cannot be read back, but burning a visitor's create budget and
  // posting suggestions as them are both real.
  const P = await freePort(PORT + BAND + 11);
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500', WG_REJECT_PER_WINDOW: '500',
  });

  const create = (headers, roomId) => request(P, 'POST', '/api/create', {
    roomId, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
  }, headers);

  const cross = await create({ 'sec-fetch-site': 'cross-site' }, 'XSTE0001');
  check('a POST that says it came from another site is refused',
    cross.status === 403 && cross.json?.error === 'cross_site', `${cross.status} ${cross.text}`);

  const sibling = await create({ 'sec-fetch-site': 'same-site' }, 'XSTE0002');
  check('and so is one from a sibling host, since this application is one origin',
    sibling.status === 403 && sibling.json?.error === 'cross_site', `${sibling.status} ${sibling.text}`);

  // The positive arms. Without these the check is satisfied by a route that refuses
  // everything, which is the failure mode a header guard most easily becomes.
  const own = await create({ 'sec-fetch-site': 'same-origin' }, 'XSTE0003');
  check('CONTROL: the page\'s own POST is accepted', own.status === 200, `${own.status} ${own.text}`);

  const typed = await create({ 'sec-fetch-site': 'none' }, 'XSTE0004');
  check('CONTROL: a user-initiated request is accepted', typed.status === 200, `${typed.status} ${typed.text}`);

  // ABSENT MEANS ALLOW, and that is a decision rather than an oversight: the header is
  // sent by every current browser, so absent means a non-browser client (curl, the
  // project's own tools/, this harness, a monitoring probe). Denying those to defend
  // against a browser that is not sending it trades a real availability break for a
  // defence in depth that per-seat capability tokens already do not depend on.
  const silent = await create({}, 'XSTE0005');
  check('a client that sends no Sec-Fetch-Site is allowed, deliberately',
    silent.status === 200, `${silent.status} ${silent.text}`);

  // It covers every POST, not just the one that was easy to reach.
  const suggestCross = await request(P, 'POST', '/api/suggest', { text: 'hi' }, { 'sec-fetch-site': 'cross-site' });
  check('the guard is on the method, so /api/suggest is covered too',
    suggestCross.status === 403 && suggestCross.json?.error === 'cross_site',
    `${suggestCross.status} ${suggestCross.text}`);

  // GET is not refused: a cross-site GET of /api/config reads nothing a visitor could not
  // read anyway, and refusing it would break an ordinary <img> or a link preview.
  const getCross = await request(P, 'GET', '/api/config', undefined, { 'sec-fetch-site': 'cross-site' });
  check('CONTROL: a cross-site GET is not refused, only a cross-site POST',
    getCross.status === 200, `${getCross.status}`);

  await srv.stop();
}

// ------------------------------------------ the reject budget cannot lock out a live gate
{
  // The budget refused EVERY api route once a key spent its allowance, so thirty ordinary
  // users holding stale links (a resumed gate that expired is a 404 no_room, through
  // nobody's fault) could take live /api/events reconnects and /api/relay offline for the
  // rest of the window. Behind a proxy whose address is not trusted, every one of those
  // users shares a single key, so thirty of them is one bucket.
  const P = await freePort(PORT + BAND + 12);
  const srv = await startServer({
    WG_HTTP_PORT: String(P), WG_STUN_ENABLED: '0',
    WG_REJECT_PER_WINDOW: '3', WG_API_WINDOW_MS: '60000',
    WG_API_PER_WINDOW: '5000', WG_PUBLIC_GET_PER_WINDOW: '5000',
    WG_CREATE_PER_WINDOW: '500', WG_JOIN_PER_WINDOW: '500',
  });

  // A real gate, created BEFORE the budget is spent, so what follows is a live session
  // and not a probe dressed as one.
  const proof = makeJoinProof();
  const gate = await request(P, 'POST', '/api/create', {
    roomId: 'GATE0001', sessionMinutes: 10, joinProofHash: proof.hash,
  });
  const joined = await request(P, 'POST', '/api/join', { roomId: 'GATE0001', joinProof: proof.proof });
  check('CONTROL: a gate exists and seats two before the budget is spent',
    gate.status === 200 && joined.status === 200, `${gate.status}/${joined.status}`);

  // Spend the budget the way an ordinary user with a dead link does.
  const stale = [];
  for (let i = 0; i < 10; i += 1) {
    stale.push((await request(P, 'GET', `/api/room?room=STAR000${i}&token=x`)).status);
  }
  check('CONTROL: the budget really is spent, so the rest of this block is not vacuous',
    stale.includes(429), `statuses ${stale.join(',')}`);

  // THE ASSERTION. Every one of these is refused as 429 by the pre-fix server.
  const relay = await request(P, 'POST', '/api/relay', {
    roomId: 'GATE0001', token: gate.json.token, to: joined.json.slotId, envelope: { n: 'a', c: 'b' },
  });
  check('a live relay is not refused by a budget spent on a different route',
    relay.status === 200, `${relay.status} ${relay.text}`);

  const events = await new Promise((resolve) => {
    const req = http.get({
      host: '127.0.0.1', port: P,
      path: `/api/events?room=GATE0001&token=${encodeURIComponent(gate.json.token)}`,
    }, (res) => { resolve(res.statusCode); req.destroy(); });
    req.on('error', () => resolve(0));
  });
  check('and neither is an /api/events reconnect', events === 200, `status ${events}`);

  const bye = await request(P, 'POST', '/api/bye', { roomId: 'GATE0001', token: joined.json.token });
  check('and neither is /api/bye', bye.status === 200, `${bye.status} ${bye.text}`);

  // The budget still bites where it was written to bite. Without this the fix would be
  // indistinguishable from deleting the budget.
  const stillProbing = await request(P, 'GET', '/api/room?room=STAR0009&token=x');
  check('CONTROL: the route that spent the budget is still refused by it',
    stillProbing.status === 429, `${stillProbing.status} ${stillProbing.text}`);

  await srv.stop();
}

// ------------------------------------------- the timeout lift happens after authorisation
{
  // index.js called req.setTimeout(0) and res.setTimeout(0) keyed on the pathname alone,
  // before handleApi had looked at the room or the token, so naming the path was enough to
  // get an unbounded timeout. Not exploitable as it stands (headersTimeout still applies
  // and the route carries no body) and therefore NOT observable over the wire: with
  // server.timeout defaulting to 0 the pre-fix and post-fix servers behave identically.
  //
  // So this is a structural assertion, stated as such rather than dressed up as a
  // behavioural one. It is the honest available check, and it fails against the pre-fix
  // source, which is the property that makes it worth having.
  const indexSrc = fs.readFileSync(path.join(ROOT, 'server', 'index.js'), 'utf8');
  const signalSrc = fs.readFileSync(path.join(ROOT, 'server', 'signal.js'), 'utf8');

  check('index.js no longer lifts a timeout on the way in to the API',
    !/req\.setTimeout\(0\)/.test(indexSrc) && !/res\.setTimeout\(0\)/.test(indexSrc),
    'server/index.js still calls setTimeout(0) before handleApi');

  const events = signalSrc.indexOf("url.pathname === '/api/events'");
  // The gate is searched FROM the events branch. The same bad_token line exists in the
  // relay route earlier in the file, and an unanchored indexOf found that one: the check
  // then passed whether or not the events branch had a guard at all.
  const gate = signalSrc.indexOf("if (!slot) return fail(res, 403, 'bad_token');", events);
  const lift = signalSrc.indexOf('req.setTimeout(0)');
  check('signal.js lifts both timeouts, and only inside the /api/events branch',
    /req\.setTimeout\(0\)/.test(signalSrc) && /res\.setTimeout\(0\)/.test(signalSrc)
    && lift > events && events !== -1,
    `events at ${events}, lift at ${lift}`);
  check('and does it only after a token has bought a seat, in that same branch',
    gate !== -1 && lift > gate, `events-branch bad_token guard at ${gate}, lift at ${lift}`);
}

process.exit(summary('http surface') ? 0 : 1);
