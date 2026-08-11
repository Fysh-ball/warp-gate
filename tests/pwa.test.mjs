// The installable app: the manifest, the icons it names, and the OS share target.
//
// The share target is the part with a real security claim attached, so most of this file
// is about proving that claim rather than about the manifest. The claim is: a file shared
// into Warp Gate from the OS never reaches the network. It is proved twice over, from
// both ends:
//
//   1. From the server. There is no route that accepts a POST anywhere on the static
//      tree, and the method guard refuses before a byte of the body is read. A share that
//      somehow escaped the worker would be refused, not uploaded.
//   2. From the worker. public/sw.js is loaded here for real, with the global fetch (and
//      WebSocket, and EventSource) replaced by counting stubs, and a genuine
//      multipart/form-data POST carrying a File is dispatched at it. The handler must
//      answer it synchronously and the network stubs must record nothing.
//
// Both halves carry negative controls, because "the stub recorded nothing" is also what a
// stub that is not installed reports.
//
// Run: node tests/pwa.test.mjs

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, summary, startServer, freePort } from './lib/harness.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = await freePort(3799);
const ORIGIN = 'https://gate.test';

// The policy as it stood BEFORE the manifest work, written out rather than derived. A
// baseline computed from the server's own source would agree with any change the server
// made to itself, which is the opposite of what a baseline is for.
const CSP_BEFORE = [
  ["default-src", "'none'"],
  ["script-src", "'self'"],
  ["style-src", "'self'"],
  ["img-src", "'self' blob:"],
  ["connect-src", "'self'"],
  ["font-src", "'self'"],
  ["worker-src", "'self'"],
  ["frame-src", "'self'"],
  ["base-uri", "'none'"],
  ["form-action", "'none'"],
  ["frame-ancestors", "'none'"],
];

/** Fetch that keeps the body as bytes. The icons are PNGs; utf8 would corrupt them. */
function fetchAsset(port, pathname, { method = 'GET', body = null, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: pathname, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, buf, text: buf.toString('utf8') });
      });
    });
    req.on('error', reject);
    req.setTimeout(6000, () => req.destroy(new Error('request timeout')));
    if (body) req.write(body);
    req.end();
  });
}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

/** Read a PNG's real dimensions out of IHDR, so a declared size can be checked, not trusted. */
function pngSize(buf) {
  if (buf.length < 24 || !buf.subarray(0, 8).equals(PNG_SIG)) return null;
  if (buf.subarray(12, 16).toString('ascii') !== 'IHDR') return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

/**
 * One predicate for "this icon entry is really served, as what it claims to be".
 *
 * A single function so the assertion and the proof-it-can-fail run the SAME code. Two
 * similar-looking copies would let the control pass while the real check rotted.
 */
async function iconServed(port, icon) {
  const res = await fetchAsset(port, icon.src);
  if (res.status !== 200) return { ok: false, why: `http ${res.status}` };
  if (res.buf.length === 0) return { ok: false, why: 'empty body' };
  const type = String(res.headers['content-type'] ?? '');
  if (!type.startsWith(icon.type)) return { ok: false, why: `content-type ${type}, expected ${icon.type}` };
  if (icon.type === 'image/png') {
    const dims = pngSize(res.buf);
    if (!dims) return { ok: false, why: 'body is not a PNG' };
    const [w, h] = String(icon.sizes).split('x').map(Number);
    if (dims.width !== w || dims.height !== h) {
      return { ok: false, why: `image is ${dims.width}x${dims.height} but the manifest says ${icon.sizes}` };
    }
  }
  if (icon.type === 'image/svg+xml' && !res.buf.toString('utf8').includes('<svg')) {
    return { ok: false, why: 'body is not an SVG' };
  }
  return { ok: true, why: `${res.buf.length} bytes, ${type}` };
}

const directiveOf = (csp, name) => (new RegExp(`(?:^|;)\\s*${name} ([^;]*)`).exec(csp) ?? [])[1]?.trim();

// ---------------------------------------------------------------- the manifest
const srv = await startServer({
  WG_HTTP_PORT: String(PORT), WG_STUN_ENABLED: '0',
  WG_PUBLIC_GET_PER_WINDOW: '5000', WG_API_PER_WINDOW: '5000', WG_REJECT_PER_WINDOW: '5000',
});

const manifestRes = await fetchAsset(PORT, '/manifest.webmanifest');
check('the manifest is served', manifestRes.status === 200, `http ${manifestRes.status}`);

const manifestType = String(manifestRes.headers['content-type'] ?? '');
check('the manifest is served as application/manifest+json',
  manifestType === 'application/manifest+json', manifestType);
// Negative control for the content-type check. A browser that gets text/html here refuses
// the manifest outright, and a test that only ever asserted "some content type" would not
// notice. Prove the comparison discriminates by pointing it at a document that is NOT a
// manifest and requiring the same expectation to be false there.
const landingType = String((await fetchAsset(PORT, '/')).headers['content-type'] ?? '');
check('CONTROL: the same content-type expectation is FALSE for the landing document',
  landingType !== 'application/manifest+json' && landingType.startsWith('text/html'), landingType);

let manifest = null;
let parseError = '';
try { manifest = JSON.parse(manifestRes.text); } catch (err) { parseError = err.message; }
check('the manifest parses as JSON', manifest !== null, parseError);
if (manifest === null) {
  process.stdout.write('the manifest did not parse; nothing below it can be measured\n');
  await srv.stop();
  process.exit(summary('pwa') ? 0 : 1);
}

check('the manifest names the app', manifest.name === 'Warp Gate' && typeof manifest.short_name === 'string'
  && manifest.short_name.length > 0 && manifest.short_name.length <= 12,
  JSON.stringify({ name: manifest.name, short_name: manifest.short_name }));
check('the manifest asks for a standalone window',
  ['standalone', 'minimal-ui', 'fullscreen'].includes(manifest.display), manifest.display);
check('the manifest scopes the app to this origin',
  manifest.scope === '/' && manifest.start_url === '/app',
  JSON.stringify({ scope: manifest.scope, start_url: manifest.start_url }));

// The colours are not a matter of taste here: they have to be the ones the stylesheet
// already uses, or the splash screen and the title bar are a different product from the
// page they wrap. Read the palette and compare, rather than eyeballing a hex string.
const css = fs.readFileSync(path.join(PUBLIC_DIR, 'css', 'style.css'), 'utf8');
const rootBlock = css.slice(css.indexOf(':root'));
const paletteBg = (/--bg:\s*(#[0-9a-fA-F]{3,8})/.exec(rootBlock) ?? [])[1];
const paletteAccent = (/--accent:\s*(#[0-9a-fA-F]{3,8})/.exec(rootBlock) ?? [])[1];
check('the stylesheet really does define the palette this test compares against',
  paletteBg === '#0b0d10' && paletteAccent === '#e8a33d',
  JSON.stringify({ paletteBg, paletteAccent }));
check('the manifest theme and background colours come from the stylesheet palette',
  manifest.theme_color === paletteBg && manifest.background_color === paletteBg,
  JSON.stringify({ theme_color: manifest.theme_color, background_color: manifest.background_color, paletteBg }));

// ---------------------------------------------------------------- the icons
check('the manifest lists icons', Array.isArray(manifest.icons) && manifest.icons.length > 0,
  JSON.stringify(manifest.icons?.length));

const sizesListed = new Set(manifest.icons.map((i) => i.sizes));
check('the manifest offers a 192 and a 512 icon',
  sizesListed.has('192x192') && sizesListed.has('512x512'), [...sizesListed].join(','));
const purposes = manifest.icons.map((i) => String(i.purpose ?? 'any'));
check('at least one icon is maskable', purposes.some((p) => p.split(/\s+/).includes('maskable')),
  purposes.join(','));
check('and at least one is not, so a platform that does not mask gets an unshrunken mark',
  purposes.some((p) => p.split(/\s+/).includes('any')), purposes.join(','));
check('every maskable icon is offered at both 192 and 512',
  ['192x192', '512x512'].every((s) => manifest.icons.some(
    (i) => i.sizes === s && String(i.purpose ?? '').split(/\s+/).includes('maskable'))),
  purposes.join(','));

const iconResults = [];
for (const icon of manifest.icons) {
  const result = await iconServed(PORT, icon);
  iconResults.push([icon.src, result]);
  // Status code asserted explicitly. A 404 body is still a body, and a check that only
  // looked at "did bytes come back" would read a not-found page as a served icon.
  check(`the icon ${icon.src} is served, and is really ${icon.sizes} ${icon.type}`,
    result.ok, result.why);
}
check('every icon the manifest names was served',
  iconResults.every(([, r]) => r.ok), iconResults.filter(([, r]) => !r.ok).map(([s]) => s).join(','));

// Negative control 1: a path that does not exist must FAIL the same predicate. Without
// this, iconServed() could be returning ok for everything and every line above is noise.
const ghost = await iconServed(PORT, { src: '/icons/icon-does-not-exist.png', sizes: '192x192', type: 'image/png' });
check('CONTROL: an icon path that does not exist fails the same check',
  ghost.ok === false && /http 404/.test(ghost.why), JSON.stringify(ghost));

// Negative control 2: the size check must discriminate. Point the predicate at a real,
// served 192 icon while claiming it is 512, and require it to say so.
const wrongSize = await iconServed(PORT, { src: '/icons/icon-192.png', sizes: '512x512', type: 'image/png' });
check('CONTROL: a real icon declared at the wrong size fails the same check',
  wrongSize.ok === false && /192x192 but the manifest says 512x512/.test(wrongSize.why),
  JSON.stringify(wrongSize));

// Negative control 3: the content-type arm of the predicate must discriminate too.
const wrongType = await iconServed(PORT, { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/svg+xml' });
check('CONTROL: a real icon declared as the wrong content type fails the same check',
  wrongType.ok === false && /content-type image\/png/.test(wrongType.why), JSON.stringify(wrongType));

// ---------------------------------------------------------------- start_url is real
const start = await fetchAsset(PORT, manifest.start_url);
check('the manifest start_url resolves to a real route', start.status === 200, `http ${start.status}`);
check('and it is the gate document, not the landing and not a 404 page',
  /id="screen-connected"/.test(start.text) && !/class="lp-hero"/.test(start.text),
  `${start.text.length} bytes`);
// Control: the same assertion applied to a URL that does not exist must fail, so "200 and
// contains the gate marker" is a measurement rather than a constant.
const noSuchStart = await fetchAsset(PORT, '/app-does-not-exist');
check('CONTROL: a start_url that does not exist would not have passed that check',
  noSuchStart.status !== 200 && !/id="screen-connected"/.test(noSuchStart.text),
  `http ${noSuchStart.status}`);

// ---------------------------------------------------------------- the policy
const csp = String(start.headers['content-security-policy'] ?? '');
let keptAll = true;
for (const [name, value] of CSP_BEFORE) {
  const got = directiveOf(csp, name);
  if (got !== value) keptAll = false;
  check(`the policy still carries ${name} ${value}`, got === value, String(got));
}
check('every directive the policy had before the manifest is still there, unchanged', keptAll, csp);
check('the policy now also allows a manifest from this origin, and only this origin',
  directiveOf(csp, 'manifest-src') === "'self'", String(directiveOf(csp, 'manifest-src')));
// The second addition since CSP_BEFORE was written, and the only one. A received video or
// audio file is previewed from a blob: URL, and a media element loads through media-src,
// not img-src: without this the directive falls back to default-src 'none' and every
// player fails with "Media load rejected by URL safety check". Asserted as an exact string
// so widening it to data: or to an origin has to come past this line.
check('and a media element may load the blob: URLs this page makes, and nothing else',
  directiveOf(csp, 'media-src') === "'self' blob:", String(directiveOf(csp, 'media-src')));
// Nothing else may have been added along the way. A policy that grew three directives when
// two were asked for is a policy nobody reviewed. The count is manifest-src (the manifest
// work this file was written for) plus media-src (inline video and audio previews), and
// both are asserted by name above, so a rename cannot satisfy the arithmetic on its own.
const directiveNames = csp.split(';').map((d) => d.trim().split(/\s+/)[0]).filter(Boolean);
check('the policy gained exactly two directives and no more',
  directiveNames.length === CSP_BEFORE.length + 2, `${directiveNames.length}: ${directiveNames.join(' ')}`);
// Negative control for the presence test itself: a directive that was never in this
// policy must read as absent. Otherwise directiveOf() returning something for everything
// would make all of the above pass.
check('CONTROL: a directive that is not in the policy reads as absent',
  directiveOf(csp, 'object-src') === undefined, String(directiveOf(csp, 'object-src')));
check('the policy still admits no external origin and no wildcard',
  !/https?:\/\//.test(csp) && !/\*/.test(csp), csp);
check("the policy still allows neither 'unsafe-inline' nor 'unsafe-eval'",
  !/unsafe-inline|unsafe-eval/.test(csp), csp);
// form-action stays 'none'. The share target is a POST, but it is not a form in a
// document: the OS starts it and the service worker answers it, so no document's
// form-action is consulted and there was never a reason to widen it.
check('the share target did not need form-action widened',
  directiveOf(csp, 'form-action') === "'none'", String(directiveOf(csp, 'form-action')));

const manifestCsp = String(manifestRes.headers['content-security-policy'] ?? '');
check('the manifest itself is served under the same policy as everything else',
  manifestCsp.includes("manifest-src 'self'"), manifestCsp);

// ---------------------------------------------------------------- the share target route
const st = manifest.share_target ?? {};
check('the manifest declares a share target', typeof st === 'object' && st !== null && !!st.action,
  JSON.stringify(st));
check('the share target is a POST, because a GET target cannot carry a file',
  String(st.method).toUpperCase() === 'POST', String(st.method));
check('the share target is multipart/form-data, which is what carries a file part',
  st.enctype === 'multipart/form-data', String(st.enctype));
check('the share target accepts a file part named "file"',
  Array.isArray(st.params?.files) && st.params.files[0]?.name === 'file'
  && Array.isArray(st.params.files[0]?.accept) && st.params.files[0].accept.includes('image/*'),
  JSON.stringify(st.params));
check('the share target action is a same-origin path inside the manifest scope',
  typeof st.action === 'string' && st.action.startsWith('/') && st.action.startsWith(manifest.scope),
  String(st.action));

// A GET of the action lands on the gate rather than a dead end, for the person who pastes
// the URL and for a browser with no worker installed.
const shareGet = await fetchAsset(PORT, st.action);
check('a GET of the share target action serves the gate', shareGet.status === 200
  && /id="screen-connected"/.test(shareGet.text), `http ${shareGet.status}`);

// THE POINT. A POST of a file to the share action must not be accepted by this server at
// all. This is the fallback path, reached only when no worker is in control; it has to
// fail closed. 405 comes from the method guard, which runs before any body is read.
const MARKER = 'WGSHARE-MARKER-4f2c9a-do-not-leak';
const boundary = '----wgtest9799';
const multipart = Buffer.from(
  `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="holiday.png"\r\n`
  + `Content-Type: image/png\r\n\r\n${MARKER}${'x'.repeat(4096)}\r\n--${boundary}--\r\n`,
);
const posted = await fetchAsset(PORT, st.action, {
  method: 'POST',
  body: multipart,
  headers: { 'content-type': `multipart/form-data; boundary=${boundary}`, 'content-length': multipart.length },
});
check('the server refuses a POST to the share target action outright',
  posted.status === 405 && /method_not_allowed/.test(posted.text), `${posted.status} ${posted.text.slice(0, 120)}`);
check('and the refusal does not echo one byte of the shared file back',
  !posted.text.includes(MARKER), posted.text.slice(0, 200));
check('the shared bytes reached no log on the server',
  srv.stderr() === '' && !srv.stdout().includes(MARKER), `${srv.stderr().slice(0, 200)}`);
// The same refusal on the gate itself and on the manifest, so 405 is the server's answer
// to an upload anywhere on the static tree and not a special case for one path.
for (const target of ['/app', '/manifest.webmanifest', '/icons/icon-192.png']) {
  const res = await fetchAsset(PORT, target, {
    method: 'POST', body: multipart,
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}`, 'content-length': multipart.length },
  });
  check(`a POST to ${target} is refused as well, so there is no upload route anywhere`,
    res.status === 405, `http ${res.status}`);
}

// The 405 is a method guard that runs BEFORE the handler, so the body is never read.
// Asserted against the source, with a control that proves the pattern can miss.
const serverSrc = fs.readFileSync(path.join(ROOT, 'server', 'index.js'), 'utf8');
const guardPattern = /if \(req\.method !== 'GET' && req\.method !== 'HEAD'\) \{\s*return sendJson\(res, 405/;
check('the server refuses a non-GET before it ever reaches the static handler',
  guardPattern.test(serverSrc), 'method guard not found in server/index.js');
check('CONTROL: that pattern does NOT match a copy of the source with the guard removed',
  !guardPattern.test(serverSrc.replace(guardPattern, '// guard removed for the control')),
  'the guard pattern matches source it should not');

// ---------------------------------------------------------------- worker, page, manifest agree
const swSrc = fs.readFileSync(path.join(PUBLIC_DIR, 'sw.js'), 'utf8');
const shareMod = await import(path.join(PUBLIC_DIR, 'js', 'share.js'));
check('the page module imports cleanly outside a browser, so nothing runs at import time',
  typeof shareMod.claimSharedFiles === 'function', typeof shareMod.claimSharedFiles);
const agreeOn = (literal) => swSrc.includes(`'${literal}'`);
check('the worker and the page agree on the share cache name',
  agreeOn(shareMod.SHARE_CACHE) && shareMod.SHARE_CACHE === 'wg-share-v1', shareMod.SHARE_CACHE);
check('the worker and the page agree on the share key prefix',
  agreeOn(shareMod.SHARE_PREFIX), shareMod.SHARE_PREFIX);
check('the worker and the manifest agree on the share action',
  agreeOn(shareMod.SHARE_ACTION) && st.action === shareMod.SHARE_ACTION,
  `${st.action} vs ${shareMod.SHARE_ACTION}`);
// Control: the agreement test must be able to say no. A name neither file uses has to
// read as a disagreement, or agreeOn() is just returning true.
check('CONTROL: a cache name neither file uses reads as a disagreement',
  !agreeOn('wg-share-v-nonexistent'), 'agreeOn matched a literal that is not in sw.js');

await srv.stop();

// ---------------------------------------------------------------- the worker itself
//
// public/sw.js is loaded here for real (it is a plain script, so a Function wrapper is
// enough) with an instrumented global scope. Nothing is reimplemented: a copy of the
// handler would prove things about the copy.

/** A Cache Storage that stores bytes, so a Response can be read more than once. */
function fakeCacheStorage() {
  const store = new Map();
  const keyOf = (req) => (typeof req === 'string' ? new URL(req, ORIGIN).href : req.url);
  const openOne = (name) => {
    if (!store.has(name)) store.set(name, new Map());
    const entries = store.get(name);
    return {
      async put(req, res) {
        const bytes = Buffer.from(await res.arrayBuffer());
        entries.set(keyOf(req), { bytes, headers: [...res.headers] });
      },
      async match(req) {
        const hit = entries.get(keyOf(req));
        return hit ? new Response(hit.bytes, { headers: hit.headers }) : undefined;
      },
      async keys() { return [...entries.keys()].map((u) => new Request(u)); },
      async delete(req) { return entries.delete(keyOf(req)); },
    };
  };
  return {
    store,
    open: async (name) => openOne(name),
    delete: async (name) => store.delete(name),
    keys: async () => [...store.keys()],
  };
}

function makeWorkerScope(caches) {
  const listeners = { fetch: [], message: [], install: [], activate: [] };
  const clients = new Map();
  const scope = {
    location: { origin: ORIGIN, href: `${ORIGIN}/sw.js` },
    caches,
    crypto: globalThis.crypto,
    registration: {},
    skipWaiting() {},
    clients: {
      claim: async () => {},
      get: async (id) => clients.get(id) ?? null,
    },
    addEventListener(type, fn) {
      if (!listeners[type]) listeners[type] = [];
      listeners[type].push(fn);
    },
  };
  return { scope, listeners, clients };
}

function dispatchFetch(listeners, request) {
  let responded = null;
  const event = { request, respondWith(p) { responded = p; }, waitUntil() {} };
  for (const fn of listeners.fetch) fn(event);
  // Read straight after the synchronous dispatch: if respondWith had been deferred to a
  // microtask the browser would already have sent the request to the network.
  return { answeredSynchronously: responded !== null, response: responded };
}

const network = { calls: [] };
const realFetch = globalThis.fetch;
const realWs = globalThis.WebSocket;
const realEs = globalThis.EventSource;
const spy = (label) => (...args) => {
  network.calls.push(`${label} ${String(args[0])}`);
  throw new Error(`the worker reached the network via ${label}`);
};

let sandboxOk = true;
try {
  globalThis.fetch = spy('fetch');
  if (realWs) globalThis.WebSocket = spy('WebSocket');
  if (realEs) globalThis.EventSource = spy('EventSource');

  const caches = fakeCacheStorage();
  const { scope, listeners, clients } = makeWorkerScope(caches);
  scope.fetch = globalThis.fetch;
  // eslint-disable-next-line no-new-func
  new Function('self', swSrc)(scope);

  check('the worker registers exactly two fetch listeners', listeners.fetch.length === 2,
    String(listeners.fetch.length));

  // ---- the download path is untouched, and it is still FIRST.
  const dlOnly = { fetch: [listeners.fetch[0]] };
  const strayId = 'no-such-id';
  const stray = dispatchFetch(dlOnly, new Request(`${ORIGIN}/wg-download/${strayId}`));
  const strayRes = stray.answeredSynchronously ? await stray.response : null;
  check('the first fetch listener is still the download worker',
    strayRes !== null && strayRes.status === 404, `${stray.answeredSynchronously} ${strayRes?.status}`);

  // A whole download, through both listeners in their real order.
  const CLIENT = 'client-a';
  const posted = [];
  clients.set(CLIENT, { id: CLIENT, postMessage: (m) => posted.push(m) });
  const send = (data) => {
    for (const fn of listeners.message) fn({ data, source: { id: CLIENT }, ports: [] });
  };
  const payload = Buffer.from('the bytes of a received file');
  send({ type: 'wg-open', id: 'dl-1', name: 'note.txt', size: payload.length, mime: 'text/plain' });
  const dl = dispatchFetch(listeners, new Request(`${ORIGIN}/wg-download/dl-1`));
  check('a download request is still answered by the worker, with both listeners installed',
    dl.answeredSynchronously, 'respondWith was not called');
  const dlRes = dl.answeredSynchronously ? await dl.response : null;
  send({ type: 'wg-chunk', id: 'dl-1', chunk: payload });
  send({ type: 'wg-close', id: 'dl-1' });
  const dlBody = dlRes ? Buffer.from(await dlRes.arrayBuffer()) : Buffer.alloc(0);
  check('the download still streams its bytes and its filename header',
    dlRes?.status === 200
    && /attachment; filename\*=UTF-8''note.txt/.test(String(dlRes.headers.get('content-disposition')))
    && dlBody.equals(payload),
    `${dlRes?.status} ${dlRes?.headers.get('content-disposition')} ${dlBody.length} bytes`);

  // A stream is still bound to the client that opened it: a message from another client
  // must not be able to inject into or close it.
  send({ type: 'wg-open', id: 'dl-2', name: 'bound.txt', size: 4, mime: 'text/plain' });
  const dl2 = dispatchFetch(listeners, new Request(`${ORIGIN}/wg-download/dl-2`));
  const dl2Res = await dl2.response;
  for (const fn of listeners.message) {
    fn({ data: { type: 'wg-chunk', id: 'dl-2', chunk: Buffer.from('EVIL') }, source: { id: 'other-tab' }, ports: [] });
  }
  send({ type: 'wg-chunk', id: 'dl-2', chunk: Buffer.from('good') });
  send({ type: 'wg-close', id: 'dl-2' });
  const dl2Body = Buffer.from(await dl2Res.arrayBuffer()).toString('utf8');
  check('a stream is still bound to the client that opened it',
    dl2Body === 'good', JSON.stringify(dl2Body));

  // ---- the share path.
  const shareBytes = Buffer.from(`${MARKER} and then some actual image bytes`);
  const form = new FormData();
  form.append('file', new File([shareBytes], 'holiday photo.png', { type: 'image/png' }));
  const shareReq = new Request(`${ORIGIN}${st.action}`, { method: 'POST', body: form });

  const callsBefore = network.calls.length;
  const share = dispatchFetch(listeners, shareReq);
  check('the share POST is answered by the worker synchronously, inside the dispatch',
    share.answeredSynchronously,
    'respondWith was not called during dispatch; the request would go to the network');
  const shareRes = share.answeredSynchronously ? await share.response : null;
  check('the worker answers it with a 303, which forces the follow-up to be a GET',
    shareRes?.status === 303, String(shareRes?.status));
  check('and lands the user on the gate, with nothing about the share in the address bar',
    shareRes?.headers.get('location') === `${ORIGIN}/app`, String(shareRes?.headers.get('location')));

  check('handling the share made no network call of any kind',
    network.calls.length === callsBefore, network.calls.join(', '));

  // ---- the page picks the file back up, out of the same storage.
  const realCaches = globalThis.caches;
  globalThis.caches = caches;
  const claimed = await shareMod.claimSharedFiles();
  check('the page claims exactly the file that was shared in', claimed.length === 1, String(claimed.length));
  check('with its name and type intact',
    claimed[0]?.name === 'holiday photo.png' && claimed[0]?.type === 'image/png',
    `${claimed[0]?.name} / ${claimed[0]?.type}`);
  const claimedBytes = claimed[0] ? Buffer.from(await claimed[0].arrayBuffer()) : Buffer.alloc(0);
  check('and its bytes intact, byte for byte', claimedBytes.equals(shareBytes),
    `${claimedBytes.length} of ${shareBytes.length} bytes`);
  check('claiming a share made no network call either', network.calls.length === callsBefore,
    network.calls.join(', '));

  const again = await shareMod.claimSharedFiles();
  check('a claimed share is gone from storage, not left behind for the next load',
    again.length === 0, String(again.length));
  check('and the share cache itself is dropped once it is empty',
    (await caches.keys()).length === 0, (await caches.keys()).join(','));

  // ---- a multi-file share arrives in the order it was sent.
  //
  // The keys are sorted as strings on the way back out, so an unpadded index would put
  // the tenth file second. Twelve files is the smallest count that catches it.
  const many = new FormData();
  for (let i = 0; i < 12; i += 1) many.append('file', new File([`body ${i}`], `file-${i}.txt`, { type: 'text/plain' }));
  const manyDispatch = dispatchFetch(listeners, new Request(`${ORIGIN}${st.action}`, { method: 'POST', body: many }));
  await manyDispatch.response;
  // initShare is the one call the page makes: it registers the worker and returns the
  // share. Outside a browser there is no navigator.serviceWorker, so this also proves it
  // does not depend on the registration half succeeding.
  const manyClaimed = await shareMod.initShare();
  check('a twelve file share comes back complete', manyClaimed.length === 12, String(manyClaimed.length));
  check('and in the order it was shared, not in string order',
    manyClaimed.map((f) => f.name).join(',') === [...Array(12).keys()].map((i) => `file-${i}.txt`).join(','),
    manyClaimed.map((f) => f.name).join(','));
  check('the one call the page makes still touches no network',
    network.calls.length === callsBefore, network.calls.join(', '));

  // The gate must work where none of this exists.
  globalThis.caches = undefined;
  const noCaches = await shareMod.initShare();
  check('with no Cache Storage at all the page gets an empty list rather than an error',
    Array.isArray(noCaches) && noCaches.length === 0, JSON.stringify(noCaches));
  globalThis.caches = realCaches;

  // ---- controls for the instrument itself.
  //
  // "no network calls" is also what a spy that was never installed reports. Prove the
  // counter is live by making a call through the same global the worker would have used.
  let spyFired = false;
  try {
    await globalThis.fetch(`${ORIGIN}/probe`);
  } catch (err) {
    spyFired = /reached the network/.test(err.message);
  }
  check('CONTROL: the network spy records a call when one is made through it',
    spyFired && network.calls.length === callsBefore + 1, network.calls.join(', '));
  check('CONTROL: and that call is the only one recorded in the whole run',
    network.calls.length === 1 && network.calls[0] === `fetch ${ORIGIN}/probe`, network.calls.join(', '));

  // The share listener must not swallow anything it does not own, or an ordinary
  // navigation to the action would never reach the server.
  const getShare = dispatchFetch(listeners, new Request(`${ORIGIN}${st.action}`));
  check('a GET of the share action is left to the network, not intercepted',
    getShare.answeredSynchronously === false, 'the worker answered a GET it should have passed through');
  const otherPost = dispatchFetch(listeners, new Request(`${ORIGIN}/api/create`, { method: 'POST', body: '{}' }));
  check('a POST to any other path is left alone as well',
    otherPost.answeredSynchronously === false, 'the worker answered a POST it should have passed through');
  const crossOrigin = dispatchFetch(listeners, new Request(`https://elsewhere.test${st.action}`, { method: 'POST', body: 'x' }));
  check('and a POST to the same path on another origin is not claimed',
    crossOrigin.answeredSynchronously === false, 'the worker answered a cross-origin POST');

  // CONTROL for the dispatch harness: it must be able to report "answered". Every check
  // above that expects false would pass against a harness that always said false.
  check('CONTROL: the dispatch harness does report an intercepted request as answered',
    dl.answeredSynchronously === true && share.answeredSynchronously === true,
    `${dl.answeredSynchronously} ${share.answeredSynchronously}`);
} catch (err) {
  sandboxOk = false;
  check('the worker sandbox ran without throwing', false, err.stack);
} finally {
  globalThis.fetch = realFetch;
  if (realWs) globalThis.WebSocket = realWs;
  if (realEs) globalThis.EventSource = realEs;
}
check('the worker sandbox completed', sandboxOk, 'see the failure above');

process.exit(summary('pwa') ? 0 : 1);
