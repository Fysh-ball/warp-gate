// Rebuild this package's copy of the client from public/, and re-apply the patches.
//
// WHAT THIS IS, AND WHAT IT IS NOT
//
// It is NOT a build step. The extension in this directory is complete and checked in: it
// loads, it runs, and nobody has to execute anything to use it or to review it. Nothing
// here is minified, bundled, transpiled or generated at package time, and the project's
// "no build step" rule is about what stands between the source you read and the code that
// runs. Nothing stands between them here.
//
// It is a MAINTENANCE tool, and it exists because the alternative was worse. The extension
// has to carry a copy of public/ (see js/endpoint.js for why), and a copy maintained by
// hand rots: public/ was edited by other work in this repository twice while this directory
// was being written, and three files were silently a version behind within the hour. Making
// the copy reproducible from a recipe turns "somebody has to remember" into "run this and
// drift-check will tell you".
//
// The patches below are the complete set. Each one is an EXACT string match and this script
// refuses to run if any anchor is missing or ambiguous, because a patch that silently fails
// to apply leaves a file that looks patched, passes a casual read, and addresses the wrong
// origin at runtime.
//
//     node extension/sync-from-public.mjs      apply
//     node extension/drift-check.mjs           verify
//
// After running this, RE-READ the patched files. An anchor can still match in a file whose
// surrounding logic has changed underneath it.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(HERE, '..', 'public');

/** Files in public/ that are deliberately not copied. Kept in step with drift-check.mjs. */
const SKIP = new Set(['index.html', 'js/landing.js', 'sw.js', 'manifest.webmanifest']);

function walk(dir, base = dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full, base));
    else out.push(path.relative(base, full));
  }
  return out;
}

// ---------------------------------------------------------------- copy
let copied = 0;
for (const rel of walk(PUBLIC)) {
  if (SKIP.has(rel)) continue;
  const dest = path.join(HERE, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(path.join(PUBLIC, rel), dest);
  copied += 1;
}
if (copied === 0) {
  // The positive control. An empty or wrong PUBLIC would copy nothing, patch nothing, and
  // exit 0 with a directory full of whatever was there before.
  process.stderr.write(`nothing was copied: public/ resolved to ${PUBLIC} and is empty\n`);
  process.exit(1);
}

// ---------------------------------------------------------------- patch
const applied = [];

/** Replace exactly one occurrence, or die saying which anchor moved. */
function edit(rel, pairs) {
  const file = path.join(HERE, rel);
  let text = fs.readFileSync(file, 'utf8');
  for (const [from, to] of pairs) {
    const count = text.split(from).length - 1;
    if (count !== 1) {
      process.stderr.write(`REFUSING to patch ${rel}: the anchor below matched ${count} times, not once.\n`
        + 'public/ has changed underneath this recipe. Fix the anchor, do not loosen it.\n'
        + `--- anchor ---\n${from}\n--------------\n`);
      process.exit(1);
    }
    text = text.replace(from, to);
  }
  fs.writeFileSync(file, text);
  applied.push(rel);
}

const jsHeader = (name) => `// EXTENSION COPY of public/js/${name}. Every change is marked \`EXTENSION PATCH\` and is
// listed in extension/README.md. It is produced by extension/sync-from-public.mjs and
// checked by extension/drift-check.mjs, so diff this against public/js/${name} and the only
// hunks should be the ones named there.
//
// The copy exists because the web client writes its requests as absolute PATHS, which
// resolve against \`chrome-extension://<id>\` here and reach nothing. The upstream change
// that would delete this copy is written up in extension/README.md.

`;

edit('js/signal.js', [
  ["import { sealEnvelope, openEnvelope } from './crypto.js';",
    `${jsHeader('signal.js')}import { sealEnvelope, openEnvelope } from './crypto.js';\n`
    + '// EXTENSION PATCH: the API is not on this page\'s origin. See js/endpoint.js.\n'
    + "import { api } from './endpoint.js';"],
  ['    const url = `/api/events?room=',
    '    // EXTENSION PATCH: absolute URL, not an absolute path.\n'
    + '    const url = api(`/api/events?room='],
  ['&token=${encodeURIComponent(this.token)}`;', '&token=${encodeURIComponent(this.token)}`);'],
  ["await fetch('/api/relay', {", "await fetch(api('/api/relay'), { // EXTENSION PATCH: absolute URL"],
  ["await fetch('/api/bye', {", "await fetch(api('/api/bye'), { // EXTENSION PATCH: absolute URL"],
  ['await fetch(`/api/room?room=', 'await fetch(api(`/api/room?room='],
  ['${encodeURIComponent(token)}`, {\n    signal: AbortSignal.timeout(8000),\n  });',
    '${encodeURIComponent(token)}`), { // EXTENSION PATCH: absolute URL\n    signal: AbortSignal.timeout(8000),\n  });'],
  ["await fetch('/api/config', { signal: AbortSignal.timeout(8000) });",
    "await fetch(api('/api/config'), { signal: AbortSignal.timeout(8000) }); // EXTENSION PATCH: absolute URL"],
]);

edit('js/session.js', [
  ["import { Signal } from './signal.js';",
    `${jsHeader('session.js')}import { Signal } from './signal.js';\n`
    + "// EXTENSION PATCH: this page's origin is chrome-extension://<id>, which serves no API.\n"
    + "import { api } from './endpoint.js';"],
  ['  const res = await fetch(path, {',
    '  // EXTENSION PATCH: `path` is still an absolute API path; api() only supplies the origin.\n'
    + '  const res = await fetch(api(path), {'],
]);

edit('js/download.js', [
  [`export function supportsStreamDownload() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true;
}`,
  `export function supportsStreamDownload() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true
    // EXTENSION PATCH, and an upstream bug in its own right.
    //
    // Measured in headless Brave on 2026-08-10: on a \`chrome-extension://\` page,
    // \`'serviceWorker' in navigator\` is TRUE and \`isSecureContext\` is TRUE, so all three
    // checks above pass, and then \`navigator.serviceWorker.register('/sw.js')\` throws
    //   "Failed to register a ServiceWorker ... The user denied permission to use Service Worker."
    // Chromium does not let an extension PAGE register a worker. The only worker an MV3
    // extension gets is the one its manifest declares, and that is a different thing which
    // is not in the fetch path of this document.
    //
    // Why this is not cosmetic: transfer.js consults this predicate as a CAPABILITY GATE
    // before accepting a file. With it returning true, a receive above MEMORY_LIMIT_BYTES
    // passes the "is there anywhere for this to go" check at the top of openSink() and only
    // fails at the bottom when the worker refuses to start, which is after the user clicked
    // Accept and after the sender began. A predicate that says yes and then cannot deliver
    // is worse than one that says no.
    //
    // Tested on the SCHEME rather than by probing a registration, because a probe would have
    // to be async and this function is called synchronously from three places. Any extension
    // scheme is covered, not just Chromium's: Firefox's moz-extension and Safari's
    // safari-web-extension have the same restriction.
    && !/-extension:$/.test(globalThis.location?.protocol ?? '');
}`],
]);

edit('js/app.js', [
  ["import { initShare } from './share.js';",
    `${jsHeader('app.js')}import { initShare } from './share.js';\n`
    + '// EXTENSION PATCH: this page is not served by the signalling server, so neither the API\n'
    + "// origin nor the shareable gate link can be read off `location`. See js/endpoint.js.\n"
    + "import { signalOrigin, gateLink, DEFAULT_ORIGIN } from './endpoint.js';"],
  ['    const link = `${location.origin}${location.pathname}#${formatted}`;',
    '    // EXTENSION PATCH. Upstream this is `${location.origin}${location.pathname}#...`,\n'
    + '    // which on this page produces `chrome-extension://<id>/app.html#...`: a URL naming a\n'
    + '    // package on THIS machine, useless on the other device, and different per install.\n'
    + "    // The link has to name the signalling origin's web client, because that is what the\n"
    + '    // other device can open. gateLink() carries the full reasoning, including the honest\n'
    + '    // consequence: a peer without the extension runs code that origin served them.\n'
    + '    const link = gateLink(formatted);'],
  [`  const OFFICIAL_HOSTS = ['warpgate.fysh.site', 'wg.fysh.site'];
  const host = location.hostname;
  const isOfficial = OFFICIAL_HOSTS.includes(host);
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  if (!isOfficial && !isLocal) {
    $('instance-title').textContent = \`You are on \${host}, which is not the official instance\`;
    $('instance-disc').classList.add('warn');
    $('instance-disc').open = true;
  } else if (isLocal) {
    $('instance-title').textContent = 'You are running your own copy';
  }`,
  `  // EXTENSION PATCH: this block asks a different question here, so it answers one.
  //
  // Upstream it reads \`location.hostname\` and warns when the page came from a host that is
  // not the official instance, because upstream the host that served the page IS the party
  // controlling the encrypting code. That is no longer true here, and the check would be
  // actively misleading: \`location.hostname\` is the extension id, so the original code
  // prints "You are on hgkl...jej, which is not the official instance" and opens a red
  // warning on the one delivery path that does not have the problem the warning describes.
  //
  // What is worth saying instead is the split. The CODE came from the extension package and
  // the store's signed update channel. The SIGNALLING went to whatever origin is configured,
  // and installing something changes nothing about that: the server still sees the metadata
  // in THREAT-MODEL.md and is still not trusted with a key.
  const origin = signalOrigin();
  $('instance-title').textContent = 'Where this code came from, and where it signals';
  $('instance-origin').textContent = origin;
  if (origin !== DEFAULT_ORIGIN) $('instance-origin-note').hidden = false;`],
]);

edit('app.html', [
  ['<title>Warp Gate</title>',
    `<title>Warp Gate</title>
<!-- EXTENSION COPY of public/app.html. Every change is marked with an EXTENSION PATCH
     comment and listed in extension/README.md. Produced by extension/sync-from-public.mjs
     and checked by extension/drift-check.mjs. -->`],
  ['<link rel="manifest" href="/manifest.webmanifest">',
    `<!-- EXTENSION PATCH: the <link rel="manifest"> is gone. A web app manifest names a
     start_url, a scope and a share target on a SERVER, and this document is served out of
     an extension package, so it only produced a console 404. The share target went with it:
     that was delivered by public/sw.js, and Chromium refuses to let an extension page
     register a service worker at all. See js/download.js. -->`],
  [`      <div class="disc-body">
        <p id="instance-body">The only instance the authors run is
        <strong>https://warpgate.fysh.site</strong>. The source is public so anyone may host
        their own copy, which is encouraged, but an instance run by somebody else
        inherits none of the authors' trust.</p>`,
  `      <!-- EXTENSION PATCH. Upstream this says "whoever serves this page controls the code
           that does the encryption", which is the right thing to tell someone visiting a
           website and the wrong thing to tell someone running this package: the code did not
           come over the network at all. What replaces it splits the sentence into the two
           questions that now have different answers, and is deliberately blunt about the
           half that installing something does NOT fix. -->
      <div class="disc-body">
        <p id="instance-body"><strong>The code you are running came from this extension.</strong>
        It was installed once and it changes only when the browser applies a signed update
        from the store you installed it from. Nothing on this page was fetched over the
        network, so a server, a CDN, or anyone able to terminate TLS in front of one, cannot
        hand this device a modified copy the way they can hand one to a browser visiting a
        website. That is the single thing installing this fixes, and it is the thing the
        website version cannot fix for itself.</p>
        <p><strong>It signals to <span id="instance-origin">https://warpgate.fysh.site</span>,
        and that server is still not trusted.</strong>
        <span id="instance-origin-note" hidden>You have pointed this at an origin of your own
        choosing.</span>
        It never holds a key and every payload it relays is ciphertext, but it does see the
        metadata: your address, the timing, the room id, request sizes, how long the gate
        lasted, and your per-seat capability token. Installing an extension changes none of
        that. Nor does it protect you from a compromised device, from a browser extension
        with more privilege than this one, or from the other people in the gate, who are
        legitimate participants and can keep anything you send them.</p>
        <p>You can point this at your own server on the
        <a href="/index.html">extension's own page</a>.</p>`],
]);

// The site root. `/` is the landing document, which this package does not ship: the
// extension's own index.html stands in its place. Applied mechanically to every copied HTML
// page rather than anchored, because it is the same rewrite everywhere and a per-file anchor
// list would go stale the moment a page gains another footer link.
for (const rel of ['app.html', 'faq.html', 'privacy.html', 'terms.html', 'acceptable-use.html']) {
  const file = path.join(HERE, rel);
  const before = fs.readFileSync(file, 'utf8');
  const after = before.split('href="/#support"').join('href="/index.html#support"')
    .split('href="/"').join('href="/index.html"');
  if (after === before) {
    process.stderr.write(`REFUSING: ${rel} contains no link to the site root, so the rewrite that is `
      + 'supposed to redirect them all did nothing. Either the page changed or this loop is stale.\n');
    process.exit(1);
  }
  fs.writeFileSync(file, after);
  applied.push(`${rel} (root links)`);
}

process.stdout.write(`copied ${copied} files from public/\n`);
process.stdout.write(`patched: ${[...new Set(applied)].join(', ')}\n`);
process.stdout.write('now run: node extension/drift-check.mjs\n');
