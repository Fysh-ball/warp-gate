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
import { ships } from './pack.mjs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(HERE, '..', 'public');

/**
 * Files in public/ this package deliberately does not copy, and why.
 *
 * Stated rather than left as an absence: "it is not there" and "we decided not to ship it"
 * look identical on disk, and only one of them is a decision.
 *
 * Exported because drift-check.mjs reads THIS map rather than keeping its own. It used to
 * keep a second copy, with the reasons here and the bare names in the sync, and the comment
 * on the sync's copy asked a human to keep the two in step. public/og-card.png is what that
 * costs: a new public file the sync copied and the packer would never ship.
 */
export const NOT_SHIPPED = new Map([
  ['index.html', "the site landing page: a marketing document with no gate machinery in it. "
    + "The extension's own index.html of the same name replaces it, which is why "
    + 'drift-check.mjs skips this name when it compares the two trees.'],
  ['js/landing.js', 'only the site landing page loads it.'],
  ['sw.js', 'Chromium refuses to let an extension PAGE register a service worker, so the '
    + 'streaming download it provides cannot run here at all. See js/streamable.js.'],
  ['manifest.webmanifest', 'a web app manifest names a start_url and a scope on a server. '
    + 'There is no server here.'],
  ['robots.txt', 'tells a web crawler what to fetch from a web SERVER. There is no server '
    + 'here and no crawler reaches a chrome-extension:// page.'],
  ['sitemap.xml', 'the same: a list of URLs on the website, which are not URLs in here.'],
  ['og-card.png', 'the link-preview card a chat client fetches when someone pastes the site '
    + 'URL. Nothing scrapes a chrome-extension:// page, and pack.mjs ships by structure '
    + '(manifest.json, the top-level pages, css/ icons/ js/), so a top-level png was never '
    + 'going to reach a user. Copying it here only put an unaccounted 111 KiB in the mirror.'],
]);

function walk(dir, base = dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full, base));
    else out.push(path.relative(base, full));
  }
  return out;
}

// ---------------------------------------------------------------- the recipe
//
// Exported, because drift-check.mjs re-applies this recipe to today's public/ and compares
// the result byte-for-byte with the shipped copy. That pins a patched file's CONTENT: an
// edit to public/, to the shipped copy, or to this recipe all read as drift until this
// script is rerun.

/** rel -> [[anchor, replacement], ...]. Each anchor must match exactly once. */
export const PATCHES = new Map();

/** Register one file's anchored replacements. */
function edit(rel, pairs) {
  PATCHES.set(rel, pairs);
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

// The predicate used to live in js/download.js and moved to js/streamable.js upstream, so
// that transfer.js could ask "can this browser be handed a download" without pulling in the
// 8.5 KB of service-worker machinery that answers it. The patch followed the function rather
// than staying on the filename: download.js now re-exports the same binding, so patching the
// one definition still reaches BOTH call sites (transfer.js imports it from streamable.js
// directly, download.js re-exports it) instead of only the one that used to exist.
//
// Upstream used to document this exact failure as a KNOWN GAP; it now probes a real
// registration at module load and hardens the answer when the probe settles. On an
// extension page that probe is a doomed register() of a /sw.js this package does not even
// ship, and until it settles the answer is wrongly yes. Here the answer is knowable
// without probing: the scheme decides it, so the probe is never attempted at all.
edit('js/streamable.js', [
  [`function staticallySupported() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true;
}`,
  `function staticallySupported() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true
    // EXTENSION PATCH. Measured in headless Brave on 2026-08-10: on a \`chrome-extension://\`
    // page the three checks above are all true and \`navigator.serviceWorker.register()\`
    // still throws
    //   "Failed to register a ServiceWorker ... The user denied permission to use Service Worker."
    // Chromium does not let an extension PAGE register a worker; the only worker an MV3
    // extension gets is the one its manifest declares, which is not in this document's
    // fetch path. Returning false here also stops the module-load probe below from
    // spending a doomed registration of a /sw.js this package does not ship, and closes
    // the window where the pre-settle answer is wrongly yes.
    //
    // Tested on the SCHEME because the scheme decides it synchronously. Any extension
    // scheme is covered, not just Chromium's: Firefox's moz-extension and Safari's
    // safari-web-extension have the same restriction.
    && !/-extension:$/.test(globalThis.location?.protocol ?? '');
}`],
]);

edit('js/app.js', [
  // Anchored on the crypto.js import block. The previous anchor was the static
  // `import { initShare } from './share.js'`, which no longer exists: share.js became a lazy
  // `import('./share.js')` at the foot of the file so that opening a gate does not fetch it.
  // A vanished anchor is exactly the case this script is built to refuse, and the fix is a
  // different anchor rather than a looser one.
  //
  // Why this block and not the last static import: it is the first thing after the file's own
  // header comment, so the EXTENSION COPY banner lands where a reader looking for "is this a
  // fork" will actually see it. It is also the one import app.js cannot lose while remaining
  // app.js, and the multi-line form makes it long enough to be unique on its own: verified
  // with grep, not by eye.
  //
  // Shortened on 2026-08-11: the four gate-code symbols left this import when words.js went
  // behind loadGateCode(), so the anchor as written matched zero times and this script did
  // what it is for and refused rather than patching something else. Four names on one line
  // is still unique in the file, and it is still the block app.js cannot lose.
  [`import {
  deriveSecret, clearSecretCache, deriveRoomId, loadGateCode,
} from './crypto.js';`,
    `${jsHeader('app.js')}import {
  deriveSecret, clearSecretCache, deriveRoomId, loadGateCode,
} from './crypto.js';\n`
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
  [`  // Say plainly which instance this is. A hostile host would simply delete this, which
  // is exactly why the text says the trust question can only be settled by self-hosting.
  // The classification lives in common.js because the landing's hero carries the same
  // claim and must answer it the same way.
  const kind = instanceKind();
  if (kind === 'other') {
    $('instance-title').textContent = \`You are on \${location.hostname}, which is not the official instance\`;
    $('instance-disc').classList.add('warn');
    $('instance-disc').open = true;
  } else if (kind === 'local') {
    $('instance-title').textContent = 'You are running your own copy';
  }`,
  `  // EXTENSION PATCH: this block asks a different question here, so it answers one.
  //
  // Upstream it classifies \`location.hostname\` via common.js instanceKind() and warns when
  // the page came from a host that is not the official instance, because upstream the host
  // that served the page IS the party controlling the encrypting code. That is no longer
  // true here, and the check would be actively misleading: \`location.hostname\` is the
  // extension id, so instanceKind() answers 'other' and the original code prints "You are
  // on hgkl...jej, which is not the official instance" and opens a red warning on the one
  // delivery path that does not have the problem the warning describes. The instanceKind
  // import above survives unused rather than widening this patch.
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
     register a service worker at all. See js/streamable.js. -->`],
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

// The FAQ's operator-trust answer. Upstream it says the server sends the JavaScript that
// does the encryption, which is the one claim this package exists to make false. The
// answer here splits into the half the extension fixes and the half it does not, the same
// split app.html's disclosure already makes.
edit('faq.html', [
  [`<p>The server sends the JavaScript that does the encryption, so whoever runs the server
controls that code. A hostile operator does not need to break the cryptography: they can
serve a modified page that copies your messages straight back to them, and it would look
exactly like this one. The verification code cannot catch that either, because the same
modified page draws it.</p>`,
  `<!-- EXTENSION PATCH: upstream this answer says the server sends the encryption code,
     which is the exact property this package removes. Split the answer into the half the
     extension fixes and the half it does not. -->
<p>In this extension, the code that does the encryption did not come from the server at
all: it shipped inside the package you installed, and it changes only when your browser
applies a signed update from the store. A hostile operator cannot hand this device a
modified page. They still run the signalling, so they still see the metadata (your
address, timing, room id, request sizes) and can refuse or end a gate, but they never
hold a key.</p>
<p>Anyone who opens your gate link in an ordinary browser is outside that protection:
the server sends them the JavaScript that does the encryption, so whoever runs the
server controls the code they run, and a modified page that copies messages straight
back to the operator would look exactly like the real one. Both ends need the extension
for both ends to be covered.</p>`],
  // The size answer. The download-manager route runs on a service worker, which an
  // extension page cannot register (see js/streamable.js), so "no size limit" is only
  // true here where the choose-a-location picker exists.
  [`<p>Sending has no limit in any browser. Receiving depends on the receiving browser. On a
Chromium desktop browser a large file is written straight to a location you choose, as
it arrives, and an interrupted transfer continues into the same file: a dropped
connection picks up where it left off, and so does a reload. On other browsers, a file
over 500&nbsp;MB is handed to the browser's own download manager and written straight to
disk as it arrives, so there is still no size limit, but it goes to your usual downloads
folder. A dropped connection still carries on by itself; reloading the page is what loses
the partial file, because the browser owns it and will not hand it back. Only a browser
that supports neither route holds the file in memory, capped at 500&nbsp;MB, and Warp
Gate refuses before the transfer starts rather than failing near the end.</p>`,
  `<!-- EXTENSION PATCH: the download-manager fallback runs on a service worker, and an
     extension page cannot register one, so that route does not exist here. -->
<p>Sending has no limit in any browser. Receiving depends on the receiving browser. On a
Chromium desktop browser a large file is written straight to a location you choose, as
it arrives, and an interrupted transfer continues into the same file: a dropped
connection picks up where it left off, and so does a reload. In this extension there is
no second route: handing a file to the browser's own download manager needs a service
worker, and an extension page cannot register one. A browser without the
choose-a-location picker holds the file in memory, capped at 500&nbsp;MB, and Warp Gate
refuses before the transfer starts rather than failing near the end.</p>`],
]);

// The privacy policy's storage list is introduced with "only for", so it has to be
// exhaustive here too: the extension writes one key the website does not, and the
// service worker the website installs cannot exist on an extension page.
edit('privacy.html', [
  [`  <li><code>localStorage</code>: a record that you accepted the Terms, with the version
      and date, so you are not asked on every visit; and, if you used the motion toggle
      on the front page, your animation preference, so it holds on your next visit.</li>`,
  `  <li><code>localStorage</code>: a record that you accepted the Terms, with the version
      and date, so you are not asked on every visit; and, if you used the motion toggle
      on the front page, your animation preference, so it holds on your next visit.</li>
  <!-- EXTENSION PATCH: the extension stores one thing the website does not, and a list
       introduced with "only" has to name it. -->
  <li><code>localStorage</code>: <code>wg.signalOrigin</code>, the signalling server you
      chose on the extension's own page, if you changed it from the default. It stays
      until you clear it there.</li>`],
  [`  <li><strong>A service worker</strong>, registered every time the gate page loads. It
      is a small script this site installs in your browser so that the site can be
      installed like an app and shared into from your device's share sheet, and so that
      a received file too large to hold in memory can be handed to your browser's own
      download manager and written straight to disk, instead of being held in the page. <strong>It never sees a key
      and never decrypts anything</strong>: the page decrypts and passes it finished
      bytes. Unlike the storage above it is not removed when the gate ends, because a
      service worker belongs to the site rather than to a session. You can remove it at
      any time by clearing site data for this site in your browser's settings.</li>
  <li><strong>Cache Storage</strong>: only if you send a file into the Service through
      your device's share sheet. The service worker keeps the file's contents there,
      unencrypted, so they survive the hop from the share sheet to the gate page. This
      is the one place in browser storage that ever holds a file's contents. The entry
      is deleted the moment the gate page picks the file up, every gate load clears out
      anything left waiting, and the worker drops anything older than ten minutes.</li>`,
  `  <!-- EXTENSION PATCH: the website installs a service worker for app install, the
       share sheet and very large files, and parks share-sheet files in Cache Storage.
       An extension page cannot register a service worker, so neither exists here and
       describing them would disclose storage that cannot exist. -->
  <li><strong>No service worker, and no Cache Storage.</strong> The website version
      installs a worker so the site can be installed like an app, shared into from a
      device's share sheet, and so very large files can be handed to the browser's own
      download manager, keeping a shared file's contents in Cache Storage on the way
      through. An extension page cannot register a service worker, so this package
      never installs any script that outlives its pages and never writes a file's
      contents to browser storage.</li>`],
]);

// The site root. `/` is the landing document, which this package does not ship: the
// extension's own index.html stands in its place. Applied mechanically to every copied HTML
// page rather than anchored, because it is the same rewrite everywhere and a per-file anchor
// list would go stale the moment a page gains another footer link.
export const ROOT_LINK_PAGES = ['app.html', 'faq.html', 'privacy.html', 'terms.html', 'acceptable-use.html'];

// Link-preview metadata. A packaged page cannot be pasted into a chat, so og:* can never
// fire here, and every tag in that block names the hosted origin: dead weight inside a
// package whose whole argument is that it does not depend on that server. Stripped for the
// same reason the root links are rewritten, and by the same mechanical rule.
export const PREVIEW_BLOCK = /<meta name="description"[\s\S]*?<meta name="twitter:card" content="summary_large_image">\n/;

/** Every file this directory deliberately changes. */
export const PATCHED_FILES = new Set([...PATCHES.keys(), ...ROOT_LINK_PAGES]);

/**
 * Apply the whole recipe for one file to its upstream text. Throws if an anchor is missing
 * or ambiguous, because a patch that silently fails to apply leaves a file that looks
 * patched and addresses the wrong origin at runtime.
 */
export function patchedText(rel, text) {
  for (const [from, to] of PATCHES.get(rel) ?? []) {
    const count = text.split(from).length - 1;
    if (count !== 1) {
      throw new Error(`the ${rel} anchor below matched ${count} times, not once.\n`
        + 'public/ has changed underneath this recipe. Fix the anchor, do not loosen it.\n'
        + `--- anchor ---\n${from}\n--------------`);
    }
    text = text.replace(from, to);
  }
  if (ROOT_LINK_PAGES.includes(rel)) {
    const before = text;
    text = text.split('href="/#support"').join('href="/index.html#support"')
      .split('href="/"').join('href="/index.html"');
    if (text === before) {
      throw new Error(`${rel} contains no link to the site root, so the rewrite that is `
        + 'supposed to redirect them all did nothing. Either the page changed or this loop is stale.');
    }
    // Fails loudly rather than matching nothing quietly: a block that stops being found is
    // a block that has started shipping again, and nothing else would say so.
    if (!PREVIEW_BLOCK.test(text)) {
      throw new Error(`${rel} carries no link-preview block, so the strip meant to remove `
        + 'it did nothing. Either public/ dropped the tags or this pattern is stale.');
    }
    text = text.replace(PREVIEW_BLOCK, '');
  }
  return text;
}

// ---------------------------------------------------------------- apply, on direct run only
// Importing this module (drift-check.mjs does) must not rewrite anything.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  // Every patch is computed BEFORE anything is written. Copying first and patching second
  // meant a single stale anchor left the mirror half-patched: the refusal was loud, the
  // exit code was 1, and the tree was still wrong, which is the state drift-check then
  // reported as two separate problems instead of one.
  const patched = new Map();
  for (const rel of PATCHED_FILES) {
    try {
      patched.set(rel, patchedText(rel, fs.readFileSync(path.join(PUBLIC, rel), 'utf8')));
    } catch (err) {
      process.stderr.write(`REFUSING to patch: ${err.message}\n`);
      process.stderr.write('nothing was written: the mirror is untouched\n');
      process.exit(1);
    }
  }
  let copied = 0;
  for (const rel of walk(PUBLIC)) {
    if (NOT_SHIPPED.has(rel)) continue;
    // Structural, not another list of names. pack.mjs ships by shape, so a public/ file
    // outside that shape would be copied here and then silently dropped from the archive:
    // present in the repo, absent from the package, and nothing saying so. Refused rather
    // than skipped, because "we decided not to ship it" is a decision that belongs in
    // NOT_SHIPPED above with a reason next to it.
    if (!ships(rel)) {
      process.stderr.write(`REFUSING to copy public/${rel}: pack.mjs ships manifest.json, the `
        + 'top-level .html pages and css/ icons/ js/, so this file would sit in the mirror and '
        + 'never reach a user.\n'
        + `Add '${rel}' to NOT_SHIPPED with the reason, or put it in one of those directories.\n`);
      process.exit(1);
    }
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
  for (const [rel, text] of patched) fs.writeFileSync(path.join(HERE, rel), text);
  process.stdout.write(`copied ${copied} files from public/\n`);
  process.stdout.write(`patched: ${[...PATCHED_FILES].join(', ')}\n`);
  process.stdout.write('now run: node extension/drift-check.mjs\n');
}
