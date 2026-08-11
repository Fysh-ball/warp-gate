# Warp Gate as a browser extension

An MV3 extension that ships the Warp Gate client inside the package instead of downloading
it from a server. Nothing here is built, bundled or minified: the files in this directory
are the files that run.

## Why this exists

Warp Gate is end-to-end encrypted between browsers and the signalling server never holds a
key. The residual risk was never the transport, it was the **delivery of the client**.
The official instance sits behind Cloudflare, which terminates TLS and can therefore serve
modified JavaScript to a targeted visitor. A modified `app.js` from the same origin defeats
every guarantee the product makes, and `Content-Security-Policy` cannot help, because the
malicious code would be first-party.

`THREAT-MODEL.md` documents that this is not hypothetical: on 2026-08-10 the gate document
served from the official instance was 938 bytes larger than the file on disk, because the
CDN appends its own bot-detection bootstrap. The CSP stopped that particular injection
because it was inline. It cannot stop the same party serving a modified script file, and
there is no header that can.

An extension changes exactly one thing, and it is the one that matters: the client is
installed once, reviewed by a store, and replaced only through the store's signed channel.
The network can no longer swap it per request.

It changes **nothing else**. The signalling server still sees the metadata, the peer at the
other end is still running the web client unless they installed this too, and a compromised
device still sees everything. `index.html` in this package says all of that to the user in
their own words, and the gate's own "who is serving you this page" disclosure has been
rewritten to say it as well.

## Install it unpacked

Chromium (Chrome, Brave, Edge): `chrome://extensions`, enable Developer mode, **Load
unpacked**, choose this directory.

Firefox: `about:debugging#/runtime/this-firefox`, **Load Temporary Add-on**, choose
`manifest.json`. See "Firefox" below for what is and is not known to work there.

Click the toolbar icon to open a gate. The extension's own page (`index.html`, also the
options page) explains the security model and is where the signalling origin is set.

## Verify it

```
node extension/extension.test.mjs      # 35 checks, real browser, real local server
node extension/drift-check.mjs         # is the copied client still in step with public/?
```

`extension.test.mjs` starts a server from this tree on loopback, loads the package into a
headless Chromium with `--load-extension`, and drives the real UI. It never touches the live
deployment. Point it at a different package with `WG_EXT_TEST_DIR`.

## Architecture

### What was chosen

The whole web client is **copied** into this directory, and the four files that address the
network are patched to route through one new module, `js/endpoint.js`. That module is the
only place that knows where the signalling server is.

Static assets need no change at all, which is the reason the copy works: `public/app.html`
references everything by absolute path (`/css/style.css`, `/js/app.js`, `/icons/...`), and
an extension package's root *is* the origin root, so every one of those paths resolves
inside the package unchanged.

### What was rejected

- **Monkeypatching `fetch` and `EventSource`** in a shim loaded before the module graph.
  This needs zero edits to the copy, which would have kept it byte-identical to `public/`.
  Rejected because a global that silently rewrites the destination of every request is
  exactly the invisible indirection that stops an auditor answering "where does this byte
  go" by reading the call site. The property being shipped here is auditability; trading it
  for a smaller diff is the wrong trade.
- **A hardcoded signalling origin.** The server is the untrusted party in this design, so
  the ability to point at your own is the feature, not the risk.
- **`chrome.storage` for the origin.** It is asynchronous, and the client's boot path issues
  its first request without waiting for anything this extension controls. The race would
  present as "works on the second load". `localStorage` is synchronous, is scoped to the
  extension origin, is shared between `index.html` and `app.html`, and needs no permission.
- **A popup for the toolbar action.** The gate is a full application with a QR code, a file
  list, a chat composer and a live status log. A panel that closes when the user clicks
  anything else in the browser is a hostile place to run a transfer, so the action opens a
  tab.
- **`host_permissions: ["https://*/*"]`.** One line shorter, and it would ship an extension
  whose pitch is "the destination is yours to choose" with standing permission to talk to
  every site on the internet. The default grant is the default instance plus loopback;
  anything else goes through `optional_host_permissions` and a browser prompt at the moment
  the user changes it.

### The copy, and how it is kept honest

A fork of 14,000 lines of security-relevant JavaScript rots. It rotted **during the writing
of this directory**: `public/css/style.css`, `public/css/games.css` and `public/js/gameui.js`
were edited by other work in the repository within the hour, and the copy was silently a
version behind until `drift-check.mjs` said so. So the copy is derived from a recipe rather
than maintained by hand:

- `sync-from-public.mjs` re-copies `public/` and re-applies every patch. Each patch is an
  exact string match and the script **exits non-zero if an anchor is missing or ambiguous**,
  because a patch that silently fails to apply leaves a file that looks patched and
  addresses the wrong origin at runtime.
- `drift-check.mjs` verifies the result: every unpatched shared file is byte-identical to
  `public/`, every patched file is byte-identical to a fresh application of the recipe to
  today's `public/` (so an edit to `public/`, to the shipped copy, or to the recipe itself
  reads as drift until the sync is rerun), nothing in `public/` has gone missing without a
  stated reason, nothing unaccounted for is sitting in this directory waiting to ship
  inside the package, and the default origin in `js/endpoint.js` agrees with
  `manifest.json`'s host_permissions and with the patched disclosure in `app.html`.

Neither is a build step. The package is complete and checked in; these are the tools that
tell you when it has fallen behind.

### The patch list

| File | Change |
| --- | --- |
| `js/signal.js` | 5 request URLs go through `api()`: `/api/events`, `/api/relay`, `/api/bye`, `/api/room`, `/api/config`. |
| `js/session.js` | `postRoom()`'s `fetch(path)` goes through `api()`. Covers `/api/create` and `/api/join`. |
| `js/app.js` | The shareable gate link is `gateLink(code)` instead of `location.origin + location.pathname`. The "who is serving you this page" block is rewritten. |
| `js/streamable.js` | `supportsStreamDownload()` returns false on an extension origin. See "Streaming download" below. The patch used to sit in `js/download.js` and followed the function when upstream moved it into its own module; `download.js` re-exports the binding, so both call sites still get the patched answer. |
| `app.html` | The web app manifest link is removed, the instance disclosure is rewritten, and links to `/` point at this package's `index.html`. |
| `faq.html` | The operator-trust answer is split: the encryption code came from this package, not the server, while the signalling metadata claims stand; and the file-size answer drops the download-manager route, which needs a service worker an extension page cannot register. Links to `/` point at this package's `index.html`. |
| `privacy.html` | The storage list ("only for") gains the `wg.signalOrigin` localStorage key this package writes, and the service-worker bullet is replaced: no worker can exist on an extension page. Links to `/` point at this package's `index.html`. |
| `terms/acceptable-use.html` | Links to `/` point at this package's `index.html`. |

Files added by this directory: `manifest.json`, `index.html`, `js/endpoint.js`,
`js/options.js`, `js/background.js`, and the three `.mjs` tools.

Files in `public/` deliberately **not** shipped: `index.html` (the site landing page; this
package's own `index.html` replaces it), `js/landing.js` (only the landing loads it),
`sw.js` (an extension page cannot register a service worker), `manifest.webmanifest` (names
a `start_url` and scope on a server).

### Where this package's CSP differs from the server's

The served site's policy is `CSP_DIRECTIVES` in `server/index.js`; this package's is the
`content_security_policy.extension_pages` string in `manifest.json`. They are not the same
string and must not be, so the differences are enumerated here rather than left to be
rediscovered a directive at a time. Identical in both: `default-src 'none'`,
`script-src 'self'`, `style-src 'self'`, `img-src 'self' blob:`, `media-src 'self' blob:`,
`font-src 'self'`, `base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`.

| Directive | Server | Here | Why |
| --- | --- | --- | --- |
| `connect-src` | `'self'` | `https:`, `http://localhost:*`, `http://127.0.0.1:*` | The reason this directory exists: the client is not served by the origin it signals to, so `'self'` would block every `/api/*` call. `host_permissions` is the narrow gate; this directive cannot be narrower than the origin a user is permitted to configure. |
| `manifest-src` | `'self'` | absent | `manifest.webmanifest` is not shipped and the patch removes the `<link rel="manifest">` from `app.html`, so there is nothing to fetch. |
| `worker-src` | `'self'` | absent | `sw.js` is not shipped: Chromium refuses to let an extension page register a service worker at all. See "Streaming download is gone" below. |
| `frame-src` | `'self'` | absent | That frame exists only to dispatch a request to that service worker. With no worker there is nothing for it to do. |

`media-src 'self' blob:` was **missing here until 2026-08-10**, and it is the one difference
that was never a decision. `js/preview.js` previews a received video or audio file by
assigning a `blob:` object URL to a `<video>` or `<audio>` element, and a media element
loads through `media-src`, not `img-src`. Without the directive it inherited
`default-src 'none'` and every inline video and audio preview failed with "Media load
rejected by URL safety check", which reads to a user as a corrupt file rather than as a
policy decision. Inline IMAGE previews kept working, because `img-src` already carried
`blob:`, so the failure looked specific to the file rather than to the package. The verified
run below never previewed a file, which is how "no CSP violation" was true and this was
broken at the same time. `'self'` and `blob:` only, exactly as the server sets it and for
the reasons given there.

The camera scanner needs nothing from this policy, which is worth stating because it looks
as though it should: `js/qrscan.js` attaches the camera with `video.srcObject = stream`, and
a `MediaStream` assigned to a property is not a URL fetch, so no fetch directive is
consulted. Only the legacy `URL.createObjectURL(stream)` spelling would have gone through
`media-src`.

## What works, end to end, verified

Driven in headless Brave against a server started from this tree. Every claim below is an
assertion in `extension.test.mjs`.

- The package loads with no manifest error and its background worker starts.
- `app.html` opens from the package, and **every** script, style, image and font it loads
  came from the package. Measured off the CDP network domain from before the first byte,
  and cross-checked against `document.styleSheets` and every `script[src]`. The only
  requests that leave the package are `/api/*` calls to the configured origin.
- The extension's own page states what the extension does not protect against, and names
  the metadata the signalling server still sees.
- `GET /api/config` succeeds cross-origin from the extension page.
- A gate is really created: the onboarding gate is answered, Create is pressed, the exposure
  notice is answered, a code is minted, and **the server confirms it is holding that room**
  when asked directly.
- The copied share link points at `<signalling origin>/app#<code>`, captured off the real
  copy button rather than recomputed. The secret is not in the address bar.
- No CSP violation, no uncaught page error.
- `supportsStreamDownload()` correctly reports false.

The checks were shown to **fail**, not merely to pass. A copy of this package with one
remote `<script>` injected into `app.html` fails three of them, including the CSP recorder,
which reports `script-src-elem http://127.0.0.1:3801/js/app.js`: the extension's own policy
blocked it. `drift-check.mjs` failed for real on three genuinely drifted files before it was
ever asked to.

## What does NOT work, and what is untested

- **No second peer was driven.** There is no WebRTC handshake, no file transfer, no chat and
  no game in this run. `tests/browser.test.mjs` drives all of that against the web client
  and the extension changes none of those code paths, but that is an argument, not a
  measurement. Pairing two extension tabs is the next piece of work.
- **Streaming download is gone.** Chromium refuses to let an extension *page* register a
  service worker: `navigator.serviceWorker.register('/sw.js')` throws "The user denied
  permission to use Service Worker", even though `'serviceWorker' in navigator` and
  `isSecureContext` are both true. On Chromium this costs little, because
  `showSaveFilePicker` is the preferred route anyway and works here. On a browser without
  the picker it is a real regression: files above the 500 MB memory limit cannot be
  received. `js/streamable.js` is patched so the capability gate says no up front rather
  than accepting a transfer it cannot deliver. `js/download.js` re-exports that same
  predicate, so patching the one definition covers `transfer.js` and `download.js` both.
- **The share target is gone** with the service worker. Sharing a file into Warp Gate from
  the OS is a PWA feature and has no extension equivalent here.
- **QR scanning is untested.** `getUserMedia` on an extension page should prompt and work,
  but nothing in this run pressed the scan button. The panel moved out of `app.js` and into
  `js/scanui.js` upstream on 2026-08-10 and this package **ships it**: `app.html` here still
  carries the scan button and the `scan-panel` markup, and `js/app.js` dynamically imports
  `./scanui.js` when the button is pressed, so leaving the file out would turn a visible
  working button into a runtime import failure. Nothing in `manifest.json` gates it: MV3 has
  no camera permission, and the prompt is the browser's own against the extension origin.
- **Firefox is untested.** The manifest carries `background.scripts` alongside
  `background.service_worker` and a `browser_specific_settings.gecko` block, and adding them
  was verified not to break the Chromium load. Nothing beyond that has been run. What needs
  checking there: whether `moz-extension://` pages get the same CORS bypass from
  `host_permissions`, whether `EventSource` works cross-origin from one, and whether
  `optional_host_permissions` prompts as expected.
- **`extension.test.mjs`, `drift-check.mjs` and `sync-from-public.mjs` ship inside the
  package.** Harmless but pointless. Exclude them when zipping for a store submission.
- **The extension id is not pinned.** An unpacked load derives it from the path, so it
  changes with the checkout directory. A store submission gets a stable id from the store.

## Required follow-ups in `public/`

These were not made: `public/` is owned by other work in flight. Each one would let this
directory carry less of its own.

1. **Add `public/js/endpoint.js` upstream, defaulting to same-origin, and route the six
   request sites through it.** `signal.js` has five, `session.js` has one. Upstream the
   function is `const api = (path) => path;` and nothing changes about the served site. With
   it, the extension supplies its own `endpoint.js` and needs **zero** patches to
   `signal.js` and `session.js`, which is two thirds of the fork gone.
2. **Make the shareable link a function of the same module.** `app.js` builds it as
   `` `${location.origin}${location.pathname}#${formatted}` ``, which is right for a served
   page and wrong for any client that is not served by the server it signals to.
3. **Fix `supportsStreamDownload()` upstream.** It reports true on any origin where a page
   service worker cannot be registered, and it is consulted as a capability gate before a
   large file is accepted. This is a real bug in `public/js/streamable.js` independent of the
   extension: the predicate promises a route it cannot open, and the failure lands after the
   user has clicked Accept. Upstream now documents it as a KNOWN GAP in the doc comment above
   the function, which is an improvement on silence but is still the bug rather than the fix.
4. **Consider making the "who is serving you this page" copy data-driven** rather than
   keyed on `location.hostname`, so a client that was not served by the signalling origin
   can state its own situation without a patched block.

None of these are required for the extension to work today. It works today.

## Server changes

**None.** No file under `server/` was modified, and none needs to be. This was the open
question going in and it is worth stating the answer plainly:

- `server/signal.js:255-260` refuses a `POST` when `Sec-Fetch-Site` is `cross-site` or
  `same-site`. Measured on 2026-08-10: Chromium does **not** send a cross-site value for a
  fetch initiated by an extension page, so `POST /api/create` from `chrome-extension://…`
  reaches the route and is answered on its merits. There is no `Origin` check anywhere in
  `server/`, and no `Access-Control-Allow-*` header is ever set, which does not matter
  because `host_permissions` makes the browser skip CORS for an extension page.
- `EventSource` to `/api/events` on another origin works from an extension page and
  delivers the `hello` frame.

If a future server ever *does* start matching on `Origin`, this extension breaks completely
and the fix is a server-side allowance for `chrome-extension://` and `moz-extension://`
origins. Worth knowing before someone adds one.
