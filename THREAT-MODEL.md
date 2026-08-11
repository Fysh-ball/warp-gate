# Warp Gate threat model

Written to be precise rather than reassuring. If something is not protected, it says so.

## The construction, in one paragraph

The creating browser draws an eight-word gate code from a fixed 7776-word list, worth
103 bits, and stretches it into the 128-bit-wide room secret with PBKDF2-HMAC-SHA256 at
600,000 iterations (`public/js/crypto.js`; the arithmetic is in DESIGN.md 3.2). The
secret is derived from the code, never generated directly, and never sent to the
server: the code lives in the URL fragment, which browsers do not transmit, and it
reaches each joining device by QR code or by a link you share. The room id the server sees is
derived from that secret through HKDF, so it reveals nothing. A gate seats up to six
devices (`WG_MAX_PARTICIPANTS`, operator-configurable), and **every pair of devices**
performs its own ephemeral ECDH P-256 exchange, mixes the room secret into that
pair's key schedule as the HKDF salt, and proves to the other end that it holds the
same secret before any data flows: the exchange is two-party per pair, and a gate is
a mesh of such pairs.
An optional room password, if the creator sets one, is stretched with PBKDF2 and
appended to that salt, so that both the link and the password are then needed to
derive the same keys.
A joining device also presents a separate one-way derivation of the secret to the
server, which lets the server refuse a seat to anyone who does not hold the link
without learning anything it could decrypt with.
All application data, and all signalling, is AES-256-GCM under keys derived from that
schedule.

## Protected against

| Threat | How | Residual risk |
|---|---|---|
| The server operator reading messages or files | Payload keys come from ECDH plus a secret the server never receives | Holds only while the server serves honest code: see "You are trusting whoever serves the page" |
| The server being compromised *after* you loaded the page | It holds no plaintext and no keys at any point. Gate state is a memory map with no storage layer behind it | None for anything sent through a gate. If the operator enabled the suggestion box there is one file on disk, holding suggestions and nothing from the signalling side: see "The suggestion box" below |
| The server or Cloudflare learning peer IP addresses from the SDP | Signalling payloads are encrypted under a key derived from the room secret, so the relay sees only `{n, c}`. On delivery it stamps the sender's seat id beside the envelope as `sfrom`: that names a seat it already authenticated by token, never anything from inside the envelope | Cloudflare still sees every participant's client IP from the HTTP connections themselves |
| A participant forging the sender of a signalling frame | The server stamps the token-authenticated seat id (`sfrom`) beside the sealed envelope, and the client drops any frame where it is missing or disagrees with the sealed `from` (`public/js/signal.js`) | The server is trusted for that attribution: a hostile server could mis-attribute signalling frames, but it still cannot forge the sealed body or pass key confirmation |
| An active man in the middle at the signalling layer | Each pair's key schedule mixes the room secret, and the two ends of every link exchange an explicit key confirmation before the UI reports that link connected | Someone who obtains the link is not a man in the middle; they are a participant |
| Someone who obtains the link but not the room password | If a password was set, the key schedule needs it as well: PBKDF2-HMAC-SHA256 at 600,000 iterations, salted with the room secret, appended to the HKDF salt | Only helps if a password was set and did not travel alongside the link. The server does not and cannot enforce it |
| Recording traffic now to decrypt later | Session keys need the ephemeral ECDH secret, which dies with the tab | None for message and file content |
| Tampering with any payload | AEAD on every frame; a single altered bit fails authentication and the frame is dropped | None |
| Replaying a captured frame | A strictly increasing per-direction counter, bound into both the nonce and the authenticated data | None |
| Passing a file chunk off as a chat message | The frame type is authenticated, so relabelling breaks the tag | None |
| Guessing a room code to read traffic | The room id is derived one-way from the room secret, whose 103 bits of entropy sit behind 600,000 PBKDF2 iterations; holding the id does not yield the secret, and key confirmation fails | A guessed id can confirm a room exists, and that probe is rate limited. It can no longer take a seat: see the next row |
| A device without the link taking a seat | Joining requires presenting a proof derived from the room secret (a one-way HKDF value; the server stores only its hash and compares in constant time), and each seated participant holds an unguessable capability token. Rooms also cap at a configured seat limit (`WG_MAX_PARTICIPANTS`, default 6) | Anyone who obtains the link holds the secret, so they can take a seat: they are a participant, not an intruder |
| Data outliving the session | Gate state is a single in-memory map. No database, no logs, and a restart destroys every room | None for gate content. The optional suggestion box is the one exception and it is a separate store: what you type into it is meant to outlive your session |
| A session being reused after expiry | Idle, hard and absolute deadlines plus a sweeper, and the room is deleted on sever | None |

## The suggestion box, the one thing that touches disk

Everything above about server state being memory only is true of the signalling side. There
is one deliberate exception, and it is worth stating plainly because the shipped deployment
turns it on.

If `WG_SUGGESTIONS_PATH` is set, the landing offers a box you can type into, and
`POST /api/suggest` appends what you typed to a file. `deploy/docker-compose.yml` sets that
variable by default, so the reference deployment, `warpgate.fysh.site` included, is running
with the box on. A checkout run with no environment at all is not: the route returns 404 and
the box is never rendered.

What lands in the file is one JSON object per line holding **the text, and the hour it
arrived**, rounded so the minute and the second are gone. Deliberately absent, and it must
stay that way: the IP, the rate-limit key derived from it, the user agent, the referrer, and
anything at all from the signalling side. There is no code path between the two halves of
the server, which is what stops a suggestion being correlated with the gate its author had
open at the time.

What an operator takes on by enabling it is a file of things strangers chose to say. It
survives restarts, it is in any backup or snapshot of that volume, and it is readable by
anyone who can read the host. It is created mode 0600, capped at about 1 MiB, and refuses
rather than rotating when full, but those bound its size and its permissions, not the fact
that it exists. Leaving `WG_SUGGESTIONS_PATH` unset keeps the "nothing survives a restart"
property whole, and that is the right default for a self-hosted copy: the box is the
operator's own inbox, and on someone else's instance there is nobody to write to.

## The landing and the gate are separate documents

Everything above about what the page cannot leak rests on one thing: the page loads no
code from anywhere but this origin. `default-src 'none'` says so, and the browser
enforces it.

That guarantee is exactly as strong as the weakest thing the same document is allowed
to load, and a marketing page has commercial reasons to want to load something. So the
landing (`index.html`, at `/`) and the gate (`app.html`, at `/app`) are two documents,
with two Content-Security-Policy headers, and no shared script, storage key or JS heap.

- The gate is served with `default-src 'none'` as the fallback, and every exception to it
  is `'self'`: `script-src`, `style-src`, `img-src`, `media-src`, `connect-src`,
  `font-src`, `manifest-src`, `worker-src` and `frame-src`, plus `blob:` on `img-src` and
  on `media-src` so a received image, video or audio file can be previewed from bytes the
  page itself created. Those are the only two directives carrying `blob:` and
  `tests/http.test.mjs` enumerates them positively, so a third cannot arrive unreviewed.
  **No external origin
  appears in it at all**, and `base-uri`, `form-action` and `frame-ancestors` are
  `'none'`. Nothing an operator can configure widens it: `WG_AD_ORIGINS` is matched
  against the resolved **filename** in `server/index.js`, not against a request path, so
  no route, redirect or traversal can carry a third-party origin onto it.
- The landing may be widened by `WG_AD_ORIGINS`, and only for `script-src`, `img-src`
  and `frame-src`. Never `connect-src`, so a script running *in the landing document*
  cannot open connections of its own. That is a real narrowing and it is not
  containment: `frame-src` is widened, and a third-party frame is a separate document
  served from the sponsor's origin under the sponsor's own CSP, not this one. It can
  fetch wherever it likes and report the visitor's address and timing whatever
  `connect-src` says here. The boundary that does hold is the narrower one, and it is
  the one that matters: **a sponsor cannot reach the gate.** Empty by default, and empty
  means the two documents get a byte-identical policy.
- Nothing about a gate is reachable from the landing even in principle. The secret
  lives in a URL fragment, which is never sent to a server, and a fragment aimed at the
  landing is handed straight to `/app` before anything else runs.

The tests assert both halves against a server with the variable actually set, because a
check run only with it unset would pass on a build where the split had been undone.

What this does NOT buy you: it is a containment boundary, not a trust boundary. A
hostile operator serves both documents and the section below still applies in full.

## You are trusting whoever serves the page

This is the most important limitation in this document, and it is inherent to every
web application that does cryptography in the browser, not specific to Warp Gate.

**The server sends the JavaScript that does the encryption.** Whoever controls the
server controls that code. A malicious operator does not need to break any of the
cryptography above: they can serve a modified page that copies the room secret, or the
plaintext, straight back to them, and it would look and behave exactly like this one.
The verification code cannot detect this either, because the same modified page draws
it.

So the guarantees above should be read precisely:

- They hold against **the network**, against **anyone watching traffic**, and against a
  server that is **compromised after** you have loaded the page.
- They do **not** hold against an operator who is hostile **when they serve you the
  page**.

What follows from that:

1. **Only use an instance you trust to run honest code.** The only instance the authors
   operate is **https://warpgate.fysh.site**. Check the address bar before sending anything
   sensitive.
2. **Anyone may host their own copy**, and the project is licensed and built so that
   they can. An instance someone else runs inherits none of the authors' trust, and the
   authors cannot vouch for it, audit it, or even know it exists.
   The source is published at `https://github.com/Fysh-ball/warp-gate` and the running
   site serves that link at `/api/config`, so point 3 below is actionable: you can read
   what is meant to be running and host it yourself. Warp Gate is AGPL-3.0 and section 13
   requires that offer to be a real one.
3. **If you need certainty, host it yourself** from source you have read. That is the
   configuration where the trust question answers itself, and it is why the
   project has no dependencies and no build step: the files served are the files in the
   repository, and you can read all of them.
4. **The browser extension takes the client out of the delivery path.** `extension/`
   ships the same client inside an MV3 package, installed once through a store's signed
   channel instead of arriving from the server on every visit, so the party that
   terminates TLS no longer chooses what code runs. Say what that costs with the same
   precision as the rest of this document. The trust root moves rather than vanishes:
   it is now the store's review and signing channel, and the manifest pins no Chromium
   extension id, so the package proves it came through a store, not that it is this
   repository's build. Retargeting the signalling origin is a feature (the server is
   the untrusted party here), and it is granted through
   `optional_host_permissions: ["https://*/*"]`, a user-gesture grant that can widen
   the extension's reach to any https origin the user approves. And the signalling
   metadata is unchanged: who connected to whom, when, and from which address is
   exactly as visible to the server and its CDN as before. See `EXTENSION.md` and
   `extension/README.md`.
5. For something truly high-stakes, encrypt it yourself before sending it, so that a
   compromised page never sees the plaintext at all.

### This is not hypothetical, and it is happening on the official instance

Measured 2026-08-10, during a deploy. The gate document served from
`https://warpgate.fysh.site/app` was **938 bytes larger** than the file on disk. The
difference was a `<script>` element appended before `</body>` that none of this source
contains: Cloudflare's JS Detections bootstrap, which creates a hidden iframe and loads
`/cdn-cgi/challenge-platform/scripts/jsd/main.js` into it.

Nothing was compromised. It is stock bot detection on the CDN that terminates TLS for
this hostname, and that CDN was already in the trusted position this section describes.
Say it out loud anyway, because it is the mechanism, running, in production, on the one
page that holds a decryption key in its heap: **a party between the source and the
browser modified the document, and no part of Warp Gate had to be involved.**

Two things about it are worth knowing.

- **The Content-Security-Policy stopped it.** `script-src 'self'` with no
  `'unsafe-inline'` and no nonce means an injected inline element cannot execute, however
  it got there. Verified in a real browser rather than reasoned about: the bootstrap's
  global is undefined and the iframe it appends as its first act is absent, with a control
  proving the same probe reports the opposite once one exists. `tests/cdn-injection.test.mjs`
  is that check, and it is kept permanently because the CDN's behaviour can change with a
  dashboard toggle nobody in this repository controls.
- **The CSP is a mitigation, not the answer.** It held because the injection was an
  inline script. The same party could serve a modified `app.js` from the same origin, and
  `'self'` permits that by definition. There is no header that fixes that case. What
  answers it is taking delivery out of the request path: host it yourself from source
  you have read (point 3), or install the extension (point 4), which ships the client
  in a package this party never touches.

## Not protected against

These are real limits, not hypotheticals.

- **A compromised device, browser or extension** on either end. Everything is visible there.
- **The other participants.** Anyone holding the link is a legitimate participant. They can
  save, screenshot, and forward anything you send. There is no way to prevent this and Warp
  Gate does not pretend to.
- **Any one participant ending the gate for everybody.** `POST /api/bye` destroys the
  room, not the caller's seat, and every seated participant is authorised to send it. In
  a two-device gate that is symmetric and unremarkable. With `WG_MAX_PARTICIPANTS`
  defaulting to 6 it is a unilateral kill: one participant, or anyone who has come by
  that participant's capability token, ends the session for the other five. This is
  deliberate. A gate is one shared thing behind one shared secret, so anyone entitled to
  be in it is entitled to shut it, and there is no owner and no vote. If you need a gate
  that a single participant cannot close, this is not it.
- **Participants learning each other's IP addresses.** Every pair in a gate connects
  directly, so every participant learns every other participant's address. This is
  inherent to a direct connection and is the property most at odds with using Warp Gate
  between identities you want kept apart. It is stated in the onboarding for that reason.
- **Cloudflare metadata**, when served through a tunnel: client IPs, timing, room ids,
  request sizes, session duration, **and the per-seat capability token**. Cloudflare
  terminates TLS in that topology. The payloads it carries are ciphertext, but the
  metadata is real. The token is in that list because it travels in the query string of
  `GET /api/events`, so it is visible to the TLS-terminating CDN, to any reverse proxy,
  and to any upstream access log. It is in the URL because `EventSource` cannot set
  request headers, which is a real constraint and not an oversight, but it is still the
  URL. Holding the token decrypts nothing: it carries no part of the room secret, and
  every payload it could reach is ciphertext. What it authorises is the seat: the same
  token is what `POST /api/relay` and `POST /api/bye` check, so whoever holds it can
  inject signalling frames at a named peer and can destroy the gate for everyone in it.
  `referrer-policy: no-referrer` closes the `Referer` path; nothing closes the log path.
  The same applies to the
  STUN server, which is deliberately Cloudflare's: it learns each device's public
  address, which Cloudflare already observes from the signalling connection itself. The
  point of choosing it is that it adds no party that was not already there. STUN is
  **opt-in**: a fresh checkout advertises no STUN server and starts no UDP listener, so
  a self-hoster who copies the repository does not get an outward-facing service they
  did not ask for. `warpgate.fysh.site` sets `WG_STUN_URL` to Cloudflare's in its compose
  file, and the choice is therefore visible in the deployment rather than implicit in
  the code.
- **Your real address, even behind a proxy.** WebRTC discovers the network address of
  the interface it actually sends from. Loading the page through a proxy does not
  change that, which is why the onboarding says Warp Gate is confidential, not
  anonymous.
- **Traffic analysis.** Nothing is padded, delayed or covered. Message and file sizes and
  timings are observable to anyone watching the network.
- **Browser memory hygiene.** The operating system may page a tab's memory to disk. No
  web application can prevent that.
- **Clipboard clearing.** Best effort only. Other applications may already have taken a
  copy, and no browser guarantees a clipboard can be cleared.
- **Anonymity.** Warp Gate is confidential, not anonymous.
- **Denial of service.** Someone who merely guesses a room id can no longer occupy a
  seat: joining requires proof of knowledge of the room secret, and the proof is checked
  before the server reveals anything about the room's occupancy. What remains is
  ordinary resource flooding, which is rate limited, and a person who already holds the
  link taking a seat, which is the "other person" case above. Re-create the gate if a
  seat is held by someone unwanted.

## Design decisions worth knowing

**The room password is a second factor for a leaked link, not a substitute for the
link.** An earlier version of this document said there was no password option. There is
one now, and this is what it does and does not do.

When the creator sets a password, it is stretched with **PBKDF2-HMAC-SHA256 at 600,000
iterations**, salted with the room secret itself (`secret || "wg/v1/password"`),
and the result is **appended to the room secret in the HKDF salt** of the session key
schedule. So the derived keys depend on both values. Someone who has the link but not
the password derives different keys, fails key confirmation, and gets nothing.

Why that is not the trap a spoken password usually is: the password is never the only
secret. The link secret, 103 bits behind its own 600,000-iteration stretch, is still
there and still doing the authentication work.
An observer of the signalling channel has no offline target to grind, because they do
not hold the link secret either. The password's actual job is the case where **the link
leaks** but the password did not travel with it: pasted into the wrong chat, shoulder
surfed, screenshotted, left in a scrollback. 600,000 PBKDF2 iterations then make each
guess expensive for someone who has the link and is guessing the password.

What it is not:

- **The server does not enforce it.** The room carries a `requiresPassword` flag, the
  server stores it and reports it so the joining page can prompt, and that is all it is:
  **advisory**. The server never sees the password, cannot see it, and cannot check one.
  Do not read the flag as an access control.
- **It is not a PAKE.** A password used as the sole secret would still need CPace or
  similar, and no reviewed browser implementation is obtainable under this project's
  no-dependency constraint. That reasoning has not changed. What changed is that the
  password here is layered on top of a high-entropy link secret rather than standing in
  for one.
- **It does not stop someone who has the link from occupying a seat.** The server
  admits anyone who proves knowledge of the link secret, and the password never reaches
  it, so a person with the link but not the password can still take a seat: they derive
  different keys, fail confirmation and read nothing, but they hold the seat until the
  gate is re-created. (A guesser who has only a room id cannot take a seat at all:
  joining requires a proof derived from the link secret. See "Denial of service"
  above.)

**Opening a received file is allowlisted, and the type is forced rather than trusted.** A
`blob:` URL is same-origin with the document that created it, so navigating to a blob whose
type is `text/html` runs the sender's markup inside the gate's own origin, next to the room
key. There is no sandbox on a `blob:` document and no header that can be attached to one.
So the Open button in a transcript row exists only for types on a fixed table in
`public/js/preview.js` (raster images, the common video and audio containers, and
`text/plain` pinned to UTF-8), and the blob it navigates to is rebuilt with the type from
that table, never with the MIME the peer declared. A type that is not in the table gets no
button at all. `text/html`, `application/xhtml+xml`, `image/svg+xml`, XML and
`application/pdf` are deliberately absent: each is an active document format, and Save
already puts the file where the system's own reader can open it.

**`/api/health` returns liveness and nothing else.** It answers `{"ok":true}`. It used
to also publish a live count of open gates, which was a usage side channel on a tool
whose whole premise is that the server learns nothing: anyone could poll it and watch
when the instance was in use and by roughly how many people, and someone guessing room
ids could use it as a progress meter. The container healthcheck only ever needed `ok`,
so the count was removed rather than access-controlled.

**There is no whole-file hash.** Every chunk is individually authenticated and bound to
its position in the sequence, so a file-level hash would add no security property. What
is checked at the end is that the reassembled byte and chunk counts match what was sent.

**There is no relay in this version.** If a direct connection cannot be established, Warp
Gate says so and stops, rather than silently routing through a server. A future relay
would carry ciphertext only, and would be labelled in the interface when in use.

**Key material is non-extractable.** Session keys are `CryptoKey` objects the browser
will not export, so the raw bytes never enter JavaScript memory. Dropping the reference
on sever is the strongest erasure a browser offers, since a JavaScript byte array cannot
be reliably wiped. (One narrow engine fallback exists: a browser that refuses the direct
ECDH-to-HKDF derivation briefly holds the shared secret as bytes, which are zeroed
immediately, and the fallback announces itself rather than passing silently.)
