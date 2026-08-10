# Warp Gate

A temporary, end-to-end encrypted bridge between browsers. Open it, send what you
need, close it. Nothing is left behind.

No accounts. No installation. No database. No dependencies.

## What it does

Devices open a link. A gate seats up to six devices (`WG_MAX_PARTICIPANTS`; two is
the common case), every pair connects directly to each other over WebRTC with its own
keys, and the server drops out of the path. Over those connections they can:

- chat
- send a secret (a password, an auth key, a config snippet) with a masked display and a
  best-effort clipboard timer
- send a file, chunked and authenticated

Then any participant severs the gate, or it expires on its own.

## The official instance

**https://warpgate.fysh.site is the only instance the authors run.**

Anyone may host their own copy, and that is encouraged: it is the whole reason this is
open source and the reason there are no dependencies. But an instance somebody else runs
inherits none of this one's trust. The authors cannot audit it, vouch for it, or know it
exists.

> **The source is published**, at `https://github.com/Fysh-ball/warp-gate`, and the
> running site offers that link at `/api/config`. Warp Gate is AGPL-3.0 and section 13
> requires offering the corresponding source to anyone using it over a network, so this
> is a licence obligation rather than a courtesy: if you run a modified copy where other
> people can reach it, point `WG_SOURCE_URL` at your version.
>
> Note that the public repository is published as a single squashed commit rather than
> the full development history, because the earlier history contained deployment notes
> specific to the authors' own machines.

### Why that matters more than it might sound

The server sends the JavaScript that does the encryption, so **whoever serves the page
controls the code**. A hostile operator does not need to break any of the cryptography:
they can serve a modified page that copies the room secret straight back to them, and it
would be indistinguishable from this one. The verification code cannot catch it either,
because the same modified page draws it.

This is true of every web application that encrypts in the browser. It is not a flaw
that can be patched, so it is documented instead of glossed over. The practical
conclusions:

- Check the address bar before sending anything sensitive.
- If you need certainty, **host it yourself from source you have read**. Warp Gate has no
  dependencies and no build step precisely so that this is realistic: the files served
  are the files in this repository, and there are about twenty of them.
- For something truly high-stakes, encrypt it yourself before sending it, so a
  compromised page never sees plaintext at all.

## Running it

```sh
node server/index.js
```

That is the whole thing. Node 22 or later, no install step, no build step, no package
manager. Open `http://127.0.0.1:3095`.

### Self-hosting

```sh
git clone https://github.com/Fysh-ball/warp-gate && cd warp-gate
node server/index.js                     # http on 3095

# behind TLS, with a STUN server so it works across networks:
WG_STUN_URL=stun:stun.cloudflare.com:3478 \
WG_TRUST_PROXY=1 WG_HSTS=1 node server/index.js
```

**STUN is opt-in, and that is deliberate.** Out of the box `WG_STUN_URL` is unset and
`WG_STUN_ENABLED` is off, so Warp Gate advertises no STUN server to browsers and opens
no UDP socket. Running this repository does not hand you a third party you did not
choose or an outward-facing service you did not ask for. The cost is that connections
work on one network only until you set `WG_STUN_URL`, which the interface says plainly
rather than just failing.

Which STUN server to point at is a privacy decision, so make it deliberately.
`stun.fysh.site` does not exist; `warpgate.fysh.site` uses `stun.cloudflare.com` because
Cloudflare already terminates its TLS and therefore already sees every participant's address,
so it adds no new party. That reasoning is specific to a deployment already behind
Cloudflare and does not transfer automatically to yours. `deploy/SELF-HOSTING.md`
explains it, including why self-hosting the built-in responder in `server/stun.js`
turned out to be the more exposing option rather than the more private one.

Put any TLS terminator in front of it. `deploy/docker-compose.yml` is a working example
using a stock node image with the source mounted read-only, and `deploy/SELF-HOSTING.md`
explains the STUN and proxy choices. Every option is an environment variable in
`server/config.js`.

### Capacity

The server drops out of the data path once the peers connect, so files and messages never
touch it: their size and volume cost it nothing. What costs it is the number of gates open
at once and how many seats each one holds. A six-seat gate runs fifteen peer-to-peer links,
but those live in the browsers; the server's share is six slots and six event streams.

Measured on one process with `tools/loadtest.mjs`, each simulated device on its own
loopback address so the per-client limits do not bound the run. Baseline RSS before load
was 75 MB in every case:

| Gates | Seats each | Streams | RSS at full load | Per gate |
|---|---|---|---|---|
| 200 | 2 | 400 | 90 MB | 79 KB |
| 200 | 6 | 1,200 | 114 MB | 197 KB |
| 2,000 | 2 | 4,000 | 196 MB | 62 KB |

Handshake relays were still delivered at every load, and every gate was released on
teardown. A seat costs roughly 33-39 KB whichever way the gates are shaped, so cost tracks
seats rather than gates.

**Watch the interaction between the two defaults.** The shipped `deploy/docker-compose.yml` caps
the container at 128 MB, and the shipped `WG_MAX_ROOMS` is 200. Two hundred *full*
six-seat gates measured 114 MB, which is 89% of that limit before counting rate-limit
state. Two hundred two-seat gates is a comfortable 90 MB. If you expect large gates, either
raise `mem_limit` or lower `WG_MAX_ROOMS`: the two defaults were chosen when a gate held
exactly two devices and they have not been retuned for six.

Within a 128 MB container the practical ceiling is roughly 850 two-seat gates or 270
six-seat ones. A Raspberry Pi is still more than enough, which was the design target.

Configuration is environment variables, all optional: see `server/config.js`.

For real deployment, including the Cloudflare and STUN decisions, read
[deploy/SELF-HOSTING.md](deploy/SELF-HOSTING.md).

## How it is put together

```
server/           the signalling process, Node standard library only
  index.js        HTTP, static files, security headers, shutdown
  rooms.js        the in-memory room map, idle / hard / absolute deadlines, sweeper
  signal.js       config / health / room / create / join / relay / bye / SSE event stream
  stun.js         an RFC 5389 binding responder, off unless WG_STUN_ENABLED=1
  limits.js       rate limiting that does not retain IP addresses
public/           the client, plain ES modules, no framework
  js/crypto.js    key schedule, AEAD framing
  js/session.js   the protocol state machine
  js/peer.js      WebRTC and backpressure
  js/transfer.js  chunking and receive-sink selection
  js/download.js  streamed downloads through the browser's own download manager
  sw.js           the service worker that makes those streamed downloads possible
  js/qr.js        a QR encoder written here against ISO/IEC 18004, not a vendored library
  js/app.js       the interface
tools/            operational probes
tests/            six suites, all runnable offline
```

The server holds one `Map` of rooms, plus in-memory rate counters, and nothing else.
Restarting it destroys every live gate, which is the intended behaviour.

## Security

The short version: your messages and files are encrypted in the browser before they are
sent, the server never has the keys, and it never sees a file name or a message. The
secret lives in the part of the URL after the `#`, which browsers do not send to
servers.

The creator can also set an optional room password. It is not a login: it is stretched
with PBKDF2 at 600,000 iterations and mixed into the key schedule alongside the room
secret, so it protects the case where the link itself leaks and the password did not
travel with it. The server never sees it and cannot check it. The full description,
including what it does not do, is in the threat model.

The honest version, including what this does **not** protect you from, is in
[THREAT-MODEL.md](THREAT-MODEL.md). The design reasoning, including fifteen changes made
to the original specification and why, is in [DESIGN.md](DESIGN.md).

One thing worth repeating here: direct connections mean **every device in a gate
learns the other devices' IP addresses**. Warp Gate is confidential, not anonymous.

## Tests

```sh
bash tests/run-all.sh
```

| Suite | What it proves |
|---|---|
| `crypto` | The key schedule matches an independent implementation written from RFC 5869 with `node:crypto`. Wrong secrets, replays, type confusion, bit flips and counter rewrites all fail closed. |
| `qr` | Generated QR codes are decoded back byte-for-byte by `zbarimg`, an unrelated decoder, at every supported version. |
| `signalling` | The server over the wire: room lifecycle, tokens, join proofs, opaque relay, rate limits, expiry, reconnection and join races. |
| `http` | The HTTP surface itself: security headers, static-file containment, rate limiting on every route, and behaviour under abuse. |
| `download` | The streamed-download path in a real browser: the bytes that land on disk via the browser's own download manager hash to what the page fed in. |
| `browser` | Two tabs of a real headless browser complete the whole lifecycle: create, join by link, direct WebRTC, chat, secret, a 300 KiB file, and severing. |

The suites include negative controls, because a check that cannot fail proves nothing.
The STUN probe is run against a dead port first, and the QR decoder against a corrupted
matrix, to show each check is capable of reporting failure before its passes are
trusted.

Requirements: Node 22+, `zbarimg` for the QR suite, and a Chromium-based browser for the
browser suite.

## Licence

[GNU Affero General Public License v3.0](LICENSE).

Run it, read it, modify it, host it. Section 13 is the part worth knowing: **if you run a
modified version and let other people use it over a network, you must offer those users
the source of your modified version.**

That obligation is doing real work here. As set out above, a user cannot verify that a
host is serving honest code, and no licence can change that. What the AGPL does is oblige
an honest operator to publish their changes, and make concealing a modification a licence
violation rather than merely bad manners. Set `WG_SOURCE_URL` to wherever your copy lives
and the page will show a Source link; the server warns at startup if it is unset.
