# Warp Gate

A temporary, end-to-end encrypted bridge between two browsers. Open it, send what you
need, close it. Nothing is left behind.

No accounts. No installation. No database. No dependencies.

## What it does

Two devices open a link. They connect directly to each other over WebRTC, and the
server drops out of the path. Over that connection they can:

- chat
- send a secret (a password, an auth key, a config snippet) with a masked display and a
  best-effort clipboard timer
- send a file, chunked and authenticated

Then either side severs the gate, or it expires on its own.

## The official instance

**https://wg.fysh.site is the only instance the authors run.**

Anyone may host their own copy, and that is encouraged: it is the whole reason the source
is public and the reason there are no dependencies. But an instance somebody else runs
inherits none of this one's trust. The authors cannot audit it, vouch for it, or know it
exists.

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
  are the files in this repository, and there are about a dozen of them.
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
git clone <repository> && cd warp-gate
node server/index.js                     # http on 3095

# behind TLS, with a STUN server so it works across networks:
WG_STUN_URL=stun:stun.cloudflare.com:3478 \
WG_TRUST_PROXY=1 WG_HSTS=1 node server/index.js
```

Put any TLS terminator in front of it. `deploy/docker-compose.yml` is a working example
using a stock node image with the source mounted read-only, and `deploy/NOTES.md`
explains the STUN and proxy choices. Every option is an environment variable in
`server/config.js`.

### Capacity

The server drops out of the data path once two devices connect, so files and messages
never touch it: their size and volume cost it nothing. Only the number of gates open at
once costs anything.

Measured on one process with `tools/loadtest.mjs`:

| Concurrent gates | Live connections | Peak RSS | Per gate |
|---|---|---|---|
| 2,000 | 4,000 | 198 MB | ~66 KB |

Handshake relays were still delivered normally at that load. The default cap is 200
concurrent gates, which costs a few megabytes; raise `WG_MAX_ROOMS` if you need more. A
Raspberry Pi is more than enough, which was the design target.

Configuration is environment variables, all optional: see `server/config.js`.

For real deployment, including the Cloudflare and STUN decisions, read
[deploy/NOTES.md](deploy/NOTES.md).

## How it is put together

```
server/           the signalling process, Node standard library only
  index.js        HTTP, static files, security headers, shutdown
  rooms.js        the in-memory room map, dual TTL, sweeper
  signal.js       create / join / relay / bye / SSE event stream
  stun.js         an RFC 5389 binding responder
  limits.js       rate limiting that does not retain IP addresses
public/           the client, plain ES modules, no framework
  js/crypto.js    key schedule, AEAD framing
  js/session.js   the protocol state machine
  js/peer.js      WebRTC and backpressure
  js/transfer.js  chunking and receive-sink selection
  js/qr.js        a small QR encoder
  js/app.js       the interface
tools/            operational probes
tests/            four suites, all runnable offline
```

The server holds one `Map` of rooms and nothing else. Restarting it destroys every
live gate, which is the intended behaviour.

## Security

The short version: your messages and files are encrypted in the browser before they are
sent, the server never has the keys, and it never sees a file name or a message. The
secret lives in the part of the URL after the `#`, which browsers do not send to
servers.

The honest version, including what this does **not** protect you from, is in
[THREAT-MODEL.md](THREAT-MODEL.md). The design reasoning, including fifteen changes made
to the original specification and why, is in [DESIGN.md](DESIGN.md).

One thing worth repeating here: a direct connection means **each device learns the
other's IP address**. Warp Gate is confidential, not anonymous.

## Tests

```sh
bash tests/run-all.sh
```

| Suite | What it proves |
|---|---|
| `crypto` | The key schedule matches an independent implementation written from RFC 5869 with `node:crypto`. Wrong secrets, replays, type confusion, bit flips and counter rewrites all fail closed. |
| `qr` | Generated QR codes are decoded back byte-for-byte by `zbarimg`, an unrelated decoder, at every supported version. |
| `signalling` | The server over the wire: room lifecycle, tokens, opaque relay, rate limits, expiry, reconnection and join races. |
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
