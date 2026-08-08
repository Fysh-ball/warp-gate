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

## Running it

```sh
node server/index.js
```

That is the whole thing. Node 22 or later, no install step, no build step, no package
manager. Open `http://127.0.0.1:3095`.

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
