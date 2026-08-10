# Warp Gate

A temporary, end-to-end encrypted bridge between browsers. Open it, send what you
need, close it. Nothing is left behind.

No accounts. No installation. No database. No dependencies.

## Quickstart

```sh
git clone https://github.com/Fysh-ball/warp-gate
cd warp-gate
docker compose up -d
```

Open **<http://localhost:3095>**. That is a working gate: create one, paste the link into
a second tab, and send something.

A second *device* needs two more things, and both are covered below: the port has to leave
loopback, which means TLS has to be in front of it first, and cross-network connections
need a STUN server you have chosen.

There is no configuration step and nothing to edit first, and no `--build` flag either:
`compose.yaml` declares the build, so the first `up` builds it. The image is a stock
`node:22-alpine` plus this source tree. Nothing is compiled, so once the base image is
local the build is four `COPY`s and finishes in about a second; the first run also pulls
that ~163 MB base, and that pull is the only part you will wait for. It runs as uid 1000
with a read-only root filesystem and every capability dropped. Stop it with
`docker compose down`.

Without Docker it is one command and no install step, because there are no dependencies:

```sh
node server/index.js        # Node 22.7 or later, then open http://localhost:3095
```

**Two things are true of that gate and both matter before you show anyone else.**

**It works on your network only, until you choose a STUN server.** `WG_STUN_URL` is unset
out of the box, so browsers gather host candidates only and two devices can find each
other on one LAN and nowhere else. That is deliberate: naming a STUN server tells a third
party who is connecting, and inheriting that silently is not a decision you made. The
interface says so rather than just failing. `WG_STUN_URL=stun:stun.cloudflare.com:3478
docker compose up -d` is what the public instance uses, and
[deploy/SELF-HOSTING.md](deploy/SELF-HOSTING.md) explains why that particular choice does
not transfer automatically to a deployment that is not already behind Cloudflare.

**`http://localhost` works and `http://<your-lan-ip>` does not.** This is the trap, so it
is worth being exact about. Warp Gate encrypts with the Web Crypto API
(`crypto.subtle`), which browsers expose in a *secure context* only, and the W3C rule for
what counts is TLS **or** a loopback address: `localhost`, `127.0.0.1` and `[::1]` are
secure over plain HTTP, and `192.168.1.20` is not. So moving the published port from
`127.0.0.1:3095:3095` to `3095:3095` and browsing to the machine's LAN address gives you
a page that loads perfectly, a landing that looks right, and a gate that cannot derive a
key.

Measured 2026-08-10 in headless Chromium 147.0.7727.15 against **one** container built by
the quickstart, loading `/app` from two origins that reach the same process, so the only
variable is the address in the bar:

| Origin | `isSecureContext` | `crypto.subtle` | `navigator.serviceWorker` | `getUserMedia` |
|---|---|---|---|---|
| `http://127.0.0.1:3095` | `true` | `object` | present | `function` |
| `http://172.16.34.2:3095` | `false` | **`undefined`** | absent | `undefined` |

Both served an identical `/app` with the title "Warp Gate", which is the point: the page
renders and the primitives underneath it are gone. Nothing in `public/js` tests for
`crypto.subtle` before using it, so on the second row the failure is an uncaught
`TypeError` and not a message. The camera scanner and the streamed-download service worker
*do* check `isSecureContext`, so those two disappear quietly rather than breaking, which
is the more confusing half of the symptom.

**Put TLS in front of it before you move it off loopback.** `compose.yaml` is set up for
exactly that: it binds `127.0.0.1` and leaves the proxy to you.

Everything else, including the environment variables, the suggestion box and the
Cloudflare and STUN reasoning, is in [deploy/SELF-HOSTING.md](deploy/SELF-HOSTING.md).
The repository ships two compose files and they are not interchangeable:

| File | For |
|---|---|
| `compose.yaml` | The quickstart above. Works unedited, builds the image, binds loopback, writes nothing to disk. |
| `deploy/docker-compose.yml` | The fuller reference: what the public instance runs. Bind-mounted source instead of a built image, a Cloudflare tunnel, and the suggestion box on a host directory. |

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

The quickstart at the top of this file is the short path. This section is the detail
behind it.

```sh
node server/index.js
```

That is the whole thing. No install step, no build step, no package manager. Open
`http://127.0.0.1:3095`.

**Node 22.7 or later**, and the floor is not arbitrary: `server/*.js` are ES modules and
there is no `package.json` to declare it, so they load only on a Node that detects module
syntax on its own, which has been the default since 22.7.0. An older 22.x exits at start
with `ERR_REQUIRE_ESM`. The container has no such trap, because the image pins the `22`
tag and that always resolves above the floor.

### Self-hosting

```sh
git clone https://github.com/Fysh-ball/warp-gate && cd warp-gate

# the quickstart, again: builds the image, binds loopback, keeps nothing on disk
docker compose up -d

# or without a container at all
node server/index.js                     # http on 3095

# behind TLS, with a STUN server so it works across networks:
WG_STUN_URL=stun:stun.cloudflare.com:3478 \
WG_TRUST_PROXY=1 WG_HSTS=1 node server/index.js
```

`WG_TRUST_PROXY=1` belongs in that last line and nowhere near a directly reachable
instance: it makes the server believe a forwarding header, which anyone who can reach the
port can then write. It also fails closed in a way that looks like working. Read the
section on it in [deploy/SELF-HOSTING.md](deploy/SELF-HOSTING.md) before setting it.

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

Put any TLS terminator in front of it. `compose.yaml` at the repository root is the
working starting point and `deploy/docker-compose.yml` is the fuller reference that the
public instance runs; `deploy/SELF-HOSTING.md` explains the STUN and proxy choices and
tabulates all 43 environment variables against their defaults. `server/config.js` is the
authority for every one of them, and it refuses to start rather than fall back to a
default on a value it cannot parse.

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

**Every figure above is idle cost**, measured with gates seated and streams attached but
nothing backing up. Read them as the floor a deployment sits at, not as a bound on what
it can reach.

**Watch the interaction between the two defaults.** The shipped `deploy/docker-compose.yml` caps
the container at 128 MB, and the shipped `WG_MAX_ROOMS` is 200. Two hundred *full*
six-seat gates measured 114 MB idle, which is 89% of that limit before counting rate-limit
state. Two hundred two-seat gates is a comfortable 90 MB idle. If you expect large gates, either
raise `mem_limit` or lower `WG_MAX_ROOMS`: the two defaults were chosen when a gate held
exactly two devices and they have not been retuned for six.

Within a 128 MB container the practical *idle* ceiling is roughly 850 two-seat gates or
270 six-seat ones. A Raspberry Pi is still more than enough for that, which was the design
target.

**The idle numbers are not the worst case**, and the gap used to be enormous. A slow or
wedged reader makes the server queue bytes it cannot flush, and the per-stream cap was
1 MiB with no ceiling on the sum: 200 gates of six seats is 1,200 streams, so the
allowance in aggregate was about 1.2 GB against a 128 MB container.

That is now bounded at both levels. Each stream may hold
`WG_MAX_STREAM_BACKLOG_BYTES` of queued-but-unflushed data, **256 KiB** by default, before
`server/rooms.js` calls it a dead reader and destroys it. The sum across every stream in
the process is bounded separately by `WG_MAX_TOTAL_BACKLOG_BYTES`, 8 MiB by default: once
that is spent, the next stream that is *itself* holding queued bytes is dropped, so 1,200
stalled readers cost 8 MiB rather than 1.2 GB. A stream draining normally holds nothing and
is never dropped for somebody else's backlog, which is the property that makes an
aggregate bound safe to have at all: without it, one slow reader could evict healthy ones.

**Do not size a box from the idle table alone**, and do keep `mem_limit` set: it is the
backstop for everything this bound does not cover.

Configuration is environment variables, all optional. The complete table, every variable
against the default `server/config.js` actually applies, is in
[deploy/SELF-HOSTING.md](deploy/SELF-HOSTING.md), which also covers the Cloudflare and
STUN decisions and the one feature that touches disk.

## How it is put together

```
server/           the signalling process, Node standard library only
  index.js        HTTP, static files, security headers, shutdown
  rooms.js        the in-memory room map, idle / hard / absolute deadlines, sweeper
  signal.js       config / health / room / create / join / relay / bye / suggest / SSE
  stun.js         an RFC 5389 binding responder, off unless WG_STUN_ENABLED=1
  limits.js       rate limiting that does not retain IP addresses
  suggestions.js  the suggestion box, off unless WG_SUGGESTIONS_PATH is set. The one
                  thing this server writes to disk
public/           the client, plain ES modules, no framework
  js/crypto.js    key schedule, AEAD framing
  js/session.js   the protocol state machine
  js/link.js      one peer link: the pairwise handshake and its message types
  js/peer.js      WebRTC and backpressure
  js/transfer.js  chunking and receive-sink selection
  js/resume.js    picking a transfer back up where it stopped
  js/download.js  streamed downloads through the browser's own download manager
  sw.js           the service worker that makes those streamed downloads possible
  js/vault.js     surviving a reload on a password gate
  js/qr.js        a QR encoder written here against ISO/IEC 18004, not a vendored library
  js/qrdecode.js  the matching decoder, loaded only when the camera is used
  js/qrscan.js    camera frames to a gate code, loaded only when scanning starts
  js/saswords.js  the two spoken words, loaded at gate creation
  js/gameplay.js  the game engines, loaded only when a board is opened
  js/gameui.js    board rendering, and the one stylesheet that comes with it
  js/app.js       the interface
tools/            operational probes
tests/            every suite runnable offline, with no network and no fixtures
```

That `public/js` list is a guide to the interesting files, not the full directory:
several of them are deliberately loaded late, which is why the gate's eager weight is
smaller than the tree suggests and why `tests/size.test.mjs` fails the build if that
stops being true. For the authoritative list of suites, read `tests/run-all.sh` rather
than a count written here: a number in prose drifts the moment a suite is added, and
this one already had.

The server holds one `Map` of rooms, plus in-memory rate counters, and nothing else on
any path a gate touches. Restarting it destroys every live gate, which is the intended
behaviour.

The one exception is the suggestion box. If `WG_SUGGESTIONS_PATH` is set, `POST
/api/suggest` appends what somebody typed to a file: the text and the hour it arrived,
and deliberately no IP, no header, and nothing from the signalling side. It is off in a
bare checkout and **on in `deploy/docker-compose.yml`**, so the reference deployment does
write to disk. `deploy/SELF-HOSTING.md` says what that commits you to.

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
