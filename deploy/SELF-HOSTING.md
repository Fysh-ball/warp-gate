# Self-hosting Warp Gate

Warp Gate is deliberately small: one Node process, no dependencies, no build step, no
database. If you can run a container and put a reverse proxy in front of it, you can run
it. This file is what we learned running it in production, minus anything specific to our
own machine.

The trust argument for self-hosting is in [THREAT-MODEL.md](../THREAT-MODEL.md), and it
is the honest one: **whoever serves the page controls the code that does the
encryption.** Hosting it yourself, from source you have read, is the only configuration
where that question has a definite answer.

## Start here

The README's Quickstart is the three commands that get a gate running on your own machine,
and it is not repeated here: read it first, then come back. This document is the rest of
the road, in the order the decisions actually arrive.

| # | Step | Where |
|---|---|---|
| 1 | Get it running on loopback and send a file between two tabs | README, Quickstart |
| 2 | Decide which compose file you are building on | The two compose files, below |
| 3 | Understand why the port is on loopback before you move it | Ports |
| 4 | Put TLS in front of it. Not optional, and not a hardening step | TLS, and why plain HTTP will not do |
| 5 | Tell the server which proxy to trust, or every user shares one rate limit | WG_TRUST_PROXY is a footgun |
| 6 | Choose a STUN server, or it works on one LAN only | STUN: why it is off by default |
| 7 | Set gate lifetimes, capacity and abuse limits for your instance | Environment |
| 8 | Decide whether you want the suggestion box, and create its directory first | The suggestion box |
| 9 | Publish your source URL if you modified it | AGPL section 13 |
| 10 | Run the probes, and read them | Verifying a deployment |

Steps 4 and 5 are the two that produce a deployment which looks fine to you and is broken
for everyone else, so neither is safe to defer until after you have shown it to someone.

## The two compose files, and which one you want

Warp Gate ships two, and they are not variants of each other:

| File | Shape | Use it when |
|---|---|---|
| `compose.yaml` (repository root) | Builds the `Dockerfile`: a stock `node:22-alpine` with the source copied in. Binds loopback, writes nothing to disk, needs no edit. | You want a gate running now, or you want an image you can push to another machine. |
| `deploy/docker-compose.yml` (this directory) | No image at all: the same stock node image with the source **bind-mounted** read-only, plus a Cloudflare tunnel and the suggestion box on a host directory. | You are running what the public instance runs, and updating means `rsync` plus a restart rather than a rebuild. |

Both end up with the same process and the same environment variables. The difference is
whether the source arrives in an image layer or on a mount, and that changes exactly one
operational thing: with an image, `docker compose up -d --build` is the update; with a
mount, a file copy and `docker restart` is.

There is no build step in either sense that matters. Warp Gate has no dependencies and no
bundler, so nothing is compiled, minified or transformed on the way in. That is load
bearing rather than tidy: the trust argument above only holds while the bytes a browser
receives are the bytes in this repository, and you can check that yourself with
`curl -s https://your.host/js/crypto.js | diff - public/js/crypto.js`.

The bind-mount layout, for `deploy/docker-compose.yml`:

```
warp-gate/
  docker-compose.yml
  app/            the project: server/ and public/, mounted read-only at /app
  data/           only if you enable the suggestion box. See below: the ownership matters
  secrets/        only if you enable the bundled cloudflared service
```

### Running the published image instead of building

The `docker` workflow in `.github/workflows/` publishes `ghcr.io/fysh-ball/warp-gate` on
a `v*` tag, multi-arch for amd64 and arm64. To use it, drop the `build: .` line from
`compose.yaml` and set `image: ghcr.io/fysh-ball/warp-gate:latest`.

Weigh that against the paragraph above before you do. A published image is a build you
did not watch, from a source tree you did not read, and the entire argument for
self-hosting Warp Gate is that you can read what you are serving. Building from your own
checkout costs one second and removes a party from the chain.

## Ports

| Port | Bind | Purpose |
|---|---|---|
| 3095/tcp | loopback | HTTP and SSE. Your reverse proxy reaches it here. |
| 3479/udp | all interfaces | The bundled STUN responder. **Off by default.** |

Bind the HTTP port to loopback and let a proxy terminate TLS. Nothing about Warp Gate
should be reachable directly from the internet.

### There is a second reason to keep it on loopback, and it is not hardening

A browser exposes the Web Crypto API, service workers and the camera to a **secure
context** only. The W3C rule for what counts is TLS *or* a loopback address, so
`http://localhost`, `http://127.0.0.1` and `http://[::1]` qualify over plain HTTP and
`http://192.168.1.20` does not.

That makes "publish it on the LAN for now, add TLS later" the single worst intermediate
state available, because it does not look broken. Measured 2026-08-10, headless Chromium
147, one container, two origins reaching the same process:

| Origin | `isSecureContext` | `crypto.subtle` | service worker | `getUserMedia` |
|---|---|---|---|---|
| `http://127.0.0.1:3095` | `true` | `object` | present | `function` |
| `http://172.16.34.2:3095` | `false` | `undefined` | absent | `undefined` |

Both rendered `/app` identically. Get TLS in front of it before you move the publish off
`127.0.0.1`; if you need to test from a phone before that exists, a tunnel that terminates
TLS for you (`cloudflared`, `tailscale serve`) is a secure context and a LAN IP is not.

## TLS, and why plain HTTP will not do

This is the step that catches people, and it fails in a way that looks like a bug in Warp
Gate rather than a missing certificate.

`crypto.subtle` exists only in a **secure context**. Browsers grant that to HTTPS origins
and to loopback, and to nothing else:

| Origin | `isSecureContext` | `crypto.subtle` |
|---|---|---|
| `https://gate.example.com` | true | present |
| `http://127.0.0.1:3095` | true | present |
| `http://192.168.1.50:3095` | **false** | **undefined** |

The third row is the trap. You start it, it works perfectly in a browser on the server,
you open the LAN address on your phone to show someone, and the encryption primitives are
not there at all. Warp Gate detects this and says so rather than quietly serving a page
that cannot encrypt, but the cause is the origin, not the installation. There is no flag
that turns it off: it is the browser's rule, not ours.

So loopback to try it, TLS for anything else.

### Caddy

The least that can go wrong. Certificates are automatic and Server-Sent Events pass
through untouched:

```
gate.example.com {
    reverse_proxy 127.0.0.1:3095
}
```

### nginx

Works, with one setting that is not optional:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name gate.example.com;
    # ssl_certificate / ssl_certificate_key from certbot or your CA

    location / {
        proxy_pass http://127.0.0.1:3095;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Signalling is Server-Sent Events, and nginx buffers proxied responses by
        # default. Buffered, every event is held until the buffer fills or the response
        # ends, so the two sides never receive each other's offer: the gate sits at
        # "connecting" forever with nothing logged anywhere, because from the server's
        # side it sent the event and from the browser's side it never arrived.
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
```

### Cloudflare Tunnel

What the public instance runs, and the reason `deploy/docker-compose.yml` carries a
`cloudflared` service. It needs no inbound port at all, which is why it suits a home
connection. The origin stays on loopback and the tunnel reaches it there.

Server-Sent Events survive Cloudflare without a Websockets or gRPC setting: see
"Server-Sent Events survive a CDN, verified" below, which is a measurement rather than an
assumption.

### If you put anything in front of it

Read the `WG_TRUST_PROXY` section below before you finish. A reverse proxy makes every
request arrive from one address, and until the server is told which hop to trust, all of
your users share a single rate-limit bucket and lock each other out.

## Environment

All 43 of them, and every default below was read out of `server/config.js` rather than
remembered. **That file is the authority.** If a row here disagrees with it, this file is
the one that is wrong, and the names do not follow a single scheme, so do not guess one:
it is `WG_HTTP_PORT`, not `WG_PORT`, and only `WG_RATE_WINDOW_MS` is spelled `WG_RATE_*`
while every other limiter window is not.

Everything is optional and everything has a working default. Two behaviours of the parser
are worth knowing before you set anything:

- **A boolean is the exact string `1`.** `WG_HSTS=true`, `=yes` and `=on` are all read as
  off, silently, because the check is `=== '1'`. This applies to `WG_HSTS`,
  `WG_TRUST_PROXY` and `WG_STUN_ENABLED`.
- **A malformed number refuses to boot, naming the variable**, rather than falling back to
  the default. `WG_HTTP_PORT=0x1F` and `WG_SUGGESTIONS_MAX_BYTES=1e9` used to parse as 0
  and 1 respectively, and a small wrong number that looks like a working deployment is
  worse than a process that will not start.

### Network

| Variable | Default | Notes |
|---|---|---|
| `WG_HTTP_HOST` | `0.0.0.0` | The bind *inside* the container. What decides who can reach it is the port publish, and both shipped compose files publish to `127.0.0.1` only. |
| `WG_HTTP_PORT` | `3095` | Note the name: not `WG_PORT`. |
| `WG_TRUST_PROXY` | off | **Read the warning below before setting this.** |
| `WG_TRUSTED_PROXIES` | empty | Comma separated peer addresses allowed to set the forwarding headers, e.g. `10.0.0.4,10.0.0.5`. Loopback (`127.0.0.1`, `::1`) is always trusted and needs no entry. **`WG_TRUST_PROXY=1` does nothing unless the request actually arrives from one of these**, so a proxy that reaches the server from any other address needs its address named here. |
| `WG_HSTS` | off | Turn on only when TLS genuinely terminates in front. Browsers ignore the header on plain HTTP, so setting it on a loopback instance is inert rather than harmful, and inert is not the same as correct. |
| `WG_SOURCE_URL` | empty | Required by the licence. The server warns at every boot until it is set, and serves it at `/api/config`. See below. |
| `WG_AD_ORIGINS` | empty | Comma separated origins that widen the **landing page's** CSP only, never `/app`. Validated at boot against `scheme://host[:port]`: anything with a path, a semicolon or a control character in it refuses to start, because the value is interpolated into a header. Read below. |

### STUN

| Variable | Default | Notes |
|---|---|---|
| `WG_STUN_URL` | empty | Comma separated STUN URLs advertised to browsers, e.g. `stun:stun.cloudflare.com:3478`. Empty means none is advertised, browsers gather host candidates only, and gates work on one network and nowhere else. Which server to name is a privacy decision: read the STUN section. |
| `WG_STUN_ENABLED` | off | The **bundled** RFC 5389 responder. Opt in with `1`. Independent of `WG_STUN_URL`: turning the responder on does not advertise it, and advertising a URL does not need the responder. |
| `WG_STUN_HOST` | `0.0.0.0` | Bind for the bundled responder. |
| `WG_STUN_PORT` | `3479` | Not 3478: that port was already taken on the machine this was first deployed to. |

### Gate lifetimes

| Variable | Default | Notes |
|---|---|---|
| `WG_UNCLAIMED_TTL_MS` | `300000` (5 min) | How long a gate nobody has joined survives. Short and aggressive on purpose. |
| `WG_EMPTY_GRACE_MS` | `45000` | How long a gate with nobody attached survives. Must comfortably exceed a page reload or refreshing a tab destroys the gate; short enough that a closed tab frees the room. |
| `WG_DEFAULT_SESSION_MIN` | `30` | The pre-selected lifetime at creation. The offered choices are 10, 30 and 60 minutes and are **not** configurable by environment. |
| `WG_MAX_SESSION_MS` | `86400000` (24 h) | Backstop so a pair of forgotten tabs cannot hold a room forever. The session lifetime is an *idle* timeout that both devices push forward, so a long transfer is never cut off; this is the absolute ceiling on top of it. |

### Capacity and abuse limits

| Variable | Default | Notes |
|---|---|---|
| `WG_MAX_ROOMS` | `200` | Global concurrent gates. Read this together with `mem_limit`: 200 six-seat gates measured 114 MB idle against a 128 MB container. |
| `WG_MAX_PARTICIPANTS` | `6` | Seats per gate. Every pair runs its own peer connection and its own key schedule, so links grow O(N^2): six seats is fifteen links, twenty would be a hundred and ninety. Not a free knob. |
| `WG_MAX_RELAY_BYTES` | `65536` | Largest signalling envelope `/api/relay` will carry. |
| `WG_MAX_BODY_BYTES` | `98304` | Largest request body on the one route that carries an envelope. |
| `WG_MAX_SMALL_BODY_BYTES` | `2048` | Every other route posts a room id and a token, so an unauthenticated caller cannot force a large parse. |
| `WG_RATE_WINDOW_MS` | `300000` (5 min) | Window for the create/join limiters below. The **only** variable spelled `WG_RATE_*`. |
| `WG_CREATE_PER_WINDOW` | `10` | Gate creations per rate-limit key per `WG_RATE_WINDOW_MS`. |
| `WG_JOIN_PER_WINDOW` | `30` | Joins per key per `WG_RATE_WINDOW_MS`. |
| `WG_RELAY_PER_MIN` | `200` | Relayed envelopes per minute per **room**, not per client. |
| `WG_API_WINDOW_MS` | `60000` | Window shared by every limiter in this block below. Shorter than `WG_RATE_WINDOW_MS` because these guard cheap reads, where a long window strands an ordinary client. |
| `WG_API_PER_WINDOW` | `600` | Backstop across all routes. Generous: it exists to stop automation, not clients. |
| `WG_PUBLIC_GET_PER_WINDOW` | `30` | The unauthenticated GETs (`/api/config`, `/api/health`, `/api/room`). Nothing legitimate fetches these in a loop. **A container healthcheck does count against this**, at 2 per minute on the shipped 30 s interval. |
| `WG_REJECT_PER_WINDOW` | `30` | Charged only when a request is *refused*. A client that keeps being refused is probing; a working client never touches this budget, so it can be far tighter than the others. |
| `WG_STREAMS_PER_KEY` | `4` | Concurrent SSE streams one rate-limit key may hold. |
| `WG_MAX_STREAM_BACKLOG_BYTES` | `262144` (256 KiB) | Queued-but-unflushed bytes one SSE stream may hold before it is treated as a dead reader and destroyed. **The default dropped from 1 MiB**: the old value was per stream with no aggregate, so 1,200 stalled readers were allowed 1.2 GB against a 128 MB container. Raise it only if you have a reason a legitimate reader stalls that long. |
| `WG_MAX_TOTAL_BACKLOG_BYTES` | `8388608` (8 MiB) | The sum across every stream in the process, and the bound that actually matters, because the per-stream figure multiplies. Once it is spent, the next stream that is *itself* holding queued bytes is dropped. A stream draining normally holds nothing and is never dropped for somebody else's backlog, which is what makes an aggregate bound safe to have. |
| `WG_MAX_BUCKET_ENTRIES` | `10000` | Per rate-limit bucket. Entries are per-boot memory that an unauthenticated caller grows one key at a time, measured at 116 B each, and they live for a whole window regardless of the sweeper. |
| `WG_SWEEP_SLICE` | `2000` | Entries examined per sweep call. A full pass over large maps blocks the event loop: measured at 578 ms for 800k entries, hence the slicing. |
| `WG_STUN_PER_SEC` | `20` | Bundled-responder replies per second per source address. |
| `WG_STUN_PER_SEC_GLOBAL` | `2000` | The same, globally. A UDP source address is forgeable, so this is the only limit an attacker cannot rotate around. |

### Timers

| Variable | Default | Notes |
|---|---|---|
| `WG_SWEEP_MS` | `10000` | How often expired rooms and rate-limit entries are swept. |
| `WG_HEARTBEAT_MS` | `25000` | SSE keepalive. Must stay well under your proxy's idle timeout; 25 s was chosen against Cloudflare's verified 100 s on Free and Pro. |
| `WG_DESTROY_LINGER_MS` | `1500` | How long after `end()` the server waits before destroying the socket of a stream it has given up on. A client that ignores the close still gets its final bytes; one that has genuinely gone away stops holding a socket. |

### Suggestion box variables

Off unless `WG_SUGGESTIONS_PATH` is set. It is the one feature that writes to disk, so it
has a section of its own further down: read that before enabling it.

| Variable | Default | Notes |
|---|---|---|
| `WG_SUGGESTIONS_PATH` | empty | Absolute, or relative to the working directory. Off unless set. **The directory must already exist and be writable by the uid the process runs as.** The server does not create it. |
| `WG_SUGGESTIONS_MAX_CHARS` | `600` | Per suggestion, counted in **code points**. |
| `WG_SUGGESTIONS_MAX_TEXT_BYTES` | `1200` | The same cap in the unit the file is measured in, and the reason both exist: 600 characters of ASCII, Latin-1 or Greek all still fit, while 600 astral characters would have cost four times what the character count claimed. |
| `WG_SUGGESTIONS_PER_WINDOW` | `3` | Per rate-limit key per `WG_API_WINDOW_MS` (60 s). A person with an idea sends one; a script sends thousands. |
| `WG_SUGGESTIONS_MAX_BYTES` | `1048576` (1 MiB) | The store refuses rather than rotating when full, because rotating would delete somebody's suggestion to make room for somebody else's. About 1,700 ordinary suggestions, and at least ~800 even if every one is at `WG_SUGGESTIONS_MAX_TEXT_BYTES`. |

### The suggestion box

Off unless `WG_SUGGESTIONS_PATH` names a file in a directory that already exists. When it
is off, `/api/suggest` returns 404 and the landing does not render the box at all: a form
that posts into a 404 collects nothing and says nothing, which is worse than not asking.

This is the **only** state this server keeps outside memory. Everything else lives for the
length of a gate and is gone. So it is worth being precise about what lands in the file:

- The text, and the hour it arrived. That is the entire record.
- Not the IP, not the rate-limit key, not the user agent, not the referrer, not the minute
  or second, and nothing at all from the signalling side. There is no code path between
  the two halves of the server and there should not be one.
- Control characters are stripped at write time, because you will read this with `cat` and
  a raw ANSI escape in a stranger's suggestion would repaint your terminal.

Read it back with either of:

    cat ./data/suggestions.jsonl
    node deploy/read-suggestions.mjs ./data/suggestions.jsonl

The second one reports malformed lines instead of skipping them, which is how you tell a
truncated file from a short one.

The container is `read_only: true`, so the compose file mounts `./data` as the only
writable path that **persists**. There is one other writable path: `tmpfs: /tmp:size=8m`,
an 8 MB in-memory filesystem that is discarded on every restart and holds nothing Warp
Gate puts there. The suggestion file is the only durable write. **Create the `./data`
directory before the first start.** The server will not create it: a typo that silently
made a second store would leave you reading an empty file while suggestions land somewhere
you never look.

#### Turning it on without falling into the hole it is famous for

The root `compose.yaml` deliberately does not enable this, so the quickstart has no bind
mount and therefore no ownership to get wrong. Adding one takes three lines and one
`chown`, and the `chown` is the part that is not optional:

```sh
mkdir -p data && chmod 700 data
# The container runs as uid 1000. The directory must be owned by that uid, not by you.
sudo chown 1000:1000 data
```

then in `compose.yaml`, under the `warp-gate` service:

```yaml
    environment:
      WG_SUGGESTIONS_PATH: "/data/suggestions.jsonl"
    volumes:
      - ./data:/data
```

**Why the `chown` and not `chmod 777`, and why root does not save you.** The container
drops every capability, and `CAP_DAC_OVERRIDE` is the one that lets uid 0 ignore file
permissions. Without it, container-root is an ordinary uid that happens to be numbered 0
and owns nothing on your host. Switching the container back to `user: "0:0"` therefore
does *not* make a host-owned directory writable; it just changes which uid is refused.
This is not hypothetical: it is how the public instance spent a release accepting every
submission over HTTP and storing none of them, with the only evidence one line per attempt
in a container log nobody was reading.

The server now says so at boot, and this is what it looks like when it is wrong:

```
warp-gate WARNING: the suggestion box is ON but its store is unusable: cannot write into /data (EACCES)
warp-gate          Every submission will be refused and the file will stay empty.
warp-gate          The directory must be writable by the uid this process runs as.
```

Check for that line after the first start with `docker compose logs warp-gate`, and treat
its absence as the confirmation, not the presence of an empty file. A store that refuses
every write and a store nobody has written to look identical from outside.

### The camera

`/app` is served with `permissions-policy: camera=(self)` so it can read a gate code off
another device's screen. Every other page on the site, including the landing and every
asset, keeps `camera=()`. The frames are decoded on the device and discarded; nothing in
`public/js/qrscan.js` can upload anything, because there is no `fetch` in it.

The browser will only grant a camera in a secure context, so on a plain-HTTP instance the
scan button is never shown rather than shown and broken.

### WG_AD_ORIGINS

The landing (`/`) and the gate (`/app`) are separate documents with separate policies,
so that a page which may load somebody else's script is never the page holding a
decryption key.

This variable widens `script-src`, `img-src` and `frame-src` on the landing, and
nothing else. Deliberately **not** `connect-src`, which stops a sponsor's script running
*in the landing document* from opening connections of its own.

Do not mistake that for containment. `frame-src` is widened too, and a third-party frame
is a separate document served from the sponsor's origin under the sponsor's CSP, not this
one. It can fetch anywhere it likes and report your visitor's address and timing whatever
`connect-src` says here. **The boundary this actually buys you is that a sponsor cannot
reach the gate**: the variable is matched against the resolved filename, so no request
path, redirect or traversal carries it onto `/app`, onto an asset, or onto a legal page.
That is the property worth relying on. "A sponsor cannot phone home" is not.

Left empty, both documents get a byte-identical policy.

Setting this changes what your users are exposed to. If you set it, say so on your own
privacy page: the shipped one describes the boundary and states that no sponsor is
enabled, which stops being true the moment you set this.

### WG_TRUST_PROXY is a footgun

Behind a reverse proxy every request arrives from the proxy's address, so without this
every user shares one rate-limit bucket and any single client can lock out everybody.
With it, the server reads `CF-Connecting-IP` / `X-Forwarded-For`.

**That is only safe if the port cannot be reached except through your proxy.** Anyone who
can talk to the port directly can forge those headers and get an unlimited rate-limit key
space. The server enforces a trusted-proxy allowlist before it reads either header:
`127.0.0.1` and `::1` always, plus whatever `WG_TRUSTED_PROXIES` names. Bind the port to
loopback as well. Belt and braces.

**The allowlist fails closed, and closed looks like working.** If the request does not
arrive from a trusted address the headers are ignored and the peer address is used, which
is your proxy's address, which is one bucket for every user. Nothing logs this and nothing
errors: `WG_TRUST_PROXY=1` set without a matching `WG_TRUSTED_PROXIES` entry is exactly the
state the flag exists to prevent, wearing the flag.

**In the default container topology it IS that state, and this is now measured rather than
suspected.** A bridge-networked container reached through a published port does not see
`127.0.0.1`, even when the client was on the host's loopback: `docker-proxy` forwards the
connection and the container sees the **bridge gateway**. Measured 2026-08-10 with a
listener in a compose-created network, reached by `curl http://127.0.0.1:<published>`:

```
peer=172.16.34.1        # the container's view
gateway=172.16.34.1     # docker network inspect, same network
```

So on a bridge network, `WG_TRUST_PROXY=1` alone is inert and every user shares one
rate-limit bucket. Two ways out, and the second is better if it is available to you:

1. Name the gateway in `WG_TRUSTED_PROXIES`. **Measure it, do not copy the address above**:
   every compose project gets its own subnet, and `172.17.0.1` is only the default bridge.
   A wrong entry here trusts something that is not your proxy, which is worse than the bug.
   Re-measure after any change to the network topology.
2. Give the container `network_mode: host` if your proxy is on the same machine. The peer
   address is then genuinely `127.0.0.1`, which is trusted with no configuration and stays
   correct when the network is rebuilt.

Whichever you pick, verify it. This is a setting whose broken state and whose working
state are identical from outside until somebody trips a limit for everybody.

## STUN: why it is off by default

Two browsers behind different NATs need to discover their public addresses. Warp Gate
ships a ~50 line RFC 5389 Binding responder so you *can* self-host that, but it is
**opt-in**, because turning it on has a cost that is easy to miss:

- It needs a UDP port open to every participating browser, so a router forward and a public DNS record.
- That record publishes your home IP address, which for a privacy tool is a real
  trade-off and not an obvious win.

The public instance therefore uses Cloudflare's STUN server, on the reasoning that
Cloudflare already terminates TLS for the site and so already sees every participant's address:
using their STUN adds no party that was not already in the path. **If your own proxy is
not Cloudflare, that reasoning does not transfer.** Pick a STUN server you are willing to
tell your users about, and put it in `WG_STUN_URL`.

## Server-Sent Events survive a CDN, verified

Warp Gate signals over SSE rather than WebSocket. The single biggest risk in that choice
is a proxy buffering the stream and breaking it. Measured against a real Cloudflare
deployment: the `hello` event arrives immediately, the 25 second heartbeats arrive
individually and on time, and the connection lives well past any idle timeout. **No
WebSocket fallback is needed.**

If you use a different proxy, verify it yourself before trusting it:

```sh
curl -N -s "https://your.host/api/events?room=XXXXXXXX&token=YYY"
```

Events must appear one at a time as they happen. If they arrive in a batch when the
connection closes, your proxy is buffering and you need to disable that.

## AGPL section 13

Warp Gate is AGPL-3.0. If you run a modified copy where other people can use it over a
network, **you must offer them the corresponding source.** Set `WG_SOURCE_URL` to a URL
where your version can actually be obtained. The server prints a warning at every boot
until you do, and serves the link at `/api/config`.

A URL that does not resolve is worse than an empty one: it silences the warning while
still leaving users with no way to get the source.

## Verifying a deployment

### Straight after `docker compose up -d`

Run this against your own instance before pointing anyone at it. Every line below was run
against a container built from the repository root `compose.yaml` on 2026-08-10, and the
comment after each is what it printed.

```sh
docker compose ps                                   # warp-gate  Up (healthy)
docker compose logs warp-gate                       # read it, do not just check it exists
docker compose exec warp-gate id                    # uid=1000(node) gid=1000(node)
curl -s  http://127.0.0.1:3095/api/health           # {"ok":true}
curl -s  http://127.0.0.1:3095/api/config           # sourceUrl set, suggestions:false
curl -sI http://127.0.0.1:3095/app | grep -i permissions-policy   # camera=(self)
curl -sI http://127.0.0.1:3095/    | grep -i permissions-policy   # camera=()
```

`docker compose ps` reporting **healthy** is not a formality: the image's own HEALTHCHECK
fetches `/api/health` and parses the JSON, so a healthy container is one whose ES modules
loaded, whose port matches `WG_HTTP_PORT`, and whose event loop is still answering. A
process-liveness check would report the same green for a wedged process.

The two `permissions-policy` lines are a pair on purpose. The gate may reach a camera and
the landing page may not, so checking only the first would pass just as happily if the
grant had leaked site-wide, which is the failure that matters.

### Against the public path, once a proxy is in front

```sh
curl -s https://your.host/api/health          # {"ok":true} and nothing else
curl -s https://your.host/api/config          # includes your sourceUrl
curl -sI https://your.host/ | grep -i content-security-policy
curl -sI https://your.host/ | grep -i strict-transport-security   # only if WG_HSTS=1
```

The health endpoint deliberately returns only `{"ok":true}`. It used to report the live
room count, which is a usage side channel on a tool whose premise is that the server
learns nothing.

The test suite runs against a live deployment too:

```sh
node tests/public-e2e.mjs https://your.host
```

It drives two real browsers through a full gate lifecycle over the public path.

## Updating

With `compose.yaml` (image build):

```sh
git pull
docker compose up -d --build
```

With `deploy/docker-compose.yml` (bind mount), a copy and a restart:

```sh
rsync -a --delete server public /path/to/warp-gate/app/
docker restart warp-gate
```

Two things worth knowing before you do either:

- **A restart destroys every live gate.** That is by design: gates are session state held
  in memory and there is nothing to persist. If anyone might be mid-transfer, wait.
- **Changing an environment variable needs a recreate, not a restart.** `docker compose
  up -d` does that for you; `docker restart` does not, and the container comes back with
  the old value while the file on disk says otherwise. This is an easy hour to lose.

If you changed only `public/`, a bind-mount deployment needs neither: the files are read
from the mount on each request, so a copy is enough.

## When something is wrong

| Symptom | Almost always |
|---|---|
| Page loads, says the browser is missing what it needs | Not a secure context. You are on `http://` and not on loopback. See the TLS section. |
| Both sides sit at "connecting" and nothing happens | Server-Sent Events are being buffered by a proxy. `proxy_buffering off` for nginx. |
| Everyone gets 429 after a few gates | The forwarding header is not trusted, so every request is keyed to the proxy's address and shares one bucket. See `WG_TRUST_PROXY`. |
| The suggestion box accepts text and stores nothing | `data/` is owned by root. `cap_drop: ALL` removes `CAP_DAC_OVERRIDE`, so container-root cannot write a host directory it does not own. Create it with the right uid BEFORE first start. |
| Works on one LAN, never across the internet | No STUN. `WG_STUN_URL` is empty by default, so the browser is handed `iceServers: []` and has no way to discover its public address. See the STUN section. A few networks need a relay even with STUN, and Warp Gate has no TURN support: `iceServers` is built as `[{ urls: stunUrls }]` with no credential fields, so a TURN URL cannot be expressed. |
| A code change does not take effect | On a bind mount, the file has to actually reach `app/` on the host: check there, not in your git tree. On a built image, `docker compose up -d` without `--build` reuses the old image and reports success. |

## Operational notes

- **Restarting destroys every live room.** That is by design: room state is memory only
  and no gate ever touches disk. Restart when it is quiet. The suggestion file is the one
  thing that survives a restart, and it holds nothing about a gate.
- **Memory is capped** at 128 MB in the sample compose, and you should keep that cap even
  though backlog is now bounded in the server itself. An SSE stream is destroyed once it
  holds more than `WG_MAX_STREAM_BACKLOG_BYTES` (256 KiB) queued and unflushed, **and** the
  sum across all streams is bounded by `WG_MAX_TOTAL_BACKLOG_BYTES` (8 MiB). At
  `WG_MAX_ROOMS=200` and six seats that is 1,200 streams whose worst case is 8 MiB rather
  than the 1.2 GB the per-stream bound alone allowed. `mem_limit` is now a backstop for
  everything else in the process rather than the only thing standing between a stalled
  reader and the OOM killer.
- **There is one thing to back up, and only if you enabled it.** The suggestion file. No
  database, no uploads, no logs worth keeping: otherwise the whole deployment is the
  source tree plus an environment.
- **Your resolver may lie to you.** If a freshly created DNS record appears not to exist,
  confirm with DNS-over-HTTPS before suspecting the deployment. A cached negative answer
  looks exactly like a broken deploy.
