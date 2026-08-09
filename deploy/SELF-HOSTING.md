# Self-hosting Warp Gate

Warp Gate is deliberately small: one Node process, no dependencies, no build step, no
database. If you can run a container and put a reverse proxy in front of it, you can run
it. This file is what we learned running it in production, minus anything specific to our
own machine.

The trust argument for self-hosting is in [THREAT-MODEL.md](../THREAT-MODEL.md), and it
is the honest one: **whoever serves the page controls the code that does the
encryption.** Hosting it yourself, from source you have read, is the only configuration
where that question has a definite answer.

## What gets deployed

There is no image to build. Warp Gate has no dependencies, so the deployment is a stock
`node:22-alpine` with the source mounted read-only. Updating is a file copy and a
restart.

```
warp-gate/
  docker-compose.yml
  app/            the project: server/ and public/, mounted read-only at /app
  secrets/        only if you enable the bundled cloudflared service
```

`docker-compose.yml`, next to this file, is a working starting point. Copy the
repository into `app/`, adjust the environment, and `docker compose up -d`.

## Ports

| Port | Bind | Purpose |
|---|---|---|
| 3095/tcp | loopback | HTTP and SSE. Your reverse proxy reaches it here. |
| 3479/udp | all interfaces | The bundled STUN responder. **Off by default.** |

Bind the HTTP port to loopback and let a proxy terminate TLS. Nothing about Warp Gate
should be reachable directly from the internet.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `WG_HTTP_HOST` / `WG_HTTP_PORT` | `0.0.0.0` / `3095` | Note the names: not `WG_PORT`. |
| `WG_TRUST_PROXY` | `0` | **Read the warning below before setting this.** |
| `WG_HSTS` | `0` | Turn on only when TLS genuinely terminates in front. |
| `WG_SOURCE_URL` | empty | Required by the licence, see below. |
| `WG_STUN_ENABLED` | off | Opt in with `1`. Read the STUN section first. |
| `WG_MAX_PARTICIPANTS` | `6` | Seats per gate. Connections between peers grow O(N^2), so this is not a free knob. |
| `WG_MAX_ROOMS`, `WG_RATE_*` | see `server/config.js` | Abuse limits. |

### WG_TRUST_PROXY is a footgun

Behind a reverse proxy every request arrives from the proxy's address, so without this
every user shares one rate-limit bucket and any single client can lock out everybody.
With it, the server reads `CF-Connecting-IP` / `X-Forwarded-For`.

**That is only safe if the port cannot be reached except through your proxy.** Anyone who
can talk to the port directly can forge those headers and get an unlimited rate-limit key
space. The server enforces a trusted-proxy allowlist (loopback by default), but bind the
port to loopback as well. Belt and braces.

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

```sh
curl -s https://your.host/api/health          # {"ok":true} and nothing else
curl -s https://your.host/api/config          # includes your sourceUrl
curl -sI https://your.host/ | grep -i content-security-policy
```

The health endpoint deliberately returns only `{"ok":true}`. It used to report the live
room count, which is a usage side channel on a tool whose premise is that the server
learns nothing.

The test suite runs against a live deployment too:

```sh
node tests/public-e2e.mjs https://your.host
```

It drives two real browsers through a full gate lifecycle over the public path.

## Operational notes

- **Restarting destroys every live room.** That is by design: room state is memory only
  and nothing is written to disk. Restart when it is quiet.
- **Memory is capped** at 128 MB in the sample compose. A stalled reader used to be able
  to grow the process without bound; that is fixed, but keep a limit set anyway.
- **There is nothing to back up.** No database, no uploads, no logs worth keeping. The
  whole deployment is the source tree plus an environment.
- **Your resolver may lie to you.** If a freshly created DNS record appears not to exist,
  confirm with DNS-over-HTTPS before suspecting the deployment. A cached negative answer
  looks exactly like a broken deploy.
