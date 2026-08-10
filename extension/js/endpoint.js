// The one place in the extension that knows WHERE the signalling server is.
//
// WHY THIS FILE EXISTS AT ALL
//
// The web client is served from the same origin it signals to, so every request in it is
// written as an absolute PATH: `fetch('/api/relay')`, `new EventSource('/api/events?...')`.
// On a page whose origin is `chrome-extension://<id>` those paths resolve against the
// extension package, where there is no server and never will be, so each one is an
// immediate failure. Something has to supply the missing origin.
//
// WHAT WAS TRIED AND REJECTED
//
// 1. Monkeypatching `globalThis.fetch` and `globalThis.EventSource` in a shim loaded
//    before the module graph. This was attractive because it needs ZERO edits to the
//    copied client, which would have kept the copy byte-identical to public/ and made
//    drift trivially detectable with `diff -r`. It was rejected on the grounds that this
//    is a security tool: a global that silently rewrites the destination of every request
//    in the process is exactly the kind of invisible indirection that makes an audit
//    unable to answer "where does this byte go" by reading the call site. The whole point
//    of the extension is that the code is auditable and fixed at install time. Hiding the
//    network target behind a patched global would trade the property we are shipping for
//    a smaller diff.
//
// 2. Baking the origin in as a constant. Rejected because the SERVER is the untrusted
//    party in this design (THREAT-MODEL.md): a self-hoster pointing the client at their
//    own box is the configuration where the trust question has a definite answer, so
//    making the origin fixed would remove the one escape hatch that matters.
//
// So: explicit call sites, one module, and the four patched files each carry a comment
// saying they were patched. See extension/README.md for the exact list and for the
// upstream change that would let this copy be deleted.
//
// WHY localStorage AND NOT chrome.storage
//
// chrome.storage is asynchronous. The client's boot path fetches /api/config synchronously
// with respect to its own control flow, so an async origin lookup would introduce a race
// where the first request of the session can be issued before the configured origin has
// been read, and the failure mode is "works on the second load". localStorage is
// synchronous, is scoped to the extension origin, and is shared between index.html (where
// the user sets it) and app.html (where it is read), which is precisely the sharing this
// needs and nothing more. It also means the extension needs no `storage` permission.

/**
 * The instance the authors run. Nothing here treats it as more trustworthy than any
 * other origin: it is a default, not an endorsement, and THREAT-MODEL.md is explicit
 * that a hostile operator of ANY instance sees the same metadata.
 */
export const DEFAULT_ORIGIN = 'https://warpgate.fysh.site';

/** localStorage key. Namespaced because this origin is shared by every page we ship. */
export const ORIGIN_KEY = 'wg.signalOrigin';

/**
 * Is this a usable signalling origin?
 *
 * Deliberately strict: scheme, host, optional port, and NOTHING else. A value carrying a
 * path, a query or a fragment would be concatenated with '/api/...' further down and
 * produce a URL nobody intended, and a `javascript:` or `data:` value must never reach
 * `fetch` or `EventSource` at all. Returning the parsed origin rather than a boolean means
 * callers cannot forget to normalise: `new URL('https://x.example/').origin` drops the
 * trailing slash, which would otherwise produce '//api/config'.
 *
 * http is permitted only for loopback. A plain-http signalling server on a real network is
 * a downgrade of the transport the whole product depends on, and refusing it here is
 * cheaper than explaining it later. Loopback is exempt because a self-hoster testing on
 * 127.0.0.1 has no TLS to terminate and no network to intercept.
 *
 * @param {string} raw
 * @returns {{ ok: true, origin: string } | { ok: false, reason: string }}
 */
export function parseOrigin(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, reason: 'empty' };
  }
  let url;
  try {
    url = new URL(raw.trim());
  } catch (err) {
    // The parser's own message names the part it choked on, which is more useful than
    // anything this function could invent.
    return { ok: false, reason: `not a URL: ${err.message}` };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, reason: `scheme ${url.protocol} is not http or https` };
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol === 'http:' && !loopback) {
    return { ok: false, reason: 'plain http is only allowed for localhost' };
  }
  // `pathname` is '/' for a bare origin, so anything longer is a path the user typed.
  if ((url.pathname && url.pathname !== '/') || url.search || url.hash) {
    return { ok: false, reason: 'an origin is scheme://host[:port] with no path, query or fragment' };
  }
  return { ok: true, origin: url.origin };
}

/**
 * The origin currently written in storage, read fresh every call.
 *
 * Only the options page should use this. Everything on the request path uses
 * signalOrigin() below, which is pinned for the life of the document: see why there.
 *
 * Never throws. This is on the boot path of the gate, and a page that refuses to load
 * because a stored string went bad is worse than a page that falls back and says so in the
 * console. A bad stored value is reported rather than swallowed: `catch {}` here would turn
 * "your custom origin is being ignored" into silence.
 */
export function storedOrigin() {
  let stored = null;
  try {
    stored = globalThis.localStorage?.getItem(ORIGIN_KEY) ?? null;
  } catch (err) {
    // localStorage can throw in a partitioned or storage-disabled context. Say so; do
    // not pretend the user never configured anything.
    console.warn(`warp-gate: could not read the configured signalling origin (${err.message}); using ${DEFAULT_ORIGIN}`);
    return DEFAULT_ORIGIN;
  }
  if (stored === null) return DEFAULT_ORIGIN;
  const parsed = parseOrigin(stored);
  if (!parsed.ok) {
    console.warn(`warp-gate: the stored signalling origin ${JSON.stringify(stored)} is unusable `
      + `(${parsed.reason}); using ${DEFAULT_ORIGIN}`);
    return DEFAULT_ORIGIN;
  }
  return parsed.origin;
}

/**
 * The origin this DOCUMENT signals to, decided once when this module is evaluated.
 *
 * Pinned deliberately, and this is a security property rather than a caching one. A gate is
 * a room id plus a per-seat capability token, both minted by one server. If the origin were
 * re-read per request, changing it in another tab mid-session would send the live room id
 * and the live token to a host that was never part of that gate: the next /api/relay would
 * hand a different operator a working seat credential. Nothing decrypts with it, but it
 * authorises injecting signalling frames and destroying the gate, so it is not a thing to
 * hand out by accident.
 *
 * The cost is that a change does not apply to a page that is already open. The options page
 * says so in as many words, and a reload is the whole ceremony.
 */
const ACTIVE_ORIGIN = storedOrigin();

/** The origin in force for this document. */
export function signalOrigin() {
  return ACTIVE_ORIGIN;
}

/** Persist a signalling origin. Returns the same shape as parseOrigin so callers can report. */
export function setSignalOrigin(raw) {
  const parsed = parseOrigin(raw);
  if (!parsed.ok) return parsed;
  try {
    globalThis.localStorage.setItem(ORIGIN_KEY, parsed.origin);
  } catch (err) {
    return { ok: false, reason: `could not be saved: ${err.message}` };
  }
  return parsed;
}

/** Forget any configured origin, so the default applies again. */
export function clearSignalOrigin() {
  try {
    globalThis.localStorage.removeItem(ORIGIN_KEY);
  } catch (err) {
    console.warn(`warp-gate: could not clear the configured signalling origin: ${err.message}`);
  }
}

/**
 * Absolute URL for an API path.
 *
 * Takes the same '/api/...' string the web client uses, so a patched call site reads as
 * `api('/api/relay')` and a reviewer can see at a glance that the path is unchanged and
 * only the origin was supplied.
 */
export function api(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) {
    throw new Error(`api() takes an absolute path beginning with '/', got ${JSON.stringify(path)}`);
  }
  return `${ACTIVE_ORIGIN}${path}`;
}

/**
 * The link a gate is shared with.
 *
 * This deliberately points at the WEB client on the signalling origin, not at anything
 * inside this extension. The person receiving it is on another device and probably does
 * not have the extension installed, and a `chrome-extension://<id>/...` URL is meaningless
 * to them: it names a package on THIS machine, and even a peer who did install the
 * extension would have a different id, since Chrome derives the id per installation key.
 *
 * Be clear about what that means, because it is the honest limit of this whole approach:
 * the extension removes the delivery risk for the person USING it. A peer who follows the
 * link in an ordinary browser is running code the signalling origin served them, with
 * every caveat in THREAT-MODEL.md intact. Both ends have to install the extension for both
 * ends to be covered. The encryption between them is unaffected either way.
 *
 * '/app' rather than '/app.html' because that is the route the server publishes and the
 * one people paste into a chat; see the ROUTES map in server/index.js.
 */
export function gateLink(code) {
  return `${ACTIVE_ORIGIN}/app#${code}`;
}

/**
 * The extension match pattern that covers one origin, for chrome.permissions.
 *
 * The PORT is deliberately dropped. A match pattern is <scheme>://<host><path> and Chrome
 * rejects a host component containing a port outright, so `https://gate.example:8443/*`
 * is not a narrower permission than `https://gate.example/*`, it is an invalid one:
 * permissions.request() throws and the Save button fails for every self-hoster who runs on
 * a non-standard port. The consequence is stated rather than hidden: granting access to a
 * host grants it on every port of that host, because the platform has no way to express
 * anything finer.
 */
export function matchPatternFor(origin) {
  const url = new URL(origin);
  return `${url.protocol}//${url.hostname}/*`;
}
