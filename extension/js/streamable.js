// Whether this browser can be handed a received file as a real download.
//
// Six lines in their own file for the same reason chunkwire.js exists: transfer.js asks
// this question five times, twice from synchronous functions and once as the capability
// gate in front of accepting a large file, while the machinery that ANSWERS the question by
// doing the work (download.js: service worker registration, the stream, the credit window)
// is 8.5 KB that nothing needs until a file is actually arriving. Keeping the predicate
// static and the implementation lazy is what lets download.js off the eager graph without
// making a capability check asynchronous.
//
// One definition, imported by both transfer.js and download.js, so the predicate that gates
// the path and the predicate that guards the implementation cannot drift apart.

/**
 * KNOWN GAP, and it is a real one rather than a caveat.
 *
 * This reports what the page is ALLOWED to try, not what will work. On a page where service
 * worker registration is then refused (an extension page is the measured case: both checks
 * below are true and `register()` throws "The user denied permission to use Service
 * Worker") this returns true and openStreamDownload fails afterwards. Because transfer.js
 * consults it BEFORE offering to accept a large file, the failure lands after the user has
 * pressed Accept and the sender has started. Making it honest needs an actual registration
 * attempt, which is async and cannot be done from the synchronous call sites, so it is
 * written down here rather than papered over.
 */
export function supportsStreamDownload() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true
    // EXTENSION PATCH, and an upstream bug in its own right.
    //
    // Measured in headless Brave on 2026-08-10: on a `chrome-extension://` page,
    // `'serviceWorker' in navigator` is TRUE and `isSecureContext` is TRUE, so all three
    // checks above pass, and then `navigator.serviceWorker.register('/sw.js')` throws
    //   "Failed to register a ServiceWorker ... The user denied permission to use Service Worker."
    // Chromium does not let an extension PAGE register a worker. The only worker an MV3
    // extension gets is the one its manifest declares, and that is a different thing which
    // is not in the fetch path of this document.
    //
    // Why this is not cosmetic: transfer.js consults this predicate as a CAPABILITY GATE
    // before accepting a file. With it returning true, a receive above MEMORY_LIMIT_BYTES
    // passes the "is there anywhere for this to go" check at the top of openSink() and only
    // fails at the bottom when the worker refuses to start, which is after the user clicked
    // Accept and after the sender began. A predicate that says yes and then cannot deliver
    // is worse than one that says no.
    //
    // Tested on the SCHEME rather than by probing a registration, because a probe would have
    // to be async and this function is called synchronously from three places. Any extension
    // scheme is covered, not just Chromium's: Firefox's moz-extension and Safari's
    // safari-web-extension have the same restriction.
    && !/-extension:$/.test(globalThis.location?.protocol ?? '');
}
