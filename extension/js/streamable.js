// Whether this browser can be handed a received file as a real download.
//
// In its own file for the same reason chunkwire.js exists: transfer.js asks this question
// five times, twice from synchronous functions and once as the capability gate in front of
// accepting a large file, while the machinery that USES the answer (download.js: the
// stream, the credit window) is 8.5 KB that nothing needs until a file is actually
// arriving. Keeping the predicate synchronous and the implementation lazy is what lets
// download.js off the eager graph without making a capability check asynchronous.
//
// One definition, imported by both transfer.js and download.js, so the predicate that gates
// the path and the predicate that guards the implementation cannot drift apart.

function staticallySupported() {
  return typeof navigator !== 'undefined'
    && 'serviceWorker' in navigator
    && typeof ReadableStream === 'function'
    && globalThis.isSecureContext === true
    // EXTENSION PATCH. Measured in headless Brave on 2026-08-10: on a `chrome-extension://`
    // page the three checks above are all true and `navigator.serviceWorker.register()`
    // still throws
    //   "Failed to register a ServiceWorker ... The user denied permission to use Service Worker."
    // Chromium does not let an extension PAGE register a worker; the only worker an MV3
    // extension gets is the one its manifest declares, which is not in this document's
    // fetch path. Returning false here also stops the module-load probe below from
    // spending a doomed registration of a /sw.js this package does not ship, and closes
    // the window where the pre-settle answer is wrongly yes.
    //
    // Tested on the SCHEME because the scheme decides it synchronously. Any extension
    // scheme is covered, not just Chromium's: Firefox's moz-extension and Safari's
    // safari-web-extension have the same restriction.
    && !/-extension:$/.test(globalThis.location?.protocol ?? '');
}

// The thing that actually has to work is registering /sw.js, and the static checks above
// cannot see a refusal: on an extension page both are true and register() still rejects
// with "The user denied permission to use Service Worker", and Chromium rejects it too
// when the user has blocked site data. The call sites are synchronous, so the attempt is
// made once, here at module load, and the answer below hardens as soon as it settles.
// Registration is idempotent and this page registers /sw.js on load anyway, so the probe
// costs nothing it was not already going to spend. Until the attempt settles the answer
// is the static one, which is the pre-probe behaviour and a window of milliseconds.
let refusal = null;
if (staticallySupported()) {
  try {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch((err) => { refusal = err; });
  } catch (err) {
    refusal = err;
  }
}

export function supportsStreamDownload() {
  return staticallySupported() && refusal === null;
}
