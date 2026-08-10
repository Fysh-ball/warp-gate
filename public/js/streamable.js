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
    && globalThis.isSecureContext === true;
}
