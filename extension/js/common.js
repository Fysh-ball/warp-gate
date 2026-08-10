// The two things both documents genuinely need, and nothing else.
//
// The landing (index.html) and the gate (app.html) are separate documents on purpose, so
// that the document which may one day carry a sponsor slot never shares a script context, a
// CSP or a JS heap with the one holding a decryption key. support.js was written as the
// place for what the two have in common, and it was, until the donation panel grew a QR
// lightbox around it: a modal, a focus trap, a fade, an Escape handler and a lazy fetch of
// the encoder. app.html carries none of that markup and app.js never calls wireSupport, so
// the gate was fetching 7.2 KB of dead donation UI to reach two helpers totalling about
// twenty lines. Measured on 2026-08-10 while the gate was over its raw ceiling.
//
// So the direction of the dependency is inverted: the common half lives here, support.js
// keeps the donation panel and imports copyText from here, and the gate stops loading the
// donation panel at all. tests/size.test.mjs asserts that, and asserts the landing still
// does load it, because "the gate no longer fetches support.js" and "support.js was
// deleted" are the same shape from inside the gate's graph.
//
// Nothing in this file may touch a room, a key or a peer connection. Same rule support.js
// carries, same reason: it is loaded by the ad-bearing document.

/**
 * Write to the clipboard, reporting rather than throwing when the browser refuses.
 *
 * Returns whether it landed, so the caller can say so on the button itself. A refusal is
 * ordinary here rather than exceptional: Safari refuses outside a user gesture, Firefox
 * refuses without the permission, and an insecure context has no clipboard at all. In every
 * one of those the text is still on screen and still selectable, which is why this reports
 * and returns false instead of failing the action that asked for it.
 */
export async function copyText(text, report = () => {}) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    report(`clipboard unavailable: ${err.message}. Select and copy manually.`, 'warn');
    return false;
  }
}

/**
 * AGPL-3.0 section 13: users interacting with the program over a network must be
 * offered its source. It has to name whatever source THIS instance runs, which for
 * somebody else's deployment is not our repository, so it comes from /api/config and
 * stays hidden when the operator has not set one.
 *
 * Both documents show it, which is the whole reason it is here and not in either one: a
 * licence obligation that only half the deployment honours is not honoured.
 */
export function applySourceLink(sourceUrl) {
  const link = document.getElementById('source-link');
  if (!link || !sourceUrl) return;
  link.href = sourceUrl;
  link.hidden = false;
}
