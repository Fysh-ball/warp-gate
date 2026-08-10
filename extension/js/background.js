// The extension's background service worker.
//
// It does as close to nothing as the platform allows, on purpose. Everything that touches
// a key, a room or a byte of anyone's file happens in the gate DOCUMENT (app.html), which
// is an ordinary page with an ordinary heap that closes when the tab closes. A background
// worker is a process that outlives every tab and, in MV3, is the context with the widest
// API surface the extension has. Putting session state or network calls in here would mean
// the most privileged and longest-lived part of the extension holds material that the
// design says should live for as long as one tab and no longer.
//
// So this file exists for exactly two reasons, both of them plumbing:
//
//   1. `chrome.action.onClicked` only fires when the action has NO default_popup. A popup
//      was tried and rejected: the gate is a full application with a QR code, a file list,
//      a chat composer and a status log, and a 400x600 panel that vanishes when the user
//      clicks anything else in the browser is a hostile place to run a live transfer. A
//      tab survives focus changes; a popup does not.
//   2. On first install, open the page that explains what this does and does not protect
//      against, once. An extension that appears in the toolbar with no explanation of a
//      security claim is worse than no extension.
//
// Firefox note: `browser.*` and `chrome.*` are both present in Firefox's MV3, and
// `chrome.action`/`chrome.runtime` are the compatible spellings, so this file needs no
// per-browser branch. What Firefox does NOT support is `background.service_worker`; it
// wants `background.scripts` with an event page. That is a manifest difference rather than
// a code difference, and it is written up in extension/README.md rather than papered over
// here, because shipping a manifest that silently loads nothing on one browser is exactly
// the kind of green-looking failure this project refuses elsewhere.

const GATE_PAGE = 'app.html';
const ABOUT_PAGE = 'index.html';

/**
 * Open a page belonging to this extension in a tab.
 *
 * chrome.tabs.create is used rather than chrome.windows.create so the gate lands where the
 * user is already working. It needs no "tabs" permission for an extension-owned URL, which
 * is why this extension declares no API permissions at all.
 */
async function openOwnPage(page) {
  try {
    await chrome.tabs.create({ url: chrome.runtime.getURL(page) });
  } catch (err) {
    // Never swallow this. If the action click does nothing and nothing is logged, the
    // extension looks broken with no thread to pull. The service worker console is where
    // an operator would look.
    console.error(`warp-gate: could not open ${page}: ${err.message}`);
  }
}

chrome.action.onClicked.addListener(() => { void openOwnPage(GATE_PAGE); });

chrome.runtime.onInstalled.addListener((details) => {
  // Only on a genuine first install. An update or a browser restart re-fires onInstalled
  // with a different reason, and opening a tab every time the browser updates the
  // extension would be indistinguishable from adware.
  if (details.reason !== 'install') return;
  void openOwnPage(ABOUT_PAGE);
});
