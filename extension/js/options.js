// The extension's own page: pick which signalling server the gate talks to.
//
// This is the only place in the extension that writes the signalling origin. endpoint.js
// reads it, and nothing else touches the stored value.
//
// WHY A HOST PERMISSION IS REQUESTED RATHER THAN PRE-GRANTED
//
// The manifest ships with host_permissions for the default instance and for loopback, and
// puts every other https origin in optional_host_permissions instead. That means a fresh
// install can reach exactly two things: the instance it says it reaches, and a server on
// the machine it is running on. Anything else is a decision the user makes, at the moment
// they make it, with the browser's own prompt rather than this page's word for it.
//
// The alternative, `host_permissions: ["https://*/*"]`, was rejected. It is one line
// shorter and it makes the Save button work with no prompt, and it also means an extension
// whose entire pitch is "the code cannot be swapped and the destination is yours to
// choose" would ship with standing permission to talk to every website on the internet.
// A reviewer reading the manifest should be able to see the blast radius without reading
// any code, and with the optional split they can.
//
// The loopback grant is deliberate and not an oversight: a self-hoster testing against
// 127.0.0.1 has no third party to protect them from, and prompting for it would train the
// exact reflex ("just click allow") that the prompt for a real host depends on not having.

import {
  DEFAULT_ORIGIN, storedOrigin, setSignalOrigin, clearSignalOrigin, parseOrigin, matchPatternFor,
} from './endpoint.js';

const $ = (id) => document.getElementById(id);

const input = $('origin-input');
const status = $('origin-status');

/** Say something, and say what KIND of something it is, so colour is not the only signal. */
function say(text, kind) {
  status.textContent = text;
  status.classList.remove('error', 'muted');
  if (kind === 'bad') status.classList.add('error');
  if (kind === 'quiet') status.classList.add('muted');
}

/**
 * Does this browser expose the optional-permissions API at all?
 *
 * Firefox's MV3 has chrome.permissions, but this page is also openable as a plain file
 * during development, where `chrome` is undefined and every call here would throw a
 * ReferenceError that reads as a broken page. Feature-detect instead of assuming.
 */
function permissionsApi() {
  return typeof chrome !== 'undefined' && chrome?.permissions ? chrome.permissions : null;
}

// storedOrigin(), not signalOrigin(): this page must show what is WRITTEN, not what was
// pinned when this module was evaluated. They differ the moment Save succeeds, and a page
// that reported the pinned value would say "Signalling to <the old one>" immediately after
// telling the user it had saved the new one.
const patternFor = matchPatternFor;

async function refresh() {
  const current = storedOrigin();
  input.value = current;
  const api = permissionsApi();
  if (!api) {
    say(`Signalling to ${current}. This page cannot check host permissions here.`, 'quiet');
    return;
  }
  let granted = false;
  try {
    granted = await api.contains({ origins: [patternFor(current)] });
  } catch (err) {
    // A refusal to answer is not a grant. Say which it was.
    say(`Signalling to ${current}, but the browser would not say whether this extension `
      + `is allowed to reach it: ${err.message}`, 'bad');
    return;
  }
  if (granted) {
    say(current === DEFAULT_ORIGIN
      ? `Signalling to ${current}, the default.`
      : `Signalling to ${current}.`, 'quiet');
  } else {
    // This is reachable: a user can revoke a host permission from the browser's own
    // extension settings long after saving an origin here, and the stored value survives
    // it. Every request would then fail with an opaque network error, so name the cause.
    say(`Signalling to ${current}, but this extension is NOT allowed to reach it. `
      + 'Press Save to ask for permission again.', 'bad');
  }
}

$('origin-save').addEventListener('click', async () => {
  const raw = input.value;
  // Validated BEFORE anything is requested or stored. Asking the browser for permission to
  // reach a string that is not an origin produces a confusing prompt and then a failure.
  const parsed = parseOrigin(raw);
  if (!parsed.ok) {
    say(`That is not a usable signalling origin: ${parsed.reason}.`, 'bad');
    return;
  }
  const api = permissionsApi();

  // chrome.permissions.request must be called while the user activation from this click is
  // still live. An `await` before it spends the activation and the browser refuses with
  // "This function must be called during a user gesture", which surfaces as a Save button
  // that silently does nothing. So the request is the FIRST asynchronous thing here, and
  // the storage write happens after it rather than before.
  if (api) {
    let ok = false;
    try {
      ok = await api.request({ origins: [patternFor(parsed.origin)] });
    } catch (err) {
      say(`The browser refused to ask for permission to reach ${parsed.origin}: ${err.message}`, 'bad');
      return;
    }
    if (!ok) {
      // Deliberately does not save. Storing an origin the extension cannot reach would
      // leave the gate failing every request with a network error and this page reporting
      // success, which is the shape of bug this project treats as worse than a crash.
      say(`Permission to reach ${parsed.origin} was refused, so nothing was changed. `
        + `Still signalling to ${storedOrigin()}.`, 'bad');
      return;
    }
  }

  const saved = setSignalOrigin(parsed.origin);
  if (!saved.ok) {
    say(`Could not save that origin: ${saved.reason}.`, 'bad');
    return;
  }
  say(`Saved. New gates will signal to ${saved.origin}. A gate already open in another tab `
    + 'keeps using the origin it started with, so reload it.', null);
});

$('origin-reset').addEventListener('click', async () => {
  clearSignalOrigin();
  // The permission for a previously configured origin is deliberately NOT revoked here.
  // Revoking is the browser's own affair and doing it silently from a "use the default"
  // button would be a second, unannounced action behind one click. The page below says
  // where to do it.
  await refresh();
  say(`Back to the default, ${DEFAULT_ORIGIN}. If you granted access to another host, `
    + "you can withdraw it in the browser's extension settings.", null);
});

refresh().catch((err) => {
  say(`Could not read the current setting: ${err.message}`, 'bad');
});
