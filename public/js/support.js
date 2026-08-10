// The donation panel: copy buttons, and a QR lightbox over the addresses.
//
// This lives in its own module because the landing and the gate are two separate
// DOCUMENTS now (index.html and app.html), and that separation is the point: the
// landing may one day carry a sponsor slot, and nothing on the landing is allowed to
// share a script context, a CSP or a JS heap with the page that holds a decryption
// key. So the two documents load disjoint entry scripts.
//
// Only the landing loads this one. app.html carries no donation cards, no address
// elements and no modal markup, so wireSupport() on the gate would wire precisely
// nothing: it was never called there, and until 2026-08-10 app.js nonetheless fetched
// the whole file to reach two helpers that had no business being in it. Those moved to
// common.js, which is what both documents actually share; what is left here is the part
// only one document has markup for. tests/size.test.mjs holds that line in both
// directions: the gate must not fetch this, and the landing must.
//
// Nothing in this file touches a room, a key or a peer connection. Keep it that way:
// it is the one module the ad-bearing document is allowed to load.

import { copyText } from './common.js';

const $ = (id) => document.getElementById(id);

/**
 * Fetch the QR encoder the first time a donation address is shown.
 *
 * Reached by import() so that qr.js is not among the files a browser fetches before the
 * gate is usable: opening the donation modal is a decision nobody has made at load, and
 * this file is also loaded by the landing document, which never draws a QR unless asked.
 * Cached, so the second address is drawn without a second fetch.
 */
let qrMod = null;
async function loadQr() {
  if (!qrMod) qrMod = await import('./qr.js');
  return qrMod;
}

/**
 * Copy buttons and lazily-rendered QR codes for the donation addresses.
 * Safe to call on a document that has no support cards: it wires nothing.
 */
export function wireSupport(report = () => {}) {
  for (const btn of document.querySelectorAll('[data-copy]')) {
    btn.addEventListener('click', async () => {
      const source = $(btn.dataset.copy);
      if (!source) return;
      const label = btn.textContent;
      const copied = await copyText(source.textContent.trim(), report);
      btn.textContent = copied ? 'Copied' : 'Select it manually';
      setTimeout(() => { btn.textContent = label; }, 2500);
    });
  }

  const openQr = wireQrModal(report);
  for (const btn of document.querySelectorAll('[data-qr]')) {
    btn.addEventListener('click', () => {
      const which = btn.dataset.qr;
      const address = $(`addr-${which}`)?.textContent.trim();
      if (!address) return;
      // open() is async now that the encoder is fetched on first use, and it reports its
      // own failures. This catch is for anything it does NOT expect: without it a throw
      // past its internal try becomes an unhandled rejection with no message anywhere.
      openQr(btn.dataset.qrLabel || which.toUpperCase(), address, btn)
        .catch((err) => report(`could not open the QR code: ${err.message}`, 'warn'));
    });
  }
}

// How long the overlay's fade lasts. Kept next to the stylesheet's own duration on
// purpose: this is the wait before `hidden` goes back on, and if it undershoots the
// overlay disappears mid-fade instead of dissolving.
const QR_FADE_MS = 180;

/**
 * The QR lightbox: one dialog, reused by every address on the page.
 *
 * Returns an open(name, address, opener) function, or a no-op on a document that has
 * no modal markup, so the caller does not have to care which document it is on.
 */
function wireQrModal(report) {
  const modal = $('qr-modal');
  const canvas = $('qr-modal-canvas');
  const titleEl = $('qr-modal-title');
  const addrEl = $('qr-modal-addr');
  const closeBtn = $('qr-modal-close');
  const scrim = $('qr-modal-scrim');
  // async, so that the no-op returns a promise exactly as the real open() does. A bare
  // () => {} here would make the caller's .catch() throw on any document without the
  // modal markup, which is every document this file is loaded by except the landing.
  if (!modal || !canvas || !titleEl || !addrEl || !closeBtn || !scrim) return async () => {};

  // Whatever was focused when the dialog opened, so focus goes back where the reader
  // left it rather than to the top of the document.
  let opener = null;
  let fading = 0;

  function onKey(event) {
    if (event.key === 'Escape') close();
  }

  function close() {
    if (modal.hidden) return;
    modal.classList.remove('qr-open');
    document.removeEventListener('keydown', onKey);
    // `hidden` is what actually takes the overlay out of the layout, and setting it in
    // the same breath as removing the class would skip the fade entirely.
    clearTimeout(fading);
    fading = setTimeout(() => { modal.hidden = true; }, QR_FADE_MS);
    const back = opener;
    opener = null;
    back?.focus();
  }

  // Async only because the encoder is fetched on first use. The modal is still not shown
  // until the code is actually on the canvas, which is the behaviour that matters here: a
  // donation panel that appears with a blank white square where the address should be is
  // worse than one that appears a frame later.
  async function open(name, address, from) {
    try {
      const { encodeQr, drawQr } = await loadQr();
      drawQr(canvas, encodeQr(address));
    } catch (err) {
      // Never show a blank white square implying a scannable code.
      report(`could not render the ${name} QR code: ${err.message}. Copy the address instead.`, 'warn');
      return;
    }
    titleEl.textContent = `${name} address`;
    addrEl.textContent = address;
    canvas.setAttribute('aria-label', `${name} donation address as a QR code`);

    opener = from ?? null;
    clearTimeout(fading);
    modal.hidden = false;
    // One layout between "in the layout" and "visible", so the transition has two states
    // to move between. Without it the browser only ever sees the final one.
    //
    // Reading offsetHeight rather than requestAnimationFrame: rAF does not run in a tab
    // that is not being painted, and a modal that is opened while the tab is hidden then
    // stays at opacity 0 over the whole viewport, invisible and still eating clicks. A
    // forced layout happens whether or not the engine intends to paint.
    void modal.offsetHeight;
    modal.classList.add('qr-open');
    closeBtn.focus();
    document.addEventListener('keydown', onKey);
  }

  closeBtn.addEventListener('click', close);
  // The scrim, not the overlay: a click anywhere in the panel, including on the address
  // while selecting it, would otherwise close the thing being read.
  scrim.addEventListener('click', close);
  return open;
}

