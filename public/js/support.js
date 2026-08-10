// Support section and source link.
//
// This lives in its own module because the landing and the gate are two separate
// DOCUMENTS now (index.html and app.html), and that separation is the point: the
// landing may one day carry a sponsor slot, and nothing on the landing is allowed to
// share a script context, a CSP or a JS heap with the page that holds a decryption
// key. So the two documents load disjoint entry scripts, and the handful of things
// genuinely common to both -- the donation cards, the AGPL section 13 link -- are
// here rather than duplicated or pulled in from app.js.
//
// Nothing in this file touches a room, a key or a peer connection. Keep it that way:
// it is the one module the ad-bearing document is allowed to load.

import { encodeQr, drawQr } from './qr.js';

const $ = (id) => document.getElementById(id);

/**
 * Write to the clipboard, reporting rather than throwing when the browser refuses.
 * Returns whether it landed, so the caller can say so on the button itself.
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
      openQr(btn.dataset.qrLabel || which.toUpperCase(), address, btn);
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
  if (!modal || !canvas || !titleEl || !addrEl || !closeBtn || !scrim) return () => {};

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

  function open(name, address, from) {
    try {
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

/**
 * AGPL-3.0 section 13: users interacting with the program over a network must be
 * offered its source. It has to name whatever source THIS instance runs, which for
 * somebody else's deployment is not our repository, so it comes from /api/config and
 * stays hidden when the operator has not set one.
 */
export function applySourceLink(sourceUrl) {
  const link = $('source-link');
  if (!link || !sourceUrl) return;
  link.href = sourceUrl;
  link.hidden = false;
}
