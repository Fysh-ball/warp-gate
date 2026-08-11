/**
 * The camera scan panel: everything between pressing "scan the code with the camera" and a
 * gate code landing in the join field.
 *
 * Split out of app.js on 2026-08-10, when the disconnect, batch and pending-accept work put
 * the gate 429 B over its raw ceiling. The rule for what may leave is the one every other
 * split here obeys: it must be unreachable until somebody has made a decision that nobody
 * has made while the page is loading. This qualifies twice over. The panel is only revealed
 * on a device that can open a camera at all, and nothing in this file runs until that button
 * is pressed, which is a person choosing to scan a code rather than type one. A gate joined
 * by typing the words, which is the path on a laptop with no camera and the path anybody
 * takes when the code is already on their clipboard, never fetches a byte of it.
 *
 * It also puts this code next to what it drives. qrscan.js and qrdecode.js were already
 * behind the same decision, so the button handler was the last eager thing standing in
 * front of ~57 KB it did not use. What stayed in app.js is the part that genuinely runs on
 * every load: the one property lookup that decides whether the button may be shown at all.
 */

// Set once the panel's own controls have been wired. The button in app.js can be pressed
// again after a cancel, and this module is cached by the loader, so a second press would
// otherwise stack a second "stop the camera" listener on the same element: the panel would
// then close twice and abort a scan that a third press had already started.
let wired = false;

// The controller for the scan in flight, module level because the cancel button closes over
// nothing and has to be able to reach whatever is running now rather than what was running
// when it was wired.
let scanAbort = null;

/**
 * Open the camera, read one code, and hand it to the join path.
 *
 * @param {object} ui
 * @param {(id: string) => HTMLElement} ui.$ element lookup, passed in rather than imported
 *   so this module holds no opinion about the document it is drawing into.
 * @param {(msg: string, level?: string) => void} ui.log the message list.
 * @param {() => void} ui.joinNow the same join path the button and the Enter key use. A
 *   scanned code goes through it rather than around it, so a scan is not a second, less
 *   validated way into a gate.
 */
export async function scanIntoField({ $, log, joinNow }) {
  const btn = $('scan-btn');
  const panel = $('scan-panel');
  const video = $('scan-video');
  const note = $('scan-note');

  const close = () => {
    if (scanAbort) { scanAbort.abort(); scanAbort = null; }
    panel.hidden = true;
    btn.hidden = false;
  };

  if (!wired) {
    $('scan-cancel').addEventListener('click', close);
    wired = true;
  }

  btn.hidden = true;
  panel.hidden = false;
  note.textContent = 'Starting the camera...';

  let mod;
  try {
    mod = await import('./qrscan.js');
  } catch (err) {
    close();
    log(`the scanner could not be loaded: ${err.message}`, 'bad');
    return;
  }

  scanAbort = new AbortController();
  note.textContent = 'Point the camera at the other screen. Nothing leaves this device: '
    + 'the picture is read here and thrown away.';

  try {
    const text = await mod.scanOnce(video, { signal: scanAbort.signal });
    close();
    // Put it in the field before joining. The person watching needs to see WHAT was read,
    // especially when the scan picked up a different code than they meant, and a scanner
    // that silently acts on what it saw is a scanner nobody can correct.
    $('join-input').value = text;
    joinNow();
  } catch (err) {
    close();
    // One message per cause. A single "could not scan" for a refused permission and for a
    // laptop with no camera names neither of them.
    const said = {
      denied: 'the camera was not allowed. Type the words instead, or allow the camera in the site settings.',
      no_camera: 'no camera was found on this device.',
      in_use: 'the camera is already in use by another app.',
      timeout: 'no code was found. Try filling more of the frame with the code.',
      unsupported: 'this browser cannot open a camera.',
      cancelled: null, // the user closed it; saying so is noise
    }[err.code] ?? `the camera failed: ${err.message}`;
    if (said) log(said, 'warn');
  }
}
