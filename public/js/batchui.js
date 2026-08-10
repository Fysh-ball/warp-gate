// ONE row, one Accept, for a whole batch of files.
//
// Split out of app.js and reached through import() for the same reason qr.js, share.js,
// resume.js and download.js are: it cannot run until the OTHER device announces several
// files at once, which is a decision nobody has made while a gate is opening. Everything
// here is therefore off the eager graph that tests/size.test.mjs measures, and app.js keeps
// only the loader. The batch PROTOCOL is not here: parsing, validating and bounding the
// offer all live in link.js, on the boot path, because a control frame arrives whether or
// not this file was ever fetched. This is the drawing half and nothing else.
//
// The problem it solves is small to describe and was miserable to live with: a phone
// sending five photos made the laptop press Accept five times. The reason is real rather
// than an oversight. Accepting opens a file-system dialog, and browsers only open those
// inside a user gesture, so one gesture bought one file. The fix is not to accept without
// a gesture, it is to spend ONE gesture on the whole set: showDirectoryPicker returns a
// folder, and every file in the batch is then written into it with no further dialog.
import { formatBytes, sanitizeFilename } from './transfer.js';

/**
 * Draw (or redraw) the single accept row for one announced batch.
 *
 * `ui` carries the pieces this row needs from app.js: fileRow, rowTitle, rowStatus, log,
 * scrollMessages and the live session. They are passed rather than imported because they
 * are app.js's own DOM helpers and its one session instance, and importing app.js back
 * from here would put this module on the eager graph through the cycle.
 *
 * `d.names` are strings the OTHER device chose. They go through sanitizeFilename and reach
 * the DOM as textContent, never as HTML: a filename is the one field in this protocol a
 * peer writes and this page displays verbatim.
 */
export function renderBatchOffer(d, ui) {
  // Keyed on the batch id, so a peer announcing the same batch twice updates one row rather
  // than stacking a second Accept for consent already being asked for.
  const row = ui.fileRow(`batch-${d.batch}`, 'them', d.label);
  ui.rowTitle(row).textContent = `Accept ${d.count} files (${formatBytes(d.bytes)})?`;

  let names = row.querySelector('.file-names');
  if (!names) {
    names = document.createElement('div');
    names.className = 'file-names muted small';
    row.appendChild(names);
  }
  names.textContent = d.names.map((name) => sanitizeFilename(name, 'file')).join(', ');

  // Rebuilt rather than appended to, for that same case: two Accept buttons on one row
  // would both be live and the second click would find no batch.
  for (const old of row.querySelectorAll('button')) old.remove();

  const accept = document.createElement('button');
  accept.className = 'primary';
  accept.textContent = `Accept ${d.count} files`;
  const refuse = document.createElement('button');
  refuse.className = 'secondary';
  refuse.textContent = 'Refuse';

  accept.addEventListener('click', async () => {
    accept.disabled = true;
    refuse.disabled = true;
    let directory = null;
    if (typeof globalThis.showDirectoryPicker === 'function') {
      try {
        // Inside the click, for the same reason the single-file Accept opens its picker
        // inside the click: a gesture cannot be borrowed later. This is the good path, the
        // only one that both streams to disk AND asks once: one dialog, N files.
        directory = await globalThis.showDirectoryPicker({ id: 'warp-gate-inbox', mode: 'readwrite' });
      } catch (err) {
        if (err.name === 'AbortError') {
          // Dismissing the folder dialog is the user saying no, exactly as dismissing the
          // save dialog is, so nothing is accepted and the row stays answerable.
          ui.log('you closed the folder dialog, so nothing was accepted', 'warn');
          accept.disabled = false;
          refuse.disabled = false;
          return;
        }
        // A dialog that never opened is not a refusal. Fall through with no directory, which
        // is the route a browser without a folder picker takes, and say why rather than
        // leaving the files somewhere unexpected in silence.
        ui.log(`could not open a folder to save into (${err.name}: ${err.message}); `
          + 'these will be saved the way this browser normally saves a received file', 'warn');
        directory = null;
      }
    }
    try {
      await ui.session.acceptBatch(d.peer ?? null, { directory });
      accept.remove();
      refuse.remove();
      ui.rowStatus(row, directory
        ? `Accepted ${d.count} files into the folder you chose.`
        : `Accepted ${d.count} files.`, 'muted small');
    } catch (err) {
      ui.log(`could not start receiving these files: ${err.message}`, 'bad');
      accept.disabled = false;
      refuse.disabled = false;
    }
  });

  refuse.addEventListener('click', async () => {
    accept.disabled = true;
    refuse.disabled = true;
    try {
      await ui.session.refuseBatch(d.peer ?? null);
    } catch (err) {
      ui.log(`could not tell the other device these were refused: ${err.message}`, 'warn');
    }
    accept.remove();
    refuse.remove();
    ui.rowStatus(row, 'Refused.', 'muted small');
  });

  row.appendChild(accept);
  row.appendChild(refuse);
  ui.scrollMessages();
}
