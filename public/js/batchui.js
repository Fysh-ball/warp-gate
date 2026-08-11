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

// What each announced batch is doing, keyed by the batch id the sender minted.
//
// THE COMPLAINT THIS EXISTS FOR, verbatim: "from the perspective of a new user only one item
// is being downloaded no '6 others are queued' or 'Accepted [checkmark]'". Seven files and
// 3.2 GB were accepted in one click, and the transcript then showed the words "Accepted 7
// files." followed by a single progress bar for file one, and nothing whatsoever about files
// two to seven for as long as the first one took.
//
// The reason is structural rather than an oversight, which is why a row per file cannot be
// drawn at accept time: a transfer row is keyed by the transfer id, and the sender does not
// mint an id for a file until it sends that file's FILE_START. Files go one at a time by
// design, so ids six deep in the batch do not exist yet. What DOES exist at accept time is
// the announcement: a count, a byte total and the names, all validated in link.js before
// they were ever drawn. So the batch's own row carries the list, and each entry is moved
// through its states as the per-file events arrive. Queued is a normal state here and has to
// look like one, rather than looking like nothing happening.
const batches = new Map();

// The states one announced file moves through, and the words the row shows for each. Held as
// data rather than as branches so that "what can a file be doing" has one answer: a state
// added without a label here would render as nothing at all, which is the failure this whole
// module exists to remove.
const STATE_TEXT = {
  offered: 'waiting for you to accept',
  queued: 'waiting its turn',
  receiving: 'arriving now',
  done: 'saved',
  failed: 'did not arrive',
  refused: 'not accepted',
};

/** The slot in an announced batch that a per-file event belongs to, or null for a stranger. */
function slotFor(model, { id, name }) {
  // By id first: once a file has started, its id is the only thing that cannot be ambiguous.
  const byId = model.slots.find((s) => s.id && s.id === id);
  if (byId) return byId;
  // Then by name among the ones not yet started. Two files in one batch may legitimately
  // share a name, so this takes the FIRST unstarted match rather than assuming uniqueness.
  const clean = sanitizeFilename(name, 'file');
  // A `?? model.slots.find((s) => !s.id)` used to follow, binding a file whose name matched
  // NOTHING to whichever slot happened to be free. Removed in review on 2026-08-10 because it
  // laundered a name the user never agreed to into one they did: announce [a.txt, b.txt,
  // c.txt], accept, deliver `evil.exe` under the same batch id, and the row said "a.txt:
  // saved". That is not a display bug, it is a consent bug, because link.js's auto-accept
  // grant is keyed on the batch id, the remaining count and the size and never on the name,
  // so the sender chooses what actually lands. An arriving name nobody announced is now
  // reported AS an unannounced file by the caller below.
  return model.slots.find((s) => !s.id && s.name === clean) ?? null;
}

/**
 * Redraw one batch row's list and its summary line.
 *
 * Rebuilt from the model rather than patched in place: a batch is at most MAX_BATCH_FILES
 * entries, and a list that is rewritten whole cannot drift out of step with the counts
 * printed underneath it, which is exactly the class of bug that shows a user "6 queued" next
 * to five rows.
 */
function paintBatch(model, ui) {
  const row = document.getElementById(`transfer-batch-${model.batch}`);
  if (!row) return;
  let list = row.querySelector('.file-names');
  if (!list) {
    list = document.createElement('div');
    list.className = 'file-names muted small';
    row.appendChild(list);
  }
  // textContent per line, never innerHTML: a filename is the one field in this protocol that
  // the OTHER device writes and this page displays, so it goes through sanitizeFilename on
  // the way in and reaches the DOM as text on the way out.
  list.textContent = '';
  for (const slot of model.slots) {
    const line = document.createElement('div');
    line.className = 'file-line';
    // The unannounced marker is part of the NAME, not a class on it, because the thing that
    // has to survive is the sentence: a user reading "evil.exe: saved" has no way to know it
    // was never in the list they agreed to, and a colour they may not be able to see is not
    // an answer to that. See slotFor for the measurement.
    let what = slot.name;
    if (slot.announced === false) what += ' (this was not one of the files you were offered)';
    else if (slot.renamed) what += ` (the other device then sent it as ${slot.renamed})`;
    // TWO spans, not one text node, changed on 2026-08-10. This used to write the whole entry
    // as `${name}: ${state}`, which gave CSS nothing to work with: a text node cannot be
    // ellipsed in one part and kept in another, so a long filename pushed the state off the
    // end of the line and every entry took two lines in a 308px column. Measured on a phone
    // at 390x844 with a batch of seven, that made the list 201px against 101px, and the
    // stylesheet had to cap it at 116px with a scroller inside a transcript row. With a seam
    // the name can be the flexible, ellipsed part and the state the fixed one, so an entry is
    // one line at any width and the cap is rarely reached.
    //
    // The ": " lives at the head of the STATE, not at the tail of the name, on purpose. On
    // the tail it would be the first thing an ellipsis ate, leaving "averyverylongna..." with
    // no punctuation between the name and its state; at the head it is pinned to the part
    // that never truncates. It also keeps `line.textContent` exactly the string this module
    // has always produced, which is what tests/batchui.test.mjs reads.
    const nameEl = document.createElement('span');
    nameEl.className = 'file-line-name';
    nameEl.textContent = what;
    const stateEl = document.createElement('span');
    stateEl.className = 'file-line-state';
    stateEl.textContent = `: ${slot.detail ?? STATE_TEXT[slot.state] ?? slot.state}`;
    line.appendChild(nameEl);
    line.appendChild(stateEl);
    list.appendChild(line);
  }

  // Only announced slots, so a peer cannot inflate its own denominator by delivering files
  // nobody asked for: "3 of 5 saved" against a batch of three is a peer editing the tally.
  const tally = (state) => model.slots.filter((s) => s.announced !== false && s.state === state).length;
  const done = tally('done');
  const receiving = tally('receiving');
  const queued = tally('queued');
  const lost = tally('failed') + tally('refused');
  const strangers = model.slots.filter((s) => s.announced === false || s.renamed).length;
  if (!model.accepted) return;
  const parts = [`${done} of ${model.count} saved`];
  if (receiving) parts.push(`${receiving} arriving now`);
  if (queued) parts.push(`${queued} waiting their turn`);
  if (lost) parts.push(`${lost} did not arrive`);
  // Counted separately and never folded into the "of N", because it is a different fact: the
  // other device sent something outside what it asked permission for, and a summary that
  // absorbed it would be the same laundering slotFor stopped doing.
  if (strangers) parts.push(`${strangers} did not match what you were offered`);
  // Sequential by design, so "waiting their turn" is the true description and not an
  // apology: saying it plainly is the difference between a queue and a stall.
  ui.rowStatus(row, `${parts.join(', ')}. Files arrive one at a time.`,
    lost || strangers ? 'error small' : 'muted small');
}

/**
 * Move one file of an announced batch to a new state and repaint.
 *
 * Called from app.js's own file listeners, because those events are the only place the
 * per-file ids appear. A batch nobody announced (a single-file send, or a batch offered
 * before this module was fetched) has no model and is silently ignored: this draws a row
 * that already exists and never invents one.
 */
export function noteBatchFile({ batch, id, name, state, detail = null }, ui) {
  const model = batches.get(batch);
  if (!model) return false;
  const clean = sanitizeFilename(name, 'file');
  let slot = slotFor(model, { id, name });
  if (!slot) {
    // A file arriving under an announced batch id whose name was never announced. It is real
    // (link.js has already accepted or offered it) so it must be SEEN, and it must be seen as
    // what it is rather than wearing a name the user consented to. Appended rather than
    // dropped: a return of false here would leave the only trace of it in the single-file row
    // above, which is precisely the "which of these did I actually agree to" question this
    // module exists to answer.
    slot = { name: clean, state, id: id ?? null, detail, announced: false };
    model.slots.push(slot);
    paintBatch(model, ui);
    return true;
  }
  if (id) slot.id = id;
  // The name is re-checked on EVERY event, not only when the slot is first bound. A slot
  // matched by id was matched on a value the sender minted, so nothing about that match says
  // the sender is still using the name it announced: it can offer `a.txt`, take the slot, and
  // then send FILE_START for `evil.exe` on the same id. Renaming the slot in place would be
  // the same laundering by a slower route, so the row says both names instead.
  if (clean && slot.name !== clean && slot.announced !== false) slot.renamed = clean;
  slot.state = state;
  slot.detail = detail;
  paintBatch(model, ui);
  return true;
}

/**
 * Forget every batch. Called when the gate ends.
 *
 * link.js nulls `pendingBatch`, `batchGrant` and `refusedBatch` on close, with the reason
 * written out there: consent does not survive the gate it was given in. This map is the
 * drawing half of that same state and was never cleared at all, so peer-supplied filenames
 * sat in memory for the life of the PAGE, outliving the gate they came from and available to
 * whatever reconnected next under the same batch id. Cleared on 2026-08-10 in review.
 */
export function forgetBatches() {
  batches.clear();
}

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

  // Rebuilt on a re-announcement of the SAME batch, for the same reason the buttons below
  // are: a peer that announces twice must update one row rather than stack a second set of
  // state next to it.
  //
  // The old code kept the existing model unconditionally, on a comment claiming "the
  // announcement carries the same names in the same order". Nothing enforced that and
  // link.js's onBatchOffer replaces `pendingBatch` on the same id with whatever arrives, so
  // it was a claim about a peer's behaviour written into this device's code. Measured on
  // 2026-08-10: announce three names, re-announce the same id with two different ones, and
  // the row titled itself "Accept 2 files (5 B)?" over the three OLD names and then tallied
  // "0 of 3 saved" against a grant for 2. So the claim is CHECKED here instead of asserted.
  // An announcement that really does repeat itself keeps every slot, including the state of
  // anything already in flight, which is what that comment wanted; one that differs in any
  // way starts again, because a batch row is a picture of the offer on the table and this is
  // now a different offer.
  const names = d.names.map((name) => sanitizeFilename(name, 'file'));
  const prior = batches.get(d.batch);
  // `slots.length >= names.length` rather than equality: noteBatchFile appends a slot for a
  // file that was never announced, and one of those must not force a rebuild that would throw
  // away the very warning it was appended to carry.
  const same = prior && prior.count === d.count && prior.bytes === d.bytes
    && prior.slots.length >= names.length
    && names.every((name, i) => prior.slots[i].name === name && prior.slots[i].announced !== false);
  const model = same ? prior : {
    batch: d.batch,
    count: d.count,
    bytes: d.bytes,
    accepted: false,
    slots: names.map((name) => ({ name, state: 'offered', id: null, detail: null })),
  };
  batches.set(d.batch, model);
  paintBatch(model, ui);

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
    if (!ui.session) { ui.log('this gate has ended, so these files cannot be accepted', 'bad'); return; }
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
      // The title carries the answer from here on, because the status line below it is now
      // the running tally and the two must not both try to be the headline. "Accepted 7
      // files." with nothing under it was the whole of what a user got before.
      ui.rowTitle(row).textContent = directory
        ? `Accepted ${d.count} files (${formatBytes(d.bytes)}) into the folder you chose.`
        : `Accepted ${d.count} files (${formatBytes(d.bytes)}).`;
      model.accepted = true;
      // Everything not already moving is now waiting its turn, which is a state and has to
      // be drawn as one: this is the "6 others are queued" the report asked for.
      for (const slot of model.slots) if (slot.state === 'offered') slot.state = 'queued';
      paintBatch(model, ui);
    } catch (err) {
      ui.log(`could not start receiving these files: ${err.message}`, 'bad');
      accept.disabled = false;
      refuse.disabled = false;
    }
  });

  refuse.addEventListener('click', async () => {
    if (!ui.session) { ui.log('this gate has ended, so there is nothing to refuse', 'warn'); return; }
    accept.disabled = true;
    refuse.disabled = true;
    try {
      await ui.session.refuseBatch(d.peer ?? null);
    } catch (err) {
      ui.log(`could not tell the other device these were refused: ${err.message}`, 'warn');
    }
    accept.remove();
    refuse.remove();
    for (const slot of model.slots) slot.state = 'refused';
    model.accepted = true;
    paintBatch(model, ui);
    ui.rowStatus(row, `Refused all ${d.count} files.`, 'muted small');
  });

  row.appendChild(accept);
  row.appendChild(refuse);
  ui.scrollMessages();
}
