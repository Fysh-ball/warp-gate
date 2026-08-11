// What a receiver sees when it accepts SEVEN files at once.
//
// THE COMPLAINT THIS REPRODUCES, verbatim: "from the perspective of a new user only one item
// is being downloaded no '6 others are queued' or 'Accepted [checkmark]'". Seven files and
// 3.2 GB were accepted in one click and the transcript then showed the words "Accepted 7
// files.", one progress row for file one, and nothing whatsoever about files two to seven for
// as long as the first one took. Files arrive one at a time by design, so six of the seven
// were in a perfectly normal state that had no way of being drawn.
//
// Tested here rather than only in a browser for the same reason tests/disconnect.test.mjs
// exists: a browser test proves the wiring on one page at one moment, and what has to hold is
// that every per-file event moves the batch's own model. So this runs the REAL batchui.js
// against a stand-in document, and asserts on the text that reaches the DOM. The stand-in is
// deliberately small and dumb: it implements only what batchui.js actually touches, so a
// batchui.js that started using something else would throw rather than quietly pass.
//
// The one thing it cannot see is whether app.js still calls noteBatchFile at all, because
// app.js cannot be imported outside a browser. That edge is asserted from app.js's source at
// the bottom, and it is asserted per event rather than as one count: deleting a single
// listener's call is exactly the regression that would put files two to seven back in
// silence, and a total that says "5 calls somewhere" cannot see it.
import { check, summary } from './lib/harness.mjs';

const { noteBatchFile, renderBatchOffer, forgetBatches } = await import('../public/js/batchui.js');
const { sanitizeFilename } = await import('../public/js/transfer.js');
const fs = await import('node:fs');

// ---------------------------------------------------------------- the stand-in document

// Only what batchui.js uses: className, textContent, appendChild, remove, addEventListener,
// disabled, querySelector('.file-names') and querySelectorAll('button'). Anything else is
// absent on purpose so that reaching for it fails loudly here instead of on a phone.
class El {
  constructor(tag) {
    this.tag = tag;
    this.className = '';
    this.disabled = false;
    this.children = [];
    this.parent = null;
    this.listeners = new Map();
    this.own = '';
  }

  // Children win over own text, which is how the real thing behaves and is what lets the
  // assertions below read a whole list off one element.
  get textContent() {
    return this.children.length ? this.children.map((c) => c.textContent).join('') : this.own;
  }

  // Setting it CLEARS children. paintBatch relies on exactly that to rebuild the list, and a
  // stand-in that kept them would hide a doubling bug rather than reveal it.
  set textContent(value) {
    this.children = [];
    this.own = String(value);
  }

  appendChild(child) {
    child.parent = this;
    this.children.push(child);
    return child;
  }

  remove() {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }

  // Awaited, because both handlers in batchui.js are async and the assertions that follow a
  // click are about what they did after their await.
  async click() {
    for (const fn of this.listeners.get('click') ?? []) await fn();
  }

  matches(sel) {
    return sel.startsWith('.') ? this.className.split(/\s+/).includes(sel.slice(1)) : this.tag === sel;
  }

  descendants() {
    return this.children.flatMap((c) => [c, ...c.descendants()]);
  }

  querySelectorAll(sel) {
    return this.descendants().filter((c) => c.matches(sel));
  }

  querySelector(sel) {
    return this.querySelectorAll(sel)[0] ?? null;
  }
}

const byId = new Map();
globalThis.document = {
  createElement: (tag) => new El(tag),
  getElementById: (id) => byId.get(id) ?? null,
};
// Left undefined on purpose: a browser with no folder picker is the path that must still
// work, and it is the one that exercises the "Accepted N files." title rather than the
// "into the folder you chose" one.
delete globalThis.showDirectoryPicker;

/** app.js's own row helpers, reduced to what batchui.js is handed. */
function makeUi() {
  const seen = { logs: [], accepted: [], refused: [], scrolls: 0 };
  const ui = {
    fileRow(id) {
      const key = `transfer-${id}`;
      let row = byId.get(key);
      if (!row) {
        row = new El('div');
        row.className = 'msg file-row';
        const title = new El('div');
        title.className = 'row-title';
        row.appendChild(title);
        byId.set(key, row);
      }
      return row;
    },
    rowTitle: (row) => row.querySelector('.row-title'),
    rowStatus(row, text, cls) {
      let el = row.querySelector('.row-status');
      if (!el) {
        el = new El('div');
        el.className = 'row-status';
        row.appendChild(el);
      }
      el.statusClass = cls;
      el.textContent = text;
    },
    log: (msg, level = '') => seen.logs.push(`${level}:${msg}`),
    scrollMessages: () => { seen.scrolls += 1; },
    session: {
      async acceptBatch(peer, opts) { seen.accepted.push({ peer, opts }); },
      async refuseBatch(peer) { seen.refused.push(peer); },
    },
  };
  return { ui, seen };
}

/** The list of per-file lines currently drawn under a batch row, in order. */
function lines(batch) {
  const row = byId.get(`transfer-batch-${batch}`);
  const list = row?.querySelector('.file-names');
  return list ? list.children.map((c) => c.textContent) : [];
}

function statusOf(batch) {
  const el = byId.get(`transfer-batch-${batch}`)?.querySelector('.row-status');
  return el ? { text: el.textContent, cls: el.statusClass } : { text: null, cls: null };
}

function titleOf(batch) {
  return byId.get(`transfer-batch-${batch}`)?.querySelector('.row-title')?.textContent ?? null;
}

function buttons(batch) {
  return (byId.get(`transfer-batch-${batch}`)?.querySelectorAll('button') ?? [])
    .map((b) => b.textContent);
}

const SEVEN = ['clip-one.mp4', 'clip-two.mp4', 'clip-three.mp4', 'holiday.zip',
  'notes.txt', 'photo.heic', 'song.flac'];
const GB = 1024 * 1024 * 1024;

function offer(ui, { batch = 'b1', names = SEVEN, bytes = Math.round(3.2 * GB) } = {}) {
  renderBatchOffer({
    batch, peer: 'p1', label: 'them', count: names.length, bytes, names,
  }, ui);
}

// ---------------------------------------------------------------- 1. the offer itself
{
  const { ui } = makeUi();
  offer(ui);

  // Before the fix the row was one sentence and two buttons: the NAMES of what was being
  // asked for never appeared, so "accept 7 files" was a number and nothing else.
  check('the offer names every file it is asking about', lines('b1').length === 7, lines('b1').length);
  // Length AND content. `[].every()` is true, so a version that draws nothing at all would
  // satisfy a content-only check while showing the user exactly what they complained about.
  check('and says what each one is waiting on',
    lines('b1').length === 7 && lines('b1').every((l) => l.endsWith(': waiting for you to accept')),
    lines('b1')[0] ?? 'nothing was drawn');
  check('and the row still carries one Accept and one Refuse',
    buttons('b1').join('|') === 'Accept 7 files|Refuse', buttons('b1').join('|'));

  // No tally until it has been accepted: a running count of what has been saved is a lie
  // while the answer is still "nothing, you have not said yes".
  check('with no tally before an answer', statusOf('b1').text === null, statusOf('b1').text);

  // Announcing the same batch twice must update ONE row. Two live Accepts is a second click
  // that finds no batch, and two lists is the drift this module exists to remove.
  offer(ui);
  check('a re-announced batch updates one row rather than stacking a second',
    lines('b1').length === 7 && buttons('b1').length === 2,
    `${lines('b1').length} lines, ${buttons('b1').length} buttons`);
}

// ---------------------------------------------------------------- 2. accepting the batch
{
  const { ui, seen } = makeUi();
  offer(ui, { batch: 'b2' });
  const accept = byId.get('transfer-batch-b2').querySelectorAll('button')[0];
  await accept.click();

  check('accepting tells the session, once', seen.accepted.length === 1, seen.accepted.length);
  check('the title says what was accepted and how much',
    titleOf('b2') === 'Accepted 7 files (3.2 GB).', titleOf('b2'));
  check('the buttons are gone once answered', buttons('b2').length === 0, buttons('b2').join('|'));

  // THE FIX. Six files that have not started are six files WAITING, and that is a state with
  // a name. Before this they were absent from the screen entirely.
  check('every file not yet moving says it is waiting its turn',
    lines('b2').filter((l) => l.endsWith(': waiting its turn')).length === 7, lines('b2'));
  check('and the row carries a tally of the whole batch',
    statusOf('b2').text === '0 of 7 saved, 7 waiting their turn. Files arrive one at a time.',
    statusOf('b2').text);
}

// ---------------------------------------------------------------- 3. files arriving
{
  const { ui } = makeUi();
  offer(ui, { batch: 'b3' });
  await byId.get('transfer-batch-b3').querySelectorAll('button')[0].click();

  const noted = noteBatchFile({ batch: 'b3', id: 't1', name: 'clip-one.mp4', state: 'receiving' }, ui);
  check('an incoming file moves its own slot', noted === true, noted);
  check('and only that one', lines('b3')[0] === 'clip-one.mp4: arriving now'
    && lines('b3')[1] === 'clip-two.mp4: waiting its turn', lines('b3').slice(0, 2));
  check('the tally separates arriving from waiting',
    statusOf('b3').text === '0 of 7 saved, 1 arriving now, 6 waiting their turn. Files arrive one at a time.',
    statusOf('b3').text);

  noteBatchFile({ batch: 'b3', id: 't1', name: 'clip-one.mp4', state: 'done' }, ui);
  check('a finished file says it is saved', lines('b3')[0] === 'clip-one.mp4: saved', lines('b3')[0]);
  check('and the tally counts it',
    statusOf('b3').text === '1 of 7 saved, 6 waiting their turn. Files arrive one at a time.',
    statusOf('b3').text);
  check('and a saved batch is not styled as a problem',
    statusOf('b3').cls === 'muted small', statusOf('b3').cls);

  // A later event for the SAME transfer id must find the same slot, not the next free one.
  // Matching by name alone would move a second file the moment two of them shared a name.
  noteBatchFile({ batch: 'b3', id: 't2', name: 'clip-two.mp4', state: 'receiving' }, ui);
  noteBatchFile({ batch: 'b3', id: 't2', name: 'clip-two.mp4', state: 'done' }, ui);
  check('two files done are two lines done, not one line done twice',
    lines('b3').filter((l) => l.endsWith(': saved')).length === 2, lines('b3').slice(0, 3));
}

// ---------------------------------------------------------------- 4. what went wrong
{
  const { ui } = makeUi();
  offer(ui, { batch: 'b4' });
  await byId.get('transfer-batch-b4').querySelectorAll('button')[0].click();

  noteBatchFile({ batch: 'b4', id: 't1', name: 'clip-one.mp4', state: 'done' }, ui);
  // The severed-connection wording from link.js close() arrives on this path, and a row that
  // has GIVEN UP has to read differently from one that is merely waiting.
  noteBatchFile({
    batch: 'b4', id: 't2', name: 'clip-two.mp4', state: 'failed',
    detail: 'The connection to the other device was severed, whether by accident or on purpose',
  }, ui);

  // `?? ''` for the same reason as the markup check below: against a tree that draws no
  // lines at all this has to REPORT the absence, not throw and take the rest with it.
  check('a failed file shows the cause it was given, not a generic word',
    (lines('b4')[1] ?? '').includes('severed, whether by accident or on purpose'),
    lines('b4')[1] ?? 'no line was drawn for it');
  check('the tally reports the loss alongside the rest',
    statusOf('b4').text === '1 of 7 saved, 5 waiting their turn, 1 did not arrive. '
      + 'Files arrive one at a time.', statusOf('b4').text);
  check('and a batch with a loss in it is styled as a problem',
    statusOf('b4').cls === 'error small', statusOf('b4').cls);
}

// ---------------------------------------------------------------- 5. refusing the batch
{
  const { ui, seen } = makeUi();
  offer(ui, { batch: 'b5' });
  await byId.get('transfer-batch-b5').querySelectorAll('button')[1].click();

  check('refusing tells the other device', seen.refused.length === 1, seen.refused.length);
  check('and every file says it was not accepted',
    lines('b5').length === 7 && lines('b5').every((l) => l.endsWith(': not accepted')),
    lines('b5')[0] ?? 'nothing was drawn');
  check('and the row says so once, plainly',
    statusOf('b5').text === 'Refused all 7 files.', statusOf('b5').text);
}

// ---------------------------------------------------------------- 6. names are text
{
  const { ui } = makeUi();
  const hostile = '<img src=x onerror=alert(1)>.png';
  offer(ui, { batch: 'b6', names: [hostile, 'plain.txt'], bytes: 2048 });

  const drawn = lines('b6')[0] ?? '';
  check('a peer-chosen name is sanitised before it is drawn',
    drawn.startsWith(`${sanitizeFilename(hostile, 'file')}:`), drawn || 'no line was drawn');
  // The stand-in has no innerHTML at all, so this asserts the only thing that can be
  // asserted here and the browser suite owns the rest: nothing was parsed as markup, because
  // every line is one element whose whole content is its own text.
  // Read defensively, not because a missing list is expected but because this check has to
  // survive being run against the pre-fix tree: a control that throws here stops the suite
  // and reports nothing about the checks below it, which is a control that measured nothing.
  const list = byId.get('transfer-batch-b6')?.querySelector('.file-names');
  // Each line is TWO spans since 2026-08-10 (the name and the state, so CSS can ellipse one
  // and keep the other), so the claim is no longer "one text node" but "the leaves are text
  // and nothing below them was built as markup". Asserted at both levels: a line has exactly
  // the two spans this module creates, and neither span has element children of its own.
  check('and reaches the row as a name and a state, each of them text and neither of them '
    + 'markup',
    Boolean(list)
      && list.children.every((c) => c.children.length === 2
        && c.children.every((s) => s.children.length === 0)),
    list ? JSON.stringify(list.children.map((c) => c.children.map((s) => s.className)))
      : 'no list was drawn at all');
  check('and the two spans are named so the stylesheet can size them independently, which is '
    + 'the whole reason the seam exists',
    Boolean(list) && list.children.every((c) => c.className === 'file-line'
      && c.children[0].className === 'file-line-name'
      && c.children[1].className === 'file-line-state'),
    list ? JSON.stringify(list.children.map((c) => c.children.map((s) => s.className))) : 'no list');
}

// ---------------------------------------------------------------- 7. batches nobody announced
{
  const { ui } = makeUi();
  const noted = noteBatchFile({ batch: 'never-announced', id: 't9', name: 'x.txt', state: 'done' }, ui);
  check('an event for a batch this device never saw is ignored, not invented',
    noted === false, noted);
  check('and no row is created for it',
    byId.get('transfer-batch-never-announced') === undefined,
    'noteBatchFile must draw rows that exist and never mint one');

  // A single-file send carries no batch at all. app.js's bridge drops those before they get
  // here, and this is the belt to that brace.
  check('a file with no batch is ignored too',
    noteBatchFile({ batch: undefined, id: 't9', name: 'x.txt', state: 'done' }, ui) === false,
    'undefined batch');
}

// -------------------------------------------- 9. a name nobody announced is not laundered
{
  // MEASURED against the real module on 2026-08-10, before the fix: announce [a.txt, b.txt,
  // c.txt], accept, then deliver `evil.exe` under the same batch id, and the row read
  // "a.txt: saved". slotFor's last fallback bound any unmatched name to whichever slot was
  // still free, and link.js's auto-accept grant is keyed on the batch id, the remaining count
  // and the size, never on the name, so the SENDER chooses what actually lands. That makes
  // this a consent bug wearing a display bug's clothes.
  const { ui } = makeUi();
  offer(ui, { batch: 'b9', names: ['a.txt', 'b.txt', 'c.txt'], bytes: 3 });
  await byId.get('transfer-batch-b9').querySelectorAll('button')[0].click();
  noteBatchFile({ batch: 'b9', id: 'x1', name: 'evil.exe', state: 'done' }, ui);

  check('a file whose name was never announced does not take a consented slot',
    lines('b9')[0] === 'a.txt: waiting its turn', lines('b9')[0]);
  check('and it is shown AS an unannounced file rather than dropped in silence',
    (lines('b9')[3] ?? '') === 'evil.exe (this was not one of the files you were offered): saved',
    lines('b9')[3] ?? 'nothing was drawn for it');
  check('and it cannot edit the tally it was never counted in',
    statusOf('b9').text === '0 of 3 saved, 3 waiting their turn, 1 did not match what you '
      + 'were offered. Files arrive one at a time.', statusOf('b9').text);
  check('and a batch carrying one is styled as a problem',
    statusOf('b9').cls === 'error small', statusOf('b9').cls);

  // The slower version of the same laundering: take a slot legitimately by name, then send
  // FILE_START for something else on the id that slot is now bound to.
  noteBatchFile({ batch: 'b9', id: 'x2', name: 'b.txt', state: 'receiving' }, ui);
  noteBatchFile({ batch: 'b9', id: 'x2', name: 'swapped.exe', state: 'done' }, ui);
  check('a slot bound by id still reports the name the file actually arrived under',
    lines('b9')[1] === 'b.txt (the other device then sent it as swapped.exe): saved',
    lines('b9')[1]);
}

// ------------------------------------------- 10. two files in one batch sharing a name
{
  // Section 3 claimed to cover id precedence and duplicate names, but SEVEN has seven
  // DISTINCT names, so name-only matching satisfied it and nothing anywhere exercised the
  // duplicate case the slotFor comment is written about. Found in review on 2026-08-10.
  const { ui } = makeUi();
  offer(ui, { batch: 'b10', names: ['photo.jpg', 'photo.jpg', 'other.txt'], bytes: 3 });
  await byId.get('transfer-batch-b10').querySelectorAll('button')[0].click();

  noteBatchFile({ batch: 'b10', id: 'd1', name: 'photo.jpg', state: 'receiving' }, ui);
  check('the first of two files sharing a name takes the first slot, not both',
    lines('b10')[0] === 'photo.jpg: arriving now'
      && lines('b10')[1] === 'photo.jpg: waiting its turn', lines('b10').slice(0, 2));

  noteBatchFile({ batch: 'b10', id: 'd2', name: 'photo.jpg', state: 'receiving' }, ui);
  check('and the second takes the second, because a started slot is no longer a candidate',
    lines('b10')[0] === 'photo.jpg: arriving now'
      && lines('b10')[1] === 'photo.jpg: arriving now', lines('b10').slice(0, 2));

  // THE id-precedence claim, which needs a duplicate name to mean anything: a later event for
  // d1 must find d1's slot rather than the first slot whose name matches.
  noteBatchFile({ batch: 'b10', id: 'd1', name: 'photo.jpg', state: 'done' }, ui);
  noteBatchFile({ batch: 'b10', id: 'd2', name: 'photo.jpg', state: 'failed', detail: 'gone' }, ui);
  check('and a later event goes to the slot its OWN id holds, not the first name match',
    lines('b10')[0] === 'photo.jpg: saved' && lines('b10')[1] === 'photo.jpg: gone',
    lines('b10').slice(0, 2));
  check('CONTROL: and no unannounced slot was invented for either of them, which is what a '
    + 'duplicate name would look like if the id branch were gone',
    lines('b10').length === 3, lines('b10'));
}

// ---------------------------------- 11. a re-announcement that is not the same announcement
{
  // `batches.get(d.batch) ?? {...}` kept the existing model on the strength of a comment
  // claiming "the announcement carries the same names in the same order". Nothing enforced
  // that: link.js's onBatchOffer replaces pendingBatch on the same id with whatever arrives.
  // MEASURED before the fix: announce three names, re-announce the same id with two different
  // ones, and the row titled itself "Accept 2 files (5 B)?" over the three OLD names and then
  // tallied "0 of 3 saved" against a grant for 2.
  const { ui } = makeUi();
  offer(ui, { batch: 'b11', names: ['a.txt', 'b.txt', 'c.txt'], bytes: 3 });
  renderBatchOffer({
    batch: 'b11', peer: 'p1', label: 'them', count: 2, bytes: 5, names: ['x.bin', 'y.bin'],
  }, ui);

  check('a re-announcement carrying different files redraws the list it is asking about',
    lines('b11').join('|') === 'x.bin: waiting for you to accept|y.bin: waiting for you to accept',
    lines('b11'));
  check('and the title, the list and the tally all describe the same offer',
    titleOf('b11') === 'Accept 2 files (5 B)?' && lines('b11').length === 2,
    `${titleOf('b11')} over ${lines('b11').length} names`);
  await byId.get('transfer-batch-b11').querySelectorAll('button')[0].click();
  check('and the tally counts against the new offer rather than the abandoned one',
    statusOf('b11').text === '0 of 2 saved, 2 waiting their turn. Files arrive one at a time.',
    statusOf('b11').text);

  // The case the old comment was actually written for, which still has to hold: a peer that
  // really does repeat itself must not lose a file already in flight.
  const { ui: ui2 } = makeUi();
  offer(ui2, { batch: 'b12', names: ['a.txt', 'b.txt'], bytes: 2 });
  await byId.get('transfer-batch-b12').querySelectorAll('button')[0].click();
  noteBatchFile({ batch: 'b12', id: 'r1', name: 'a.txt', state: 'receiving' }, ui2);
  renderBatchOffer({
    batch: 'b12', peer: 'p1', label: 'them', count: 2, bytes: 2, names: ['a.txt', 'b.txt'],
  }, ui2);
  check('an announcement that really is a repeat keeps the file already in flight',
    lines('b12')[0] === 'a.txt: arriving now', lines('b12'));
}

// ---------------------------------------------- 12. consent does not outlive its own gate
{
  // link.js nulls pendingBatch, batchGrant and refusedBatch when the link closes, with the
  // reason written out there. This module's map was never cleared at all, so peer-supplied
  // filenames lived for the life of the PAGE and a later gate reusing a batch id would have
  // found them still sitting there.
  const { ui } = makeUi();
  offer(ui, { batch: 'b13', names: ['a.txt', 'b.txt'], bytes: 2 });
  check('CONTROL: the batch is known before the gate ends, so the check below can fail',
    noteBatchFile({ batch: 'b13', id: 'g1', name: 'a.txt', state: 'receiving' }, ui) === true,
    'the model has to exist first');

  forgetBatches();
  check('an event for a batch from a gate that has ended finds nothing to draw into',
    noteBatchFile({ batch: 'b13', id: 'g1', name: 'a.txt', state: 'done' }, ui) === false,
    'a burned gate must leave no model behind');
}

// ------------------------------------------- 8. app.js's own wiring, asserted from source
//
// app.js cannot be imported outside a browser, so everything it does on its own is invisible
// to a suite that drives modules. Asserted from its source instead, and asserted per claim
// rather than as one count: losing a single call is exactly the regression these are for, and
// a total that says "5 calls somewhere" cannot see it. Each string below is quoted from the
// code it is about, so a rewrite that changes the shape has to come and change this too.
{
  const src = fs.readFileSync(new URL('../public/js/app.js', import.meta.url), 'utf8');

  // Per listener, not as a total. Each of these four is a file changing state, and losing any
  // one of them puts that state back into the silence this whole module exists to end.
  const WIRED = [
    ['a file that finished arriving', "noteBatchFile(meta, 'done')"],
    ['a file that started arriving', "noteBatchFile(meta, 'receiving')"],
    ['a file that failed', "noteBatchFile(d, 'failed', d.reason)"],
    ['a file the other device refused', "noteBatchFile(d, 'refused', d.reason)"],
  ];
  for (const [what, call] of WIRED) {
    check(`app.js reports ${what} to the batch row`, src.includes(call), call);
  }

  // And that the bridge actually reaches this module rather than being a local no-op. It is
  // guarded on batchUiMod, so a gate that never loaded batchui.js stays silent instead of
  // throwing on every single-file send.
  check('the bridge calls into batchui.js', src.includes('batchUiMod.noteBatchFile('), 'bridge');
  check('and does nothing when this module was never fetched',
    src.includes('if (!meta || typeof meta.batch !== \'string\' || !batchUiMod) return;'), 'guard');

  // Consent does not outlive its gate, the other half of section 12: the module clears the
  // map and app.js is the only thing that knows when a gate ended.
  check('app.js forgets every batch when the gate ends',
    src.includes('batchUiMod.forgetBatches()'), 'forgetBatches');

  // THE STRANDED OFFER ROW. sendFilesNow's catch used to suppress itself whenever an offer
  // row existed, on the stated assumption that file-rejected had already written the reason
  // into it. False for link.js's resetForRenegotiation, which rejects the pending accept and
  // emits nothing: the row then said "Waiting for it to be accepted there" for ever. See
  // tests/disconnect.test.mjs section 6b, which drives that rejection and proves the silence.
  check('a send that rejects with no event still resolves its own offer row',
    src.includes('if (!endRow(row, `Not sent: ${err.message}`)) {'), 'endRow in sendFilesNow');
  check('and the first, most specific account of a dead transfer is the one that stands',
    src.includes("if (row.dataset.ended === '1') return true;")
      && src.includes("row.dataset.ended = '1';"), 'endRow marks the row');
  check('CONTROL: and the suppressing form it replaced is gone, so this is not both ways',
    !src.includes('if (!offeredRowId || !document.getElementById('), 'the old guard');

  // The camera button. btn.hidden, panel.hidden and the note all moved into scanui.js when
  // that panel was split out, which put a ~60 KB module fetch between the press and any
  // change on screen. The pressed state is painted here, before the await.
  check('the scan button paints its pressed state before it awaits the module',
    /btn\.hidden = true;\n\s*panel\.hidden = false;\n\s*\$\('scan-note'\)\.textContent = 'Starting the camera\.\.\.';\n\s*try \{\n\s*const mod = await import\('\.\/scanui\.js'\)/.test(src),
    'the three lines have to be above the import, not inside it');
  check('and puts the button back when the module never arrives',
    /log\(`the scanner could not be loaded/.test(src)
      && /panel\.hidden = true;\n\s*btn\.hidden = false;\n\s*log\(`the scanner could not be loaded/.test(src),
    'a failed fetch must not leave the page with nothing to press');
}

// `process.exit(... ? 0 : 1)` and not a bare `summary(...)`. This file ended on the bare call
// from the day it was written, so every check in it could print BAD and node would still exit
// 0: proved on 2026-08-10 by deleting the id branch of slotFor, which turned 2 checks BAD and
// left the exit code at 0. tests/size.test.mjs:379 states the rule for exactly this reason. A
// suite that cannot fail the build is worse than no suite, because it reports green.
process.exit(summary('batch progress') ? 0 : 1);
