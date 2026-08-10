// The streaming download path, end to end, in a real browser.
//
// This is the route that makes a large receive possible at all on a browser without
// showSaveFilePicker. Headless Brave has no picker, so it takes exactly this path, which
// means the test exercises what Firefox and Safari users would get.
//
// The assertion is the strongest available one: the bytes that land ON DISK, via the
// browser's own download manager, hash to the same value the page fed in. Not "the
// promise resolved", not "no error was thrown".

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary, startServer } from './lib/harness.mjs';
import { launchBrowser } from './lib/cdp.mjs';

const PORT = 3771;
const CDP = 9771;
const CHUNKS = 8;
const CHUNK_BYTES = 1024 * 1024;

const downloadDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-dl-'));
// A separate directory for the cross-tab attack case below, so its file cannot be
// confused with the happy-path download and each waitForFile sees only its own output.
const attackDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-dl-atk-'));
// One directory per download for the resume cases too: waitForFile takes the first name it
// finds, so two downloads sharing a directory make it a coin toss which one is hashed.
const resumeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-dl-res-'));
const dupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-dl-dup-'));
const server = await startServer({
  WG_HTTP_HOST: '127.0.0.1',
  WG_HTTP_PORT: String(PORT),
  WG_STUN_ENABLED: '0',
});
const browser = await launchBrowser({ port: CDP });

// The bytes the page will produce: deterministic, so Node can compute the same digest.
const expected = crypto.createHash('sha256');
for (let i = 0; i < CHUNKS; i += 1) {
  expected.update(Buffer.alloc(CHUNK_BYTES, i + 1));
}
const expectedHex = expected.digest('hex');

function waitForFile(dir, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = () => {
      const names = fs.readdirSync(dir).filter((n) => !n.endsWith('.crdownload'));
      if (names.length) {
        const full = path.join(dir, names[0]);
        // Settled means the size stopped changing, otherwise a partial file hashes wrong
        // and the failure looks like corruption rather than impatience.
        const a = fs.statSync(full).size;
        setTimeout(() => {
          const b = fs.statSync(full).size;
          if (a === b && b > 0) resolve(full);
          else if (Date.now() > deadline) reject(new Error('file never settled'));
          else tick();
        }, 400);
        return;
      }
      if (Date.now() > deadline) { reject(new Error(`no file appeared in ${dir} within ${timeoutMs}ms`)); return; }
      setTimeout(tick, 250);
    };
    tick();
  });
}

try {
  const tab = await browser.newTab(`http://127.0.0.1:${PORT}/`);
  await tab.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: downloadDir,
    eventsEnabled: true,
  });

  check('the page is a secure context, which a service worker requires',
    (await tab.eval('return isSecureContext;')) === true);

  const support = await tab.eval(`
    const m = await import('/js/download.js');
    return JSON.stringify({ supported: m.supportsStreamDownload() });
  `);
  check('this browser reports it can stream a download', JSON.parse(support).supported === true, support);

  // The picker is what the stream path exists to replace. If it were present here the
  // test would be measuring the wrong branch entirely.
  check('showSaveFilePicker is genuinely absent, so this really is the fallback path',
    (await tab.eval("return typeof window.showSaveFilePicker === 'undefined';")) === true);

  const result = await tab.eval(`
    const m = await import('/js/download.js');
    const sink = await m.openStreamDownload({
      name: 'stream-test.bin',
      size: ${CHUNKS * CHUNK_BYTES},
      mime: 'application/octet-stream',
    });
    for (let i = 0; i < ${CHUNKS}; i += 1) {
      await sink.write(new Uint8Array(${CHUNK_BYTES}).fill(i + 1));
    }
    await sink.finish();
    return JSON.stringify({ kind: sink.kind, wrote: ${CHUNKS * CHUNK_BYTES} });
  `);
  const r = JSON.parse(result);
  check('the sink identifies itself as the streaming one', r.kind === 'stream', result);

  const file = await waitForFile(downloadDir, 60000);
  const onDisk = fs.readFileSync(file);
  check('the browser wrote a file of exactly the declared size',
    onDisk.length === CHUNKS * CHUNK_BYTES,
    `${onDisk.length} bytes on disk, expected ${CHUNKS * CHUNK_BYTES}`);

  const actualHex = crypto.createHash('sha256').update(onDisk).digest('hex');
  check('the bytes on disk are byte-for-byte what the page fed in',
    actualHex === expectedHex,
    `disk ${actualHex.slice(0, 16)} vs expected ${expectedHex.slice(0, 16)}`);

  check('the saved name is the one the page asked for',
    path.basename(file).startsWith('stream-test'), path.basename(file));

  // Prove the digest check can fail, or "it matched" means nothing.
  const wrong = crypto.createHash('sha256').update(Buffer.concat([onDisk, Buffer.from([0])])).digest('hex');
  check('negative control: a single extra byte changes the digest',
    wrong !== actualHex);

  // An unknown id must 404 rather than hang the tab forever waiting for a body.
  const stale = await tab.eval(`
    const res = await fetch('/wg-download/definitely-not-a-real-id');
    return JSON.stringify({ status: res.status });
  `);
  check('a stale or forged download link is refused, not left hanging',
    JSON.parse(stale).status === 404, stale);

  // --------------------------------------------------------------------------------
  // Same-origin cross-tab isolation: the security fix under test.
  //
  // sw.js lives at root scope and is shared by every same-origin tab. Before the fix, a
  // second tab that knew only a stream id could send wg-abort to tear down another tab's
  // download, or wg-chunk to land attacker bytes on the victim's disk. The fix binds each
  // stream to the client that opened it (clientId recorded at wg-open; chunk/close/abort
  // dropped when event.source.id does not match) and refuses a second wg-open for a live
  // id so an attacker cannot re-seed the owning client.
  //
  // Tab A (victim) opens a real stream via the product code and writes known bytes, but
  // does not finish it, so the stream is live. Tab B (attacker), given only the id, tries
  // to re-open, inject, and abort it. Then Tab A finishes. The proof is the bytes that
  // land ON DISK: they must hash to exactly what A wrote, with none of B's bytes.
  //
  // The attack path must genuinely reach the shared worker, or every assertion here would
  // pass against the vulnerable build too. That is checked first, with a round-trip that
  // must succeed on BOTH the fixed and the broken build.

  const victim = await browser.newTab(`http://127.0.0.1:${PORT}/`);
  await victim.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: attackDir,
    eventsEnabled: true,
  });

  // Tab A opens the stream through the real product code and writes 32 known bytes, then
  // stops short of finish() so the stream stays live for the attacker. The id download.js
  // mints never leaves the tab, so we capture it by shadowing postMessage on the shared
  // worker instance (the object, not the product code) as an attacker who learned the id
  // is modelled by handing that id to Tab B.
  const openRaw = await victim.eval(`
    const m = await import('/js/download.js');
    if (!m.supportsStreamDownload()) return JSON.stringify({ error: 'unsupported' });
    if (!navigator.serviceWorker.controller) {
      await navigator.serviceWorker.register('/sw.js', { scope: '/' });
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) {
        await new Promise((res) => navigator.serviceWorker.addEventListener('controllerchange', res, { once: true }));
      }
    }
    const worker = navigator.serviceWorker.controller;
    const origPost = worker.postMessage.bind(worker);
    worker.postMessage = function (msg, transfer) {
      if (msg && msg.type === 'wg-open') window.__wgOpenId = msg.id;
      return origPost(msg, transfer);
    };
    const payload = new Uint8Array(32);
    for (let i = 0; i < payload.length; i += 1) payload[i] = (i * 7 + 3) & 0xff;
    window.__wgPayload = payload;
    const sink = await m.openStreamDownload({ name: 'victim.bin', size: payload.length, mime: 'application/octet-stream' });
    window.__wgSink = sink;
    await sink.write(payload);
    return JSON.stringify({ id: window.__wgOpenId, kind: sink.kind });
  `);
  const open = JSON.parse(openRaw);
  check('tab A opened a live stream download through the product code', open.kind === 'stream' && typeof open.id === 'string' && open.id.length > 0, openRaw);
  const victimId = open.id;

  // The bytes Tab A fed in, recomputed in Node so the on-disk digest is checked against an
  // independent source, not against a value the browser also produced.
  const victimPayload = Buffer.alloc(32);
  for (let i = 0; i < victimPayload.length; i += 1) victimPayload[i] = (i * 7 + 3) & 0xff;
  const victimExpectedHex = crypto.createHash('sha256').update(victimPayload).digest('hex');
  const evilBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef]);

  // Tab B, a genuinely separate same-origin tab. First prove it can reach the shared
  // worker at all: a wg-open round-trip for a throwaway id must be acknowledged. This must
  // hold on the vulnerable build too, so a failure of the guard checks below cannot be
  // dismissed as "the message never arrived".
  const attacker = await browser.newTab(`http://127.0.0.1:${PORT}/`);
  const reachRaw = await attacker.eval(`
    if (!navigator.serviceWorker.controller) {
      await navigator.serviceWorker.register('/sw.js', { scope: '/' });
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) {
        await new Promise((res) => navigator.serviceWorker.addEventListener('controllerchange', res, { once: true }));
      }
    }
    const worker = navigator.serviceWorker.controller;
    let ack = null;
    try {
      ack = await new Promise((resolve, reject) => {
        const ch = new MessageChannel();
        const t = setTimeout(() => reject(new Error('worker never answered tab B')), 5000);
        ch.port1.onmessage = (e) => { clearTimeout(t); resolve(e.data); };
        worker.postMessage({ type: 'wg-open', id: 'attacker-reachability-probe', name: 'x', size: 0, mime: 'application/octet-stream' }, [ch.port2]);
      });
    } catch (err) { return JSON.stringify({ reachable: false, error: err.message }); }
    return JSON.stringify({ reachable: !!(ack && ack.ok), controlled: !!navigator.serviceWorker.controller });
  `);
  const reach = JSON.parse(reachRaw);
  check('tab B genuinely reaches the shared worker (else the attack proves nothing)',
    reach.reachable === true, reachRaw);

  // The attack: from Tab B, using only the victim's id.
  //   1. a second wg-open for the live id (collision guard must refuse it, not re-seed),
  //   2. wg-chunk to inject attacker bytes into the victim's stream,
  //   3. wg-abort to tear the victim's stream down.
  // A trailing acked wg-open from Tab B flushes the queue: because messages from one client
  // are delivered in order, its ack proves the worker has already processed 1-3 before Tab
  // A is allowed to finish.
  const attackRaw = await attacker.eval(`
    const worker = navigator.serviceWorker.controller;
    const id = ${JSON.stringify(victimId)};
    const reopen = await new Promise((resolve, reject) => {
      const ch = new MessageChannel();
      const t = setTimeout(() => reject(new Error('no reopen answer')), 5000);
      ch.port1.onmessage = (e) => { clearTimeout(t); resolve(e.data); };
      worker.postMessage({ type: 'wg-open', id, name: 'evil', size: 999, mime: 'application/octet-stream' }, [ch.port2]);
    });
    const evil = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const buf = evil.slice().buffer;
    worker.postMessage({ type: 'wg-chunk', id, chunk: buf }, [buf]);
    worker.postMessage({ type: 'wg-abort', id, reason: 'attacker abort' });
    const flush = await new Promise((resolve, reject) => {
      const ch = new MessageChannel();
      const t = setTimeout(() => reject(new Error('no flush answer')), 5000);
      ch.port1.onmessage = (e) => { clearTimeout(t); resolve(e.data); };
      worker.postMessage({ type: 'wg-open', id: 'attacker-flush-' + Date.now(), name: 'x', size: 0, mime: 'application/octet-stream' }, [ch.port2]);
    });
    return JSON.stringify({ reopenOk: !!(reopen && reopen.ok), reopenReason: reopen && reopen.reason, flushed: !!(flush && flush.ok) });
  `);
  const attack = JSON.parse(attackRaw);
  check('the wg-open collision guard refuses a second open for a live id, not re-seeding it',
    attack.reopenOk === false, attackRaw);
  check('tab B\'s attack messages were confirmed processed by the worker before A finished',
    attack.flushed === true, attackRaw);

  // Now Tab A finishes its own stream. On the fixed build the attacker's abort was dropped,
  // so this closes normally and the file lands. On a build with the clientId check removed,
  // the abort already tore the stream down and this close hits nothing.
  await victim.eval(`await window.__wgSink.finish(); return '1';`);

  let victimBytes = null;
  let victimErr = null;
  try {
    const victimFile = await waitForFile(attackDir, 30000);
    victimBytes = fs.readFileSync(victimFile);
  } catch (err) {
    victimErr = err.message;
  }
  check('cross-tab attack: the victim download still completed (its stream was not torn down)',
    victimBytes !== null, victimErr || '');
  check('cross-tab attack: the victim file is exactly its own byte count, with no injected bytes',
    victimBytes !== null && victimBytes.length === victimPayload.length,
    victimBytes ? `${victimBytes.length} bytes, expected ${victimPayload.length}` : 'no file landed');
  check('cross-tab attack: the victim bytes on disk hash to exactly what tab A fed in',
    victimBytes !== null && crypto.createHash('sha256').update(victimBytes).digest('hex') === victimExpectedHex,
    victimBytes ? `${crypto.createHash('sha256').update(victimBytes).digest('hex').slice(0, 16)} vs ${victimExpectedHex.slice(0, 16)}` : 'no file landed');
  check('cross-tab attack: the attacker\'s injected bytes are absent from the victim file',
    victimBytes !== null && victimBytes.indexOf(evilBytes) === -1,
    victimBytes ? `DEADBEEF at index ${victimBytes.indexOf(evilBytes)}` : 'no file landed');
  // --------------------------------------------------------------------------------
  // Chunk-level resume.
  //
  // The roadmap gap this closes: a dropped connection used to restart the file, because
  // the only thing either side could say about progress was one byte count, and that is
  // only true while the receiver's writes are a strict prefix of the sender's reads. The
  // moment a channel dies mid-file that stops being true.
  //
  // These run over the SERVICE WORKER sink deliberately. It is the route a phone takes
  // (no showSaveFilePicker on iOS or Firefox), it is the one that cannot seek, and it is
  // therefore the hardest one for out-of-order delivery. The assertion is the same one the
  // rest of this file uses: the bytes that land on disk via the browser's own download
  // manager, hashed against a digest Node computed independently.

  const RCHUNK = 64 * 1024;
  const RCHUNKS = 12;
  const RSIZE = RCHUNK * RCHUNKS;
  // Chunk i is filled with one repeated byte, so a chunk written at the wrong index or
  // written twice moves the digest rather than hiding inside identical bytes.
  const fillFor = (i) => (i * 37 + 11) & 0xff;
  const wholeExpected = crypto.createHash('sha256');
  for (let i = 0; i < RCHUNKS; i += 1) wholeExpected.update(Buffer.alloc(RCHUNK, fillFor(i)));
  const wholeExpectedHex = wholeExpected.digest('hex');

  const resumeTab = await browser.newTab(`http://127.0.0.1:${PORT}/`);
  await resumeTab.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: resumeDir,
    eventsEnabled: true,
  });

  // The drop is modelled exactly as the product experiences it: the sink stays open (a
  // dropped data channel does not destroy it; link.js keeps `incoming` precisely so it
  // is not), the sender stops mid-file, and one chunk that was already in flight lands
  // AFTER the chunk before it was lost. That leaves a hole, which is the whole point: a
  // scalar byte offset cannot describe "I hold 0 to 4 and also 6".
  const resumeRaw = await resumeTab.eval(`
    const dl = await import('/js/download.js');
    const r = await import('/js/resume.js');
    const t = await import('/js/transfer.js');
    const CHUNK = ${RCHUNK}, TOTAL = ${RCHUNKS}, SIZE = ${RSIZE};
    const fill = (i) => (i * 37 + 11) & 0xff;
    const chunkFor = (i) => new Uint8Array(CHUNK).fill(fill(i));

    const sink = await dl.openStreamDownload({ name: 'resume-test.bin', size: SIZE, mime: 'application/octet-stream' });
    const indexed = r.createIndexedSink(sink, { chunkSize: CHUNK, size: SIZE });
    const token = r.mintResumeToken();
    const inbound = { meta: { id: 'T-resume', size: SIZE, chunkSize: CHUNK }, sink: indexed, token };

    // First attempt: 0..4 in order, then 6 arriving with 5 still missing, then the drop.
    for (const i of [0, 1, 2, 3, 4, 6]) {
      const framed = r.frameChunk(i, chunkFor(i));
      const got = r.unframeChunk(framed);
      await indexed.write(got.index, got.bytes);
    }
    const afterDrop = { position: indexed.position, held: indexed.held };

    // Receiver asks. Sender plans. Receiver checks the answer before writing a byte.
    const request = r.buildResumeRequest({ id: 'T-resume', token, indexed });
    const plan = r.planResumeResponse(request, { id: 'T-resume', size: SIZE, chunkSize: CHUNK, token });
    const verdict = r.judgeResumeResponse(inbound, { id: 'T-resume', token, offset: plan.offset });

    // Sender reads only what was asked for, off a real File, through the real framing.
    const whole = new Uint8Array(SIZE);
    for (let i = 0; i < TOTAL; i += 1) whole.set(chunkFor(i), i * CHUNK);
    const file = new File([whole], 'resume-test.bin', { type: 'application/octet-stream' });
    let resent = 0, duplicates = 0, indices = [];
    for await (const piece of t.readChunkRanges(file, CHUNK, plan.ranges)) {
      const framed = r.frameChunk(piece.index, piece.bytes);
      const got = r.unframeChunk(framed);
      const outcome = await indexed.write(got.index, got.bytes);
      if (outcome.duplicate) duplicates += 1;
      resent += got.bytes.byteLength;
      indices.push(got.index);
    }
    await indexed.finish();
    return JSON.stringify({
      have: request.have,
      received: request.received,
      ranges: plan.ranges,
      planOk: plan.ok === true,
      planBytes: plan.bytes,
      verdictOk: verdict.ok === true,
      afterDrop, resent, duplicates, indices,
      position: indexed.position,
    });
  `);
  const res = JSON.parse(resumeRaw);

  check('a chunk that arrives ahead of a hole is held, not dropped and not written early',
    res.afterDrop.position === 5 * RCHUNK && res.afterDrop.held === 6, resumeRaw);
  check('the resume request describes the hole, not just a byte count',
    JSON.stringify(res.have) === JSON.stringify([[0, 5], [6, 7]]), resumeRaw);
  check('the byte offset it reports is the contiguous prefix only',
    res.received === 5 * RCHUNK, resumeRaw);
  check('the sender plans exactly the missing chunk ranges, skipping the one held past the hole',
    res.planOk === true && JSON.stringify(res.ranges) === JSON.stringify([[5, 6], [7, 12]]), resumeRaw);
  check('the receiver accepts a resume that echoes its own token and offset',
    res.verdictOk === true, resumeRaw);
  // The gap the roadmap named: half this file was already held, so half of it must move.
  check('the resume moves ONLY the missing chunks, not the file',
    res.resent === RSIZE - 6 * RCHUNK && res.resent === res.planBytes,
    `resent ${res.resent}, planned ${res.planBytes}, whole file ${RSIZE}`);
  check('nothing already held was re-sent, so no duplicate had to be discarded',
    res.duplicates === 0 && JSON.stringify(res.indices) === JSON.stringify([5, 7, 8, 9, 10, 11]), resumeRaw);

  const resumeFile = await waitForFile(resumeDir, 60000);
  const resumeBytes = fs.readFileSync(resumeFile);
  check('the resumed download is exactly the declared size on disk',
    resumeBytes.length === RSIZE, `${resumeBytes.length} bytes, expected ${RSIZE}`);
  const resumeHex = crypto.createHash('sha256').update(resumeBytes).digest('hex');
  check('the resumed file on disk is byte-for-byte the whole original, hole filled in place',
    resumeHex === wholeExpectedHex, `disk ${resumeHex.slice(0, 16)} vs expected ${wholeExpectedHex.slice(0, 16)}`);

  // --------------------------------------------------------------------------------
  // A duplicate chunk must be idempotent, not appended.
  //
  // This is what a re-send after a drop looks like when the two sides disagree by one
  // chunk. Appending it produces a file that is longer than it should be with every chunk
  // after the duplicate shifted, and the only thing that would catch it is a final length
  // check on a count the sender also got wrong.

  const DCHUNKS = 4;
  const DSIZE = RCHUNK * DCHUNKS;
  const dupExpected = crypto.createHash('sha256');
  for (let i = 0; i < DCHUNKS; i += 1) dupExpected.update(Buffer.alloc(RCHUNK, fillFor(i)));
  const dupExpectedHex = dupExpected.digest('hex');

  const dupTab = await browser.newTab(`http://127.0.0.1:${PORT}/`);
  await dupTab.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: dupDir,
    eventsEnabled: true,
  });

  const dupRaw = await dupTab.eval(`
    const dl = await import('/js/download.js');
    const r = await import('/js/resume.js');
    const CHUNK = ${RCHUNK}, SIZE = ${DSIZE};
    const fill = (i) => (i * 37 + 11) & 0xff;
    const chunkFor = (i) => new Uint8Array(CHUNK).fill(fill(i));

    const sink = await dl.openStreamDownload({ name: 'dup-test.bin', size: SIZE, mime: 'application/octet-stream' });
    const indexed = r.createIndexedSink(sink, { chunkSize: CHUNK, size: SIZE });
    const outcomes = [];
    for (const i of [0, 1, 1, 2, 3]) {
      outcomes.push(await indexed.write(i, chunkFor(i)));
    }
    await indexed.finish();
    return JSON.stringify({
      outcomes,
      position: indexed.position,
      held: indexed.held,
      ranges: indexed.ledger.toWire(),
    });
  `);
  const dup = JSON.parse(dupRaw);
  check('the second copy of a chunk is reported as a duplicate rather than written',
    dup.outcomes[2] && dup.outcomes[2].duplicate === true && dup.outcomes[2].written === false, dupRaw);
  check('a duplicate does not advance the write position',
    dup.position === DSIZE, `position ${dup.position}, expected ${DSIZE}`);
  check('a duplicate is counted once in the ledger, not twice',
    dup.held === DCHUNKS && JSON.stringify(dup.ranges) === JSON.stringify([[0, DCHUNKS]]), dupRaw);

  const dupFile = await waitForFile(dupDir, 60000);
  const dupBytes = fs.readFileSync(dupFile);
  check('a duplicate chunk did not lengthen the file on disk',
    dupBytes.length === DSIZE, `${dupBytes.length} bytes, expected ${DSIZE}`);
  const dupHex = crypto.createHash('sha256').update(dupBytes).digest('hex');
  check('the file with a duplicated chunk hashes to the original, so nothing was appended twice',
    dupHex === dupExpectedHex, `disk ${dupHex.slice(0, 16)} vs expected ${dupExpectedHex.slice(0, 16)}`);

  // --------------------------------------------------------------------------------
  // Resuming onto a partial file that ends in the MIDDLE of a chunk.
  //
  // The seekable sink, tested against a real FileSystemFileHandle. Headless Brave has no
  // showSaveFilePicker, but the origin private file system hands out the same interface
  // with no permission to grant, which is the case createSink already documents as
  // "nothing to grant" rather than a failure. So this exercises openDiskSink for real.
  //
  // Why it matters: the authority on how much has been received is the file itself, and a
  // file recovered after a reload can end part way through a chunk. Appending the next
  // chunk onto that partial one splices it into the middle of the file. Every later byte
  // shifts, the total length still comes out right because the missing tail of the partial
  // chunk is never counted, and no length check on either side can see it.

  const OCHUNKS = 8;
  const OSIZE = RCHUNK * OCHUNKS;
  const STRAY = 100;
  const opfsExpected = crypto.createHash('sha256');
  for (let i = 0; i < OCHUNKS; i += 1) opfsExpected.update(Buffer.alloc(RCHUNK, fillFor(i)));
  const opfsExpectedHex = opfsExpected.digest('hex');

  const opfsRaw = await resumeTab.eval(`
    const t = await import('/js/transfer.js');
    const r = await import('/js/resume.js');
    const CHUNK = ${RCHUNK}, TOTAL = ${OCHUNKS}, SIZE = ${OSIZE}, STRAY = ${STRAY};
    const fill = (i) => (i * 37 + 11) & 0xff;
    const chunkFor = (i) => new Uint8Array(CHUNK).fill(fill(i));
    const meta = { id: 'T-disk', name: 'disk-resume.bin', mime: 'application/octet-stream', size: SIZE, chunkSize: CHUNK };

    const root = await navigator.storage.getDirectory();
    // Fresh every run, or a previous run's leftovers decide the answer.
    try { await root.removeEntry('wg-disk-resume.bin'); } catch (err) { void err; }
    const handle = await root.getFileHandle('wg-disk-resume.bin', { create: true });

    // What a reload finds: three whole chunks committed, plus a stray tail that is part of
    // a fourth chunk and not the whole of it.
    const seed = await handle.createWritable();
    for (let i = 0; i < 3; i += 1) await seed.write(chunkFor(i));
    await seed.write(new Uint8Array(STRAY).fill(fill(3)));
    await seed.close();
    const onDisk = (await handle.getFile()).size;

    const sink = await t.createSink(meta, { handle, startOffset: onDisk });
    const opened = sink.position;
    const whole = r.chunksOnDisk(sink.position, CHUNK, SIZE);
    await sink.seekTo(whole * CHUNK);
    const rewound = sink.position;

    const ledger = new r.ChunkLedger(r.chunkCount(SIZE, CHUNK));
    for (let i = 0; i < whole; i += 1) ledger.mark(i);
    const indexed = r.createIndexedSink(sink, { chunkSize: CHUNK, size: SIZE, ledger, written: whole * CHUNK });
    const token = r.mintResumeToken();

    const request = r.buildResumeRequest({ id: 'T-disk', token, indexed, crossedReload: true });
    const plan = r.planResumeResponse(request, { id: 'T-disk', size: SIZE, chunkSize: CHUNK, token });

    const source = new Uint8Array(SIZE);
    for (let i = 0; i < TOTAL; i += 1) source.set(chunkFor(i), i * CHUNK);
    const file = new File([source], 'disk-resume.bin', { type: 'application/octet-stream' });
    let resent = 0;
    for await (const piece of t.readChunkRanges(file, CHUNK, plan.ranges)) {
      const got = r.unframeChunk(r.frameChunk(piece.index, piece.bytes));
      await indexed.write(got.index, got.bytes);
      resent += got.bytes.byteLength;
    }
    await indexed.finish();

    const finished = await handle.getFile();
    const digest = await crypto.subtle.digest('SHA-256', await finished.arrayBuffer());
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
    return JSON.stringify({ onDisk, opened, whole, rewound, received: request.received, ranges: plan.ranges, resent, size: finished.size, hex });
  `);
  const op = JSON.parse(opfsRaw);
  check('the partial file really does end mid-chunk, or this case proves nothing',
    op.onDisk === 3 * RCHUNK + STRAY && op.opened === op.onDisk, opfsRaw);
  check('a file ending mid-chunk counts only its WHOLE chunks as received',
    op.whole === 3 && op.received === 3 * RCHUNK, opfsRaw);
  check('the sink rewinds to the last whole chunk rather than appending onto a partial one',
    op.rewound === 3 * RCHUNK, opfsRaw);
  check('the resume asks for the partial chunk again, and everything after it',
    JSON.stringify(op.ranges) === JSON.stringify([[3, OCHUNKS]]) && op.resent === OSIZE - 3 * RCHUNK, opfsRaw);
  check('the file the disk sink closed is exactly the declared size, with no stray tail left in it',
    op.size === OSIZE, `${op.size} bytes, expected ${OSIZE}`);
  check('the disk-resumed file is byte-for-byte the original, checked against a digest Node computed',
    op.hex === opfsExpectedHex, `page ${String(op.hex).slice(0, 16)} vs node ${opfsExpectedHex.slice(0, 16)}`);

  // --------------------------------------------------------------------------------
  // A resume offer for a transfer this side never accepted must be refused, and the
  // refusal must not say which of the several possible reasons it was.
  //
  // The channel is already authenticated per pair, so this is not about an outsider. It is
  // about a peer restarting a transfer that was refused, failed or already finished by
  // reusing its id, and about a resume offer being usable as a probe for what this device
  // already holds. Both are closed by the same thing: the receiver mints a token when it
  // creates a sink, and only a resume that echoes that token is acted on.

  const refuseRaw = await resumeTab.eval(`
    const r = await import('/js/resume.js');
    const CHUNK = ${RCHUNK}, SIZE = ${RSIZE};
    const token = r.mintResumeToken();
    const other = r.mintResumeToken();

    // A transfer this device holds and HAS accepted, so there is something to leak.
    const accepted = {
      meta: { id: 'T-held', size: SIZE, chunkSize: CHUNK },
      token,
      sink: { position: 3 * CHUNK },
    };
    // The same file, offered but never accepted: no sink, no token, nothing agreed.
    const offeredOnly = { meta: { id: 'T-held', size: SIZE, chunkSize: CHUNK }, token: null, sink: null };

    const noTransfer = r.judgeResumeResponse(null, { id: 'T-held', token, offset: 3 * CHUNK });
    const notAccepted = r.judgeResumeResponse(offeredOnly, { id: 'T-held', token, offset: 3 * CHUNK });
    const wrongToken = r.judgeResumeResponse(accepted, { id: 'T-held', token: other, offset: 3 * CHUNK });
    const noToken = r.judgeResumeResponse(accepted, { id: 'T-held', offset: 3 * CHUNK });
    const wrongId = r.judgeResumeResponse(accepted, { id: 'T-somebody-elses', token, offset: 3 * CHUNK });
    const rightToken = r.judgeResumeResponse(accepted, { id: 'T-held', token, offset: 3 * CHUNK });

    // The sender half of the same guard: a resume request for a transfer that was never
    // accepted (so this side minted no token for it) is refused identically.
    const sendersRefusal = r.planResumeResponse(
      { kind: 'file-resume', id: 'T-held', token, received: 0, have: [] },
      { id: 'T-held', size: SIZE, chunkSize: CHUNK, token: null },
    );

    return JSON.stringify({
      noTransfer, notAccepted, wrongToken, noToken, wrongId, rightToken, sendersRefusal,
      identical: [notAccepted, wrongToken, noToken, wrongId].every(
        (v) => JSON.stringify(v) === JSON.stringify(noTransfer),
      ),
      keys: Object.keys(noTransfer).sort(),
    });
  `);
  const ref = JSON.parse(refuseRaw);
  check('a resume offer for a transfer this device never accepted is refused',
    ref.notAccepted.ok === false && ref.notAccepted.code === 'unknown_transfer', refuseRaw);
  check('a resume offer with the wrong token, for a transfer this device does hold, is refused',
    ref.wrongToken.ok === false && ref.wrongToken.code === 'unknown_transfer', refuseRaw);
  check('a resume offer with no token at all is refused',
    ref.noToken.ok === false, refuseRaw);
  check('every refusal is byte-identical, so the reply cannot say which state this device is in',
    ref.identical === true, refuseRaw);
  check('a refusal carries no offset, byte count or held-chunk list to probe with',
    JSON.stringify(ref.keys) === JSON.stringify(['code', 'ok', 'reason']), refuseRaw);
  check('the sender refuses a resume for a transfer it never got an accept for',
    ref.sendersRefusal.ok === false && ref.sendersRefusal.code === 'unknown_transfer', refuseRaw);
  // Without this the four refusals above would pass against a build that refuses everything.
  check('negative control: the same offer with the right token and offset IS accepted',
    ref.rightToken.ok === true && ref.rightToken.offset === 3 * RCHUNK, refuseRaw);

  // --------------------------------------------------------------------------------
  // Which sink createSink actually hands back, per browser, for a file over the in-memory
  // limit.
  //
  // This is the branch that made "phone to laptop does not work" possible: the streaming
  // route below the picker was unreachable, because both guards above it covered its whole
  // condition. A browser with no picker was refused before it could get there, and a
  // browser whose picker failed to open was refused too, so the only receiver that could
  // take a large file was a Chromium desktop whose Save dialog completed.
  //
  // Asked of createSink directly rather than through a transfer: the branch is decided
  // before a byte moves, so a fabricated meta answers it exactly and a 520 MiB transfer
  // over loopback WebRTC does not (two were attempted, both hung the rig).
  const MIB = 1024 * 1024;
  const BIG = 520 * MIB;
  const SMALL = 40 * MIB;

  const branchRaw = await resumeTab.eval(`
    const t = await import('/js/transfer.js');
    const d = await import('/js/download.js');
    const real = globalThis.showSaveFilePicker;
    const ask = async (size, picker) => {
      if (picker === null) delete globalThis.showSaveFilePicker;
      else globalThis.showSaveFilePicker = picker;
      try {
        const sink = await t.createSink({ name: 'clip.mp4', size, mime: 'video/mp4' });
        const out = { ok: true, kind: sink.kind, note: sink.note ?? null };
        try { await sink.abort('probe'); } catch (err) { void err; }
        return out;
      } catch (err) {
        return { ok: false, name: err.name, message: err.message };
      } finally {
        if (real === undefined) delete globalThis.showSaveFilePicker;
        else globalThis.showSaveFilePicker = real;
      }
    };
    const throws = async () => { throw new TypeError('\`accept\` cannot be empty.'); };
    const cancels = async () => { const e = new Error('The user aborted a request.'); e.name = 'AbortError'; throw e; };
    const works = async () => (await navigator.storage.getDirectory()).getFileHandle('branch-probe.mp4', { create: true });

    // The route the guards used to jump over. Proves it works at this size in THIS browser,
    // without which "the fallback was unreachable" is only half a bug report.
    let reachable;
    try {
      const sink = await d.openStreamDownload({ name: 'clip.mp4', size: BIGSIZE, mime: 'video/mp4' });
      await sink.write(new Uint8Array(1024));
      reachable = { ok: true, kind: sink.kind, wrote: sink.position };
      await sink.abort('probe');
    } catch (err) { reachable = { ok: false, message: err.message }; }

    return JSON.stringify({
      limit: t.MEMORY_LIMIT_BYTES,
      streams: d.supportsStreamDownload(),
      noPicker: await ask(BIGSIZE, null),
      pickerThrows: await ask(BIGSIZE, throws),
      pickerCancelled: await ask(BIGSIZE, cancels),
      pickerWorks: await ask(BIGSIZE, works),
      smallThrows: await ask(SMALLSIZE, throws),
      reachable,
    });
  `.replace(/BIGSIZE/g, String(BIG)).replace(/SMALLSIZE/g, String(SMALL)));
  const br = JSON.parse(branchRaw);

  check('this browser can stream downloads, or the whole block below proves nothing',
    br.streams === true && br.limit === 500 * MIB, branchRaw);
  check('a receiver with no save picker gets a sink for a file over the memory limit',
    br.noPicker.ok === true, branchRaw);
  check('and that sink is the streaming download, not memory it cannot hold',
    br.noPicker.kind === 'stream', `kind=${br.noPicker.kind}`);
  check('a picker that fails to open falls through to the streaming download too',
    br.pickerThrows.ok === true && br.pickerThrows.kind === 'stream', branchRaw);
  check('and it explains why the dialog it promised never appeared',
    typeof br.pickerThrows.note === 'string' && /download manager/.test(br.pickerThrows.note),
    String(br.pickerThrows.note));
  // The one case that must still fail. canAccept promises that dismissing the dialog
  // cancels the transfer, so a cancel may not quietly start a download instead.
  check('dismissing the save dialog still cancels, rather than downloading it anyway',
    br.pickerCancelled.ok === false && /could not open a save location/.test(br.pickerCancelled.message),
    branchRaw);
  check('negative control: a working picker still wins, so this did not just disable the picker',
    br.pickerWorks.ok === true && br.pickerWorks.kind === 'disk', branchRaw);
  check('negative control: under the limit a failed picker still falls back to memory',
    br.smallThrows.ok === true && br.smallThrows.kind === 'memory', branchRaw);
  check('negative control: the streaming route really does work at this size in this browser',
    br.reachable.ok === true && br.reachable.wrote === 1024, JSON.stringify(br.reachable));
} finally {
  await browser.close();
  await server.stop();
  fs.rmSync(downloadDir, { recursive: true, force: true });
  fs.rmSync(attackDir, { recursive: true, force: true });
  fs.rmSync(resumeDir, { recursive: true, force: true });
  fs.rmSync(dupDir, { recursive: true, force: true });
}

process.exit(summary('streaming download') ? 0 : 1);
