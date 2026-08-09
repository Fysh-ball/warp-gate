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
} finally {
  await browser.close();
  await server.stop();
  fs.rmSync(downloadDir, { recursive: true, force: true });
  fs.rmSync(attackDir, { recursive: true, force: true });
}

process.exit(summary('streaming download') ? 0 : 1);
