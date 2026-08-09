// Module-level tests for public/js/transfer.js, run INSIDE a real browser against the
// served modules.
//
// These exist because the disk-sink path is unreachable through the UI: this browser has
// no showSaveFilePicker at all (not merely a gesture requirement), so createSink can
// never take the picker branch. openDiskSink is exercised for real here through an OPFS
// FileSystemFileHandle, which is the same object type the picker returns and which
// createSink accepts directly via its `handle` option.
//
// Nothing here is a substitute for an end-to-end claim, and nothing end-to-end in this
// suite relies on it.

import { check, summary } from '../lib/harness.mjs';
import { startServer } from '../lib/harness.mjs';
import { launchBrowser, findBrowser } from '../lib/cdp.mjs';

const PORT = 3978;
const CDP = 9779;

if (!findBrowser()) { process.stdout.write('BAD  no browser\n'); process.exit(1); }
const server = await startServer({ WG_HTTP_PORT: String(PORT), WG_PUBLIC_GET_PER_WINDOW: '500' });
const browser = await launchBrowser({ port: CDP });
const tab = await browser.newTab(`http://127.0.0.1:${PORT}/`);
await tab.waitFor("!!document.getElementById('screen-home')", { label: 'page loaded' });

const run = (body) => tab.eval(`
  const T = await import('/js/transfer.js');
  ${body}
`);

try {
  // ---------------------------------------------------------------- constants in force
  const consts = JSON.parse(await run(`
    return JSON.stringify({
      chunk: T.CHUNK_BYTES, mem: T.MEMORY_LIMIT_BYTES,
      prefix: T.FINGERPRINT_PREFIX_BYTES, checkpoint: T.CHECKPOINT_BYTES,
      canDisk: T.canStreamToDisk(),
    });
  `));
  check('MEMORY_LIMIT_BYTES is 500 MiB as documented', consts.mem === 500 * 1024 * 1024, String(consts.mem));
  check('this browser genuinely has no showSaveFilePicker, so the picker branch is unreachable',
    consts.canDisk === false, `canStreamToDisk()=${consts.canDisk}`);

  // ---------------------------------------------------------------- canAccept boundaries
  const accept = JSON.parse(await run(`
    const D = await import('/js/download.js');
    const L = T.MEMORY_LIMIT_BYTES;
    return JSON.stringify({
      stream: D.supportsStreamDownload(),
      zero: T.canAccept(0), below: T.canAccept(L - 1), at: T.canAccept(L),
      over: T.canAccept(L + 1), huge: T.canAccept(L * 100),
    });
  `));
  check('canAccept: exactly at the limit is accepted', accept.at.ok === true && accept.at.requiresDisk === false,
    JSON.stringify(accept.at));
  // Past the memory limit there are two truthful answers and which one is right depends on
  // the browser, so the assertion has to branch the same way canAccept does. This used to
  // assert the refusal unconditionally, which stopped being true the moment the service
  // worker started streaming large receives into the browser's own download manager: the
  // check then reported a capability as a regression.
  if (accept.stream) {
    check('canAccept: one byte over is accepted via the download manager, with a note saying so',
      accept.over.ok === true && /download manager/.test(accept.over.note ?? ''), JSON.stringify(accept.over));
  } else {
    check('canAccept: one byte over is refused when there is neither a disk sink nor a stream download',
      accept.over.ok === false && /exceeds/.test(accept.over.reason), JSON.stringify(accept.over));
  }
  check('canAccept: zero bytes is accepted', accept.zero.ok === true, JSON.stringify(accept.zero));

  // ---------------------------------------------------------------- readChunks guards
  const chunks = JSON.parse(await run(`
    const real = new Blob([new Uint8Array(10).fill(7)]);
    const lying = { name: 'lying', size: 100, slice: (s, e) => real.slice(s, e) };
    const drain = async (file, size, off) => {
      const out = [];
      for await (const c of T.readChunks(file, size, off)) out.push(c.byteLength);
      return out;
    };
    const grab = async (fn) => { try { await fn(); return 'no throw'; } catch (e) { return e.message; } };
    const f = new File([new Uint8Array(40)], 'f.bin');
    return JSON.stringify({
      exact: await drain(f, 16, 0),
      atEnd: await drain(f, 16, 40),
      negative: await grab(() => drain(f, 16, -1)),
      past: await grab(() => drain(f, 16, 41)),
      fractional: await grab(() => drain(f, 16, 1.5)),
      nan: await drain(f, 16, NaN),
      shortRead: await grab(() => drain(lying, 16, 0)),
    });
  `));
  check('readChunks yields the whole file in order', JSON.stringify(chunks.exact) === '[16,16,8]', JSON.stringify(chunks.exact));
  check('readChunks at exactly the end yields nothing rather than throwing',
    JSON.stringify(chunks.atEnd) === '[]', JSON.stringify(chunks.atEnd));
  check('readChunks refuses a negative offset', /cannot resume/.test(chunks.negative), chunks.negative);
  check('readChunks refuses an offset past the end', /cannot resume/.test(chunks.past), chunks.past);
  check('readChunks refuses a fractional offset', /cannot resume/.test(chunks.fractional), chunks.fractional);
  check('readChunks refuses a short read instead of yielding a truncated file',
    /could not be read in full/.test(chunks.shortRead), chunks.shortRead);
  check('readChunks silently treats a NaN offset as 0 (recorded: the guard is upstream, not here)',
    JSON.stringify(chunks.nan) === '[16,16,8]', JSON.stringify(chunks.nan));

  // ---------------------------------------------------------------- fingerprints
  const fp = JSON.parse(await run(`
    const grab = async (fn) => { try { return { ok: true, v: await fn() }; } catch (e) { return { ok: false, v: e.message }; } };
    const f1 = new File([new Uint8Array(1000).fill(1)], 'a.bin');
    const f2 = new File([new Uint8Array(1000).fill(2)], 'a.bin');
    const real = new Blob([new Uint8Array(10)]);
    const lying = { name: 'lying', size: 100, slice: (s, e) => real.slice(s, e) };
    const a = await T.fingerprintFile(f1);
    const b = await T.fingerprintFile(f2);
    return JSON.stringify({
      same: T.compareFingerprints(a, a),
      differentContent: T.compareFingerprints(a, b),
      missingWant: T.compareFingerprints(null, a),
      missingGot: T.compareFingerprints(a, null),
      bothMissing: T.compareFingerprints(null, null),
      differentAlgo: T.compareFingerprints(a, { ...a, algo: 'SHA-1' }),
      differentPrefix: T.compareFingerprints(a, { ...a, prefixBytes: 1 }),
      differentSize: T.compareFingerprints(a, { ...a, size: 999 }),
      differentName: T.compareFingerprints(a, { ...a, name: 'b.bin' }),
      shortRead: await grab(() => T.fingerprintFile(lying)),
    });
  `));
  check('a fingerprint matches itself', fp.same.ok === true);
  check('different content with the same size and name is caught',
    fp.differentContent.ok === false, JSON.stringify(fp.differentContent));
  check('a missing fingerprint fails closed on both sides',
    fp.missingWant.ok === false && fp.missingGot.ok === false && fp.bothMissing.ok === false);
  check('a different algorithm, prefix, size or name all fail closed',
    [fp.differentAlgo, fp.differentPrefix, fp.differentSize, fp.differentName].every((v) => v.ok === false));
  check('fingerprintFile refuses a short header read',
    fp.shortRead.ok === false && /could not be read/.test(fp.shortRead.v), JSON.stringify(fp.shortRead));

  // ---------------------------------------------------------------- memory sink
  //
  // The overflow is driven with ONE 50 MiB buffer pushed repeatedly: the sink counts
  // byteLength per write, so the limit is crossed without ever allocating 500 MiB.
  const mem = JSON.parse(await run(`
    const sink = await T.createSink({ name: 'm.bin', size: 10, mime: 'text/plain' }, { preferMemory: true });
    await sink.write(new Uint8Array([1, 2, 3]));
    await sink.write(new Uint8Array([4, 5]));
    const midPosition = sink.position;
    const blob = await sink.finish();
    const text = [...new Uint8Array(await blob.arrayBuffer())].join(',');

    const big = await T.createSink({ name: 'big.bin', size: 1, mime: '' }, { preferMemory: true });
    const block = new Uint8Array(50 * 1024 * 1024);
    let wrote = 0;
    let first = null;
    while (first === null && wrote < 600 * 1024 * 1024) {
      try { await big.write(block); wrote += block.byteLength; }
      catch (e) { first = e.message; }
    }
    let second = null;
    try { await big.write(new Uint8Array(1)); } catch (e) { second = e.message; }
    let afterFinish = null;
    try { await big.finish(); } catch (e) { afterFinish = e.message; }

    const ab = await T.createSink({ name: 'ab.bin', size: 4 }, { preferMemory: true });
    await ab.write(new Uint8Array([9, 9]));
    await ab.abort('test');
    let afterAbort = null;
    try { await ab.finish(); } catch (e) { afterAbort = e.message; }

    let overLimit = null;
    try { await T.createSink({ name: 'x', size: T.MEMORY_LIMIT_BYTES + 1 }, { preferMemory: true }); }
    catch (e) { overLimit = e.message; }

    return JSON.stringify({
      kind: sink.kind, handle: sink.handle, wantsCheckpoint: sink.wantsCheckpoint,
      midPosition, text, wrote, first, second, afterFinish, afterAbort, overLimit,
    });
  `));
  check('the memory sink reassembles content in order', mem.text === '1,2,3,4,5', mem.text);
  check('the memory sink reports no handle, so a reload can tell it is unrecoverable',
    mem.handle === null && mem.kind === 'memory' && mem.wantsCheckpoint === false, JSON.stringify(mem));
  check('the memory sink refuses to exceed MEMORY_LIMIT_BYTES',
    /in-memory limit of .* exceeded/.test(String(mem.first)), String(mem.first));
  check('the overflow latches: a later write repeats the same error rather than re-failing differently',
    mem.second === mem.first, `${mem.second} vs ${mem.first}`);
  check('finish() after overflow throws rather than handing back a truncated blob',
    mem.afterFinish === mem.first, String(mem.afterFinish));
  check('finish() after abort throws rather than handing back a partial blob',
    /test/.test(String(mem.afterAbort)), String(mem.afterAbort));
  check('createSink refuses an over-limit file before allocating anything',
    /cannot be held in memory/.test(String(mem.overLimit)), String(mem.overLimit));

  // ---------------------------------------------------------------- disk sink, for real
  //
  // OPFS handles are FileSystemFileHandle, the same interface showSaveFilePicker returns.
  // createSink takes them through the `handle` option, which is the path adoptInbound
  // uses after a reload. This is the ONLY way this browser can reach openDiskSink.
  const disk = JSON.parse(await run(`
    const grab = async (fn) => { try { return { ok: true, v: await fn() }; } catch (e) { return { ok: false, v: e.message }; } };
    const root = await navigator.storage.getDirectory();
    const read = async (h) => [...new Uint8Array(await (await h.getFile()).arrayBuffer())].join(',');

    const h1 = await root.getFileHandle('one.bin', { create: true });
    const meta = { name: 'one.bin', size: 6, mime: '' };
    const s1 = await T.createSink(meta, { handle: h1, startOffset: 0 });
    const kind = s1.kind;
    const hasHandle = Boolean(s1.handle);
    await s1.write(new Uint8Array([1, 2, 3]));
    const p1 = s1.position;
    await s1.write(new Uint8Array([4, 5, 6]));
    const p2 = s1.position;
    const finished = await s1.finish();
    const content1 = await read(h1);

    // Resume onto what is already there: keepExistingData plus a seek.
    const s2 = await T.createSink(meta, { handle: h1, startOffset: 6 });
    const resumeAt = s2.position;
    await s2.write(new Uint8Array([7, 8]));
    await s2.finish();
    const content2 = await read(h1);

    // A resume offset beyond what the file actually holds must be CLAMPED, never trusted.
    const s3 = await T.createSink(meta, { handle: h1, startOffset: 999999 });
    const clamped = s3.position;
    await s3.abort('done probing');

    // Checkpointing: close, reopen, seek, keep writing. This is what makes a reload
    // resumable, and it is the part most likely to silently truncate.
    const h2 = await root.getFileHandle('two.bin', { create: true });
    const s4 = await T.createSink({ name: 'two.bin', size: 9 }, { handle: h2, startOffset: 0 });
    await s4.write(new Uint8Array([1, 2, 3]));
    const cpAt = await s4.checkpoint();
    const durableMid = await read(h2);
    await s4.write(new Uint8Array([4, 5, 6]));
    await s4.checkpoint();
    await s4.write(new Uint8Array([7, 8, 9]));
    await s4.finish();
    const content3 = await read(h2);

    // The failure latch.
    const h3 = await root.getFileHandle('three.bin', { create: true });
    const s5 = await T.createSink({ name: 'three.bin', size: 3 }, { handle: h3, startOffset: 0 });
    await s5.write(new Uint8Array([1]));
    await s5.abort('deliberate');
    const afterAbortWrite = await grab(() => s5.write(new Uint8Array([2])));
    const afterAbortCheckpoint = await grab(() => s5.checkpoint());
    const afterAbortFinish = await grab(() => s5.finish());

    return JSON.stringify({
      kind, hasHandle, p1, p2, finished, content1, resumeAt, content2, clamped,
      cpAt, durableMid, content3, afterAbortWrite, afterAbortCheckpoint, afterAbortFinish,
    });
  `));
  check('createSink with a real FileSystemFileHandle produces a disk sink',
    disk.kind === 'disk' && disk.hasHandle === true, JSON.stringify({ kind: disk.kind, hasHandle: disk.hasHandle }));
  check('the disk sink tracks position and writes content in order',
    disk.p1 === 3 && disk.p2 === 6 && disk.content1 === '1,2,3,4,5,6',
    JSON.stringify({ p1: disk.p1, p2: disk.p2, content1: disk.content1 }));
  check('finish() on a disk sink returns no blob (the bytes are already in the file)',
    disk.finished === null, String(disk.finished));
  check('re-opening at the existing length APPENDS rather than truncating',
    disk.resumeAt === 6 && disk.content2 === '1,2,3,4,5,6,7,8', JSON.stringify(disk.content2));
  check('a resume offset beyond the real file length is clamped to what the file holds',
    disk.clamped === 8, `startOffset 999999 produced position ${disk.clamped}`);
  check('checkpoint() commits what has been written so far to the real file',
    disk.cpAt === 3 && disk.durableMid === '1,2,3', JSON.stringify({ cpAt: disk.cpAt, durableMid: disk.durableMid }));
  check('writing across two checkpoints produces the whole file, in order',
    disk.content3 === '1,2,3,4,5,6,7,8,9', String(disk.content3));
  check('the disk sink latches after abort: write, checkpoint and finish all refuse',
    disk.afterAbortWrite.ok === false && disk.afterAbortCheckpoint.ok === false && disk.afterAbortFinish.ok === false,
    JSON.stringify([disk.afterAbortWrite, disk.afterAbortCheckpoint, disk.afterAbortFinish]));

  // ---------------------------------------------------------------- filename sanitising
  const names = JSON.parse(await run(`
    const cases = ['ok.txt', '../../etc/passwd', '..\\\\..\\\\cmd.exe', '.hidden', '..', '.', '   ',
      '', 'a\\u0000b.txt', 'inv\\u202Egnp.exe', 'x'.repeat(400) + '.tar.gz', '\\u{1F680}.png', '文件.txt'];
    return JSON.stringify(cases.map((c) => [c.length > 40 ? c.slice(0, 12) + '...' : c, T.sanitizeFilename(c)]));
  `));
  const byInput = Object.fromEntries(names);
  check('a path is flattened, never traversed',
    byInput['../../etc/passwd'] === '_.._etc_passwd', byInput['../../etc/passwd']);
  check('a backslash path is flattened too', !byInput['..\\..\\cmd.exe'].includes('\\'), byInput['..\\..\\cmd.exe']);
  check('a leading dot is stripped', byInput['.hidden'] === 'hidden', byInput['.hidden']);
  check('"." and ".." and spaces all fall back to a safe name',
    byInput['.'] === 'warp-gate-file' && byInput['..'] === 'warp-gate-file'
    && byInput['   '] === 'warp-gate-file' && byInput[''] === 'warp-gate-file',
    JSON.stringify([byInput['.'], byInput['..'], byInput['   '], byInput['']]));
  check('a NUL and a bidi override are removed',
    !Object.values(byInput).some((v) => /[\u0000-\u001f\u202a-\u202e]/.test(v)), JSON.stringify(names));
  check('emoji and CJK are preserved', byInput['\u{1F680}.png'] === '\u{1F680}.png' && byInput['文件.txt'] === '文件.txt',
    JSON.stringify([byInput['\u{1F680}.png'], byInput['文件.txt']]));
  const long = names.find(([k]) => k.startsWith('xxxxxxxxxxxx'));
  check('a 400 character name is truncated to 120 and keeps its extension',
    long[1].length <= 120 && long[1].endsWith('.gz'), `${long[1].length} chars, ends ${long[1].slice(-8)}`);

  // ---------------------------------------------------------------- resume record store
  const idb = JSON.parse(await run(`
    const grab = async (fn) => { try { return { ok: true, v: await fn() }; } catch (e) { return { ok: false, v: e.message }; } };
    const root = await navigator.storage.getDirectory();
    const h = await root.getFileHandle('rec.bin', { create: true });
    await T.saveResume('ROOM1234', { id: 'x', meta: { name: 'n', size: 1 }, received: 5, handle: h });
    const back = await T.loadResume('ROOM1234');
    const isHandle = Boolean(back && back.handle && typeof back.handle.getFile === 'function');
    await T.clearResume('ROOM1234');
    const gone = await T.loadResume('ROOM1234');
    const noRoom = await grab(() => T.saveResume('', {}));
    // A live, non-cloneable object must be reported, not swallowed.
    const live = await grab(() => T.saveResume('ROOM1234', { sink: { write() {} } }));
    return JSON.stringify({ received: back && back.received, isHandle, gone, noRoom, live });
  `));
  check('a resume record round-trips with a live file handle',
    idb.received === 5 && idb.isHandle === true, JSON.stringify(idb));
  check('clearing a resume record really removes it', idb.gone === null, JSON.stringify(idb.gone));
  check('a resume record with no room is refused', idb.noRoom.ok === false, JSON.stringify(idb.noRoom));
  check('a non-cloneable record is reported rather than silently dropped',
    idb.live.ok === false && /could not write the resume index/.test(idb.live.v), JSON.stringify(idb.live));

  check('no page error was thrown in the unit run', tab.pageErrors.length === 0, tab.pageErrors.join(' | '));
} finally {
  await browser.close();
  await server.stop();
}

process.exit(summary('stress/units (module level, not end-to-end)') ? 0 : 1);
