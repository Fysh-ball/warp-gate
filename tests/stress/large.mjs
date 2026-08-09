// The size boundaries that actually exist in the code:
//   AUTO_ACCEPT_BYTES   10 MiB  (session.js:60)   at, and one byte over
//   MEMORY_LIMIT_BYTES 500 MiB  (transfer.js:12)  at, one byte over, and well over
//
// Every transfer is verified by CONTENT, not by a byte count.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, digestReceived, chainHashFile, logText, evalWithGesture } from './lib/pair.mjs';

const PORT = 3984;
const STUN = 3985;
const CDP = 9784;
const DIR = '/home/user/.cache/wg-stress/large';
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

const MIB = 1024 * 1024;
const AUTO_ACCEPT = 10 * MIB;
const MEM_LIMIT = 500 * MIB;

/** Write a file of exactly `size` bytes of non-repeating content. */
function makeFile(name, size) {
  const p = path.join(DIR, name);
  const fd = fs.openSync(p, 'w');
  try {
    const block = 1 * MIB;
    let written = 0;
    let counter = 0;
    while (written < size) {
      const n = Math.min(block, size - written);
      // Deterministic but position-dependent, so a duplicated or dropped block shows up.
      const buf = crypto.createHash('sha512').update(String(counter)).digest();
      const chunk = Buffer.alloc(n);
      for (let i = 0; i < n; i += buf.length) buf.copy(chunk, i, 0, Math.min(buf.length, n - i));
      if (n >= 4) chunk.writeUInt32BE(counter, 0);
      fs.writeSync(fd, chunk, 0, n);
      written += n;
      counter += 1;
    }
  } finally {
    fs.closeSync(fd);
  }
  if (fs.statSync(p).size !== size) throw new Error(`wanted ${size} bytes, wrote ${fs.statSync(p).size}`);
  return p;
}

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

const rowFor = async (tab, name) => (await rows(tab)).find((r) => r.title.includes(name));

try {
  const picker = await b.eval("return typeof window.showSaveFilePicker;");
  check('recording what the receiving browser reports for showSaveFilePicker',
    picker === 'function' || picker === 'undefined', `typeof showSaveFilePicker = ${picker}`);
  process.stdout.write(`     note: canStreamToDisk() is ${picker === 'function'} in this browser\n`);

  // ------------------------------------------------------------ exactly at auto-accept
  const at = makeFile('at-10MiB.bin', AUTO_ACCEPT);
  await a.setFileInput('#file-input', [at]);
  await b.waitFor("__wgRows().some(r => r.title.includes('at-10MiB.bin') && r.buttons.includes('Save'))",
    { timeout: 180000, label: '10 MiB exactly received' });
  const atRow = await rowFor(b, 'at-10MiB.bin');
  check('a file of exactly AUTO_ACCEPT_BYTES is taken with no prompt',
    !atRow.buttons.includes('Accept'), JSON.stringify(atRow.buttons));
  check('a file of exactly AUTO_ACCEPT_BYTES arrives with identical content',
    (await digestReceived(b, atRow.id)) === chainHashFile(at));

  // ------------------------------------------------------------ one byte over
  const over = makeFile('over-10MiB.bin', AUTO_ACCEPT + 1);
  await a.setFileInput('#file-input', [over]);
  await b.waitFor("__wgRows().some(r => r.title.includes('over-10MiB.bin') && r.buttons.includes('Accept'))",
    { timeout: 60000, label: 'one byte over auto-accept prompts' });
  check('one byte over AUTO_ACCEPT_BYTES prompts the receiver instead of taking it silently', true);
  // A real user activation, so showSaveFilePicker is genuinely attempted rather than
  // failing for a reason the harness invented.
  await evalWithGesture(b, `
    const row = __wgRows().find(r => r.title.includes('over-10MiB.bin'));
    const el = document.getElementById(row.id);
    [...el.querySelectorAll('button')].find(x => x.textContent === 'Accept').click();
    return true;
  `);
  await b.waitFor("__wgRows().some(r => r.title.includes('over-10MiB.bin') && (r.buttons.includes('Save') || /Written to|failed/i.test(r.text)))",
    { timeout: 180000, label: 'the accepted 10 MiB + 1 file settled' });
  const overRow = await rowFor(b, 'over-10MiB.bin');
  const overLog = await logText(b);
  process.stdout.write(`     note: sink for the accepted file -> ${/holding the file in memory|save dialog unavailable|memory/i.test(overLog) ? 'memory fallback' : 'disk or unstated'}\n`);
  if (overRow.buttons.includes('Save')) {
    check('10 MiB + 1 arrives with identical content once accepted',
      (await digestReceived(b, overRow.id)) === chainHashFile(over));
  } else {
    check('10 MiB + 1 was written straight to disk (content not readable from the page)',
      /Written to the location you chose/.test(overRow.text), overRow.text.slice(0, 200));
  }

  // ------------------------------------------------------------ exactly the memory limit
  const atMem = makeFile('at-500MiB.bin', MEM_LIMIT);
  await a.setFileInput('#file-input', [atMem]);
  await b.waitFor("__wgRows().some(r => r.title.includes('at-500MiB.bin') && (r.buttons.includes('Accept') || /exceeds|cannot/i.test(r.text)))",
    { timeout: 120000, label: '500 MiB exactly offered' });
  const memOffer = await rowFor(b, 'at-500MiB.bin');
  check('a file of exactly MEMORY_LIMIT_BYTES is offered rather than refused up front',
    memOffer.buttons.includes('Accept'), memOffer.text.slice(0, 240));
  await evalWithGesture(b, `
    const row = __wgRows().find(r => r.title.includes('at-500MiB.bin'));
    const el = document.getElementById(row.id);
    const btn = [...el.querySelectorAll('button')].find(x => x.textContent === 'Accept');
    if (btn) btn.click();
    return true;
  `);
  const memSettled = await b.waitFor(`(() => {
    const r = __wgRows().find(x => x.title.includes('at-500MiB.bin'));
    if (!r) return '';
    if (r.buttons.includes('Save')) return 'save';
    if (/Written to the location/.test(r.text)) return 'disk';
    if (/failed|could not|too large|exceeds/i.test(r.text)) return 'refused';
    return '';
  })()`, { timeout: 600000, label: '500 MiB exactly settled' });
  process.stdout.write(`     note: 500 MiB exactly settled as "${memSettled}"\n`);
  const memRow = await rowFor(b, 'at-500MiB.bin');
  if (memSettled === 'save') {
    check('a file of exactly MEMORY_LIMIT_BYTES arrives with identical content',
      (await digestReceived(b, memRow.id)) === chainHashFile(atMem));
  } else {
    check('a file of exactly MEMORY_LIMIT_BYTES completes rather than being refused at the limit',
      memSettled === 'disk', `${memSettled}: ${memRow.text.slice(0, 300)}`);
  }
  // Free the page's copy before the next one.
  await b.eval("__wg.blobs.length = 0; return true;");

  // ------------------------------------------------------------ one byte over the limit
  const overMem = makeFile('over-500MiB.bin', MEM_LIMIT + 1);
  await a.setFileInput('#file-input', [overMem]);
  const overMemState = await b.waitFor(`(() => {
    const r = __wgRows().find(x => x.title.includes('over-500MiB.bin'));
    if (!r) return '';
    if (r.buttons.includes('Accept')) return 'offered';
    if (/exceeds|cannot be held|too large/i.test(r.text)) return 'refused-up-front';
    return '';
  })()`, { timeout: 120000, label: '500 MiB + 1 offered or refused' });
  process.stdout.write(`     note: 500 MiB + 1 -> ${overMemState}\n`);
  if (overMemState === 'offered') {
    await evalWithGesture(b, `
      const row = __wgRows().find(r => r.title.includes('over-500MiB.bin'));
      const el = document.getElementById(row.id);
      const btn = [...el.querySelectorAll('button')].find(x => x.textContent === 'Accept');
      if (btn) btn.click();
      return true;
    `);
  }
  // Whatever happens, the SENDER must be told, and must not sit waiting forever.
  const senderTold = await a.waitFor(`(() => {
    const t = document.getElementById('log').textContent;
    return /refused the file|could not send|too large|save location/i.test(t) ? t.slice(-400) : '';
  })()`, { timeout: 180000, label: 'the sender is told about the over-limit file' })
    .catch((err) => `TIMEOUT: ${err.message}`);
  check('a file over MEMORY_LIMIT_BYTES ends with the SENDER told why, not left waiting',
    !String(senderTold).startsWith('TIMEOUT'), String(senderTold).slice(-300));

  const stuck = await a.eval(`
    const rs = __wgRows().filter(r => r.title.includes('over-500MiB.bin'));
    return JSON.stringify(rs.map(r => ({ status: r.status, sent: r.sent, total: r.total })));
  `);
  process.stdout.write(`     note: sender row for the over-limit file: ${stuck}\n`);

  check('no page error was thrown during the size run',
    a.pageErrors.length === 0 && b.pageErrors.length === 0,
    [...a.pageErrors, ...b.pageErrors].join(' | '));
} finally {
  await pair.close();
  fs.rmSync(DIR, { recursive: true, force: true });
}

process.exit(summary('stress/large') ? 0 : 1);
