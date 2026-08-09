// One byte over MEMORY_LIMIT_BYTES, and well over, on a browser with no
// showSaveFilePicker (which is every browser this harness can drive headlessly).
//
// There are now TWO truthful behaviours here and which one applies depends on the browser,
// so this file branches the same way canAccept() does:
//
//   no streaming download  canAccept() refuses before a byte is streamed. BOTH sides are
//                          told, the refusal is visible in the transcript and not only
//                          buried in the log, and the gate still works afterwards.
//   streaming download     the service worker hands the file to the browser's own download
//                          manager, so there is no ceiling and no up-front refusal. An
//                          assertion that still demanded one would report a capability as
//                          a regression, which is worse than no assertion.
//
// The refusal path is not dead code: it is what every browser without the service worker
// still does, and it is what runs whenever supportsStreamDownload() is false.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, digestReceived, chainHashFile, logText } from './lib/pair.mjs';

const PORT = 3980;
const STUN = 3981;
const CDP = 9781;
const DIR = '/home/user/.cache/wg-stress/overlimit';
const MIB = 1024 * 1024;
const MEM_LIMIT = 500 * MIB;
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

function makeFile(name, size) {
  const p = path.join(DIR, name);
  const fd = fs.openSync(p, 'w');
  try {
    const block = Buffer.alloc(MIB, 0x5a);
    let written = 0;
    while (written < size) {
      const n = Math.min(block.length, size - written);
      fs.writeSync(fd, block, 0, n);
      written += n;
    }
  } finally { fs.closeSync(fd); }
  if (fs.statSync(p).size !== size) throw new Error(`wanted ${size}, wrote ${fs.statSync(p).size}`);
  return p;
}

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

try {
  const picker = await b.eval('return typeof window.showSaveFilePicker;');
  process.stdout.write(`     note: receiver showSaveFilePicker = ${picker}, so canStreamToDisk() is ${picker === 'function'}\n`);
  const streamsToDownloads = await b.eval(
    "const D = await import('/js/download.js'); return D.supportsStreamDownload() === true;",
  );
  process.stdout.write(`     note: receiver supportsStreamDownload() = ${streamsToDownloads}\n`);

  // The whole point of the streaming download path is that there is no ceiling to refuse
  // at, so the up-front refusal this file was written around does not happen. Assert the
  // DECISION instead, which is the part that would regress, and do not move 1.2 GB across
  // a loopback twice to re-observe a prompt: units.mjs covers canAccept's boundaries
  // directly, and an un-accepted 700 MiB offer would leave the receiver's file path busy
  // and break the "gate still works" check below for reasons that are not a bug.
  const overLimitCases = streamsToDownloads ? [] : [['over-by-one', MEM_LIMIT + 1], ['well-over', 700 * MIB]];
  if (streamsToDownloads) {
    const verdict = JSON.parse(await b.eval(
      `const T = await import('/js/transfer.js'); return JSON.stringify(T.canAccept(${MEM_LIMIT} + 1));`,
    ));
    check('a browser with the streaming download path accepts past the in-memory limit rather than refusing',
      verdict.ok === true, JSON.stringify(verdict));
    check('and says where the file will actually go, since the user does not choose it',
      /download manager|downloads folder/i.test(verdict.note ?? ''), JSON.stringify(verdict));
    // The negative control for the pair above. "Accepted, with a note about the download
    // manager" would also be printed by a canAccept that returned that for everything, so
    // require a file UNDER the limit to be accepted with no such note: the note has to be
    // produced by the size branch, not by the function.
    const under = JSON.parse(await b.eval(
      `const T = await import('/js/transfer.js'); return JSON.stringify(T.canAccept(${MEM_LIMIT}));`,
    ));
    check('a file inside the in-memory limit is accepted WITHOUT the download-manager note',
      under.ok === true && under.requiresDisk === false
      && !/download manager|downloads folder/i.test(under.note ?? ''), JSON.stringify(under));
  }

  for (const [label, size] of overLimitCases) {
    const name = `${label}.bin`;
    const src = makeFile(name, size);
    const rowsBefore = (await rows(b)).length;
    await a.setFileInput('#file-input', [src]);

    const receiverSaid = await b.waitFor(`(() => {
      const t = document.getElementById('log').textContent;
      const m = t.match(/refused incoming file:[^]*/);
      if (m) return m[0].slice(0, 240);
      const r = __wgRows().find(x => x.title.includes(${JSON.stringify(name)}));
      if (r && /exceeds|cannot/i.test(r.text)) return 'ROW:' + r.text.slice(0, 200);
      if (r && r.buttons.includes('Accept')) return 'OFFERED';
      return '';
    })()`, { timeout: 180000, label: `${name}: receiver reaction` }).catch((e) => `TIMEOUT:${e.message}`);
    check(`[${label}] the receiver refuses a file over the in-memory limit up front`,
      /exceeds|in-memory limit/i.test(String(receiverSaid)), String(receiverSaid).slice(0, 300));

    const senderSaid = await a.waitFor(`(() => {
      const t = document.getElementById('log').textContent;
      const m = t.match(/the other device refused the file:[^]*/);
      return m ? m[0].slice(0, 260) : '';
    })()`, { timeout: 120000, label: `${name}: sender told` }).catch((e) => `TIMEOUT:${e.message}`);
    check(`[${label}] the SENDER is told why, not left waiting`,
      !String(senderSaid).startsWith('TIMEOUT'), String(senderSaid).slice(0, 300));

    const rowsAfter = await rows(b);
    const row = rowsAfter.find((r) => r.title.includes(name));
    check(`[${label}] the refusal appears in the transcript, not only in the diagnostic log`,
      Boolean(row) && /exceed|cannot|limit/i.test(row.text),
      `${rowsAfter.length - rowsBefore} new rows; row=${row ? JSON.stringify(row.text.slice(0, 160)) : 'none'}`);

    fs.rmSync(src);
  }

  // The gate must still be usable.
  const small = path.join(DIR, 'after.bin');
  fs.writeFileSync(small, crypto.randomBytes(256 * 1024));
  await a.setFileInput('#file-input', [small]);
  await b.waitFor("__wgRows().some(r => r.title.includes('after.bin') && r.buttons.includes('Save'))",
    { timeout: 90000, label: 'a normal file after two refusals' });
  const okRow = (await rows(b)).find((r) => r.title.includes('after.bin'));
  check(overLimitCases.length
    ? 'the gate still transfers normally after two over-limit refusals'
    : 'the gate still transfers normally after the over-limit decisions',
  (await digestReceived(b, okRow.id)) === chainHashFile(small));

  const logs = `${await logText(a)} || ${await logText(b)}`;
  check('no frame was rejected', !/frame rejected/.test(logs), logs.slice(-200));
} finally {
  await pair.close();
  fs.rmSync(DIR, { recursive: true, force: true });
}

process.exit(summary('stress/over-limit') ? 0 : 1);
