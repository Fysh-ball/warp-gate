// A 20000 x 20000 PNG. Tiny on the wire (a few hundred KiB of deflated zeros), 1.6 GB
// once a browser tries to decode it into a bitmap, and under AUTO_ACCEPT_BYTES so the
// receiver is never asked. Run last and on its own: if it takes the tab down, that is the
// finding.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, digestReceived, chainHashFile, logText } from './lib/pair.mjs';

const PORT = 3974;
const STUN = 3975;
const CDP = 9775;
const DIR = '/home/user/.cache/wg-stress/giant';
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i];
    for (let k = 0; k < 8; k += 1) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** Grayscale 8-bit PNG of the given dimensions, filled with a single value. */
function makeGiantPng(file, w, h) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // colour type: grayscale
  const deflate = zlib.deflateSync(Buffer.alloc((w + 1) * h), { level: 9 });
  fs.writeFileSync(file, Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflate),
    chunk('IEND', Buffer.alloc(0)),
  ]));
  return file;
}

const giant = makeGiantPng(path.join(DIR, 'giant.png'), 20000, 20000);
check('the 20000x20000 PNG is small on the wire',
  fs.statSync(giant).size < 5 * 1024 * 1024, `${fs.statSync(giant).size} bytes`);

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

try {
  await a.setFileInput('#file-input', [giant]);
  const settled = await b.waitFor(`(() => {
    const r = __wgRows().find(x => x.title.includes('giant.png'));
    if (!r) return '';
    if (r.buttons.includes('Save')) return 'save';
    if (/failed|refuse|could not/i.test(r.text)) return 'failed:' + r.text.slice(0, 160);
    return '';
  })()`, { timeout: 180000, label: 'the giant PNG settled' }).catch((e) => `TIMEOUT:${e.message}`);
  check('a 20000x20000 PNG transfers without killing the receiving tab',
    settled === 'save', String(settled));

  if (settled === 'save') {
    const row = (await rows(b)).find((r) => r.title.includes('giant.png'));
    process.stdout.write(`     note: inline <img> state -> ${JSON.stringify(row.img)}\n`);
    const got = await digestReceived(b, row.id);
    check('the giant PNG arrives byte-identical', got === chainHashFile(giant), `want ${chainHashFile(giant)} got ${got}`);
    check('the receiving tab is still responsive afterwards',
      (await b.eval('return 1 + 1;')) === 2);
  }

  // And the gate still works.
  const after = path.join(DIR, 'after.bin');
  fs.writeFileSync(after, crypto.randomBytes(128 * 1024));
  await a.setFileInput('#file-input', [after]);
  const ok = await b.waitFor("__wgRows().some(r => r.title.includes('after.bin') && r.buttons.includes('Save')) ? 'ok' : ''",
    { timeout: 90000, label: 'a normal file after the giant one' }).catch((e) => `TIMEOUT:${e.message}`);
  check('the gate still transfers after the giant image', ok === 'ok', String(ok));

  const logs = `${await logText(a)} || ${await logText(b)}`;
  check('no frame was rejected', !/frame rejected/.test(logs), logs.slice(-200));
  check('no page error was thrown', a.pageErrors.length === 0 && b.pageErrors.length === 0,
    [...a.pageErrors, ...b.pageErrors].join(' | '));
} finally {
  await pair.close();
  fs.rmSync(DIR, { recursive: true, force: true });
}

process.exit(summary('stress/giant-image') ? 0 : 1);
