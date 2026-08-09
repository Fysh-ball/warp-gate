// Rig check. Proves the harness can pair two tabs, move a file, and that the content
// digest it uses can actually FAIL. A verification that has never failed is not evidence.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, digestReceived, chainHashFile, chainHashBuffer, logText } from './lib/pair.mjs';

const PORT = 3980;
const STUN = 3981;
const CDP = 9780;
const DIR = '/home/user/.cache/wg-stress/smoke';
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

// --- negative control on the digest itself, before anything is measured with it.
const p1 = path.join(DIR, 'ctl-a.bin');
const p2 = path.join(DIR, 'ctl-b.bin');
const body = crypto.randomBytes(9 * 1024 * 1024); // spans several 4 MiB slices
fs.writeFileSync(p1, body);
const swapped = Buffer.concat([body.subarray(4 * 1024 * 1024), body.subarray(0, 4 * 1024 * 1024)]);
fs.writeFileSync(p2, swapped);
check('the content digest agrees with itself', chainHashFile(p1) === chainHashBuffer(body), chainHashFile(p1));
check('the content digest DETECTS reordered blocks of identical bytes',
  chainHashFile(p1) !== chainHashFile(p2),
  `${chainHashFile(p1)} vs ${chainHashFile(p2)}`);

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
try {
  const src = path.join(DIR, 'payload.bin');
  const payload = crypto.randomBytes(700 * 1024);
  fs.writeFileSync(src, payload);
  const want = chainHashFile(src);

  await pair.a.setFileInput('#file-input', [src]);
  await pair.b.waitFor("__wgRows().some(r => r.buttons.includes('Save'))",
    { timeout: 60000, label: 'tab B finished receiving' });

  const received = await rows(pair.b);
  const row = received.find((r) => r.buttons.includes('Save'));
  const got = await digestReceived(pair.b, row.id);
  check('a 700 KiB file arrives with identical CONTENT, not just an identical byte count',
    got === want, `want ${want} got ${got}`);

  const logs = await logText(pair.b);
  check('no frame was rejected', !/frame rejected/.test(logs), logs.slice(-200));
} finally {
  await pair.close();
}

process.exit(summary('stress/smoke') ? 0 : 1);
