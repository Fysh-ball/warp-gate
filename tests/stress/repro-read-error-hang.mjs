// SMALLEST REPRODUCTION of the read-error hang.
//
// The sender's file becomes unreadable mid-stream. driveOutbound catches the read error
// and calls abandonOutbound (session.js:1371), which never sends the peer anything. The
// receiver keeps an open sink and a live `this.incoming` forever: it never fails the
// transfer, and because onFileStart refuses while `this.incoming` is set, every later
// file from that sender is rejected too. The gate's file path is wedged for good.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, logText } from './lib/pair.mjs';

const PORT = 3990;
const STUN = 3991;
const CDP = 9790;
const DIR = '/home/user/.cache/wg-stress/repro';
const MIB = 1024 * 1024;
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

try {
  // 20 MiB, so it is over AUTO_ACCEPT_BYTES and the sender waits for Accept: that gives a
  // deterministic moment to shrink the file, with no timing race.
  const src = path.join(DIR, 'vanishes.bin');
  fs.writeFileSync(src, crypto.randomBytes(20 * MIB));
  await a.setFileInput('#file-input', [src]);
  await b.waitFor("__wgRows().some(r => r.title.includes('vanishes.bin') && r.buttons.includes('Accept'))",
    { timeout: 60000, label: 'the file was offered' });

  fs.truncateSync(src, 3 * MIB);
  await b.eval(`
    const r = __wgRows().find(x => x.title.includes('vanishes.bin'));
    [...document.getElementById(r.id).querySelectorAll('button')]
      .find(x => x.textContent === 'Accept').click();
    return true;
  `);

  // The SENDER notices, immediately and correctly.
  const senderTold = await a.waitFor(`(() => {
    const t = document.getElementById('log').textContent;
    return /could not be read|read in full/.test(t) ? t.slice(-260) : '';
  })()`, { timeout: 60000, label: 'the sender detects the short read' });
  check('the SENDER detects the short read and says so', Boolean(senderTold), senderTold);

  // Give the receiver a generous window to be told anything at all.
  await new Promise((r) => { setTimeout(r, 20000); });

  const recvRows = await rows(b);
  const row = recvRows.find((r) => r.title.includes('vanishes.bin'));
  const recvLog = await logText(b);
  check('the RECEIVER is told the transfer ended',
    /failed|could not|refuse|stopped/i.test(row.text) || /transfer failed/i.test(recvLog),
    `row=${JSON.stringify({ status: row.status, sent: row.sent, total: row.total, text: row.text.slice(0, 200) })} `
    + `log=${JSON.stringify(recvLog.slice(-260))}`);

  // The consequence: the receiver still holds `incoming`, so nothing else can be sent.
  const second = path.join(DIR, 'second.bin');
  fs.writeFileSync(second, crypto.randomBytes(64 * 1024));
  await a.setFileInput('#file-input', [second]);
  const secondOutcome = await b.waitFor(`(() => {
    const r = __wgRows().find(x => x.title.includes('second.bin'));
    if (r && r.buttons.includes('Save')) return 'DELIVERED';
    const t = document.getElementById('log').textContent;
    if (/another transfer is already in progress/.test(t)) return 'BLOCKED';
    return '';
  })()`, { timeout: 45000, label: 'a later file after the read error' }).catch(() => 'NOTHING');
  const senderLog = await logText(a);
  check('a LATER file still gets through after a read error killed the previous one',
    secondOutcome === 'DELIVERED',
    `outcome=${secondOutcome}; sender log tail=${JSON.stringify(senderLog.slice(-300))}`);
} finally {
  await pair.close();
  fs.rmSync(DIR, { recursive: true, force: true });
}

process.exit(summary('stress/repro-read-error-hang') ? 0 : 1);
