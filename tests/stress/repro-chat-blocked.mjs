// SMALLEST REPRODUCTION of chat being stuck behind an outbound file.
//
// session.js:1359 driveOutbound() wraps the ENTIRE read-seal-send loop in this.enqueue().
// sendChat() (session.js:1221) uses the same enqueue() chain, so a message typed while a
// file is going out cannot be sealed until the last chunk has been sent. The comment at
// session.js:1322 says chat "still flows while the other side decides", which is true only
// of the acceptance wait, not of the streaming that follows it.
//
// Also checks the file-complete byte count the sender is shown.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, sendChat, logText } from './lib/pair.mjs';

const PORT = 3976;
const STUN = 3977;
const CDP = 9777;
const DIR = '/home/user/.cache/wg-stress/hol';
const MIB = 1024 * 1024;
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

try {
  const src = path.join(DIR, 'slow.bin');
  fs.writeFileSync(src, crypto.randomBytes(150 * MIB));
  await a.setFileInput('#file-input', [src]);
  await b.waitFor("__wgRows().some(r => r.title.includes('slow.bin') && r.buttons.includes('Accept'))",
    { timeout: 60000, label: 'file offered' });
  await b.eval(`
    const r = __wgRows().find(x => x.title.includes('slow.bin'));
    [...document.getElementById(r.id).querySelectorAll('button')].find(x => x.textContent === 'Accept').click();
    return true;
  `);
  await b.waitFor(`(() => {
    const r = __wgRows().find(x => x.title.includes('slow.bin'));
    return r && r.sent > 10 * 1024 * 1024 ? 'moving' : '';
  })()`, { timeout: 120000, label: 'transfer under way' });

  const atSend = await b.eval("const r = __wgRows().find(x => x.title.includes('slow.bin')); return JSON.stringify({sent: r.sent, total: r.total});");
  const t0 = Date.now();
  await sendChat(a, 'HOL-PROBE');

  // Poll finely and record the transfer position at the exact moment the chat lands.
  let observed = null;
  const deadline = Date.now() + 300000;
  while (Date.now() < deadline) {
    const snap = await b.eval(`
      const chat = [...document.querySelectorAll('#messages .msg-text')].some(x => x.textContent === 'HOL-PROBE');
      const r = __wgRows().find(x => x.title.includes('slow.bin'));
      return JSON.stringify({ chat, sent: r ? r.sent : null, total: r ? r.total : null, done: Boolean(r && r.buttons.includes('Save')) });
    `);
    const s = JSON.parse(snap);
    if (s.chat) { observed = { ...s, ms: Date.now() - t0 }; break; }
    if (s.done) { observed = { ...s, ms: Date.now() - t0, chatAfterDone: true }; }
    await new Promise((r) => { setTimeout(r, 100); });
  }
  process.stdout.write(`     note: transfer was at ${atSend} when the message was typed\n`);
  process.stdout.write(`     note: message landed at ${JSON.stringify(observed)}\n`);

  check('a message typed mid-transfer arrives before the transfer finishes',
    Boolean(observed) && observed.chat === true && observed.done === false,
    `observed=${JSON.stringify(observed)} (transfer position when typed: ${atSend})`);

  await b.waitFor("__wgRows().some(r => r.title.includes('slow.bin') && r.buttons.includes('Save'))",
    { timeout: 300000, label: 'transfer finished' });

  // The sender's own "they finished receiving it" line.
  const senderLog = await logText(a);
  const line = (senderLog.match(/the other device finished receiving the file \([^)]*\)/) || [''])[0];
  check('the sender is shown the real number of bytes the peer received',
    Boolean(line) && !/\(0 B\)/.test(line),
    `${line || 'no file-complete line at all'} for a ${150 * MIB} byte file`);
} finally {
  await pair.close();
  fs.rmSync(DIR, { recursive: true, force: true });
}

process.exit(summary('stress/repro-chat-blocked') ? 0 : 1);
