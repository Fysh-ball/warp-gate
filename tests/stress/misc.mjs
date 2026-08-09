// Two leftovers worth pinning down precisely:
//   1. what happens to the text a user typed when the send fails
//   2. whether the RECEIVING side can still chat while a file is coming in
//      (the send-queue block is one-directional; this proves which direction)

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, sendChat, logText } from './lib/pair.mjs';

const PORT = 3972;
const STUN = 3973;
const CDP = 9773;
const DIR = '/home/user/.cache/wg-stress/misc';
const MIB = 1024 * 1024;
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

try {
  // ------------------------------- chat from the RECEIVING side during a transfer
  const src = path.join(DIR, 'incoming.bin');
  fs.writeFileSync(src, crypto.randomBytes(120 * MIB));
  await a.setFileInput('#file-input', [src]);
  await b.waitFor("__wgRows().some(r => r.title.includes('incoming.bin') && r.buttons.includes('Accept'))",
    { timeout: 60000, label: 'file offered' });
  await b.eval(`
    const r = __wgRows().find(x => x.title.includes('incoming.bin'));
    [...document.getElementById(r.id).querySelectorAll('button')].find(x => x.textContent === 'Accept').click();
    return true;
  `);
  await b.waitFor(`(() => {
    const r = __wgRows().find(x => x.title.includes('incoming.bin'));
    return r && r.sent > 10 * 1024 * 1024 ? 'moving' : '';
  })()`, { timeout: 120000, label: 'transfer under way' });

  const t0 = Date.now();
  await sendChat(b, 'FROM-RECEIVER');
  let landed = null;
  const deadline = Date.now() + 300000;
  while (Date.now() < deadline) {
    const snap = await a.eval(`
      const chat = [...document.querySelectorAll('#messages .msg-text')].some(x => x.textContent === 'FROM-RECEIVER');
      const r = __wgRows().find(x => x.title.includes('incoming.bin'));
      return JSON.stringify({ chat, sent: r ? r.sent : null, total: r ? r.total : null });
    `);
    const s = JSON.parse(snap);
    if (s.chat) { landed = { ...s, ms: Date.now() - t0 }; break; }
    await new Promise((r) => { setTimeout(r, 100); });
  }
  process.stdout.write(`     note: receiver-to-sender message landed at ${JSON.stringify(landed)}\n`);
  check('the RECEIVING side can still chat while a file is coming in',
    Boolean(landed) && landed.ms < 5000 && landed.sent < landed.total,
    JSON.stringify(landed));

  const senderLog = await logText(a);
  check('no frame was rejected', !/frame rejected/.test(senderLog), senderLog.slice(-200));

  // Chunk size is negotiated against what the connection will actually carry, rather
  // than pinned at the 16 KiB floor. The failure mode worth catching is silent: the code
  // still runs, returns the floor, and a 30 GiB file costs 1.97 million AEAD seals
  // instead of about 123 thousand. Nothing else would notice.
  const sctp = await a.eval(`
    // pc.sctp is null until the SCTP transport exists, so reading it too early reports
    // nothing and reads as "inert". Wait for an open channel first.
    const open = () => ((window.__wgLink && window.__wgLink()) || []).some((c) => c.readyState === 'open');
    for (let i = 0; i < 100 && !open(); i += 1) await new Promise((r) => setTimeout(r, 100));
    const reported = ((window.__wg && window.__wg.pcs) || [])
      .map((pc) => (pc.sctp ? pc.sctp.maxMessageSize : undefined))
      .filter((v) => Number.isFinite(v));
    return JSON.stringify({ reported });
  `);
  const reported = JSON.parse(sctp).reported[0];
  check('the connection reports an SCTP message size at all, so negotiation has an input',
    Number.isFinite(reported), sctp);
  check('the negotiated chunk is larger than the 16 KiB floor, so negotiation is not inert',
    Number.isFinite(reported) && Math.floor(Math.min(reported - 26, 256 * 1024) / 1024) * 1024 > 16 * 1024,
    `maxMessageSize=${reported}`);
} finally {
  await pair.close();
  fs.rmSync(DIR, { recursive: true, force: true });
}

process.exit(summary('stress/misc') ? 0 : 1);
