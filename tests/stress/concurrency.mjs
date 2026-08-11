// Concurrency and interruption: transfers overlapping each other, chat competing with a
// transfer, a data channel cut mid-stream, a receiver reload mid-stream, and a gate
// burned mid-stream. Content is verified after every recovery.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, digestReceived, chainHashFile, logText, sendChat } from './lib/pair.mjs';

const DIR = '/home/user/.cache/wg-stress/conc';
const MIB = 1024 * 1024;
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

const makeFile = (name, size) => {
  const p = path.join(DIR, name);
  fs.writeFileSync(p, crypto.randomBytes(size));
  return p;
};

const rowFor = async (tab, name) => (await rows(tab)).find((r) => r.title.includes(name));

const accept = (tab, name) => tab.eval(`
  const r = __wgRows().find(x => x.title.includes(${JSON.stringify(name)}));
  if (!r) return 'no row';
  const btn = [...document.getElementById(r.id).querySelectorAll('button')]
    .find(x => x.textContent === 'Accept');
  if (btn) btn.click();
  return btn ? 'clicked' : 'no button';
`);

let ports = 3992;
let cdp = 9792;
const nextPorts = () => {
  ports += 2;
  cdp += 1;
  return { port: ports, stunPort: ports + 1, cdpPort: cdp };
};

// ------------------------------------------------------------------ 1. two sends at once
{
  const pair = await openPair(nextPorts());
  const { a, b } = pair;
  try {
    const f1 = makeFile('conc-a.bin', 4 * MIB);
    const f2 = makeFile('conc-b.bin', 4 * MIB);
    // Two independent user actions overlapping: an attach and a drop, neither awaited.
    await a.eval(`
      const bin = Uint8Array.from(atob(${JSON.stringify(fs.readFileSync(f2).toString('base64'))}), c => c.charCodeAt(0));
      const dt = new DataTransfer();
      dt.items.add(new File([bin], 'conc-b.bin', { type: 'application/octet-stream' }));
      window.__wgDrop = () => {
        window.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }));
        window.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
      };
      return true;
    `);
    await a.setFileInput('#file-input', [f1]);
    await a.eval('window.__wgDrop(); return true;');

    const outcome = await b.waitFor(`(() => {
      const done = __wgRows().filter(r => /conc-[ab]\\.bin/.test(r.title) && r.buttons.includes('Save'));
      return done.length === 2 ? 'BOTH' : '';
    })()`, { timeout: 60000, label: 'both overlapping files arrive' }).catch(() => 'NOT_BOTH');
    const senderLog = await logText(a);
    check('two overlapping sends both reach the peer',
      outcome === 'BOTH',
      `${outcome}; sender log tail=${JSON.stringify(senderLog.slice(-300))}`);
    if (outcome === 'BOTH') {
      const r1 = await rowFor(b, 'conc-a.bin');
      const r2 = await rowFor(b, 'conc-b.bin');
      check('overlapping send A content intact', (await digestReceived(b, r1.id)) === chainHashFile(f1));
      check('overlapping send B content intact', (await digestReceived(b, r2.id)) === chainHashFile(f2));
    }
  } finally { await pair.close(); }
}

// ------------------------------------------- 2. chat while this side is mid-transfer
{
  const pair = await openPair(nextPorts());
  const { a, b } = pair;
  try {
    const big = makeFile('during.bin', 120 * MIB);
    await a.setFileInput('#file-input', [big]);
    await b.waitFor("__wgRows().some(r => r.title.includes('during.bin') && r.buttons.includes('Accept'))",
      { timeout: 60000, label: 'the 120 MiB file was offered' });
    await accept(b, 'during.bin');
    // Wait until the transfer is demonstrably under way, so the message is genuinely
    // competing with it rather than racing the handshake.
    await b.waitFor(`(() => {
      const r = __wgRows().find(x => x.title.includes('during.bin'));
      return r && r.sent > 8 * 1024 * 1024 ? 'moving' : '';
    })()`, { timeout: 120000, label: 'the transfer is under way' });

    const started = Date.now();
    await sendChat(a, 'PING-DURING-TRANSFER');
    const winner = await b.waitFor(`(() => {
      const chat = [...document.querySelectorAll('#messages .msg-text')]
        .some(x => x.textContent === 'PING-DURING-TRANSFER');
      const r = __wgRows().find(x => x.title.includes('during.bin'));
      const done = Boolean(r && r.buttons.includes('Save'));
      if (chat && !done) return 'CHAT_FIRST';
      if (done && !chat) return 'FILE_FIRST';
      if (chat && done) return 'SAME_POLL';
      return '';
    })()`, { timeout: 300000, label: 'chat or file completion, whichever comes first' });
    const elapsed = Date.now() - started;
    process.stdout.write(`     note: chat sent mid-transfer resolved as ${winner} after ${elapsed} ms\n`);
    check('a chat message sent during an outbound transfer is not stuck behind the whole file',
      winner === 'CHAT_FIRST',
      `${winner} after ${elapsed} ms: session.js driveOutbound() takes the same enqueue() lock as sendChat()`);

    await b.waitFor("__wgRows().some(r => r.title.includes('during.bin') && r.buttons.includes('Save'))",
      { timeout: 300000, label: 'the 120 MiB file finished' });
    const row = await rowFor(b, 'during.bin');
    check('the 120 MiB file arrives with identical content',
      (await digestReceived(b, row.id)) === chainHashFile(big));
  } finally { await pair.close(); }
}

// ------------------------------------------------- 3. both peers sending at once
{
  const pair = await openPair(nextPorts());
  const { a, b } = pair;
  try {
    const fa = makeFile('from-a.bin', 6 * MIB);
    const fb = makeFile('from-b.bin', 6 * MIB);
    await Promise.all([
      a.setFileInput('#file-input', [fa]),
      b.setFileInput('#file-input', [fb]),
    ]);
    const both = await Promise.all([
      b.waitFor("__wgRows().some(r => r.title.includes('from-a.bin') && r.buttons.includes('Save'))",
        { timeout: 120000, label: 'B received A\'s file' }).then(() => true).catch((e) => e.message),
      a.waitFor("__wgRows().some(r => r.title.includes('from-b.bin') && r.buttons.includes('Save'))",
        { timeout: 120000, label: 'A received B\'s file' }).then(() => true).catch((e) => e.message),
    ]);
    check('simultaneous sends in both directions both complete',
      both[0] === true && both[1] === true, JSON.stringify(both));
    if (both[0] === true) {
      const r = await rowFor(b, 'from-a.bin');
      check('A to B content intact under simultaneous transfer',
        (await digestReceived(b, r.id)) === chainHashFile(fa));
    }
    if (both[1] === true) {
      const r = await rowFor(a, 'from-b.bin');
      check('B to A content intact under simultaneous transfer',
        (await digestReceived(a, r.id)) === chainHashFile(fb));
    }
  } finally { await pair.close(); }
}

// ------------------------------------- 4. cut the data channel mid-transfer, then resume
{
  const pair = await openPair(nextPorts());
  const { a, b } = pair;
  try {
    const f = makeFile('resumes.bin', 60 * MIB);
    await a.setFileInput('#file-input', [f]);
    await b.waitFor("__wgRows().some(r => r.title.includes('resumes.bin') && r.buttons.includes('Accept'))",
      { timeout: 60000, label: 'the resumable file was offered' });
    await accept(b, 'resumes.bin');
    const atCut = await b.waitFor(`(() => {
      const r = __wgRows().find(x => x.title.includes('resumes.bin'));
      return r && r.sent > 5 * 1024 * 1024 ? r.sent : 0;
    })()`, { timeout: 120000, label: 'the transfer got going before the cut' });

    // A real close on the real RTCDataChannel the app is using.
    const cut = await a.eval("const c = __wgLink().at(-1); const s = c && c.readyState; if (c) c.close(); return s;");
    check('the data channel was open when it was cut', cut === 'open', String(cut));
    process.stdout.write(`     note: cut at ${atCut} bytes received\n`);

    const settled = await b.waitFor(`(() => {
      const r = __wgRows().find(x => x.title.includes('resumes.bin'));
      if (!r) return '';
      if (r.buttons.includes('Save')) return 'COMPLETE';
      if (/failed|could not/i.test(r.text)) return 'FAILED:' + r.text.slice(0, 200);
      return '';
    })()`, { timeout: 300000, label: 'the cut transfer settled' }).catch((e) => `TIMEOUT:${e.message}`);
    check('a transfer cut mid-stream resumes and completes', settled === 'COMPLETE', String(settled));
    if (settled === 'COMPLETE') {
      const row = await rowFor(b, 'resumes.bin');
      const got = await digestReceived(b, row.id);
      check('the resumed file is byte-identical to the source, not spliced or short',
        got === chainHashFile(f), `want ${chainHashFile(f)} got ${got}`);
      const rlog = await logText(b);
      check('the resume actually happened rather than the whole file being resent',
        /continuing from/i.test(rlog), rlog.slice(-300));
    }
  } finally { await pair.close(); }
}

// ------------------------------------------------- 5. reload the receiver mid-transfer
{
  const pair = await openPair(nextPorts());
  const { a, b } = pair;
  try {
    const f = makeFile('reloaded.bin', 60 * MIB);
    await a.setFileInput('#file-input', [f]);
    await b.waitFor("__wgRows().some(r => r.title.includes('reloaded.bin') && r.buttons.includes('Accept'))",
      { timeout: 60000, label: 'the file was offered before the reload' });
    await accept(b, 'reloaded.bin');
    await b.waitFor(`(() => {
      const r = __wgRows().find(x => x.title.includes('reloaded.bin'));
      return r && r.sent > 5 * 1024 * 1024 ? 'moving' : '';
    })()`, { timeout: 120000, label: 'the transfer got going before the reload' });

    await b.send('Page.reload', {});
    await b.waitFor("!!document.getElementById('screen-connected')", { timeout: 60000, label: 'tab B came back' });

    // A memory sink cannot survive a reload; the honest outcome is that BOTH sides are
    // told, promptly, rather than the sender holding the file open forever.
    const receiverTold = await b.waitFor(`(() => {
      const t = document.getElementById('log').textContent;
      return /cannot be continued|start again|discarded/i.test(t) ? t.slice(-260) : '';
    })()`, { timeout: 120000, label: 'the reloaded receiver explains itself' }).catch((e) => `TIMEOUT:${e.message}`);
    check('a receiver that reloads mid-transfer says the transfer cannot be continued',
      !String(receiverTold).startsWith('TIMEOUT'), String(receiverTold).slice(-260));

    const senderTold = await a.waitFor(`(() => {
      const t = document.getElementById('log').textContent;
      return /start again|refused|could not|reloading the page/i.test(t) ? t.slice(-320) : '';
    })()`, { timeout: 120000, label: 'the sender is released' }).catch((e) => `TIMEOUT:${e.message}`);
    check('the SENDER is released rather than left holding the file open',
      !String(senderTold).startsWith('TIMEOUT'), String(senderTold).slice(-320));

    // And the gate still works afterwards.
    const small = makeFile('after-reload.bin', 512 * 1024);
    await a.setFileInput('#file-input', [small]);
    const after = await b.waitFor("__wgRows().some(r => r.title.includes('after-reload.bin') && r.buttons.includes('Save')) ? 'ok' : ''",
      { timeout: 90000, label: 'a file sent after the reload' }).catch((e) => `TIMEOUT:${e.message}`);
    check('the gate still carries files after a receiver reload', after === 'ok', String(after));
    if (after === 'ok') {
      const r = await rowFor(b, 'after-reload.bin');
      check('and that file is byte-identical', (await digestReceived(b, r.id)) === chainHashFile(small));
    }
  } finally { await pair.close(); }
}

// ------------------------------------------------------ 6. burn the gate mid-transfer
{
  const pair = await openPair(nextPorts());
  const { a, b } = pair;
  try {
    const f = makeFile('burned.bin', 60 * MIB);
    await a.setFileInput('#file-input', [f]);
    await b.waitFor("__wgRows().some(r => r.title.includes('burned.bin') && r.buttons.includes('Accept'))",
      { timeout: 60000, label: 'the file was offered before the burn' });
    await accept(b, 'burned.bin');
    await b.waitFor(`(() => {
      const r = __wgRows().find(x => x.title.includes('burned.bin'));
      return r && r.sent > 5 * 1024 * 1024 ? 'moving' : '';
    })()`, { timeout: 120000, label: 'the transfer got going before the burn' });

    await a.eval("document.getElementById('sever').click(); return true;");
    const bSevered = await b.waitFor("!document.getElementById('screen-severed').hidden ? 'severed' : ''",
      { timeout: 60000, label: 'the receiver saw the gate burned' }).catch((e) => `TIMEOUT:${e.message}`);
    check('burning the gate mid-transfer moves the receiver to the severed screen',
      bSevered === 'severed', String(bSevered));

    const partial = await b.eval(`
      const rs = __wgRows().filter(r => r.title.includes('burned.bin'));
      return JSON.stringify(rs.map(r => ({ buttons: r.buttons, sent: r.sent, total: r.total, text: r.text.slice(0, 160) })));
    `);
    check('a burned transfer is never offered as a saveable file',
      partial !== '[]' && !partial.includes('"Save"'), partial);
    process.stdout.write(`     note: receiver row after the burn: ${partial}\n`);

    const aSevered = await a.eval("return !document.getElementById('screen-severed').hidden;");
    check('the burning side lands on the severed screen too', aSevered === true, String(aSevered));
  } finally { await pair.close(); }
}

fs.rmSync(DIR, { recursive: true, force: true });
process.exit(summary('stress/concurrency') ? 0 : 1);
