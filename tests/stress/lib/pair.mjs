// Stress-test rig: one real server, one headless browser, two paired tabs.
//
// Everything here drives the SHIPPED UI (#create-btn, #join-input, #file-input,
// #chat-input, #messages, #sever). Nothing stubs the app's own modules.

import fs from 'node:fs';
import crypto from 'node:crypto';
import { startServer } from '../../lib/harness.mjs';
import { launchBrowser, findBrowser } from '../../lib/cdp.mjs';

export const SLICE = 4 * 1024 * 1024;

/**
 * Order-sensitive content digest that Node and the browser can both compute without
 * ever holding the whole payload. h_0 = 32 zero bytes; h_i = SHA256(h_{i-1} || slice_i).
 * A byte count alone cannot detect reordering; this can.
 */
export function chainHashFile(filePath, slice = SLICE) {
  let h = Buffer.alloc(32);
  const fd = fs.openSync(filePath, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const buf = Buffer.alloc(slice);
    let off = 0;
    while (off < size) {
      const n = fs.readSync(fd, buf, 0, Math.min(slice, size - off), off);
      if (n <= 0) throw new Error(`short read on ${filePath} at ${off}`);
      h = crypto.createHash('sha256').update(Buffer.concat([h, buf.subarray(0, n)])).digest();
      off += n;
    }
    return `${h.toString('hex')}:${size}`;
  } finally {
    fs.closeSync(fd);
  }
}

export function chainHashBuffer(buffer, slice = SLICE) {
  let h = Buffer.alloc(32);
  for (let off = 0; off < buffer.length; off += slice) {
    const part = buffer.subarray(off, Math.min(off + slice, buffer.length));
    h = crypto.createHash('sha256').update(Buffer.concat([h, part])).digest();
  }
  return `${h.toString('hex')}:${buffer.length}`;
}

// Injected before any page script. Two jobs: keep every Blob that the app turns into an
// object URL (the inline previews and every Save click), and expose a digest routine
// that matches chainHashFile byte for byte.
const PRELUDE = `
(() => {
  const w = globalThis;
  w.__wg = { blobs: [], errors: [], slice: ${SLICE} };
  const realCreate = URL.createObjectURL.bind(URL);
  URL.createObjectURL = (obj) => {
    const url = realCreate(obj);
    try { if (obj && typeof obj.size === 'number') w.__wg.blobs.push({ url, blob: obj }); } catch (e) { w.__wg.errors.push(String(e)); }
    return url;
  };
  // Swallow the navigation a Save click triggers so a download prompt cannot wedge a tab.
  const realClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function click() {
    if (this.download && String(this.href || '').startsWith('blob:')) { w.__wg.saved = (w.__wg.saved || 0) + 1; return; }
    return realClick.call(this);
  };
  // Keep a handle on the real RTCPeerConnection and its data channels so a test can cut
  // the link the way a network does, mid-transfer. Purely additive: the app still gets a
  // genuine RTCPeerConnection and never sees this wrapper.
  w.__wg.pcs = [];
  w.__wg.chans = [];
  const RealPC = w.RTCPeerConnection;
  function InstrumentedRTCPeerConnection(...args) {
    const pc = new RealPC(...args);
    w.__wg.pcs.push(pc);
    const create = pc.createDataChannel.bind(pc);
    pc.createDataChannel = (...rest) => { const ch = create(...rest); w.__wg.chans.push(ch); return ch; };
    pc.addEventListener('datachannel', (e) => w.__wg.chans.push(e.channel));
    return pc;
  }
  InstrumentedRTCPeerConnection.prototype = RealPC.prototype;
  w.RTCPeerConnection = InstrumentedRTCPeerConnection;
  w.__wgLink = () => w.__wg.chans.filter((c) => c.label === 'wg');

  w.__wgHash = async (blob) => {
    let h = new Uint8Array(32);
    const size = blob.size;
    for (let off = 0; off < size; off += w.__wg.slice) {
      const part = new Uint8Array(await blob.slice(off, Math.min(off + w.__wg.slice, size)).arrayBuffer());
      const cat = new Uint8Array(h.length + part.length);
      cat.set(h); cat.set(part, h.length);
      h = new Uint8Array(await crypto.subtle.digest('SHA-256', cat));
    }
    return [...h].map((b) => b.toString(16).padStart(2, '0')).join('') + ':' + size;
  };
  w.__wgRows = () => [...document.querySelectorAll('#messages .msg')].map((row) => {
    const bar = row.querySelector('progress');
    const img = row.querySelector('img.msg-image');
    return {
      id: row.id || '',
      cls: row.className,
      title: (row.querySelector('.file-title') || {}).textContent || '',
      status: (row.querySelector('.file-status') || {}).textContent || '',
      text: row.textContent || '',
      buttons: [...row.querySelectorAll('button')].map((b) => b.textContent),
      sent: bar ? bar.value : null,
      total: bar ? bar.max : null,
      img: img ? { complete: img.complete, w: img.naturalWidth, h: img.naturalHeight, alt: img.alt } : null,
    };
  });
})();
`;

async function instrument(tab) {
  await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: PRELUDE });
}

/** Boot server + browser and pair two tabs through the real create/join flow. */
export async function openPair({ port, stunPort, cdpPort, serverEnv = {} }) {
  if (!findBrowser()) throw new Error('no Chromium-based browser found');
  const server = await startServer({
    WG_HTTP_PORT: String(port),
    WG_STUN_PORT: String(stunPort),
    WG_STUN_ENABLED: '1',
    WG_STUN_URL: `stun:127.0.0.1:${stunPort}`,
    WG_CREATE_PER_WINDOW: '500',
    WG_JOIN_PER_WINDOW: '500',
    WG_REJECT_PER_WINDOW: '2000',
    WG_PUBLIC_GET_PER_WINDOW: '2000',
    WG_API_PER_WINDOW: '20000',
    WG_RELAY_PER_MIN: '5000',
    WG_EMPTY_GRACE_MS: '60000',
    ...serverEnv,
  });
  const origin = `http://127.0.0.1:${port}`;
  const browser = await launchBrowser({ port: cdpPort });

  const a = await browser.newTab('about:blank');
  await instrument(a);
  await a.send('Page.navigate', { url: origin });
  await a.waitFor("!!document.getElementById('screen-onboarding')", { label: 'tab A loaded' });
  // Clear the clickwrap the same way a user does.
  await a.waitFor("!document.getElementById('screen-onboarding').hidden || !document.getElementById('screen-home').hidden",
    { label: 'tab A first screen' });
  await a.eval(`
    const c = document.getElementById('agree-check');
    if (c && !document.getElementById('screen-onboarding').hidden) {
      c.checked = true;
      c.dispatchEvent(new Event('change', { bubbles: true }));
      document.getElementById('onboarding-done').click();
    }
    return true;
  `);
  await a.waitFor("!document.getElementById('screen-home').hidden", { label: 'tab A home' });

  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 25000, label: 'tab A waiting' });
  await a.eval("document.getElementById('reveal-share').click(); return true;");
  const code = await a.waitFor("(document.getElementById('room-code').textContent || '').trim()",
    { label: 'gate code revealed' });

  const b = await browser.newTab('about:blank');
  await instrument(b);
  await b.send('Page.navigate', { url: `${origin}/#${code}` });
  await b.waitFor("!!document.getElementById('screen-home')", { label: 'tab B loaded' });

  await a.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 40000, label: 'tab A connected' });
  await b.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 40000, label: 'tab B connected' });

  return {
    server,
    browser,
    origin,
    code,
    a,
    b,
    async close() {
      try { await browser.close(); } catch (err) { void err; }
      try { await server.stop(); } catch (err) { void err; }
    },
  };
}

/** Every transfer row as the page renders it. */
export const rows = (tab) => tab.eval('return JSON.stringify(__wgRows());').then(JSON.parse);

export const logText = (tab) => tab.eval("return document.getElementById('log').textContent;");

export const msgText = (tab) => tab.eval("return document.getElementById('messages').textContent;");

/**
 * Click Save on a received row and digest the exact Blob the app handed to saveBlob.
 * Nothing is trusted from a byte counter: this is the reassembled content itself.
 */
export async function digestReceived(tab, rowId) {
  return tab.eval(`
    const row = document.getElementById(${JSON.stringify(rowId)});
    if (!row) return 'NO_ROW';
    const before = __wg.blobs.length;
    const save = [...row.querySelectorAll('button')].find((x) => x.textContent === 'Save');
    if (!save) return 'NO_SAVE_BUTTON';
    save.click();
    const rec = __wg.blobs[__wg.blobs.length - 1];
    if (!rec || __wg.blobs.length === before) return 'NO_BLOB_CAPTURED';
    return await __wgHash(rec.blob);
  `);
}

/**
 * Run an expression with a REAL user activation.
 *
 * showSaveFilePicker and FileSystemHandle.requestPermission are gated on user
 * activation, so a plain Runtime.evaluate click can never reach them: the failure it
 * produces would be the harness's, not the product's.
 */
export async function evalWithGesture(tab, expression) {
  const result = await tab.send('Runtime.evaluate', {
    expression: `(async () => { ${expression} })()`,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
  }
  return result.result?.value;
}

/** Send text through the composer exactly as a user would. */
export async function sendChat(tab, text, { secret = false } = {}) {
  return tab.eval(`
    const t = document.getElementById('secret-toggle');
    t.checked = ${secret ? 'true' : 'false'};
    document.getElementById('chat-input').value = ${JSON.stringify(text)};
    document.getElementById('chat-form').requestSubmit();
    return true;
  `);
}
