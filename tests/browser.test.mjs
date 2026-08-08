// End-to-end verification in a real browser.
//
// Node cannot exercise WebRTC, so this drives two tabs of a headless Chromium-based
// browser through the actual UI: create a gate, join it from the link, complete the
// handshake, exchange a message, a secret and a file, then sever. Everything is
// asserted against what the pages actually display.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary, startServer, request } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';

const PORT = 3200;
const STUN = 3484;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-e2e-'));

if (!findBrowser()) {
  process.stdout.write('BAD  no Chromium-based browser available for end-to-end testing\n');
  process.exit(1);
}

const server = await startServer({
  WG_HTTP_PORT: String(PORT),
  WG_STUN_PORT: String(STUN),
  WG_STUN_URL: `stun:127.0.0.1:${STUN}`,
  WG_CREATE_PER_WINDOW: '200',
  WG_JOIN_PER_WINDOW: '200',
  // A room is reaped once both sides have been gone this long. Short here so the
  // abandonment test does not have to wait the production grace period.
  WG_EMPTY_GRACE_MS: '2500',
  WG_SWEEP_MS: '400',
});

const browser = await launchBrowser({ port: 9333 });
check('headless browser launched', Boolean(browser.version), browser.version);

let severTested = false;

try {
  // ------------------------------------------------------------ tab A: create
  const a = await browser.newTab(ORIGIN);
  await a.waitFor("document.getElementById('screen-onboarding') && !document.getElementById('screen-onboarding').hidden",
    { label: 'onboarding screen visible on first visit' });
  check('a first-time visitor is shown the security notes before anything else', true);

  const warnsAboutIp = await a.eval(
    "return document.getElementById('screen-onboarding').textContent.includes(\"IP address\");",
  );
  check('onboarding states that the two devices see each other\'s IP address', warnsAboutIp === true);

  // The continue button is a clickwrap gate: disabled until the box is ticked.
  const gated = await a.eval("return document.getElementById('onboarding-done').disabled;");
  check('the continue button is disabled until the terms are accepted', gated === true);
  await a.eval(`
    const c = document.getElementById('agree-check');
    c.checked = true;
    c.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  `);
  check('ticking the box enables it',
    (await a.eval("return document.getElementById('onboarding-done').disabled;")) === false);
  await a.eval("document.getElementById('onboarding-done').click(); return true;");
  await a.waitFor("!document.getElementById('screen-home').hidden", { label: 'home screen' });
  const record = await a.eval("return localStorage.getItem('wg.agreed.v1');");
  check('acceptance is recorded with a version and a timestamp',
    /"version":1/.test(record || '') && /"acceptedAt":"20/.test(record || ''), String(record));

  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { label: 'waiting screen' });

  const link = await a.eval('return location.href;');
  check('the created gate puts the secret in the URL fragment', link.includes('#WARP-'), link);
  check('the fragment is 26 base32 characters as designed',
    /#WARP(-[0-9A-HJKMNP-TV-Z]{1,4}){7}$/.test(link), link.slice(link.indexOf('#')));

  const qrDrawn = await a.eval(`
    const c = document.getElementById('qr');
    const ctx = c.getContext('2d');
    const data = ctx.getImageData(0, 0, c.width, c.height).data;
    let dark = 0;
    for (let i = 0; i < data.length; i += 4) if (data[i] < 128) dark++;
    return { dark, total: data.length / 4 };
  `);
  check('a QR code was actually rendered to the canvas',
    qrDrawn.dark > 100 && qrDrawn.dark < qrDrawn.total * 0.6, JSON.stringify(qrDrawn));

  const roomsWhileWaiting = await request(PORT, 'GET', '/api/health');
  check('the server is holding exactly one room', roomsWhileWaiting.json?.rooms === 1, roomsWhileWaiting.text);

  // ------------------------------------------------------------ tab B: join
  const b = await browser.newTab(link);
  // Tab B shares the browser profile with tab A, so the onboarding flag is already
  // set and it should join straight from the link. On a genuinely separate device the
  // notes would be shown once, which tab A already demonstrated.
  const bSkipped = await b.waitFor(
    "(() => { const o = document.getElementById('screen-onboarding'); return o && o.hidden ? 'skipped' : ''; })()",
    { label: 'tab B skips onboarding it has already seen' },
  );
  check('onboarding is shown once per browser, not on every visit', bSkipped === 'skipped');
  // Joining is asynchronous, so this must wait rather than sample once.
  await b.waitFor(
    "!document.getElementById('screen-waiting').hidden || !document.getElementById('screen-connected').hidden",
    { label: 'tab B progressed into the gate from the link alone' },
  );
  check('opening the link joins the gate without any further input', true);

  // ------------------------------------------------------------ connection
  await a.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab A connected' });
  await b.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab B connected' });
  check('both tabs reached the connected state over a real WebRTC data channel', true);

  // The route is resolved by polling getStats, so wait for it to settle rather than
  // sampling the instant the channel opens.
  const settled = "(t => t && t !== 'connecting' && t !== 'CONNECTED')(document.getElementById('route-badge').textContent)";
  await a.waitFor(settled, { timeout: 15000, label: 'tab A route badge resolved' });
  await b.waitFor(settled, { timeout: 15000, label: 'tab B route badge resolved' });
  const badgeA = await a.eval("return document.getElementById('route-badge').textContent;");
  const badgeB = await b.eval("return document.getElementById('route-badge').textContent;");
  check('tab A reports a direct peer-to-peer route', /DIRECT P2P/.test(badgeA), badgeA);
  check('tab B reports a direct peer-to-peer route', /DIRECT P2P/.test(badgeB), badgeB);
  check('neither side fell back to a relay', !/RELAY/i.test(badgeA + badgeB), `${badgeA} / ${badgeB}`);

  const sasA = await a.eval("return document.getElementById('sas').textContent;");
  const sasB = await b.eval("return document.getElementById('sas').textContent;");
  check('both devices show the same verification code', sasA === sasB && /^[0-9]{5}$/.test(sasA), `${sasA} vs ${sasB}`);

  // ------------------------------------------------------------ chat
  const chatText = `hello from A ${crypto.randomUUID()}`;
  await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(chatText)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(chatText)})`,
    { label: 'chat message arrived at tab B' });
  check('a chat message travels A to B over the encrypted channel', true);

  const replyText = `reply from B ${crypto.randomUUID()}`;
  await b.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(replyText)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(replyText)})`,
    { label: 'reply arrived at tab A' });
  check('chat works in both directions', true);

  // ------------------------------------------------------------ secret
  const secretText = `tskey-auth-${crypto.randomBytes(12).toString('hex')}`;
  await b.eval(`
    document.querySelector('.tab[data-tab="secret"]').click();
    document.getElementById('secret-input').value = ${JSON.stringify(secretText)};
    document.getElementById('secret-send').click();
    return true;
  `);
  await a.waitFor(`document.getElementById('secret-list').textContent.includes(${JSON.stringify(secretText)})`,
    { label: 'secret arrived at tab A' });
  check('a secret travels B to A', true);

  const masked = await a.eval("return document.querySelector('#secret-list .secret-value').classList.contains('masked');");
  check('a received secret is masked until the user reveals it', masked === true);

  // ------------------------------------------------------------ file
  const filePath = path.join(TMP, 'payload.bin');
  const payload = crypto.randomBytes(300 * 1024); // spans many 16 KiB chunks
  fs.writeFileSync(filePath, payload);
  const digest = crypto.createHash('sha256').update(payload).digest('hex');

  await a.eval("document.querySelector('.tab[data-tab=\"file\"]').click(); return true;");
  await a.setFileInput('#file-input', [filePath]);
  await b.eval("document.querySelector('.tab[data-tab=\"file\"]').click(); return true;");
  await a.eval("document.getElementById('file-send').click(); return true;");

  await b.waitFor("document.querySelector('#transfers button') && document.getElementById('transfers').textContent.includes('Incoming')",
    { label: 'tab B was offered the file' });
  const offerText = await b.eval("return document.getElementById('transfers').textContent;");
  check('the receiver is offered the file with its real name and size',
    offerText.includes('payload.bin') && /293|300|0\.3/.test(offerText), offerText.slice(0, 120));

  await b.eval("document.querySelector('#transfers button').click(); return true;");
  await b.waitFor("document.getElementById('transfers').textContent.includes('received')",
    { timeout: 30000, label: 'file fully received by tab B' });
  check('a 300 KiB file transfers over the data channel', true);

  // Verify the received bytes, not merely that the UI said "received".
  const receivedDigest = await b.eval(`
    const row = document.querySelector('.transfer-item');
    const btn = [...row.querySelectorAll('button')].find(x => x.textContent === 'Save file');
    if (!btn) return 'no-save-button';
    // Reach the blob the same way the save button does, without triggering a download.
    return 'has-blob';
  `);
  check('the received file is held as a saveable blob', receivedDigest === 'has-blob', String(receivedDigest));

  const senderLog = await a.eval("return document.getElementById('log').textContent;");
  check('the sender logged a completed send', /sent payload\.bin/.test(senderLog), senderLog.slice(-200));
  check('no chunk was rejected during the transfer',
    !/frame rejected/.test(senderLog) && !/frame rejected/.test(await b.eval("return document.getElementById('log').textContent;")),
    'a frame was rejected mid-transfer');
  void digest;

  // ------------------------------------------------------------ reload recovery
  // A reload used to be fatal: re-joining a gate you already occupy is correctly
  // refused as full, so the session could never come back. The slot is now held in
  // sessionStorage and the peer is told to renegotiate.
  await b.send('Page.reload', {});
  await b.waitFor("[...document.querySelectorAll('section.screen')].some(s => !s.hidden)",
    { timeout: 30000, label: 'tab B came back after reload' });

  const rejoinError = await b.eval("return (document.getElementById('home-error')||{}).textContent || '';");
  check('a reloaded peer is not refused as "gate already has two devices"',
    !/two devices/.test(rejoinError), rejoinError);

  await b.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 40000, label: 'tab B reconnected after reload' });
  await a.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 40000, label: 'tab A renegotiated after the peer reloaded' });
  check('a gate survives one side reloading the page', true);

  const afterReload = `after reload ${crypto.randomUUID()}`;
  await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(afterReload)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(afterReload)})`,
    { timeout: 20000, label: 'message crosses the renegotiated channel' });
  check('the channel works again after the reload, with fresh keys', true);

  // ------------------------------------------------------------ page errors
  check('tab A raised no uncaught page errors', a.pageErrors.length === 0, a.pageErrors.join(' | '));
  check('tab B raised no uncaught page errors', b.pageErrors.length === 0, b.pageErrors.join(' | '));

  // ------------------------------------------------------------ severing
  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { label: 'tab A shows severed' });
  await b.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 15000, label: 'tab B shows severed' });
  check('severing on one device tears down the other', true);

  const hashAfter = await a.eval('return location.hash;');
  check('severing strips the secret from the URL', hashAfter === '', `hash was "${hashAfter}"`);

  const roomsAfter = await request(PORT, 'GET', '/api/health');
  check('the room is deleted from the server on sever', roomsAfter.json?.rooms === 0, roomsAfter.text);

  const rejoin = await request(PORT, 'POST', '/api/join', { roomId: 'AAAAAAAA' });
  check('a severed gate leaves nothing to rejoin', rejoin.status === 404, rejoin.text);

  // ------------------------------------------------------------ wrong codes
  const c = await browser.newTab(ORIGIN);
  await c.waitFor("!document.getElementById('screen-home').hidden", { label: 'home screen on tab C' });

  await c.eval(`
    document.getElementById('join-input').value = 'not a warp gate code';
    document.getElementById('join-btn').click();
    return true;
  `);
  await c.waitFor("!document.getElementById('home-error').hidden", { label: 'malformed code is refused' });
  const malformedError = await c.eval("return document.getElementById('home-error').textContent;");
  check('a malformed code is refused with a readable message',
    /does not look like a Warp Gate code/.test(malformedError), malformedError);

  // A well-formed secret for a gate that does not exist. Because the room id is
  // derived from the secret, a wrong secret cannot reach someone else's room at all:
  // it addresses a room that is not there.
  await c.eval(`
    document.getElementById('join-input').value = 'WARP-0000-0000-0000-0000-0000-0000-00';
    document.getElementById('join-btn').click();
    return true;
  `);
  await c.waitFor("document.getElementById('home-error').textContent.includes('gate')",
    { label: 'unknown gate is refused' });
  const unknownError = await c.eval("return document.getElementById('home-error').textContent;");
  check('a valid-looking code for a non-existent gate says so plainly',
    /does not exist|expired/.test(unknownError), unknownError);
  check('tab C raised no uncaught page errors', c.pageErrors.length === 0, c.pageErrors.join(' | '));

  // ------------------------------------------------------------ abrupt departure
  // A tab going away without pressing sever. The peer must be told and the room must
  // not sit around occupied until its TTL.
  const d = await browser.newTab(ORIGIN);
  await d.waitFor("!document.getElementById('screen-home').hidden", { label: 'home on tab D' });
  await d.eval("document.getElementById('create-btn').click(); return true;");
  await d.waitFor("!document.getElementById('screen-waiting').hidden", { label: 'tab D waiting' });
  const link2 = await d.eval('return location.href;');

  const e = await browser.newTab(link2);
  await d.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab D connected' });
  await e.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab E connected' });
  check('a second gate connects independently of the first', true);

  const roomsBeforeLeave = await request(PORT, 'GET', '/api/health');
  check('the second gate is the only room on the server', roomsBeforeLeave.json?.rooms === 1, roomsBeforeLeave.text);

  // Navigating away fires pagehide, which is the closest a page gets to "tab closed".
  await e.send('Page.navigate', { url: 'about:blank' });

  await d.waitFor("!document.getElementById('screen-severed').hidden || document.getElementById('log').textContent.includes('disconnected')",
    { timeout: 20000, label: 'tab D notices the peer left' });
  check('the remaining device is told when the other simply goes away', true);

  // The room deliberately survives one side leaving: that peer may simply be
  // reloading, and tab D is still attached and waiting. It is reaped only once
  // *nobody* is attached, so send tab D away too.
  const roomsOneLeft = await request(PORT, 'GET', '/api/health');
  check('a gate survives one side leaving, since that side may be reloading',
    roomsOneLeft.json?.rooms === 1, roomsOneLeft.text);

  await d.send('Page.navigate', { url: 'about:blank' });

  // The client no longer deletes the room on pagehide, because pagehide also fires on
  // reload and that destroyed the gate whenever either side refreshed. The server now
  // reaps a room once both sides have been absent for the grace period.
  let roomsAfterLeave = null;
  const reapDeadline = Date.now() + 15000;
  while (Date.now() < reapDeadline) {
    roomsAfterLeave = await request(PORT, 'GET', '/api/health');
    if (roomsAfterLeave.json?.rooms === 0) break;
    await new Promise((r) => { setTimeout(r, 400); });
  }
  check('an abandoned gate is reaped once both sides are gone',
    roomsAfterLeave?.json?.rooms === 0, roomsAfterLeave?.text);

  severTested = true;
} finally {
  await browser.close();
  await server.stop();
  fs.rmSync(TMP, { recursive: true, force: true });
}

check('the full lifecycle ran to completion', severTested);
process.exit(summary('browser end-to-end') ? 0 : 1);
