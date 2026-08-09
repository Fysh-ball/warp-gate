// Multi-participant gates, in real browsers.
//
// A gate is a full mesh: every PAIR runs its own RTCPeerConnection, its own ECDH and its
// own Channel with its own replay counters. Node cannot exercise any of that, so this
// drives three tabs of a headless Chromium-based browser through the actual UI and asserts
// against what the pages really do.
//
// What is proved here, and why each one needs proving:
//   - all three links come up, and each pair derives its OWN verification code
//   - one message reaches BOTH other participants
//   - one file arrives byte-identical at BOTH, hashed rather than counted
//   - the cap refuses the participant past the limit and costs the seated ones nothing
//   - one participant leaving leaves the remaining link working
//   - each pair's replay counter is its own: a frame replayed from one peer is refused,
//     and the other link carries on with a counter that was never touched
//
// Run: node tests/mesh.test.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, summary, startServer, request } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';

const PORT = 3800;
const STUN = 3801;
const CDP_PORT = 9800;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-mesh-'));

// Three, not six, so the ceiling is reachable inside one test run. The mesh code does not
// know the number: it connects to whoever the roster names.
const CAP = 3;

/**
 * Instrumentation injected into a tab BEFORE the app loads.
 *
 * Two hooks, both of which observe rather than change behaviour:
 *
 *  1. Every RTCDataChannel this page opens or accepts is recorded, along with the last
 *     frame it received and a sequence number. That is what lets the replay test take a
 *     real sealed frame off one specific link and hand it back to the page. There is no
 *     other way in: the frame is decrypted inside Channel.open, and the whole point is to
 *     replay the ciphertext exactly as it arrived rather than a reconstruction of it.
 *
 *  2. URL.createObjectURL keeps a reference to every Blob it is given, so a received file
 *     can be hashed. saveBlob() is what calls it, so pressing Save on a finished transfer
 *     is what puts the received bytes within reach. Counting bytes would not do: a
 *     transfer can be the right length and still be wrong.
 *
 *  3. Everything this page ever sends, at three layers, so "the display name is never
 *     transmitted" can be checked rather than asserted:
 *       __plain  the PLAINTEXT handed to crypto.subtle.encrypt. This is the layer that
 *                matters. Searching the ciphertext for a name would pass on any build,
 *                including one that puts the name straight into a chat frame, because
 *                AES-GCM hides everything equally well. Both senders go through here: the
 *                signalling envelope and every sealed data-channel frame.
 *       __wire   the bytes actually written to an RTCDataChannel, in case something ever
 *                sends a frame without sealing it first.
 *       __posts  the bodies of every fetch, which is how a relayed envelope leaves the
 *                page, in case something ever relays outside the envelope.
 *     All three are captured before the app's own module ever runs, so nothing can be
 *     sent behind them.
 */
const PROBE = `
  window.__seq = 0;
  window.__chans = [];
  window.__blobs = [];
  window.__plain = [];
  window.__wire = [];
  window.__posts = [];

  // latin1 maps every byte to a character, so a substring search over binary is exact for
  // the ASCII names being looked for and never throws on a byte that is not valid UTF-8.
  const asText = (data) => {
    if (typeof data === 'string') return data;
    if (data === null || data === undefined) return '';
    if (ArrayBuffer.isView(data)) {
      return new TextDecoder('latin1').decode(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
    }
    if (data instanceof ArrayBuffer) return new TextDecoder('latin1').decode(new Uint8Array(data));
    return String(data);
  };

  const realEncrypt = crypto.subtle.encrypt;
  crypto.subtle.encrypt = function (algorithm, key, data) {
    try { window.__plain.push(asText(data)); } catch (err) { window.__plain.push('<uncaptured: ' + err.message + '>'); }
    return realEncrypt.call(this, algorithm, key, data);
  };

  const realDcSend = RTCDataChannel.prototype.send;
  RTCDataChannel.prototype.send = function (data) {
    try { window.__wire.push(asText(data)); } catch (err) { window.__wire.push('<uncaptured: ' + err.message + '>'); }
    return realDcSend.call(this, data);
  };

  const realFetch = window.fetch;
  window.fetch = function (input, init) {
    try { if (init && init.body !== undefined) window.__posts.push(asText(init.body)); }
    catch (err) { window.__posts.push('<uncaptured: ' + err.message + '>'); }
    return realFetch.call(this, input, init);
  };

  const watch = (ch) => {
    if (!ch || typeof ch.addEventListener !== 'function' || ch.__watched) return ch;
    ch.__watched = true;
    ch.__lastIn = null;
    ch.__seq = 0;
    ch.__count = 0;
    ch.addEventListener('message', (event) => {
      ch.__lastIn = event.data;
      ch.__count += 1;
      ch.__seq = ++window.__seq;
    });
    window.__chans.push(ch);
    return ch;
  };

  const realCreate = RTCPeerConnection.prototype.createDataChannel;
  RTCPeerConnection.prototype.createDataChannel = function (...args) {
    return watch(realCreate.apply(this, args));
  };
  const realAdd = RTCPeerConnection.prototype.addEventListener;
  RTCPeerConnection.prototype.addEventListener = function (name, cb, ...rest) {
    if (name === 'datachannel' && typeof cb === 'function') {
      return realAdd.call(this, name, (event) => { watch(event.channel); cb(event); }, ...rest);
    }
    return realAdd.call(this, name, cb, ...rest);
  };

  const realUrl = URL.createObjectURL.bind(URL);
  URL.createObjectURL = (blob) => { window.__blobs.push(blob); return realUrl(blob); };
`;

/** Open a tab with the probe installed, then navigate it. */
async function probedTab(browser, url) {
  const tab = await browser.newTab('about:blank');
  await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: PROBE });
  await tab.send('Page.navigate', { url });
  await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: `${url} loaded` });
  return tab;
}

const send = (tab, text) => tab.eval(`
  document.getElementById('chat-input').value = ${JSON.stringify(text)};
  document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
  return true;
`);

const occurrences = (tab, text) => tab.eval(`
  const t = document.getElementById('messages').textContent;
  return t.split(${JSON.stringify(text)}).length - 1;
`);

/**
 * Who this tab thinks is in the gate: slot id -> the name it DISPLAYS for that slot.
 *
 * Read out of the roster the user actually sees. Reading it out of session state would
 * make "every tab shows the same name" true by construction on any build that shares an
 * object, and these three tabs share nothing but a room secret.
 */
const namesOf = async (tab) => JSON.parse(await tab.eval(`
  const out = { self: null, names: {} };
  for (const chip of document.querySelectorAll('#roster .who-chip')) {
    const slot = (chip.title.match(/^slot ([^,]+)/) || [])[1];
    const name = (chip.querySelector('.who-name') || {}).textContent || '';
    if (!slot || !name) continue;
    out.names[slot] = name;
    if (chip.classList.contains('self')) out.self = slot;
  }
  return JSON.stringify(out);
`));

/**
 * Look for a set of strings in everything this page has ever sent.
 *
 * Returns the counters as well as the hits, and the caller asserts on BOTH. A leak check
 * over three empty arrays finds nothing and reports a pass, which is exactly the shape of
 * check that reads green when the probe itself is broken.
 */
const leakScan = async (tab, needles) => JSON.parse(await tab.eval(`
  const needles = ${JSON.stringify(needles)};
  const hits = [];
  const scan = (arr, where) => {
    for (const item of arr) {
      for (const needle of needles) if (item.includes(needle)) hits.push(where + ': ' + needle);
    }
  };
  scan(window.__plain, 'plaintext handed to encrypt');
  scan(window.__wire, 'data channel frame');
  scan(window.__posts, 'relayed request body');
  return JSON.stringify({
    plain: window.__plain.length, wire: window.__wire.length, posts: window.__posts.length,
    hits,
  });
`));

/** SHA-256 of the newest captured Blob, computed inside the page. */
const hashNewestBlob = (tab) => tab.eval(`
  const blob = window.__blobs[window.__blobs.length - 1];
  if (!blob) return null;
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return { size: bytes.length,
           hash: [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('') };
`);

if (!findBrowser()) {
  process.stdout.write('BAD  no Chromium-based browser available for end-to-end testing\n');
  process.exit(1);
}

const server = await startServer({
  WG_HTTP_PORT: String(PORT),
  WG_STUN_PORT: String(STUN),
  WG_STUN_URL: `stun:127.0.0.1:${STUN}`,
  WG_MAX_PARTICIPANTS: String(CAP),
  WG_CREATE_PER_WINDOW: '200',
  WG_JOIN_PER_WINDOW: '200',
  WG_REJECT_PER_WINDOW: '500',
  WG_PUBLIC_GET_PER_WINDOW: '500',
  // Four tabs from one address, and a reload puts a second stream up before the first is
  // reaped. The production default of four would refuse a tab for reasons that have
  // nothing to do with what is being measured here.
  WG_STREAMS_PER_KEY: '30',
  WG_EMPTY_GRACE_MS: '2500',
  WG_SWEEP_MS: '400',
});

const cfg = await request(PORT, 'GET', '/api/config');
check('the server under test really is configured for a mesh',
  cfg.json?.maxParticipants === CAP, cfg.text);

const browser = await launchBrowser({ port: CDP_PORT });
check('headless browser launched', Boolean(browser.version), browser.version);

let ranToCompletion = false;

try {
  // ------------------------------------------------------------ tab A opens the gate
  const a = await probedTab(browser, ORIGIN);
  await a.waitFor("[...document.querySelectorAll('section.screen')].some((s) => !s.hidden)",
    { label: 'tab A loaded' });
  // First visit in this profile: accept the terms once, then every later tab skips it.
  await a.eval(`
    const c = document.getElementById('agree-check');
    if (c && !document.getElementById('screen-onboarding').hidden) {
      c.checked = true;
      c.dispatchEvent(new Event('change', { bubbles: true }));
      document.getElementById('onboarding-done').click();
    }
    return true;
  `);
  await a.waitFor("!document.getElementById('screen-home').hidden", { label: 'tab A home screen' });

  const capNote = await a.eval("return (document.getElementById('cap-note') || {}).textContent || '';");
  check('the page states the seat count the server actually enforces',
    capNote.includes(String(CAP)), capNote);

  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { label: 'tab A waiting' });
  await a.eval("document.getElementById('reveal-share').click(); return true;");
  await a.waitFor("document.getElementById('share-shown').hidden === false", { label: 'tab A share revealed' });
  const code = await a.eval("return document.getElementById('room-code').textContent.trim();");
  const link = `${ORIGIN}/#${code}`;
  check('tab A produced a gate code', /^WARP-/.test(code), code);

  // ------------------------------------------------------------ B and C join
  const b = await probedTab(browser, link);
  const c = await probedTab(browser, link);

  const connected = "!document.getElementById('screen-connected').hidden";
  await a.waitFor(connected, { timeout: 30000, label: 'tab A connected' });
  await b.waitFor(connected, { timeout: 30000, label: 'tab B connected' });
  await c.waitFor(connected, { timeout: 30000, label: 'tab C connected' });

  // "Connected" as a screen only says one link came up. In a mesh of three each tab must
  // hold TWO live links, which is what the roster counts, and each pair must have derived
  // its own verification code: a single code shared across the room would mean a group key,
  // which is exactly the design that was rejected.
  const rosterOf = (tab) => tab.eval(`
    const chips = [...document.querySelectorAll('#roster .who-chip')].filter((x) => !x.classList.contains('self'));
    return JSON.stringify({
      peers: chips.length,
      live: chips.filter((x) => x.classList.contains('live')).length,
      text: chips.map((x) => x.textContent),
    });
  `);
  for (const [name, tab] of [['A', a], ['B', b], ['C', c]]) {
    await tab.waitFor("[...document.querySelectorAll('#roster .who-chip.live')].length === 2",
      { timeout: 30000, label: `tab ${name} has two live links` });
    const r = JSON.parse(await rosterOf(tab));
    check(`tab ${name} holds a live link to each of the other two`,
      r.peers === 2 && r.live === 2, await rosterOf(tab));
  }

  // Each pair derives its own five-digit code, and the three pairs are not all the same.
  const codesOf = (tab) => tab.eval(`
    return JSON.stringify([...document.querySelectorAll('#roster .who-chip')]
      .filter((x) => !x.classList.contains('self'))
      .map((x) => (x.textContent.match(/\\b[0-9]{5}\\b/) || [null])[0]));
  `);
  const sasA = JSON.parse(await codesOf(a));
  const sasB = JSON.parse(await codesOf(b));
  const sasC = JSON.parse(await codesOf(c));
  check('every link shows a five digit verification code of its own',
    [...sasA, ...sasB, ...sasC].every((s) => /^[0-9]{5}$/.test(s ?? '')),
    JSON.stringify({ sasA, sasB, sasC }));
  check('the three pairs did NOT all derive the same code, so the keys are pairwise',
    new Set([...sasA, ...sasB, ...sasC]).size === 3,
    JSON.stringify({ sasA, sasB, sasC }));
  // ...and the two ends of one pair agree. Three pairs, each seen from both sides: the
  // multiset of six codes must be exactly the three pair codes, twice each.
  const counts = {};
  for (const s of [...sasA, ...sasB, ...sasC]) counts[s] = (counts[s] ?? 0) + 1;
  check('and both ends of each pair agree on theirs',
    Object.values(counts).every((n) => n === 2) && Object.keys(counts).length === 3,
    JSON.stringify(counts));

  // ------------------------------------------------------------ display names
  //
  // The one property the whole derivation exists for, and the one a mesh can break in a
  // way two parties cannot: every participant must compute the SAME name for a given
  // slot, itself included. Names come from HKDF(S, "wg/v1/name" || slotId), and all three
  // tabs hold S and see the same roster of slot ids, so all three must agree.
  //
  // This is what rules out the obvious derivation. Hashing the peer's ephemeral public key
  // is per-PAIR: A's key toward B is not A's key toward C, so B and C would print two
  // different names for A and this block would fail on the first tab it compared.
  for (const [name, tab] of [['A', a], ['B', b], ['C', c]]) {
    // The predicate insists on the SHAPE of a name, not merely on three pills existing:
    // the seat letter is the placeholder before a name lands, and waiting for "three pills"
    // would sample the roster mid-derivation and then fail on the shape a line later.
    await tab.waitFor(`[...document.querySelectorAll('#roster .who-chip .who-name')]
      .filter((x) => /^[A-Z][a-z]+ [A-Z][a-z]+/.test(x.textContent)).length === 3`,
    { timeout: 30000, label: `tab ${name} named all three participants` });
  }
  const seenBy = { A: await namesOf(a), B: await namesOf(b), C: await namesOf(c) };
  const slots = Object.keys(seenBy.A.names).sort();

  check('each tab names all three participants, itself included',
    Object.values(seenBy).every((r) => Object.keys(r.names).length === 3),
    JSON.stringify(seenBy));
  check('all three tabs are talking about the same three slots',
    Object.values(seenBy).every((r) => JSON.stringify(Object.keys(r.names).sort()) === JSON.stringify(slots)),
    JSON.stringify(Object.values(seenBy).map((r) => Object.keys(r.names).sort())));

  const disagreements = [];
  for (const slot of slots) {
    const values = new Set(Object.values(seenBy).map((r) => r.names[slot]));
    if (values.size !== 1) disagreements.push(`${slot}: ${[...values].join(' / ')}`);
  }
  check('every tab derives the SAME name for the same participant',
    disagreements.length === 0, disagreements.join(' | '));

  const meshNames = slots.map((slot) => seenBy.A.names[slot]);
  check('the three participants have three different names',
    new Set(meshNames).size === 3, JSON.stringify(meshNames));
  check('every name is two calm words, bounded in length',
    meshNames.every((n) => /^[A-Z][a-z]+ [A-Z][a-z]+( [0-9A-HJKMNP-TV-Z]+)?$/.test(n) && n.length <= 32),
    JSON.stringify(meshNames));
  check('each tab knows which of the three names is its own',
    new Set([seenBy.A.self, seenBy.B.self, seenBy.C.self]).size === 3
    && [seenBy.A, seenBy.B, seenBy.C].every((r) => slots.includes(r.self)),
    JSON.stringify([seenBy.A.self, seenBy.B.self, seenBy.C.self]));
  check('and marks it as itself rather than leaving it unnamed',
    (await a.eval("return document.querySelector('#roster .who-chip.self').textContent;"))
      === `${seenBy.A.names[seenBy.A.self]} (you)`,
    await a.eval("return document.querySelector('#roster .who-chip.self').textContent;"));

  // ------------------------------------------------------------ one message, two readers
  const broadcast = `hello everyone ${crypto.randomUUID()}`;
  await send(a, broadcast);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(broadcast)})`,
    { timeout: 20000, label: 'the message reached tab B' });
  await c.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(broadcast)})`,
    { timeout: 20000, label: 'the message reached tab C' });
  check('one message from one participant reached both of the others exactly once',
    (await occurrences(b, broadcast)) === 1 && (await occurrences(c, broadcast)) === 1,
    `B ${await occurrences(b, broadcast)}, C ${await occurrences(c, broadcast)}`);

  // Each recipient is told WHICH participant it came from, by name, rather than an
  // anonymous "them" that names nobody in a room of three. The row and the roster have to
  // agree: two places naming the same person differently is worse than one place naming
  // nobody, and it is what a per-link derivation would produce here.
  const rowLabel = (tab, text) => tab.eval(`
    const row = [...document.querySelectorAll('#messages .msg')]
      .find((m) => m.textContent.includes(${JSON.stringify(text)}));
    return row ? (row.querySelector('.who') || {}).textContent || '' : '';
  `);
  const labelledB = await rowLabel(b, broadcast);
  const labelledC = await rowLabel(c, broadcast);
  check('a received message is labelled with the sender\'s name',
    labelledB === seenBy.B.names[seenBy.A.self],
    `row says ${JSON.stringify(labelledB)}, roster says ${JSON.stringify(seenBy.B.names[seenBy.A.self])}`);
  check('and both recipients label it with the same name, which is the sender\'s own',
    labelledB === labelledC && labelledB === seenBy.A.names[seenBy.A.self],
    `B ${JSON.stringify(labelledB)}, C ${JSON.stringify(labelledC)}, sender calls itself `
    + JSON.stringify(seenBy.A.names[seenBy.A.self]));
  check('the sender\'s own copy still reads "you"',
    (await rowLabel(a, broadcast)) === 'you', await rowLabel(a, broadcast));

  // ------------------------------------------------------------ one file, two readers
  const filePath = path.join(TMP, 'payload.bin');
  const payload = crypto.randomBytes(300 * 1024); // spans many chunks on every link
  fs.writeFileSync(filePath, payload);
  const digest = crypto.createHash('sha256').update(payload).digest('hex');

  await a.setFileInput('#file-input', [filePath]);
  const saved = "[...document.querySelectorAll('#messages button')].some((x) => x.textContent === 'Save')";
  await b.waitFor(saved, { timeout: 60000, label: 'tab B finished receiving the file' });
  await c.waitFor(saved, { timeout: 60000, label: 'tab C finished receiving the file' });

  // Hash it. A length check would pass on a file that is the right size and wrong content,
  // which is precisely the failure a mesh could introduce by crossing two peers' streams.
  const pressSave = (tab) => tab.eval(`
    const btn = [...document.querySelectorAll('#messages button')].find((x) => x.textContent === 'Save');
    if (!btn) return false;
    btn.click();
    return true;
  `);
  for (const [name, tab] of [['B', b], ['C', c]]) {
    check(`tab ${name} offers the received file for saving`, (await pressSave(tab)) === true);
    const got = await hashNewestBlob(tab);
    check(`the file arrived at tab ${name} byte-identical to what tab A sent`,
      got?.hash === digest && got?.size === payload.length,
      `${got?.size} bytes, sha256 ${got?.hash} vs ${digest}`);
  }
  // The negative control for the hash itself: the same computation over different bytes
  // must NOT match, or "identical" is a claim about a check that always says yes.
  const wrong = await b.eval(`
    const bytes = new Uint8Array([1, 2, 3]);
    const d = await crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
  `);
  check('the in-page hash distinguishes different bytes, so a match means something',
    wrong !== digest, `${wrong} vs ${digest}`);

  // ------------------------------------------------------------ the cap
  const d = await probedTab(browser, link);
  await d.waitFor("!document.getElementById('home-error').hidden",
    { timeout: 30000, label: 'the fourth device is refused' });
  const refusal = await d.eval("return document.getElementById('home-error').textContent;");
  check('the participant past the cap is refused, and told why',
    /full/i.test(refusal) && refusal.includes(String(CAP)), refusal);
  const dState = await d.eval(`
    return JSON.stringify({
      screens: [...document.querySelectorAll('section.screen')].filter((s) => !s.hidden).map((s) => s.id),
      slots: Object.keys(sessionStorage).filter((k) => k.startsWith('wg.slot.')),
    });
  `);
  check('and takes no slot on the way out',
    JSON.parse(dState).slots.length === 0 && JSON.parse(dState).screens.includes('screen-home'), dState);

  // The half that is easy to skip: the refusal must cost the seated participants nothing.
  const afterRefusal = `still working ${crypto.randomUUID()}`;
  await send(a, afterRefusal);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(afterRefusal)})`,
    { timeout: 20000, label: 'tab B unaffected by the refused joiner' });
  await c.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(afterRefusal)})`,
    { timeout: 20000, label: 'tab C unaffected by the refused joiner' });
  check('the three seated participants are unaffected by the refusal',
    (await occurrences(b, afterRefusal)) === 1 && (await occurrences(c, afterRefusal)) === 1);

  // ------------------------------------------------------------ independent replay counters
  //
  // Two claims, and they fail in different ways. A frame replayed from ONE peer must be
  // refused; and the OTHER peer's link must be untouched by it, which is only true if each
  // pair keeps its own counter. Raising B's counter well above C's first is what makes the
  // second claim testable: with one shared counter, C's next frame would be behind it and
  // would be dropped.
  for (let i = 0; i < 5; i += 1) {
    await send(b, `filler ${i}`);
    await a.waitFor(`document.getElementById('messages').textContent.includes('filler ${i}')`,
      { timeout: 20000, label: `filler ${i} reached tab A` });
  }

  const marker = `replay me ${crypto.randomUUID()}`;
  await send(b, marker);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(marker)})`,
    { timeout: 20000, label: 'the frame to be replayed reached tab A' });

  const before = await a.eval("return document.getElementById('log').textContent;");
  check('no frame had been rejected at tab A before the replay',
    !/frame rejected/.test(before), before.slice(-200));

  // Hand the page back the exact ciphertext it just accepted, on the exact channel it
  // arrived on. The newest-used channel is B's, because B is what just sent.
  const replayed = await a.eval(`
    const chans = window.__chans.filter((ch) => ch.__lastIn);
    if (chans.length < 2) return { error: 'expected two watched channels, saw ' + chans.length };
    chans.sort((x, y) => y.__seq - x.__seq);
    const fromB = chans[0];
    fromB.dispatchEvent(new MessageEvent('message', { data: fromB.__lastIn }));
    return { channels: chans.length };
  `);
  check('the replay probe found both of this tab links', replayed?.channels === 2, JSON.stringify(replayed));

  await a.waitFor("document.getElementById('log').textContent.includes('frame rejected')",
    { timeout: 15000, label: 'tab A refused the replayed frame' });
  const rejection = await a.eval("return document.getElementById('log').textContent;");
  check('the replayed frame is refused as a replay, not decrypted again',
    /frame rejected: replay or reorder/.test(rejection), rejection.slice(-240));
  check('and it was NOT rendered a second time',
    (await occurrences(a, marker)) === 1, `rendered ${await occurrences(a, marker)} times`);

  // The other link must be completely untouched. C's counter is far behind B's, so if the
  // two pairs shared one, this message would be refused as a replay too.
  const fromC = `untouched ${crypto.randomUUID()}`;
  await send(c, fromC);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(fromC)})`,
    { timeout: 20000, label: 'the other link still delivers after the replay' });
  check('the other pair counter was not disturbed by the replay',
    (await occurrences(a, fromC)) === 1);

  // And B's own link still works: a rejected replay never advanced its counter either.
  const afterReplay = `b still here ${crypto.randomUUID()}`;
  await send(b, afterReplay);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(afterReplay)})`,
    { timeout: 20000, label: 'the replayed-from link still delivers' });
  check('the link the replay came from still works', (await occurrences(a, afterReplay)) === 1);

  // ------------------------------------------------------------ one participant leaves
  await c.send('Page.navigate', { url: 'about:blank' });
  // The server holds a departure for a grace period first, because a reload puts the
  // stream straight back and a reload is not a departure.
  await a.waitFor("document.getElementById('log').textContent.includes('disconnected')",
    { timeout: 30000, label: 'tab A is told the third participant left' });
  await b.waitFor("document.getElementById('log').textContent.includes('disconnected')",
    { timeout: 30000, label: 'tab B is told the third participant left' });

  const stillConnected = await Promise.all([a, b].map((tab) => tab.eval(`
    return JSON.stringify({
      screens: [...document.querySelectorAll('section.screen')].filter((s) => !s.hidden).map((s) => s.id),
      live: [...document.querySelectorAll('#roster .who-chip.live')].length,
    });
  `)));
  check('the remaining participants stay on the connected screen',
    stillConnected.every((s) => JSON.parse(s).screens.includes('screen-connected')),
    stillConnected.join(' | '));
  check('and each still shows exactly one live link, to the other',
    stillConnected.every((s) => JSON.parse(s).live === 1), stillConnected.join(' | '));

  const afterDeparture = `just us now ${crypto.randomUUID()}`;
  await send(a, afterDeparture);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(afterDeparture)})`,
    { timeout: 20000, label: 'the remaining pair can still exchange a message' });
  check('one participant leaving does not disturb the others',
    (await occurrences(b, afterDeparture)) === 1);
  const backwards = `and back ${crypto.randomUUID()}`;
  await send(b, backwards);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(backwards)})`,
    { timeout: 20000, label: 'the remaining pair still works in the other direction' });
  check('the remaining link works in both directions', (await occurrences(a, backwards)) === 1);

  // A name lasts as long as the gate does. Everything above happened between reading the
  // roster and reading it again: three links came up, a file crossed both of them, a frame
  // was replayed and refused, a joiner was turned away at the cap and a participant left.
  // None of that is an input to HKDF(S, "wg/v1/name" || slotId), so none of it may move a
  // name. The two who stayed must still be called exactly what they were called.
  const namesLater = await namesOf(a);
  const stayed = slots.filter((slot) => slot !== seenBy.C.self);
  check('a name is stable for the life of the gate, including when somebody leaves',
    stayed.length === 2 && stayed.every((slot) => namesLater.names[slot] === seenBy.A.names[slot]),
    `${JSON.stringify(namesLater.names)} vs ${JSON.stringify(seenBy.A.names)}`);

  // ------------------------------------------------------------ names are never sent
  //
  // The name is DERIVED on both sides, never transmitted, and that is the whole reason a
  // peer cannot choose or forge one. Proving it needs the plaintext layer: searching the
  // ciphertext would pass on any build at all, including one that puts the name straight
  // into a chat frame, because AES-GCM conceals a leak exactly as well as it conceals a
  // message. window.__plain holds what was handed to crypto.subtle.encrypt, which is every
  // signalling envelope and every sealed data-channel frame this page produced.
  //
  // Spacing and case are searched for too, so a name smuggled through as "AmberMeadow" or
  // "amber meadow" would still be caught.
  const nameNeedles = meshNames.flatMap((n) => [
    n, n.toLowerCase(), n.replace(/ /g, ''), n.replace(/ /g, '').toLowerCase(),
  ]);
  for (const [name, tab] of [['A', a], ['B', b]]) {
    const scan = await leakScan(tab, nameNeedles);
    // Without this the assertion below is satisfied by a probe that captured nothing, which
    // is what a leak check looks like when it is broken rather than when it is passing.
    check(`tab ${name}'s probe captured traffic at all three layers to search`,
      scan.plain > 0 && scan.wire > 0 && scan.posts > 0,
      `plaintexts ${scan.plain}, frames ${scan.wire}, request bodies ${scan.posts}`);
    check(`no participant's name appears in anything tab ${name} sent`,
      scan.hits.length === 0, scan.hits.join(' | '));
  }
  // The control for the two lines above: the same search over the same captures DOES find
  // a string that really was transmitted. So "no hits" is a fact about the names and not
  // about a search that never matches anything.
  const control = await leakScan(a, [broadcast]);
  check('the same search finds a string that WAS sent, so a leak would have been found',
    control.hits.length > 0, JSON.stringify(control.hits).slice(0, 200));

  // ------------------------------------------------------------ nothing threw
  check('tab A raised no uncaught page errors', a.pageErrors.length === 0, a.pageErrors.join(' | '));
  check('tab B raised no uncaught page errors', b.pageErrors.length === 0, b.pageErrors.join(' | '));

  // ------------------------------------------------------------ severing tells everybody
  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { label: 'tab A severed' });
  await b.waitFor("!document.getElementById('screen-severed').hidden",
    { timeout: 20000, label: 'tab B was told the gate was burned' });
  check('severing ends the gate for every participant', true);

  check('the server wrote nothing to stderr', server.stderr() === '', server.stderr().slice(0, 400));
  ranToCompletion = true;
} finally {
  await browser.close();
  await server.stop();
  fs.rmSync(TMP, { recursive: true, force: true });
}

check('the whole mesh lifecycle ran to completion', ranToCompletion);
process.exit(summary('mesh end-to-end') ? 0 : 1);
