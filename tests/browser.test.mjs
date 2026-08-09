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
import { check, summary, startServer, request, makeJoinProof } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';
import { parseSecret, deriveRoomId, deriveJoinProof } from '../public/js/crypto.js';
import {
  deriveDisplayName, deriveNameSeed, nameFromSeed, resolveDisplayNames, NAME_SPACE,
} from '../public/js/session.js';

const PORT = 3785;
const STUN = 3786;
const CDP_PORT = 9762;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-e2e-'));

/**
 * Ask the server directly about one specific room, without any live occupancy gauge.
 *
 * /api/health used to report a room count and six assertions in this file leaned on it.
 * It reports liveness and nothing else now, and it should: a live count of open gates is
 * an attack progress meter on a tool whose premise is that the server learns nothing.
 *
 * These two probes read the only room facts the server still discloses, and each is
 * about ONE id rather than a global total:
 *   held  - a create for that id is refused as room_exists, so the id is in the map.
 *   gone  - a join for that id, presenting the correct proof, is refused as no_room.
 * `no_room` is decided before the join proof is examined, so it means "not in the map"
 * and not "your proof was wrong".
 */
async function roomHeld(roomId) {
  const r = await request(PORT, 'POST', '/api/create', {
    roomId, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
  });
  return { held: r.status === 409 && r.json?.error === 'room_exists', status: r.status, body: r.text };
}

async function roomGone(roomId, secret) {
  const joinProof = secret ? await deriveJoinProof(secret) : makeJoinProof().proof;
  const r = await request(PORT, 'POST', '/api/join', { roomId, joinProof });
  return { gone: r.status === 404 && r.json?.error === 'no_room', status: r.status, body: r.text };
}

/**
 * What one tab believes about who is in the gate.
 *
 * Read out of the roster the user actually sees, not out of any internal state: the claim
 * being tested is that two devices DISPLAY the same names, and a shared object read twice
 * would be true by construction. The slot id comes from the pill's title, which is where
 * the page puts routing information, and the name from its own element, so a verification
 * code sharing the pill cannot be mistaken for part of the name.
 */
const rosterOf = async (tab) => JSON.parse(await tab.eval(`
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

const NAME_SHAPE = /^[A-Z][a-z]+ [A-Z][a-z]+( [0-9A-HJKMNP-TV-Z]+)?$/;

// Order-independent, because the roster lists this device first and the two tabs are
// therefore never in the same order. Comparing the objects as written would report a
// disagreement between two tabs that agree perfectly, which is a failing test that says
// nothing about the product.
const canonicalNames = (names) => JSON.stringify(Object.keys(names).sort().map((k) => [k, names[k]]));

// Wait for a roster where `count` pills carry something SHAPED like a name. The seat letter
// is the placeholder while the derivation is in flight, so a predicate that only counted
// pills would sample the roster mid-derivation and fail on the shape one line later.
const NAMED_ROSTER = (count) => `[...document.querySelectorAll('#roster .who-chip .who-name')]
  .filter((x) => /^[A-Z][a-z]+ [A-Z][a-z]+/.test(x.textContent)).length === ${count}`;

/** The room id a gate code addresses, recomputed here rather than read off the page. */
async function roomIdFor(code) {
  const secret = parseSecret(code);
  if (!secret) throw new Error(`the page produced a gate code this test cannot parse: ${code}`);
  return { secret, roomId: await deriveRoomId(secret) };
}

// ---------------------------------------------------------------- display names
//
// The derivation itself, before any browser is involved. It is the same module the page
// loads, so these assert the shipped code and not a restatement of it.
//
//     name_seed = HKDF(S, "wg/v1/name" || slotId)
//
// Fixed secrets and fixed slot ids, so every assertion below is deterministic. Random
// fixtures would make the "these all differ" claims flaky at roughly one run in a
// thousand, and a test that fails once in a thousand runs gets ignored the one time it
// means something.
{
  const S1 = new Uint8Array(16).fill(0x11);
  const S2 = new Uint8Array(16).fill(0x22);
  const SLOTS = ['aaaaaaaa', 'bbbbbbbb', 'cccccccc', 'dddddddd', 'eeeeeeee', 'ffffffff'];

  const under1 = [];
  const under2 = [];
  for (const slot of SLOTS) {
    under1.push(await deriveDisplayName(S1, slot));
    under2.push(await deriveDisplayName(S2, slot));
  }

  check('the vocabulary is at least a few thousand pairings',
    NAME_SPACE === 8192, `NAME_SPACE is ${NAME_SPACE}`);

  check('a name is two title-cased words and nothing else',
    under1.every((n) => /^[A-Z][a-z]+ [A-Z][a-z]+$/.test(n)), JSON.stringify(under1));
  check('and is bounded well under what the renderer will accept',
    under1.concat(under2).every((n) => n.length <= 32), JSON.stringify(under1.concat(under2)));

  const again = await deriveDisplayName(S1, SLOTS[0]);
  check('the same secret and the same slot always give the same name',
    again === under1[0], `${again} vs ${under1[0]}`);

  check('different slots in one gate get different names',
    new Set(under1).size === SLOTS.length, JSON.stringify(under1));

  // THE reason the room secret is mixed in. Without it the input is the slot id alone,
  // which the SERVER chooses: it could grind ids until a participant's name came out
  // abusive. With S in the derivation the same slot id under a different secret is an
  // unrelated name, so the server cannot aim at anything. A derivation that ignored S
  // would produce identical lists here and fail on this line.
  check('the room secret decides the name, so the server cannot grind slot ids for one',
    SLOTS.every((_, i) => under1[i] !== under2[i]),
    `${JSON.stringify(under1)} vs ${JSON.stringify(under2)}`);
  check('and a new gate renames everybody, so a name is no cross-gate identifier',
    under1.every((n) => !under2.includes(n)),
    `${JSON.stringify(under1)} vs ${JSON.stringify(under2)}`);

  const seed = await deriveNameSeed(S1, SLOTS[0]);
  check('the seed is the full 128 bits the derivation asks for',
    seed instanceof Uint8Array && seed.length === 16, `${seed?.length} bytes`);

  // A secret of the wrong length must throw rather than name anybody: every other
  // derivation in this app fails closed on that and this one is not the exception.
  let rejected = '';
  try {
    await deriveNameSeed(new Uint8Array(8), SLOTS[0]);
  } catch (err) {
    rejected = err.message;
  }
  check('a wrong-length room secret is refused instead of naming somebody',
    /room secret/.test(rejected), rejected || 'it returned a name');

  // Collision handling. Two seeds crafted to select the same adjective and the same noun:
  // 0x45 & 63 === 0x05 & 63 and 0x8a & 127 === 0x0a & 127.
  const seedA = Uint8Array.from([0x05, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  const seedB = Uint8Array.from([0x45, 0x8a, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
  // The positive control: these really do collide before resolution, so the assertion
  // below is about the resolver and not about two seeds that were never going to clash.
  check('the collision fixture really does collide before it is resolved',
    nameFromSeed(seedA) === nameFromSeed(seedB), `${nameFromSeed(seedA)} / ${nameFromSeed(seedB)}`);

  const forward = resolveDisplayNames([['one', seedA], ['two', seedB]]);
  const backward = resolveDisplayNames([['two', seedB], ['one', seedA]]);
  check('a collision is resolved into two distinct names',
    forward.get('one') !== forward.get('two'),
    `${forward.get('one')} / ${forward.get('two')}`);
  check('by a distinguishing character taken from each seed, not by picking at random',
    /^[A-Z][a-z]+ [A-Z][a-z]+ [0-9A-HJKMNP-TV-Z]$/.test(forward.get('one'))
    && /^[A-Z][a-z]+ [A-Z][a-z]+ [0-9A-HJKMNP-TV-Z]$/.test(forward.get('two')),
    `${forward.get('one')} / ${forward.get('two')}`);
  // The property that makes the resolution safe in a mesh: two devices learn the roster in
  // whatever order the server sends it, and must still print the same thing.
  check('and the resolution does not depend on the order the roster arrived in',
    forward.get('one') === backward.get('one') && forward.get('two') === backward.get('two'),
    `${forward.get('one')}/${backward.get('one')} ${forward.get('two')}/${backward.get('two')}`);
  check('a name that did not collide is left as its two words',
    resolveDisplayNames([['only', seedA]]).get('only') === nameFromSeed(seedA),
    resolveDisplayNames([['only', seedA]]).get('only'));
}

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
  // The room probes in this file are deliberately refused requests (409 room_exists,
  // 404 no_room), and every refusal is charged to the reject budget. Left at its
  // production default the polling loops would run out of budget and start reading 429,
  // which is not an answer about any room.
  WG_REJECT_PER_WINDOW: '500',
  WG_PUBLIC_GET_PER_WINDOW: '500',
  // A room is reaped once both sides have been gone this long. Short here so the
  // abandonment test does not have to wait the production grace period.
  WG_EMPTY_GRACE_MS: '2500',
  WG_SWEEP_MS: '400',
});

const browser = await launchBrowser({ port: CDP_PORT });
check('headless browser launched', Boolean(browser.version), browser.version);
// launchBrowser refuses to attach to a browser it did not start, so this also records
// which process the whole run is actually being measured against.
check('the harness is driving the browser it started itself',
  Number.isInteger(browser.pid) && browser.debugPort === CDP_PORT,
  `pid ${browser.pid} on ${browser.debugPort}`);

// ============================================================ layout, CSP, contrast
//
// The redesign asserted, not eyeballed. Everything in this block runs in its own tabs
// at explicit viewport sizes, before the gate lifecycle below touches anything.
//
// Set WG_LAYOUT_ONLY=1 to run ONLY this block. That exists so each check here can be
// re-run against a deliberately broken tree cheaply enough that proving it CAN fail is
// routine rather than an event. The mode prints its own banner and its own summary
// label, and it never reports the lifecycle as having run.
const LAYOUT_ONLY = process.env.WG_LAYOUT_ONLY === '1';

// Registered with Page.addScriptToEvaluateOnNewDocument BEFORE any navigation, so it is
// present in the document from its first byte and survives reloads. Registering a
// listener after the page has loaded has produced a false clean result here before: the
// violations had already been reported to a document that no longer existed.
const CSP_PROBE = `
  window.__csp = [];
  document.addEventListener('securitypolicyviolation', (e) => {
    window.__csp.push((e.violatedDirective || '?') + ' <- '
      + (e.blockedURI || e.sourceFile || 'inline') + ':' + (e.lineNumber || 0));
  });
`;

// One colour engine, used by every contrast assertion below. Backgrounds are composited
// down the ancestor chain rather than read off the element, because the banners and the
// washes are translucent and reading `backgroundColor` alone reports rgba(0,0,0,0) as
// black and calls an unreadable pair fine.
const COLOUR_FNS = `
  const num = (c) => (c.match(/[0-9.]+/g) || []).map(Number);
  const rgbOf = (c) => { const n = num(c); return n.length >= 3 ? n.slice(0, 3) : null; };
  const alphaOf = (c) => { const n = num(c); return n.length > 3 ? n[3] : 1; };
  const blend = (fg, bg, a) => fg.map((v, i) => v * a + bg[i] * (1 - a));
  const lum = (rgb) => { const [r, g, b] = rgb.map((v) => {
    const x = v / 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
  }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  function bgOf(el) {
    const layers = [];
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const c = getComputedStyle(n).backgroundColor;
      const rgb = rgbOf(c); const a = alphaOf(c);
      if (rgb && a > 0) { layers.push({ rgb, a }); if (a >= 1) break; }
    }
    if (!layers.length) return [255, 255, 255];
    let out = layers[layers.length - 1].rgb;
    for (let i = layers.length - 2; i >= 0; i -= 1) out = blend(layers[i].rgb, out, layers[i].a);
    return out;
  }
  function ratioOf(el) {
    const cs = getComputedStyle(el);
    const bg = bgOf(el);
    const fgRaw = rgbOf(cs.color);
    if (!fgRaw) return null;
    const fg = alphaOf(cs.color) >= 1 ? fgRaw : blend(fgRaw, bg, alphaOf(cs.color));
    const l1 = Math.max(lum(fg), lum(bg));
    const l2 = Math.min(lum(fg), lum(bg));
    return (l1 + 0.05) / (l2 + 0.05);
  }
  // WCAG AA: 4.5:1 for body text, 3:1 for large text (>=24px, or >=18.66px and bold).
  function needFor(el) {
    const cs = getComputedStyle(el);
    const px = parseFloat(cs.fontSize) || 16;
    const weight = Number(cs.fontWeight) || 400;
    return (px >= 24 || (px >= 18.66 && weight >= 700)) ? 3 : 4.5;
  }
  // Every element that paints its own text, not just a hand-written list of selectors:
  // a list only ever covers the pairs somebody remembered.
  function auditContrast(root) {
    const bad = [];
    let counted = 0;
    for (const el of (root || document).querySelectorAll('*')) {
      if (el.closest('.sr-only')) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) < 0.35) continue;
      const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
      if (!own) continue;
      const box = el.getBoundingClientRect();
      if (box.width < 2 || box.height < 2) continue;
      const r = ratioOf(el);
      if (r === null) continue;
      counted += 1;
      const need = needFor(el);
      if (r < need) {
        bad.push({
          what: (el.tagName + (el.id ? '#' + el.id : '') + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\\s+/).join('.') : '')).slice(0, 70),
          ratio: Number(r.toFixed(2)),
          need,
          text: el.textContent.trim().slice(0, 40),
        });
      }
    }
    return { counted, bad };
  }
`;

// Geometry of one screen: where the column sits, where the primary action sits, and
// whether the status log is on top of anything a person could click.
const GEOMETRY = `
  const r = (el) => { const b = el.getBoundingClientRect(); return {
    x: Math.round(b.x), y: Math.round(b.y), w: Math.round(b.width), h: Math.round(b.height),
    top: Math.round(b.top), bottom: Math.round(b.bottom), left: Math.round(b.left), right: Math.round(b.right) }; };
  // What is actually PAINTED, not what the box model says. An element inside a scroll
  // container has a rect that keeps going past the container's edge; it is clipped, not
  // drawn. Comparing raw rects reported the footer link one pixel below the scrollport as
  // sitting under the log panel, which is a measurement artefact and not something a user
  // could ever see. Clip to every scrolling ancestor, then to the viewport.
  function visibleRect(el) {
    const b = el.getBoundingClientRect();
    let top = b.top; let bottom = b.bottom; let left = b.left; let right = b.right;
    for (let n = el.parentElement; n && n.nodeType === 1; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.overflow === 'visible' && cs.overflowX === 'visible' && cs.overflowY === 'visible') continue;
      const c = n.getBoundingClientRect();
      top = Math.max(top, c.top); bottom = Math.min(bottom, c.bottom);
      left = Math.max(left, c.left); right = Math.min(right, c.right);
    }
    top = Math.max(top, 0); left = Math.max(left, 0);
    bottom = Math.min(bottom, window.innerHeight); right = Math.min(right, window.innerWidth);
    return { top, bottom, left, right, w: right - left, h: bottom - top };
  }
  function geometry(primarySel) {
    const main = document.querySelector('main');
    const log = document.getElementById('log');
    const scroller = document.querySelector('.page') || document.scrollingElement;
    const logShown = log && log.textContent.trim() !== '' && log.getBoundingClientRect().height > 0;
    const logRect = logShown ? r(log) : null;
    const prim = primarySel ? document.querySelector(primarySel) : null;
    const fold = logRect ? logRect.top : window.innerHeight;
    const hits = [];
    if (logRect) {
      for (const el of document.querySelectorAll('a, button, input, select, textarea, summary, [tabindex]')) {
        if (el.closest('#log')) continue;
        const cs = getComputedStyle(el);
        if (cs.visibility === 'hidden' || cs.display === 'none') continue;
        const b = visibleRect(el);
        if (b.w < 1 || b.h < 1) continue;
        if (b.bottom > logRect.top && b.top < logRect.bottom
            && b.right > logRect.left && b.left < logRect.right) {
          hits.push((el.id || el.tagName + '.' + el.className).toString().slice(0, 44)
            + '@' + Math.round(b.top) + '-' + Math.round(b.bottom));
        }
      }
    }
    return {
      win: { w: window.innerWidth, h: window.innerHeight },
      main: main ? r(main) : null,
      deadLeft: main ? Math.round(main.getBoundingClientRect().left) : null,
      deadRight: main ? Math.round(window.innerWidth - main.getBoundingClientRect().right) : null,
      primary: prim ? r(prim) : null,
      primaryAboveFold: prim ? (r(prim).bottom <= fold && Math.round(scroller.scrollTop) === 0) : null,
      fold,
      logShown: Boolean(logShown),
      logRect,
      logHits: hits,
      scrollTop: Math.round(scroller.scrollTop),
      scrollHeight: Math.round(scroller.scrollHeight),
    };
  }
`;

/** A tab with the CSP listener installed before its first navigation. */
async function guardedTab(url, { width, height, mobile = false, theme = null } = {}) {
  const tab = await browser.newTab('about:blank');
  await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: CSP_PROBE });
  if (width) {
    await tab.send('Emulation.setDeviceMetricsOverride', {
      width, height, deviceScaleFactor: 1, mobile,
    });
  }
  if (theme) {
    await tab.send('Emulation.setEmulatedMedia', {
      features: [{ name: 'prefers-color-scheme', value: theme }],
    });
  }
  await tab.send('Page.navigate', { url });
  await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: `loaded ${url}` });
  return tab;
}

const forgetAgreement = `
  localStorage.removeItem('wg.agreed.v1');
  return true;
`;

const agreeInPage = `
  localStorage.setItem('wg.agreed.v1', JSON.stringify({ version: 1, acceptedAt: new Date().toISOString() }));
  return true;
`;

/** Force one screen on for a geometry measurement, the way app.js's show() would. */
const showScreen = (id) => `
  for (const s of document.querySelectorAll('section.screen')) s.hidden = s.id !== ${JSON.stringify(id)};
  const extras = document.getElementById('extras');
  if (extras) extras.hidden = !['screen-onboarding', 'screen-home', 'screen-severed'].includes(${JSON.stringify(id)});
  return true;
`;

/** Fill the status log with real log lines, the way app.js's log() does. */
const fillLog = `
  const box = document.getElementById('log');
  box.textContent = '';
  for (const line of ['gathering addresses', 'connected directly, candidate type host',
                      'the other device accepted the file', 'transfer complete']) {
    const div = document.createElement('div');
    div.textContent = line;
    box.appendChild(div);
  }
  return box.getBoundingClientRect().height;
`;

{
  // ---------------------------------------------------------------- onboarding, wide
  const SCREENS = ['screen-onboarding', 'screen-home', 'screen-password', 'screen-waiting',
    'screen-connected', 'screen-severed', 'screen-failed'];

  const wide = await guardedTab(ORIGIN, { width: 1920, height: 1080 });
  await wide.eval(forgetAgreement);
  await wide.send('Page.reload', {});
  await wide.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'onboarding shown at 1920x1080' });
  await wide.eval(COLOUR_FNS + GEOMETRY + 'return true;');
  const ob1920 = JSON.parse(await wide.eval(GEOMETRY + "return JSON.stringify(geometry('#onboarding-done'));"));

  // Measured before this work: 640px of column with 630px of dead margin on each side of
  // a 1900px window, i.e. a phone layout on a widescreen.
  check('onboarding uses the width of a desktop window, not a phone column',
    ob1920.main.w >= 1100, `main is ${ob1920.main.w}px at ${ob1920.win.w}x${ob1920.win.h}`);
  check('and the dead margin either side is no longer half the screen',
    ob1920.deadLeft < 400 && ob1920.deadRight < 400,
    `${ob1920.deadLeft}px left, ${ob1920.deadRight}px right`);
  check('the agree button is reachable at 1920x1080 without scrolling',
    ob1920.primaryAboveFold === true,
    `button bottom ${ob1920.primary?.bottom}, fold ${ob1920.fold}, scrollTop ${ob1920.scrollTop}`);

  // The consent claim: a wide screen shows MORE of the disclosure, not less. All five
  // panels are open, and the agreement is neither shortened nor clipped.
  const disclosure = JSON.parse(await wide.eval(`
    const discs = [...document.querySelectorAll('#screen-onboarding details.disc')];
    const label = document.querySelector('#screen-onboarding .check span');
    const box = label.getBoundingClientRect();
    return JSON.stringify({
      total: discs.length,
      open: discs.filter((d) => d.open).length,
      bodyText: discs.reduce((n, d) => n + d.querySelector('.disc-body').textContent.trim().length, 0),
      visibleBodies: discs.filter((d) => d.querySelector('.disc-body').getBoundingClientRect().height > 20).length,
      agreementChars: label.textContent.trim().length,
      agreementClipped: getComputedStyle(label).textOverflow === 'ellipsis'
        || label.scrollHeight > Math.ceil(box.height) + 2,
      ticked: document.getElementById('agree-check').checked,
      buttonDisabled: document.getElementById('onboarding-done').disabled,
    });
  `));
  check('all five disclosures are open on a desktop, so the wide layout shows more not less',
    disclosure.total === 5 && disclosure.open === 5 && disclosure.visibleBodies === 5,
    JSON.stringify(disclosure));
  check('the disclosures still carry their full text, none of it moved behind a link',
    disclosure.bodyText > 2000, `${disclosure.bodyText} characters of disclosure body`);
  check('the agreement is shown in full, not clipped or abbreviated',
    disclosure.agreementChars > 300 && disclosure.agreementClipped === false,
    JSON.stringify(disclosure));
  check('the box is unticked and the button disabled on arrival, so agreeing stays deliberate',
    disclosure.ticked === false && disclosure.buttonDisabled === true, JSON.stringify(disclosure));

  // ---------------------------------------------------------------- the status log
  //
  // With the log non-empty on EVERY screen, nothing clickable may be underneath it. The
  // log used to be a fixed overlay: the reservation it carried only applied at the very
  // bottom of the document, so at any other scroll offset it simply covered whatever was
  // there. It is a layout row now.
  const overlaps = [];
  for (const id of SCREENS) {
    await wide.eval(showScreen(id));
    const h = await wide.eval(fillLog);
    const g = JSON.parse(await wide.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
    // Bottom of the scroll range as well as the top: a fixed panel is only harmless at
    // one of them, and a check that samples one scroll position would miss the other.
    await wide.eval("const p = document.querySelector('.page') || document.scrollingElement; p.scrollTop = p.scrollHeight; return true;");
    const g2 = JSON.parse(await wide.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
    await wide.eval("const p = document.querySelector('.page') || document.scrollingElement; p.scrollTop = 0; return true;");
    overlaps.push({ id, h, shown: g.logShown, hits: g.logHits.concat(g2.logHits) });
  }
  check('a non-empty status log is actually on screen, so the test below is measuring something',
    overlaps.every((o) => o.shown && o.h > 10), JSON.stringify(overlaps.map((o) => [o.id, o.h])));
  check('and it covers no button, link or field on any screen, at the top or bottom of the page',
    overlaps.every((o) => o.hits.length === 0),
    JSON.stringify(overlaps.filter((o) => o.hits.length).map((o) => [o.id, o.hits])));

  // The capability sentence is still told, and told somewhere that is not the log.
  await wide.eval(showScreen('screen-onboarding'));
  const capability = JSON.parse(await wide.eval(`
    const note = document.getElementById('receive-note');
    return JSON.stringify({
      canStream: typeof window.showSaveFilePicker === 'function',
      shown: note ? !note.hidden : false,
      text: note ? note.textContent.trim() : '',
      inLog: document.getElementById('log').textContent.includes('download manager'),
    });
  `));
  check('the browser used for this run really cannot stream to disk, so the note is under test',
    capability.canStream === false, `showSaveFilePicker is ${capability.canStream ? 'present' : 'absent'}`);
  check('the size-limit warning is still shown, and in the page rather than in the log',
    capability.shown && /download manager/.test(capability.text) && capability.inLog === false,
    JSON.stringify(capability).slice(0, 220));

  // ---------------------------------------------------------------- CSP
  const cspWide = await wide.eval('return JSON.stringify(window.__csp);');
  check('the whole redesign raises no CSP violation: no inline style, no inline script',
    cspWide === '[]', cspWide);
  // The listener itself, proven. A style attribute set from markup is exactly what
  // style-src 'self' refuses, so if this does NOT report, the assertion above was empty.
  await wide.eval(`
    const probe = document.createElement('div');
    probe.setAttribute('style', 'color: red');
    document.body.appendChild(probe);
    probe.remove();
    return true;
  `);
  await wide.waitFor('window.__csp.length > 0', { timeout: 5000, label: 'the CSP listener reports a planted violation' });
  const planted = await wide.eval('return JSON.stringify(window.__csp);');
  check('the CSP listener catches a planted inline style, so the clean result above is real',
    /style-src/.test(planted), planted);
  wide.close();

  // ---------------------------------------------------------------- 1440x900
  const laptop = await guardedTab(ORIGIN, { width: 1440, height: 900 });
  await laptop.eval(forgetAgreement);
  await laptop.send('Page.reload', {});
  await laptop.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'onboarding at 1440x900' });
  const ob1440 = JSON.parse(await laptop.eval(GEOMETRY + "return JSON.stringify(geometry('#onboarding-done'));"));
  check('the agree button is reachable at 1440x900 without scrolling',
    ob1440.primaryAboveFold === true,
    `button bottom ${ob1440.primary?.bottom}, fold ${ob1440.fold}`);
  check('and the column still leaves a margin rather than running to the window edge',
    ob1440.deadLeft >= 60 && ob1440.deadRight >= 60,
    `${ob1440.deadLeft}px left, ${ob1440.deadRight}px right`);
  const cspLaptop = await laptop.eval('return JSON.stringify(window.__csp);');
  check('no CSP violation at 1440x900 either', cspLaptop === '[]', cspLaptop);
  laptop.close();

  // ---------------------------------------------------------------- 390x844
  const phone = await guardedTab(ORIGIN, { width: 390, height: 844, mobile: true });
  await phone.eval(forgetAgreement);
  await phone.send('Page.reload', {});
  await phone.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'onboarding at 390x844' });
  const obPhone = JSON.parse(await phone.eval(GEOMETRY + "return JSON.stringify(geometry('#onboarding-done'));"));
  const phoneDisc = JSON.parse(await phone.eval(`
    const discs = [...document.querySelectorAll('#screen-onboarding details.disc')];
    return JSON.stringify({ open: discs.filter((d) => d.open).length, total: discs.length,
      titles: discs.every((d) => d.querySelector('.disc-title').getBoundingClientRect().height > 0) });
  `));
  check('the phone keeps one full-width column',
    obPhone.main.w === obPhone.win.w, `main ${obPhone.main.w} in ${obPhone.win.w}`);
  // Five open panels on a phone would bury the agreement under thousands of pixels, so
  // they collapse there. Every title is still on the page: nothing is hidden, only closed.
  check('the disclosures collapse on a phone, and every one of them is still listed',
    phoneDisc.open === 0 && phoneDisc.total === 5 && phoneDisc.titles === true, JSON.stringify(phoneDisc));
  const phoneLog = await phone.eval(fillLog);
  const phoneGeom = JSON.parse(await phone.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
  check('the status log covers nothing on a phone either',
    phoneLog > 10 && phoneGeom.logShown && phoneGeom.logHits.length === 0,
    JSON.stringify(phoneGeom.logHits));
  phone.close();

  // ---------------------------------------------------------------- contrast, both themes
  //
  // Every element that paints its own text, on every screen, in both palettes. Not a list
  // of pairs somebody remembered to add.
  for (const theme of ['dark', 'light']) {
    const t = await guardedTab(ORIGIN, { width: 1440, height: 900, theme });
    // The tabs share one browser profile, so whether onboarding is showing depends on
    // what an earlier tab did. Say which state this one wants instead of inheriting it.
    await t.eval(agreeInPage);
    await t.send('Page.reload', {});
    await t.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: `home in ${theme}` });
    const findings = [];
    let counted = 0;
    for (const id of SCREENS) {
      await t.eval(showScreen(id));
      await t.eval(fillLog);
      const out = JSON.parse(await t.eval(COLOUR_FNS + `return JSON.stringify(auditContrast(document.body));`));
      counted += out.counted;
      for (const b of out.bad) findings.push({ screen: id, ...b });
    }
    check(`every visible text pair meets WCAG AA in the ${theme} theme`,
      findings.length === 0, JSON.stringify(findings).slice(0, 400));
    check(`and the ${theme} sweep actually looked at the text, rather than finding nothing to look at`,
      counted > 150, `${counted} text elements measured`);

    // Prove the sweep can fail: plant a pair that is deliberately unreadable and require
    // it to be caught. Without this, "0 findings" is equally consistent with a broken
    // checker. CSSOM, so it is not itself a CSP violation.
    const caught = JSON.parse(await t.eval(COLOUR_FNS + `
      const host = document.getElementById('screen-onboarding');
      host.hidden = false;
      const bad = document.createElement('p');
      bad.id = 'contrast-canary';
      bad.textContent = 'this pair is deliberately unreadable';
      bad.style.color = getComputedStyle(document.body).backgroundColor;
      bad.style.fontSize = '14px';
      host.appendChild(bad);
      const out = auditContrast(host);
      bad.remove();
      return JSON.stringify(out.bad.filter((b) => b.what.includes('contrast-canary')));
    `));
    check(`the ${theme} contrast sweep catches a planted low-contrast pair`,
      caught.length === 1 && caught[0].ratio < 1.2, JSON.stringify(caught));

    // ------------------------------------------------------- the legal pages
    for (const page of ['faq', 'terms', 'privacy', 'acceptable-use']) {
      const lp = await guardedTab(`${ORIGIN}/${page}.html`, { width: 1440, height: 900, theme });
      const legal = JSON.parse(await lp.eval(COLOUR_FNS + `
        const h1 = document.querySelector('main.legal h1');
        const h2 = document.querySelector('main.legal h2');
        const brow = document.querySelector('main.legal .eyebrow');
        const p = document.querySelector('main.legal p');
        const audit = auditContrast(document.body);
        return JSON.stringify({
          hasEyebrow: Boolean(brow),
          eyebrowMono: brow ? /mono|Menlo|SFMono/i.test(getComputedStyle(brow).fontFamily) : false,
          eyebrowTracking: brow ? parseFloat(getComputedStyle(brow).letterSpacing) : 0,
          h1Size: h1 ? parseFloat(getComputedStyle(h1).fontSize) : 0,
          h1Tracking: h1 ? parseFloat(getComputedStyle(h1).letterSpacing) : 0,
          h2Rule: h2 ? getComputedStyle(h2).borderTopWidth : '0px',
          measure: p ? Math.round(p.getBoundingClientRect().width) : 0,
          bad: audit.bad, counted: audit.counted,
          csp: window.__csp,
        });
      `));
      check(`${page}.html opens with the same eyebrow and display headline as the app (${theme})`,
        legal.hasEyebrow && legal.eyebrowMono && legal.eyebrowTracking > 1
        && legal.h1Size >= 26 && legal.h1Tracking < 0,
        JSON.stringify(legal).slice(0, 200));
      check(`${page}.html rules its sections and keeps prose to a measure (${theme})`,
        legal.h2Rule !== '0px' && legal.measure > 300 && legal.measure <= 800,
        `rule ${legal.h2Rule}, prose ${legal.measure}px`);
      check(`${page}.html meets WCAG AA throughout in the ${theme} theme`,
        legal.bad.length === 0 && legal.counted > 20,
        JSON.stringify({ bad: legal.bad, counted: legal.counted }).slice(0, 300));
      check(`${page}.html raises no CSP violation (${theme})`,
        JSON.stringify(legal.csp) === '[]', JSON.stringify(legal.csp));
      lp.close();
    }
    t.close();
  }

  // ---------------------------------------------------------------- home still fits
  const homeTab = await guardedTab(ORIGIN, { width: 1920, height: 1080 });
  await homeTab.eval(agreeInPage);
  await homeTab.send('Page.reload', {});
  await homeTab.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'home at 1920x1080' });
  const home = JSON.parse(await homeTab.eval(GEOMETRY + "return JSON.stringify(geometry('#cta-open'));"));
  check('the home screen breathes wider on a large window without becoming a dashboard',
    home.main.w >= 1150 && home.main.w <= 1300, `main is ${home.main.w}px at ${home.win.w}px`);
  check('and its primary call to action is still above the fold',
    home.primaryAboveFold === true, `bottom ${home.primary?.bottom}, fold ${home.fold}`);
  homeTab.close();

  // Several tabs above accepted the terms to reach the home screen, and every tab shares
  // one browser profile. The lifecycle below opens as a FIRST-TIME visitor, so the flag
  // is handed back the way it was found. Asserted rather than assumed: leaving it set
  // makes the first wait of the lifecycle time out twenty seconds later, a long way from
  // the line that caused it.
  const reset = await browser.newTab(ORIGIN);
  await reset.eval(forgetAgreement);
  const clearedFlag = await reset.eval("return localStorage.getItem('wg.agreed.v1');");
  check('the layout block leaves the profile with the terms unaccepted, as it found it',
    clearedFlag === null, String(clearedFlag));
  reset.close();
}

if (LAYOUT_ONLY) {
  process.stdout.write('\nSUBSET MODE (WG_LAYOUT_ONLY=1): the gate lifecycle was NOT run.\n');
  await browser.close();
  await server.stop();
  fs.rmSync(TMP, { recursive: true, force: true });
  process.exit(summary('browser layout subset') ? 0 : 1);
}

let severTested = false;

try {
  // ------------------------------------------------------------ tab A: create
  const a = await browser.newTab(ORIGIN);
  await a.waitFor("document.getElementById('screen-onboarding') && !document.getElementById('screen-onboarding').hidden",
    { label: 'onboarding screen visible on first visit' });
  // The waitFor above already threw if onboarding never appeared, so restating it adds
  // a passing line and no information. What is worth asserting independently is that
  // onboarding is the ONLY thing shown: a first-time visitor must not be able to reach
  // the create button behind it.
  const firstVisit = await a.eval(`
    return JSON.stringify([...document.querySelectorAll('section.screen')]
      .filter((s) => !s.hidden).map((s) => s.id));
  `);
  check('a first-time visitor is shown the security notes and nothing else',
    firstVisit === '["screen-onboarding"]', firstVisit);

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

  // The support block sits on the quiet screens. Its links must actually be legible:
  // a class-specificity slip once rendered the Ko-fi label accent-on-accent, i.e.
  // a solid button with invisible text.
  const contrast = await a.eval(`
    const el = document.querySelector('a.kofi');
    if (!el) return { missing: true };
    const s = getComputedStyle(el);
    const parse = (c) => (c.match(/[0-9.]+/g) || []).slice(0, 3).map(Number);
    const lum = (rgb) => {
      const [r, g, b] = rgb.map((v) => {
        const x = v / 255;
        return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const fg = parse(s.color);
    const bg = parse(s.backgroundColor);
    if (fg.length < 3 || bg.length < 3) return { unknown: true, color: s.color, bg: s.backgroundColor };
    const l1 = Math.max(lum(fg), lum(bg));
    const l2 = Math.min(lum(fg), lum(bg));
    return { ratio: (l1 + 0.05) / (l2 + 0.05), text: el.textContent.trim() };
  `);
  check('the support link has visible text', Boolean(contrast.text), JSON.stringify(contrast));
  check('the support link text contrasts with its own background',
    contrast.ratio >= 4.5, `contrast ratio ${contrast.ratio?.toFixed(2)}`);

  const donateLinks = await a.eval(`
    return JSON.stringify([...document.querySelectorAll('a.kofi, .foot a')].map(x => x.getAttribute('href')));
  `);
  // An author rule with an explicit display beats the UA stylesheet's [hidden]
  // display:none. That showed the donation QR as a blank white box, and would have
  // done the same to the pairing QR. Assert real invisibility, not just the attribute.
  const hiddenReally = await a.eval(`
    const offenders = [];
    for (const el of document.querySelectorAll('[hidden]')) {
      if (el.offsetParent !== null || el.getClientRects().length > 0) {
        offenders.push(el.id || el.className || el.tagName);
      }
    }
    return JSON.stringify(offenders);
  `);
  check('every element marked hidden is actually invisible',
    hiddenReally === '[]', `still rendered: ${hiddenReally}`);

  check('the Ko-fi link points at the configured handle',
    /ko-fi\.com\/fysh_yum/.test(donateLinks), donateLinks);

  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { label: 'waiting screen' });

  // The secret must not sit in the address bar: it would be readable for the whole
  // session by anyone who can see the screen, or any screenshot or recording.
  const barUrl = await a.eval('return location.href;');
  check('the secret is NOT left in the address bar', !barUrl.includes('WARP-'), barUrl);
  check('the address bar has no fragment at all',
    !barUrl.includes('#') || barUrl.endsWith('#'), barUrl);

  // Nor on screen until the user asks for it.
  const beforeReveal = await a.eval(`
    return JSON.stringify({
      codeText: (document.getElementById('room-code') || {}).textContent || '',
      shownHidden: document.getElementById('share-shown').hidden,
    });
  `);
  const br = JSON.parse(beforeReveal);
  check('the gate code is not displayed until revealed', br.shownHidden && br.codeText === '', beforeReveal);

  await a.eval("document.getElementById('reveal-share').click(); return true;");
  await a.waitFor("document.getElementById('share-shown').hidden === false", { label: 'share panel revealed' });

  const code = await a.eval("return document.getElementById('room-code').textContent.trim();");
  check('the revealed code is a 26 character Crockford secret',
    /^WARP(-[0-9A-HJKMNP-TV-Z]{1,4}){7}$/.test(code), code);
  const link = `${ORIGIN}/#${code}`;

  const qrDrawn = await a.eval(`
    const c = document.getElementById('qr');
    const ctx = c.getContext('2d');
    const data = ctx.getImageData(0, 0, c.width, c.height).data;
    let dark = 0;
    for (let i = 0; i < data.length; i += 4) if (data[i] < 128) dark++;
    return { dark, total: data.length / 4 };
  `);
  check('a QR code is rendered once revealed',
    qrDrawn.dark > 100 && qrDrawn.dark < qrDrawn.total * 0.6, JSON.stringify(qrDrawn));

  await a.eval("document.getElementById('hide-share').click(); return true;");
  check('hiding puts the code away again',
    (await a.eval("return document.getElementById('share-shown').hidden && document.getElementById('room-code').textContent === '';")) === true);

  // The room id is derived from the secret, so the harness can address the very room
  // this tab created without the server ever having to publish a count.
  const gate1 = await roomIdFor(code);
  const held = await roomHeld(gate1.roomId);
  check('the gate this tab created is really held on the server', held.held, `${held.status} ${held.body}`);
  // Negative control for the probe itself: an id nobody created must NOT read as held,
  // or "held" is just what this function always says.
  const neverMade = await roomHeld('ZZZZZZZZ');
  check('the same probe reports an uncreated id as not held',
    neverMade.held === false && neverMade.status === 200, `${neverMade.status} ${neverMade.body}`);
  await request(PORT, 'POST', '/api/bye', { roomId: 'ZZZZZZZZ', token: neverMade.body && JSON.parse(neverMade.body).token });

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
  // Independent of the wait above: the joiner never saw an error, and never had to type
  // the code into the join box, which is what "without any further input" means.
  const joinedClean = await b.eval(`
    return JSON.stringify({
      error: (document.getElementById('home-error') || {}).textContent || '',
      errorShown: !(document.getElementById('home-error') || {}).hidden,
      typed: (document.getElementById('join-input') || {}).value || '',
    });
  `);
  const jc = JSON.parse(joinedClean);
  check('opening the link joins the gate without any further input',
    jc.error === '' && jc.typed === '', joinedClean);

  const joinerUrl = await b.eval('return location.href;');
  check('the joiner strips the secret from its address bar too',
    !joinerUrl.includes('WARP-'), joinerUrl);

  // ------------------------------------------------------------ connection
  await a.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab A connected' });
  await b.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab B connected' });
  // "Connected" as a screen is what the waits already established. What has to be true
  // independently is that the connection is a real RTCPeerConnection in the connected
  // state with an open data channel, rather than a UI that showed the screen optimistically.
  const rtcState = await a.eval(`
    const stubbed = window.RTCPeerConnection && /Blocked|PublicOnly/.test(window.RTCPeerConnection.name);
    return JSON.stringify({
      stubbed: Boolean(stubbed),
      secureContextCrypto: Boolean(window.crypto && window.crypto.subtle),
      sas: (document.getElementById('sas') || {}).textContent || '',
      screens: [...document.querySelectorAll('section.screen')].filter((s) => !s.hidden).map((s) => s.id),
    });
  `);
  const rs = JSON.parse(rtcState);
  check('both tabs reached the connected state over a real, unstubbed WebRTC stack',
    rs.stubbed === false && rs.screens.length === 1 && rs.screens[0] === 'screen-connected',
    rtcState);

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

  // ------------------------------------------------------------ display names
  //
  // A two-party gate is the common case, so this is where the naming has to read well:
  // one pill for each side, both named, ours marked as ours.
  await a.waitFor(NAMED_ROSTER(2), { timeout: 20000, label: 'tab A named the participants' });
  await b.waitFor(NAMED_ROSTER(2), { timeout: 20000, label: 'tab B named the participants' });

  const rosterA = await rosterOf(a);
  const rosterB = await rosterOf(b);
  const gate1Names = [...Object.values(rosterA.names), ...Object.values(rosterB.names)];

  check('each device names both participants of a two-party gate',
    Object.keys(rosterA.names).length === 2 && Object.keys(rosterB.names).length === 2,
    JSON.stringify({ rosterA, rosterB }));
  check('every name is two calm words, bounded in length',
    gate1Names.every((n) => NAME_SHAPE.test(n) && n.length <= 32), JSON.stringify(gate1Names));
  check('the two participants are not given the same name',
    new Set(Object.values(rosterA.names)).size === 2, JSON.stringify(rosterA.names));

  // The claim the whole derivation exists to support. Both tabs hold the same room secret
  // and both see the same two slot ids, so both must print the same name for each slot.
  // A name derived from a per-link key would put two different strings here.
  check('both devices derive the SAME name for the same participant',
    canonicalNames(rosterA.names) === canonicalNames(rosterB.names),
    `${JSON.stringify(rosterA.names)} vs ${JSON.stringify(rosterB.names)}`);
  check('including each device\'s name for itself, which is what the other one calls it',
    rosterA.names[rosterA.self] === rosterB.names[rosterA.self]
    && rosterB.names[rosterB.self] === rosterA.names[rosterB.self],
    `${JSON.stringify(rosterA)} | ${JSON.stringify(rosterB)}`);

  const selfChip = await a.eval("return document.querySelector('#roster .who-chip.self').textContent;");
  check('your own pill carries your name and says it is you',
    selfChip === `${rosterA.names[rosterA.self]} (you)`, selfChip);

  // ------------------------------------------------------------ chat
  const chatText = `hello from A ${crypto.randomUUID()}`;
  await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(chatText)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(chatText)})`,
    { label: 'chat message arrived at tab B' });
  // The wait above is what proves it arrived; restating that adds a passing line and no
  // information. Delivered EXACTLY once is a separate claim, and a duplicated frame is
  // a real failure mode on a channel that renegotiates.
  const deliveries = await b.eval(`
    const text = document.getElementById('messages').textContent;
    return text.split(${JSON.stringify(chatText)}).length - 1;
  `);
  check('a chat message travels A to B exactly once', deliveries === 1, `rendered ${deliveries} times`);

  // A row is labelled with the SENDER'S name, and with the same name this tab's roster
  // shows for that slot. Two places naming the same person differently would be worse
  // than either place naming nobody.
  const rowLabel = (tab, text) => tab.eval(`
    const row = [...document.querySelectorAll('#messages .msg')]
      .find((m) => m.textContent.includes(${JSON.stringify(text)}));
    return row ? (row.querySelector('.who') || {}).textContent || '' : '';
  `);
  const chatLabel = await rowLabel(b, chatText);
  check('a received message is labelled with the sender\'s name',
    chatLabel === rosterB.names[rosterA.self],
    `row says ${JSON.stringify(chatLabel)}, roster says ${JSON.stringify(rosterB.names[rosterA.self])}`);
  const ownLabel = await rowLabel(a, chatText);
  check('and your own message still reads "you" rather than your own name',
    ownLabel === 'you', ownLabel);

  const replyText = `reply from B ${crypto.randomUUID()}`;
  await b.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(replyText)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(replyText)})`,
    { label: 'reply arrived at tab A' });

  // ------------------------------------------------------------ secret
  const secretText = `tskey-auth-${crypto.randomBytes(12).toString('hex')}`;
  await b.eval(`
    document.getElementById('secret-toggle').checked = true;
    document.getElementById('chat-input').value = ${JSON.stringify(secretText)};
    document.getElementById('chat-form').requestSubmit();
    document.getElementById('secret-toggle').checked = false;
    return true;
  `);
  // A masked secret must NOT be waited for by its plaintext: the plaintext is
  // deliberately kept out of the DOM until the recipient reveals it, because #messages
  // is aria-live and a screen reader would otherwise read an arriving secret out loud.
  // Wait for the bubble, then assert the plaintext is absent, then reveal it.
  await a.waitFor("!!document.querySelector('#messages .secret-value.masked')",
    { label: 'secret bubble arrived at tab A' });

  const secretBeforeReveal = await a.eval(`
    const el = document.querySelector('#messages .secret-value.masked');
    return JSON.stringify({
      masked: el.classList.contains('masked'),
      ariaHidden: el.getAttribute('aria-hidden'),
      placeholder: el.textContent,
      plaintextAnywhereInPage: document.body.textContent.includes(${JSON.stringify(secretText)}),
    });
  `);
  const br2 = JSON.parse(secretBeforeReveal);
  check('a received secret is masked until the user reveals it', br2.masked === true, secretBeforeReveal);
  check('and its plaintext is not in the page at all while masked',
    br2.plaintextAnywhereInPage === false && br2.placeholder.includes(String(secretText.length)),
    secretBeforeReveal);
  check('the masked value is hidden from assistive technology too',
    br2.ariaHidden === 'true', String(br2.ariaHidden));

  await a.eval(`
    const row = document.querySelector('#messages .secret-value.masked').closest('.is-secret');
    [...row.querySelectorAll('button')].find((x) => x.textContent === 'Reveal').click();
    return true;
  `);
  await a.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(secretText)})`,
    { label: 'secret readable once revealed' });
  // The positive control for the assertion above: the plaintext really can appear in
  // the page, so "not in the page while masked" is a fact about masking and not about
  // a value that never arrives.
  const revealed = await a.eval(`return document.body.textContent.includes(${JSON.stringify(secretText)});`);
  check('a secret travels B to A and is readable once revealed', revealed === true, String(revealed));

  check('the secret toggle resets, so the next message is not accidentally hidden',
    (await b.eval("return document.getElementById('secret-toggle').checked;")) === false);

  // ------------------------------------------------------------ file
  const filePath = path.join(TMP, 'payload.bin');
  const payload = crypto.randomBytes(300 * 1024); // spans many 16 KiB chunks
  fs.writeFileSync(filePath, payload);
  const digest = crypto.createHash('sha256').update(payload).digest('hex');

  // Choosing files sends them; there is no separate send step and no tab to find.
  await a.setFileInput('#file-input', [filePath]);

  // Under the auto-accept threshold, so the receiver is never asked.
  await b.waitFor("document.getElementById('messages').textContent.includes('payload.bin')",
    { timeout: 30000, label: 'tab B saw the incoming file' });
  const noPrompt = await b.eval("return !!document.querySelector('#messages button.primary');");
  check('a small file is accepted without prompting the receiver', noPrompt === false);

  await b.waitFor("[...document.querySelectorAll('#messages button')].some(x => x.textContent === 'Save')",
    { timeout: 40000, label: 'file fully received by tab B' });

  const rowText = await b.eval("return document.getElementById('messages').textContent;");
  check('the received file shows its real name and size',
    rowText.includes('payload.bin') && /293|300|0\.3/.test(rowText), rowText.slice(-140));

  const senderLog = await a.eval("return document.getElementById('log').textContent;");
  check('no chunk was rejected during the transfer',
    !/frame rejected/.test(senderLog) && !/frame rejected/.test(await b.eval("return document.getElementById('log').textContent;")),
    'a frame was rejected mid-transfer');
  void digest;

  // An image should appear inline rather than only as a download.
  const png = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64',
  );
  const imgPath = path.join(TMP, 'pixel.png');
  fs.writeFileSync(imgPath, png);
  await a.setFileInput('#file-input', [imgPath]);
  await b.waitFor("!!document.querySelector('#messages img.msg-image')",
    { timeout: 30000, label: 'image rendered inline for the receiver' });
  check('the inline image actually decoded',
    (await b.eval("const i = document.querySelector('#messages img.msg-image'); return i.complete && i.naturalWidth > 0;")) === true);

  // ------------------------------------------------------------ reload recovery
  // A reload used to be fatal: re-joining a gate you already occupy is correctly
  // refused as full, so the session could never come back. The slot is now held in
  // sessionStorage and the peer is told to renegotiate.
  const sasBeforeReload = await a.eval("return document.getElementById('sas').textContent;");
  await b.send('Page.reload', {});
  await b.waitFor("[...document.querySelectorAll('section.screen')].some(s => !s.hidden)",
    { timeout: 30000, label: 'tab B came back after reload' });

  const rejoinError = await b.eval("return (document.getElementById('home-error')||{}).textContent || '';");
  check('a reloaded peer is not refused as "gate already has two devices"',
    !/two devices/.test(rejoinError), rejoinError);

  // 60s, not 40s. A reload is the most expensive path in the app: the slot is resumed, the
  // peer is told to start over, BOTH sides generate a fresh key pair, and a complete ICE
  // run follows. On a loaded machine (this suite runs straight after the 600-abort
  // descriptor storm) 40s was occasionally not enough, and a patience bound expiring is
  // not the same finding as a reconnect failing. The assertion itself is unchanged: the
  // page must reach the connected screen, and the SAS check below still proves it did so
  // with new keys rather than by reusing the old session.
  await b.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 60000, label: 'tab B reconnected after reload' });
  await a.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 60000, label: 'tab A renegotiated after the peer reloaded' });
  // The screens coming back is what the waits established. The independent claim is that
  // the SERVER still holds the same gate: a reload that destroyed and recreated the room
  // would look identical from the two pages, and used to be exactly what happened.
  const survived = await roomHeld(gate1.roomId);
  check('a gate survives one side reloading the page', survived.held, `${survived.status} ${survived.body}`);

  const afterReload = `after reload ${crypto.randomUUID()}`;
  await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(afterReload)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(afterReload)})`,
    { timeout: 20000, label: 'message crosses the renegotiated channel' });
  // "With fresh keys" is the part the wait cannot show. The short authentication string
  // is a fingerprint of the derived session, so a renegotiation that reused the old keys
  // would come back with the same digits.
  const sasAfterReload = await a.eval("return document.getElementById('sas').textContent;");
  const sasAfterReloadB = await b.eval("return document.getElementById('sas').textContent;");
  check('the renegotiated channel derived a new session, not the old one',
    /^[0-9]{5}$/.test(sasAfterReload) && sasAfterReload !== sasBeforeReload,
    `${sasBeforeReload} -> ${sasAfterReload}`);
  check('and both sides agree on the new one',
    sasAfterReload === sasAfterReloadB, `${sasAfterReload} vs ${sasAfterReloadB}`);

  // Names are STABLE for the life of the gate, and this is the sharpest place to prove it:
  // the reload above replaced the ephemeral keys of the pair, which the line right before
  // this one just measured by watching the verification code change. A name derived from
  // that key material would have changed with it. This one is derived from the room secret
  // and the slot id, neither of which a reload touches, so both tabs must still print
  // exactly what they printed before.
  const rosterAfterA = await rosterOf(a);
  const rosterAfterB = await rosterOf(b);
  check('a name is unchanged by a reload, even though the session keys were replaced',
    canonicalNames(rosterAfterA.names) === canonicalNames(rosterA.names)
    && canonicalNames(rosterAfterB.names) === canonicalNames(rosterB.names),
    `${JSON.stringify(rosterAfterA.names)} vs ${JSON.stringify(rosterA.names)}`);
  check('and the two devices still agree on it',
    canonicalNames(rosterAfterA.names) === canonicalNames(rosterAfterB.names),
    `${JSON.stringify(rosterAfterA.names)} vs ${JSON.stringify(rosterAfterB.names)}`);

  // ------------------------------------------------------------ blocked WebRTC
  // A browser configured to block WebRTC finishes gathering with zero candidates and
  // can never connect. This was observed for real in Brave with "WebRTC IP handling
  // policy: Disable non-proxied UDP". Chromium's matching command-line flag does not
  // reproduce it in this build, so the condition is injected directly: what needs
  // verifying is that Warp Gate reacts to it, not that Chromium implements it.
  check('the capability banner stays hidden on a browser that can connect',
    (await a.eval("return document.getElementById('webrtc-warning').hidden;")) === true);

  const z = await browser.newTab('about:blank');
  await z.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `
      class BlockedPC {
        constructor() { this.iceGatheringState = 'complete'; }
        createDataChannel() { return {}; }
        async createOffer() { return { type: 'offer', sdp: '' }; }
        async setLocalDescription() {}
        addEventListener(name, cb) {
          // Signal end-of-gathering having produced nothing at all.
          if (name === 'icecandidate') setTimeout(() => cb({ candidate: null }), 10);
        }
        removeEventListener() {}
        close() {}
      }
      window.__realPC = window.RTCPeerConnection;
      window.RTCPeerConnection = BlockedPC;
    `,
  });
  await z.send('Page.navigate', { url: ORIGIN });
  // Every lookup here must tolerate a document that has not parsed yet: Page.navigate
  // resolves before the new page exists, so a bare getElementById intermittently
  // throws on null.
  await z.waitFor("document.readyState === 'complete'",
    { timeout: 30000, label: 'stubbed page finished loading' });
  await z.waitFor("[...document.querySelectorAll('section.screen')].some(s => !s.hidden)",
    { timeout: 30000, label: 'app loaded with WebRTC stubbed out' });
  await z.waitFor("((document.getElementById('webrtc-warning') || {}).hidden) === false",
    { timeout: 20000, label: 'capability banner shown when nothing can be gathered' });
  // "Before a gate is created" is the load-bearing half and the wait says nothing about
  // it. The page must still be on home with no gate opened, not sitting on the waiting
  // screen having already taken a room the browser can never use.
  const blockedState = await z.eval(`
    return JSON.stringify({
      screens: [...document.querySelectorAll('section.screen')].filter((s) => !s.hidden).map((s) => s.id),
      slots: Object.keys(sessionStorage).filter((k) => k.startsWith('wg.')),
    });
  `);
  const bs = JSON.parse(blockedState);
  check('a browser that gathers no addresses is detected before any gate is created',
    !bs.screens.includes('screen-waiting') && !bs.screens.includes('screen-connected')
    && bs.slots.length === 0, blockedState);

  const hint = await z.eval("return document.getElementById('webrtc-warning-text').textContent;");
  check('the warning points at a browser setting rather than blaming the network',
    /WebRTC|IP handling|extension/i.test(hint) && !/firewall|carrier/i.test(hint), hint.slice(0, 160));

  const guidance = await z.eval(`
    const path = document.getElementById('webrtc-settings-path');
    return JSON.stringify({
      steps: [...document.querySelectorAll('#webrtc-steps li')].map(li => li.textContent),
      pathShown: !document.getElementById('webrtc-path-row').hidden,
      pathText: path.textContent,
      pathIsAnchor: path.tagName === 'A' || !!path.closest('a'),
      reassurance: document.getElementById('webrtc-reassurance').textContent,
      hasCopy: !!document.getElementById('webrtc-copy-path'),
      hasRecheck: !!document.getElementById('webrtc-recheck'),
    });
  `);
  const g = JSON.parse(guidance);
  check('numbered steps are given, not just a paragraph', g.steps.length >= 3, `${g.steps.length} steps`);
  check('the settings address is shown with a copy button',
    g.pathShown && g.pathText.length > 0 && g.hasCopy, guidance.slice(0, 160));
  // Chromium refuses to navigate to brave:// and chrome:// from a page, so shipping a
  // link would present the user with something that silently does nothing.
  check('the settings address is NOT a link, which browsers would refuse to open',
    g.pathIsAnchor === false);
  check('the user is told the change is reversible',
    /back|finished|temporar/i.test(g.reassurance), g.reassurance.slice(0, 120));
  check('a re-check control is offered so no manual reload is needed', g.hasRecheck);

  // A browser set to "Default public interface only" suppresses host candidates on
  // purpose but works fine over STUN. Reporting that as blocked was a false positive
  // on precisely the setting the warning tells people to choose.
  const priv = await browser.newTab('about:blank');
  await priv.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `
      const RealPC = window.RTCPeerConnection;
      class PublicOnlyPC {
        constructor(cfg) { this.hasStun = !!(cfg && cfg.iceServers && cfg.iceServers.length); }
        createDataChannel() { return {}; }
        async createOffer() { return { type: 'offer', sdp: '' }; }
        async setLocalDescription() {}
        addEventListener(name, cb) {
          if (name !== 'icecandidate') return;
          setTimeout(() => {
            // Host candidates suppressed; a public address only via STUN.
            if (this.hasStun) cb({ candidate: { type: 'srflx' } });
            cb({ candidate: null });
          }, 10);
        }
        removeEventListener() {}
        close() {}
      }
      window.RTCPeerConnection = PublicOnlyPC;
    `,
  });
  await priv.send('Page.navigate', { url: ORIGIN });
  await priv.waitFor("document.readyState === 'complete'", { timeout: 30000 });
  await priv.waitFor("[...document.querySelectorAll('section.screen')].some(s => !s.hidden)",
    { timeout: 30000, label: 'app loaded in the public-interface-only browser' });
  // Give the two-stage probe time to run both stages before judging.
  await new Promise((r) => { setTimeout(r, 3000); });
  const privState = await priv.eval(`
    const b = document.getElementById('webrtc-warning');
    return JSON.stringify({
      shown: b ? !b.hidden : false,
      isNote: b ? b.classList.contains('note') : false,
      title: (document.getElementById('webrtc-warning-title') || {}).textContent || '',
      text: (document.getElementById('webrtc-warning-text') || {}).textContent || '',
    });
  `);
  const ps = JSON.parse(privState);
  check('a browser that only exposes its public address is NOT called blocked',
    !/blocking|cannot make direct/i.test(ps.title), ps.title);
  check('it is told instead that same-network pairs may fail',
    ps.shown && ps.isNote && /same network/i.test(ps.title + ps.text), privState.slice(0, 200));

  // Recovery: once the browser can gather again, Re-check must clear the banner.
  await z.eval("window.RTCPeerConnection = window.__realPC; return true;");
  await z.eval("document.getElementById('webrtc-recheck').click(); return true;");
  await z.waitFor("((document.getElementById('webrtc-warning') || {}).hidden) === true",
    { timeout: 20000, label: 'banner clears after Re-check once WebRTC works' });

  // ------------------------------------------------------------ page errors
  check('tab A raised no uncaught page errors', a.pageErrors.length === 0, a.pageErrors.join(' | '));
  check('tab B raised no uncaught page errors', b.pageErrors.length === 0, b.pageErrors.join(' | '));

  // ------------------------------------------------------------ severing
  // Baseline for the storage assertions after the gate ends. Without this, "the secret
  // is not in sessionStorage" is satisfied by a build that never put it there, and the
  // check would report OK against a page that lost the resume feature entirely.
  const storageWhileLive = await Promise.all([a, b].map((tab) => tab.eval(`
    return JSON.stringify({
      secret: sessionStorage.getItem('wg.secret'),
      slots: Object.keys(sessionStorage).filter((k) => k.startsWith('wg.slot.')),
    });
  `)));
  const liveA = JSON.parse(storageWhileLive[0]);
  const liveB = JSON.parse(storageWhileLive[1]);
  check('while the gate is live, both tabs really are holding the room secret',
    typeof liveA.secret === 'string' && liveA.secret.startsWith('WARP-')
    && typeof liveB.secret === 'string' && liveB.secret.startsWith('WARP-'),
    `A ${typeof liveA.secret}, B ${typeof liveB.secret}`);
  check('and both are holding a slot to resume from',
    liveA.slots.length === 1 && liveB.slots.length === 1,
    `A ${JSON.stringify(liveA.slots)}, B ${JSON.stringify(liveB.slots)}`);

  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { label: 'tab A shows severed' });
  await b.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 15000, label: 'tab B shows severed' });

  const hashAfter = await a.eval('return location.hash;');
  check('severing strips the secret from the URL', hashAfter === '', `hash was "${hashAfter}"`);

  // The gate has ended, so the room secret goes with it, on BOTH sides. Only the local
  // Sever button used to clear it: when the PEER severed, when the TTL expired or when
  // the room closed, the secret sat in sessionStorage for the life of the tab, which is
  // exactly the window the severed screen invites the user to leave open. Tab A ended
  // it locally and tab B was told; both endings are asserted here.
  const storageAfter = await Promise.all([a, b].map((tab) => tab.eval(`
    return JSON.stringify({
      secret: sessionStorage.getItem('wg.secret'),
      slots: Object.keys(sessionStorage).filter((k) => k.startsWith('wg.slot.')),
      anyWarp: Object.entries(sessionStorage).concat(Object.entries(localStorage))
        .filter(([, v]) => typeof v === 'string' && v.includes('WARP-')).map(([k]) => k),
    });
  `)));
  const goneA = JSON.parse(storageAfter[0]);
  const goneB = JSON.parse(storageAfter[1]);
  check('the device that pressed Sever forgets the room secret',
    goneA.secret === null && goneA.slots.length === 0, storageAfter[0]);
  check('the device that was TOLD the gate ended forgets it too',
    goneB.secret === null && goneB.slots.length === 0, storageAfter[1]);
  check('no gate code is left anywhere in either tab\'s storage',
    goneA.anyWarp.length === 0 && goneB.anyWarp.length === 0,
    `A ${JSON.stringify(goneA.anyWarp)}, B ${JSON.stringify(goneB.anyWarp)}`);

  // Reported need: transporting a password when the connection drops should not mean
  // running the whole gate again just to re-read what already arrived.
  const transcript = await a.eval(`
    const holder = document.getElementById('transcript-holder');
    return JSON.stringify({
      shown: holder ? !holder.hidden : false,
      text: (document.getElementById('transcript-mount') || {}).textContent || '',
      persisted: Object.keys(localStorage).some(k => k.startsWith('wg.transcript'))
        || Object.keys(sessionStorage).some(k => k.startsWith('wg.transcript')),
    });
  `);
  const tr = JSON.parse(transcript);
  check('what was exchanged is still readable after severing', tr.shown, transcript.slice(0, 120));
  check('the severed transcript still contains the conversation',
    tr.text.length > 0, `${tr.text.length} chars`);
  check('the transcript is never written to storage', tr.persisted === false);

  await a.eval("document.getElementById('clear-transcript').click(); return true;");
  check('clearing the transcript empties it',
    (await a.eval("return document.getElementById('transcript-mount').textContent.length === 0 && document.getElementById('transcript-holder').hidden;")) === true);

  // Destruction, asserted against the id that actually existed. The old form joined
  // 'AAAAAAAA', an id no test ever created, so it answered 404 whether or not the real
  // room had been deleted.
  const severedGone = await roomGone(gate1.roomId, gate1.secret);
  check('the room is deleted from the server on sever', severedGone.gone, `${severedGone.status} ${severedGone.body}`);
  const severedNotHeld = await roomHeld(gate1.roomId);
  check('and its id is free to be created again',
    severedNotHeld.held === false && severedNotHeld.status === 200,
    `${severedNotHeld.status} ${severedNotHeld.body}`);
  // That last probe just created a room; do not leave it holding the id.
  await request(PORT, 'POST', '/api/bye', {
    roomId: gate1.roomId, token: JSON.parse(severedNotHeld.body).token,
  });

  // ------------------------------------------------------------ a new gate renames everyone
  //
  // The SAME two devices, in a new gate. Both the room secret and the slot ids are fresh,
  // so both names must be too: a name that carried over would be a handle for correlating
  // one gate with the next, which is the one thing a disposable identifier must never be.
  // This is why nothing about a name is persisted anywhere.
  await a.send('Page.navigate', { url: ORIGIN });
  await b.send('Page.navigate', { url: ORIGIN });
  await a.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'tab A back at home' });
  await b.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'tab B back at home' });

  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { label: 'tab A opened a second gate' });
  await a.eval("document.getElementById('reveal-share').click(); return true;");
  await a.waitFor("document.getElementById('share-shown').hidden === false", { label: 'tab A revealed the new code' });
  const rematchCode = await a.eval("return document.getElementById('room-code').textContent.trim();");
  const rematch = await roomIdFor(rematchCode);
  await b.eval(`
    document.getElementById('join-input').value = ${JSON.stringify(rematchCode)};
    document.getElementById('join-btn').click();
    return true;
  `);
  await a.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 30000, label: 'tab A connected in the second gate' });
  await b.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 30000, label: 'tab B connected in the second gate' });
  await a.waitFor(NAMED_ROSTER(2), { timeout: 20000, label: 'the second gate named its participants' });
  await b.waitFor(NAMED_ROSTER(2), { timeout: 20000, label: 'tab B named the second gate\'s participants' });

  const rematchA = await rosterOf(a);
  const rematchB = await rosterOf(b);
  const rematchNames = Object.values(rematchA.names);
  check('the same two devices still agree on names in a second gate',
    canonicalNames(rematchA.names) === canonicalNames(rematchB.names),
    `${JSON.stringify(rematchA.names)} vs ${JSON.stringify(rematchB.names)}`);
  check('and every one of them is different from the first gate, so names do not link gates',
    rematchNames.length === 2 && rematchNames.every((n) => !gate1Names.includes(n)),
    `now ${JSON.stringify(rematchNames)}, before ${JSON.stringify([...new Set(gate1Names)])}`);
  check('nor is any name written to storage, where it would outlive the gate',
    (await a.eval(`
      return Object.entries(sessionStorage).concat(Object.entries(localStorage))
        .filter(([, v]) => typeof v === 'string'
          && ${JSON.stringify(rematchNames)}.some((n) => v.includes(n))).length;
    `)) === 0);

  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 20000, label: 'the second gate was burned' });
  const rematchGone = await roomGone(rematch.roomId, rematch.secret);
  check('and the second gate is cleaned up behind it',
    rematchGone.gone, `${rematchGone.status} ${rematchGone.body}`);

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
  // The secret is no longer in the address bar, so reveal it to build the link.
  await d.eval("document.getElementById('reveal-share').click(); return true;");
  await d.waitFor("document.getElementById('share-shown').hidden === false", { label: 'tab D share revealed' });
  const code2 = await d.eval("return document.getElementById('room-code').textContent.trim();");
  const link2 = ORIGIN + '/#' + code2;

  const e = await browser.newTab(link2);
  await d.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab D connected' });
  await e.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 25000, label: 'tab E connected' });

  const gate2 = await roomIdFor(code2);
  check('a second gate connects independently of the first',
    gate2.roomId !== gate1.roomId, `${gate2.roomId} vs ${gate1.roomId}`);

  // "The only room" without a global counter: the new gate is held, and the old one is
  // still gone. Both halves have to hold, and each can fail on its own.
  const secondHeld = await roomHeld(gate2.roomId);
  const firstStillGone = await roomGone(gate1.roomId, gate1.secret);
  check('the second gate is held on the server', secondHeld.held, `${secondHeld.status} ${secondHeld.body}`);
  check('and the first gate is still gone, so nothing accumulated',
    firstStillGone.gone, `${firstStillGone.status} ${firstStillGone.body}`);

  // Navigating away fires pagehide, which is the closest a page gets to "tab closed".
  await e.send('Page.navigate', { url: 'about:blank' });

  await d.waitFor("!document.getElementById('screen-severed').hidden || document.getElementById('log').textContent.includes('disconnected')",
    { timeout: 20000, label: 'tab D notices the peer left' });
  // The wait accepts either of two outcomes, so it cannot say which one happened. Say it.
  const noticed = await d.eval(`
    return JSON.stringify({
      log: document.getElementById('log').textContent,
      severed: !document.getElementById('screen-severed').hidden,
    });
  `);
  const nt = JSON.parse(noticed);
  check('the remaining device is told when the other simply goes away',
    /disconnect|left|away|gone/i.test(nt.log) || nt.severed, nt.log.slice(-200));

  // The room deliberately survives one side leaving: that peer may simply be
  // reloading, and tab D is still attached and waiting. It is reaped only once
  // *nobody* is attached, so send tab D away too.
  const oneLeft = await roomHeld(gate2.roomId);
  check('a gate survives one side leaving, since that side may be reloading',
    oneLeft.held, `${oneLeft.status} ${oneLeft.body}`);

  await d.send('Page.navigate', { url: 'about:blank' });

  // The client no longer deletes the room on pagehide, because pagehide also fires on
  // reload and that destroyed the gate whenever either side refreshed. The server now
  // reaps a room once both sides have been absent for the grace period.
  let reaped = null;
  const reapDeadline = Date.now() + 15000;
  while (Date.now() < reapDeadline) {
    reaped = await roomGone(gate2.roomId, gate2.secret);
    // A refused probe is charged to the reject budget, so a long poll can end up being
    // rate limited. Stop rather than let 429 masquerade as the room's real state.
    if (reaped.gone || reaped.status === 429) break;
    await new Promise((r) => { setTimeout(r, 400); });
  }
  check('an abandoned gate is reaped once both sides are gone',
    reaped?.gone === true,
    reaped?.status === 429
      ? 'the probe was rate limited before the room was reaped, so this measured nothing'
      : `last answer: ${reaped?.status} ${reaped?.body}`);

  severTested = true;
} finally {
  await browser.close();
  await server.stop();
  fs.rmSync(TMP, { recursive: true, force: true });
}

check('the full lifecycle ran to completion', severTested);
process.exit(summary('browser end-to-end') ? 0 : 1);
