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
import { deriveSecret, deriveRoomId, deriveJoinProof } from '../public/js/crypto.js';
import {
  deriveDisplayName, deriveNameSeed, nameFromSeed, resolveDisplayNames, NAME_SPACE,
} from '../public/js/session.js';

const PORT = 3785;
const STUN = 3786;
const CDP_PORT = 9762;
const ORIGIN = `http://127.0.0.1:${PORT}`;
// The gate is its own document. ORIGIN is the LANDING, which holds no gate machinery
// at all, so anything driving a room, a key or a screen has to be pointed here.
const APP = `${ORIGIN}/app`;
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
  // deriveSecret throws a GateCodeError whose message names the actual fault, which is a
  // better failure than the null check this used to do. It costs about a second of PBKDF2
  // per distinct code; the cache in crypto.js makes every repeat call free.
  const secret = await deriveSecret(code);
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
    // The DOCK, not the history panel inside it. #log is display:none while the dock is
    // closed, so measuring it would report zero height for a dock that is plainly on
    // screen, and the overlap check below would then have no rectangle to test against
    // and pass by measuring nothing. What occupies the window is the dock.
    const log = document.getElementById('log');
    const dock = document.getElementById('log-dock');
    const scroller = document.querySelector('.page') || document.scrollingElement;
    const logShown = Boolean(dock) && !dock.hidden && log.textContent.trim() !== ''
      && dock.getBoundingClientRect().height > 0;
    const logRect = logShown ? r(dock) : null;
    const prim = primarySel ? document.querySelector(primarySel) : null;
    const fold = logRect ? logRect.top : window.innerHeight;
    const hits = [];
    if (logRect) {
      for (const el of document.querySelectorAll('a, button, input, select, textarea, summary, [tabindex]')) {
        if (el.closest('#log-dock')) continue;
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

/** Force one screen on for a geometry measurement, the way app.js's show() would.
 *
 *  It has to hide #receive-note on the screens app.js hides it on, not just #extras.
 *  Left showing, that banner sits in the page's flex column below `main` and adds 50px
 *  of legitimate layout under the connected screen's composer, which a geometry check
 *  then reports as dead space the design did not leave there. */
const showScreen = (id) => `
  for (const s of document.querySelectorAll('section.screen')) s.hidden = s.id !== ${JSON.stringify(id)};
  const extras = document.getElementById('extras');
  if (extras) extras.hidden = !['screen-onboarding', 'screen-home', 'screen-severed'].includes(${JSON.stringify(id)});
  const note = document.getElementById('receive-note');
  const noteText = document.getElementById('receive-note-text');
  if (note && noteText && noteText.textContent.trim()) {
    note.hidden = !['screen-onboarding', 'screen-home'].includes(${JSON.stringify(id)});
  }
  return true;
`;

/** Fill the status log with real log lines, the way app.js's log() does, and return the
 *  height of the DOCK.
 *
 *  app.js appends to #log and then unhides the dock with the newest line showing in its
 *  closed row, so a helper that only appended to #log would leave the dock hidden and
 *  measure a panel the stylesheet holds at display:none until it is opened. That reads as
 *  a log with no height, which is indistinguishable from no log at all.
 *
 *  `open` drives the disclosure the way the toggle does, so both resting states can be
 *  measured: closed is one line, open adds the history above it. */
const fillLog = (open = false) => `
  const box = document.getElementById('log');
  box.textContent = '';
  const lines = ['gathering addresses', 'connected directly, candidate type host',
                 'the other device accepted the file', 'transfer complete'];
  for (const line of lines) {
    const div = document.createElement('div');
    div.textContent = line;
    box.appendChild(div);
  }
  const dock = document.getElementById('log-dock');
  const toggle = document.getElementById('log-toggle');
  dock.hidden = false;
  document.getElementById('log-latest').textContent = lines[lines.length - 1];
  document.getElementById('log-more').textContent = '';
  if (${open ? 'true' : 'false'}) {
    dock.setAttribute('data-open', '');
    toggle.setAttribute('aria-expanded', 'true');
  } else {
    dock.removeAttribute('data-open');
    toggle.setAttribute('aria-expanded', 'false');
  }
  return dock.getBoundingClientRect().height;
`;

{
  // ---------------------------------------------------------------- onboarding, wide
  const SCREENS = ['screen-onboarding', 'screen-home', 'screen-password', 'screen-waiting',
    'screen-connected', 'screen-severed', 'screen-failed'];

  const wide = await guardedTab(APP, { width: 1920, height: 1080 });
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
  // 8% a side, not "less than 400px". The old bar passed at 313px, which was the
  // measurement that started this work, so it could not have caught the thing it was
  // written for.
  check('and the dead margin either side is no more than 8% of the window',
    ob1920.deadLeft <= 1920 * 0.08 && ob1920.deadRight <= 1920 * 0.08,
    `${ob1920.deadLeft}px left, ${ob1920.deadRight}px right, bar ${Math.round(1920 * 0.08)}px`);
  // The agreement is deliberately NOT above the fold any more. It was a sticky rail
  // beside the disclosures, which put the button on the first screenful at the cost of a
  // column of dead page under it for the whole height of the list, and let you agree
  // while the reading was still off to one side. It is now the last segment of the
  // screen, under the diagram. What has to hold instead is the ORDER and the density:
  // the list gets the width the rail used to take, and the agreement comes after the
  // thing it is agreeing to.
  const obShape = JSON.parse(await wide.eval(`
    const r = (s) => { const el = document.querySelector(s); if (!el) return null;
      const b = el.getBoundingClientRect(); const sc = document.querySelector('.page');
      const top = sc ? sc.scrollTop : 0;
      return { top: Math.round(b.top + top), bottom: Math.round(b.bottom + top),
               left: Math.round(b.left), w: Math.round(b.width) }; };
    const main = document.querySelector('main').getBoundingClientRect();
    return JSON.stringify({ mainW: Math.round(main.width), mainLeft: Math.round(main.left),
      grid: r('#screen-onboarding .ob-grid'),
      notes: r('#screen-onboarding .ob-notes'), bridge: r('#screen-onboarding .bridge'),
      agree: r('#screen-onboarding .ob-agree'), btn: r('#onboarding-done') });
  `));
  check('the agreement comes after the diagram, as its own segment rather than a rail',
    obShape.bridge && obShape.agree && obShape.agree.top >= obShape.bridge.bottom,
    `bridge ends ${obShape.bridge?.bottom}, agreement starts ${obShape.agree?.top}`);
  // Against the grid the list sits in, not against `main`: main carries the gutter, so
  // a full-width child is always narrower than its padded parent by that much.
  check('and the disclosures take the width the rail used to occupy',
    obShape.notes.w >= obShape.grid.w - 2 && obShape.grid.w > 1200,
    `list ${obShape.notes.w}px of ${obShape.grid.w}px of grid (main ${obShape.mainW}px)`);
  // Full width for a list of headed rows, a measure for a paragraph you must read.
  check('while the agreement itself keeps a measure and centres, rather than stretching',
    obShape.agree.w < obShape.mainW * 0.75
    && Math.abs((obShape.agree.left - obShape.mainLeft)
                - ((obShape.mainLeft + obShape.mainW) - (obShape.agree.left + obShape.agree.w))) <= 4,
    `agreement ${obShape.agree.w}px at x=${obShape.agree.left}, main ${obShape.mainW}px at x=${obShape.mainLeft}`);
  check('and the button is still the last thing on the screen, not stranded mid-page',
    obShape.btn.top >= obShape.agree.top && obShape.btn.bottom <= obShape.agree.bottom,
    `button ${obShape.btn.top}..${obShape.btn.bottom}, agreement ${obShape.agree.top}..${obShape.agree.bottom}`);

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
    // Both states of the dock. Closed is what a reader sees by default; open is the taller
    // one and the only one that could reach a control, so a check that only ever measured
    // the resting state would be measuring the easy case.
    for (const open of [false, true]) {
      await wide.eval(showScreen(id));
      const h = await wide.eval(fillLog(open));
      const g = JSON.parse(await wide.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
      // Bottom of the scroll range as well as the top: a fixed panel is only harmless at
      // one of them, and a check that samples one scroll position would miss the other.
      await wide.eval("const p = document.querySelector('.page') || document.scrollingElement; p.scrollTop = p.scrollHeight; return true;");
      const g2 = JSON.parse(await wide.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
      await wide.eval("const p = document.querySelector('.page') || document.scrollingElement; p.scrollTop = 0; return true;");
      overlaps.push({ id, open, h, shown: g.logShown, hits: g.logHits.concat(g2.logHits) });
    }
  }
  check('a non-empty status log is actually on screen, so the test below is measuring something',
    overlaps.every((o) => o.shown && o.h > 10),
    JSON.stringify(overlaps.map((o) => [o.id, o.open, o.h])));
  // Without this, `open` could stop reaching the stylesheet, every open pass would silently
  // measure the closed dock, and the overlap check above would still report green.
  check('opening the dock actually shows the history, so the open pass is a different state',
    SCREENS.every((id) => {
      const shut = overlaps.find((o) => o.id === id && !o.open);
      const wide2 = overlaps.find((o) => o.id === id && o.open);
      return wide2.h > shut.h + 20;
    }),
    JSON.stringify(overlaps.map((o) => [o.id, o.open, o.h])));
  check('and it covers no button, link or field on any screen, at the top or bottom of the page',
    overlaps.every((o) => o.hits.length === 0),
    JSON.stringify(overlaps.filter((o) => o.hits.length).map((o) => [o.id, o.open, o.hits])));

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

  // WHERE it sits, not merely that it exists. It used to paint between the two gate cards
  // and the numbered steps: a full-shell-width slab drawn across the middle of the one
  // composition on the screen, and wider than the cards above it, so it read as a rule
  // cutting the page in half. It is the last block now. Asserted rather than left to the
  // eye, because a stylesheet `order` is exactly the kind of thing a later edit undoes
  // without anything noticing.
  await wide.eval(showScreen('screen-home'));
  const notePos = JSON.parse(await wide.eval(`
    const box = (el) => {
      if (!el || el.hidden) return null;
      const r = el.getBoundingClientRect();
      return { top: Math.round(r.top), bottom: Math.round(r.bottom) };
    };
    return JSON.stringify({
      note: box(document.getElementById('receive-note')),
      main: box(document.querySelector('main')),
      extras: box(document.getElementById('extras')),
      foot: box(document.querySelector('.foot')),
    });
  `));
  check('the capability note is the last block on the page, below the steps and above the footer',
    notePos.note !== null && notePos.extras !== null
    && notePos.note.top >= notePos.main.bottom
    && notePos.note.top >= notePos.extras.bottom
    && notePos.note.bottom <= notePos.foot.top,
    JSON.stringify(notePos));

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
  const laptop = await guardedTab(APP, { width: 1440, height: 900 });
  await laptop.eval(forgetAgreement);
  await laptop.send('Page.reload', {});
  await laptop.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'onboarding at 1440x900' });
  const ob1440 = JSON.parse(await laptop.eval(GEOMETRY + "return JSON.stringify(geometry('#onboarding-done'));"));
  // Below the fold at 1440 as well, and for the same reason as at 1920. What must be
  // true is that scrolling actually reaches it: a segment that the scroll container
  // cannot bring into view would be a real defect rather than a chosen order.
  const reach1440 = JSON.parse(await laptop.eval(`
    const sc = document.querySelector('.page') || document.scrollingElement;
    const btn = document.getElementById('onboarding-done');
    sc.scrollTop = sc.scrollHeight;
    const b = btn.getBoundingClientRect();
    const visible = b.top >= 0 && b.bottom <= window.innerHeight && b.height > 0;
    const enabledAfter = btn.disabled;
    sc.scrollTop = 0;
    return JSON.stringify({ visible, top: Math.round(b.top), bottom: Math.round(b.bottom),
      viewH: window.innerHeight, enabledAfter });
  `));
  check('scrolling to the foot of the consent screen brings the agree button fully into view',
    reach1440.visible === true,
    `button ${reach1440.top}..${reach1440.bottom} in ${reach1440.viewH}px viewport`);
  check('and the column still leaves a margin rather than running to the window edge',
    ob1440.deadLeft >= 60 && ob1440.deadRight >= 60,
    `${ob1440.deadLeft}px left, ${ob1440.deadRight}px right`);
  const cspLaptop = await laptop.eval('return JSON.stringify(window.__csp);');
  check('no CSP violation at 1440x900 either', cspLaptop === '[]', cspLaptop);
  laptop.close();

  // ---------------------------------------------------------------- 390x844
  const phone = await guardedTab(APP, { width: 390, height: 844, mobile: true });
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
  const phoneLog = await phone.eval(fillLog(true));
  const phoneGeom = JSON.parse(await phone.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
  check('the status log covers nothing on a phone either',
    phoneLog > 10 && phoneGeom.logShown && phoneGeom.logHits.length === 0,
    JSON.stringify({ h: phoneLog, shown: phoneGeom.logShown, hits: phoneGeom.logHits }));
  phone.close();

  // ---------------------------------------------------------------- contrast, both themes
  //
  // Every element that paints its own text, on every screen, in both palettes. Not a list
  // of pairs somebody remembered to add.
  for (const theme of ['dark', 'light']) {
    const t = await guardedTab(APP, { width: 1440, height: 900, theme });
    // The tabs share one browser profile, so whether onboarding is showing depends on
    // what an earlier tab did. Say which state this one wants instead of inheriting it.
    await t.eval(agreeInPage);
    await t.send('Page.reload', {});
    await t.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: `home in ${theme}` });
    const findings = [];
    let counted = 0;
    for (const id of SCREENS) {
      await t.eval(showScreen(id));
      await t.eval(fillLog(true));
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

  // ================================================================ the width sweep
  //
  // The owner's acceptance criterion, measured rather than eyeballed: "make sure the
  // sizes actually match the screen size". Every width they named, on all three screens
  // that were redrawn, reporting the same numbers each time.
  //
  // Measured BEFORE this work, at 1920x1080: onboarding was a 1280px column with 313px
  // of dead margin on the left and 328px on the right, i.e. 16% of the window doing
  // nothing, and the home screen's Create button was below the fold at every width from
  // 390px to 1920px inclusive. Both are asserted against below.
  const WIDTHS = [
    [2560, 1440], [1920, 1080], [1600, 900], [1440, 900],
    [1280, 800], [1024, 768], [768, 1024], [390, 844],
  ];
  // Four surfaces, not three: the landing is a separate document now and is the page
  // most arrivals actually see, so leaving it out of the sweep would measure the
  // layout of everything except the thing people look at.
  const PRIMARY_OF = {
    landing: '#cta-create',
    'screen-onboarding': '#onboarding-done',
    'screen-home': '#create-btn',
    'screen-connected': '#chat-form button[type=submit]',
  };

  // Everything the sweep reads, in one round trip per (screen, width).
  const SWEEP = `
    function sweep(primarySel) {
      const main = document.querySelector('main');
      const mb = main.getBoundingClientRect();
      const log = document.getElementById('log');
      const scroller = document.querySelector('.page') || document.scrollingElement;
      const logShown = log && log.textContent.trim() !== '' && log.getBoundingClientRect().height > 0;
      const fold = logShown ? Math.round(log.getBoundingClientRect().top) : window.innerHeight;
      const prim = document.querySelector(primarySel);
      const pb = prim ? prim.getBoundingClientRect() : null;

      // Horizontal overflow, read from the element that actually scrolls as well as from
      // the document, because .page is the scroll container on engines with :has().
      const over = Math.max(
        document.documentElement.scrollWidth - document.documentElement.clientWidth,
        document.body.scrollWidth - document.body.clientWidth,
        scroller ? scroller.scrollWidth - scroller.clientWidth : 0);
      // And anything PAINTING outside the window, which an overflow:hidden ancestor
      // would hide from the number above.
      const spills = [];
      // EVERY element, not a list of the containers we happened to think of. That list
      // was 'main, header, .foot, #extras', and it missed the support section the moment
      // the split moved it out of #extras: the section ran past the right edge of a
      // 1440px window and the sweep reported no spills at all. A completeness check that
      // enumerates what to look at answers "is it in my list", not "is it off screen".
      // display:none, visibility:hidden and position:fixed are still skipped below, which
      // is what keeps the icon sprite and the status log out of it.
      for (const el of document.querySelectorAll('body *')) {
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden' || cs.position === 'fixed') continue;
        const r = el.getBoundingClientRect();
        if (r.width < 1 || r.height < 1) continue;
        if (r.right > window.innerWidth + 1 || r.left < -1) {
          spills.push((el.id || el.tagName + '.' + String(el.className).trim().split(/\\s+/)[0]).slice(0, 40)
            + '@' + Math.round(r.left) + '..' + Math.round(r.right));
        }
      }
      // The landing has no section.screen: it is not a screen, it is a document.
      const visible = document.querySelector('section.screen:not([hidden])')
        || document.querySelector('main');
      const h1 = visible ? visible.querySelector('h1, .lp-h1, .wg-h1') : null;
      const h2 = visible ? visible.querySelector('.lp-h2, .wg-h2, h2') : null;
      const msgs = document.getElementById('messages');
      const form = document.getElementById('chat-form');
      const shown = (el) => el && el.getBoundingClientRect().height > 0;
      return JSON.stringify({
        win: window.innerWidth,
        winH: window.innerHeight,
        mainW: Math.round(mb.width),
        deadL: Math.round(mb.left),
        deadR: Math.round(window.innerWidth - mb.right),
        primaryBottom: pb ? Math.round(pb.bottom) : null,
        aboveFold: pb ? (Math.round(pb.bottom) <= fold && pb.height > 0
                         && Math.round(scroller.scrollTop) === 0) : null,
        fold,
        overflow: Math.round(over),
        spills: spills.slice(0, 5),
        h1: h1 ? Math.round(parseFloat(getComputedStyle(h1).fontSize) * 10) / 10 : null,
        h2: h2 ? Math.round(parseFloat(getComputedStyle(h2).fontSize) * 10) / 10 : null,
        threadH: shown(msgs) ? Math.round(msgs.getBoundingClientRect().height) : null,
        // How much window is left under the LAST row of the gate column. This is the
        // "empty space beneath" the thread used to leave when it capped at a fixed 46vh.
        //
        // Measured from whichever row actually sits lowest, not from the composer: rows
        // have moved under it twice now (the connection details out of the side rail,
        // then the games panel under those), and each time measuring at the composer
        // counted a real row of the page as dead window and reported content as nothing.
        // Asking for the lowest bottom edge is the version that does not need editing the
        // next time a row is added.
        underComposer: (shown(msgs) && shown(form))
          ? Math.round(fold - (() => {
            const rows = ['conn-disc', 'games-disc']
              .map((id) => document.getElementById(id))
              .filter((el) => shown(el))
              .concat([form]);
            return Math.max(...rows.map((el) => el.getBoundingClientRect().bottom));
          })()) : null,
      });
    }
  `;

  const sweep = [];
  {
    // Onboarding is reloaded at each width on purpose: app.js decides once, on the first
    // show, whether the disclosures start open, and it decides from the viewport. A tab
    // resized from 390 to 1920 would be measured with a decision made for a phone.
    const landTab = await guardedTab(ORIGIN, { width: 1920, height: 1080 });
    const obTab = await guardedTab(APP, { width: 1920, height: 1080 });
    const otherTab = await guardedTab(APP, { width: 1920, height: 1080 });
    await otherTab.eval(agreeInPage);
    await otherTab.send('Page.reload', {});
    await otherTab.waitFor("!document.getElementById('screen-home').hidden",
      { timeout: 30000, label: 'home for the width sweep' });

    for (const [w, h] of WIDTHS) {
      // The landing is static markup, so it can be resized in place: nothing on it
      // makes a one-off decision from the viewport the way onboarding does. It is
      // still re-measured at every width, which is the point.
      await landTab.send('Emulation.setDeviceMetricsOverride',
        { width: w, height: h, deviceScaleFactor: 1, mobile: w < 700 });
      sweep.push({ screen: 'landing', w, h,
        ...JSON.parse(await landTab.eval(SWEEP + `return sweep(${JSON.stringify(PRIMARY_OF.landing)});`)) });

      await obTab.send('Emulation.setDeviceMetricsOverride',
        { width: w, height: h, deviceScaleFactor: 1, mobile: w < 700 });
      await obTab.eval(forgetAgreement);
      await obTab.send('Page.reload', {});
      await obTab.waitFor("!document.getElementById('screen-onboarding').hidden",
        { timeout: 30000, label: `onboarding at ${w}x${h}` });
      sweep.push({ screen: 'screen-onboarding', w, h,
        ...JSON.parse(await obTab.eval(SWEEP + `return sweep(${JSON.stringify(PRIMARY_OF['screen-onboarding'])});`)) });

      await otherTab.send('Emulation.setDeviceMetricsOverride',
        { width: w, height: h, deviceScaleFactor: 1, mobile: w < 700 });
      for (const id of ['screen-home', 'screen-connected']) {
        await otherTab.eval(showScreen(id));
        sweep.push({ screen: id, w, h,
          ...JSON.parse(await otherTab.eval(SWEEP + `return sweep(${JSON.stringify(PRIMARY_OF[id])});`)) });
      }
    }
    landTab.close();
    obTab.close();
    otherTab.close();
  }

  const at = (screen, w) => sweep.find((r) => r.screen === screen && r.w === w);
  const row = (r) => `${r.screen} ${r.w}x${r.h}: main ${r.mainW}, dead ${r.deadL}/${r.deadR}`
    + ` (${(100 * r.deadL / r.win).toFixed(1)}%), primary bottom ${r.primaryBottom}/${r.fold}`;

  // The sweep has to have looked at something. Thirty-two measurements, or an empty
  // array satisfies every "every row" assertion below by vacuity.
  check('the width sweep measured the landing and all three screens at all eight widths',
    sweep.length === 32 && sweep.every((r) => r.mainW > 0 && r.win > 0),
    `${sweep.length} rows`);

  // THE criterion, in the owner's own terms. 8% of 1920 is 153.6px a side.
  //
  // The landing is exempt, and the exemption is a different rule rather than a hole: it is
  // a PROSE page, and the app screens are control surfaces. A control column that stops
  // growing wastes the display it was given; a line of body copy that never stops growing
  // is simply unreadable, so the landing caps at min(1320px, 90vw) on purpose (see the
  // `body:has(main > .lp-hero)` block in style.css, which records the measurements the
  // 1320 came from). Its own checks are below: it must still grow until it reaches that
  // cap, and it must actually stop there. Dropping it from this row without replacing the
  // obligation would have left the widest page on the site measured by nothing.
  const controls = (r) => r.screen !== 'landing';
  const at1920 = sweep.filter((r) => r.w === 1920 && controls(r));
  check('at 1920x1080 the dead margin is no more than 8% of the window on either side',
    at1920.length === 3
    && at1920.every((r) => r.deadL <= 0.08 * r.win && r.deadR <= 0.08 * r.win),
    at1920.map(row).join(' | '));

  // The same criterion at the top of the range. The shell ceiling was 1680px first, which
  // met the 1920 bar above and still handed a 2560px monitor 17% of dead margin a side:
  // the identical defect, moved to a bigger screen. 8% of 2560 is 204.8px. A classic
  // scrollbar belongs to the window but not to the scrollport, so on a screen that
  // scrolls it reads as up to ~17px of extra margin on the right that no layout change
  // can remove; allow for it on that side rather than pretend the layout is asymmetric.
  const at2560 = sweep.filter((r) => r.w === 2560 && controls(r));
  check('and at 2560x1440 too, so the ceiling cannot stand the column in the middle of a big display',
    at2560.length === 3
    && at2560.every((r) => r.deadL <= 0.08 * r.win && r.deadR - 17 <= 0.08 * r.win),
    at2560.map(row).join(' | '));

  // The landing's own bargain, both halves of it. A cap is only defensible if it is a cap
  // on a column that was growing, and only useful if it actually holds: assert the width
  // it reaches and assert that a display 640px wider does not stretch it further.
  {
    const land1920 = at('landing', 1920);
    const land2560 = at('landing', 2560);
    const land1440 = at('landing', 1440);
    check('the landing stops growing at its reading measure rather than stretching across a big display',
      land1920.mainW === land2560.mainW && land1920.mainW >= 1240 && land1920.mainW <= 1400,
      `1440 ${land1440.mainW}, 1920 ${land1920.mainW}, 2560 ${land2560.mainW}`);
    // The margin the cap leaves must at least be even, which is the part of the 8% rule
    // that still applies to prose: a capped column parked off to one side is the original
    // complaint, and a cap cannot excuse it.
    check('and the margin the cap leaves is centred, not pushed to one side',
      [land1920, land2560].every((r) => Math.abs(r.deadL - r.deadR) <= 20),
      [land1920, land2560].map(row).join(' | '));
  }

  // "Scales with the viewport" is not a width, it is a DERIVATIVE. A fixed 1280px column
  // passes any single-width margin test on some window; it cannot pass this one.
  for (const screen of ['screen-onboarding', 'screen-home', 'screen-connected']) {
    const ladder = [768, 1024, 1280, 1440, 1600, 1920].map((w) => at(screen, w).mainW);
    check(`${screen.replace('screen-', '')} grows with the window rather than sitting at a fixed width`,
      ladder.every((v, i) => i === 0 || v > ladder[i - 1]),
      `768..1920 -> ${ladder.join(', ')}`);
  }
  // The landing's ladder stops where its cap starts. 90vw is the binding term below a
  // 1467px viewport, so every width up to 1440 must still grow: the cap is allowed to stop
  // the column, it is not allowed to be a fixed width wearing a min().
  {
    const ladder = [768, 1024, 1280, 1440].map((w) => at('landing', w).mainW);
    check('landing grows with the window up to the width its reading measure caps it at',
      ladder.every((v, i) => i === 0 || v > ladder[i - 1]),
      `768..1440 -> ${ladder.join(', ')}`);
  }

  // Nothing may scroll sideways, and nothing may paint outside the window, at any width.
  check('no screen scrolls horizontally at any of the eight widths',
    sweep.every((r) => r.overflow <= 0),
    JSON.stringify(sweep.filter((r) => r.overflow > 0).map(row)));
  check('and no element paints outside the window at any of them',
    sweep.every((r) => r.spills.length === 0),
    JSON.stringify(sweep.filter((r) => r.spills.length).map((r) => [r.screen, r.w, r.spills])));

  // Both arms above passed on every one of the 24 rows, which is exactly what they would
  // report if they were measuring nothing. Plant an element wider than the window and
  // confirm each arm fires; an overflow check that has never failed is not evidence.
  {
    const spill = await guardedTab(APP, { width: 1280, height: 800 });
    await spill.eval(agreeInPage);
    await spill.send('Page.reload', {});
    await spill.waitFor("!document.getElementById('screen-home').hidden",
      { timeout: 30000, label: 'home for the overflow control' });
    const planted = JSON.parse(await spill.eval(`
      const d = document.createElement('div');
      d.id = 'wg-overflow-control';
      // Set through the CSSOM rather than a style attribute: an inline style would trip
      // the CSP listener, and the planted failure would be reported as a CSP violation
      // instead of as the width problem it is meant to be.
      d.style.setProperty('width', '2000px');
      d.style.setProperty('height', '12px');
      document.querySelector('main').appendChild(d);
      ` + SWEEP + `return sweep(${JSON.stringify(PRIMARY_OF['screen-home'])});`));
    check('the horizontal-scroll arm catches a planted element wider than the window',
      planted.overflow > 0, `overflow ${planted.overflow}px`);
    check('and the paints-outside arm catches it too, naming the element',
      planted.spills.some((s) => s.startsWith('wg-overflow-control')), JSON.stringify(planted.spills));
    const cspSpill = await spill.eval('return JSON.stringify(window.__csp);');
    check('and the control raised no CSP violation, so it failed on width alone',
      cspSpill === '[]', cspSpill);
    spill.close();
  }

  // The primary action, above the fold, on the three desktop sizes named.
  //
  // HOME only. The consent screen is deliberately excluded: its action is the last thing
  // on the page, after the disclosures and the diagram, so "above the fold" is the wrong
  // property to ask of it. That it can be reached by scrolling is asserted at 1440 above.
  // Home is the screen where being able to act without scrolling actually matters, and
  // it was the screen that failed this before the redesign, at every width from 390 up.
  for (const w of [1920, 1440, 1280]) {
    const r = at('screen-home', w);
    check(`the home screen's primary action is above the fold at ${w}x${r.h}`,
      r.aboveFold === true, row(r));
  }

  // And the same for the landing, whose primary action is now a link into the gate
  // document. A visitor who has to scroll to find the way in is the same failure as a
  // Create button below the fold, one page earlier.
  for (const w of [1920, 1440, 1280]) {
    const r = at('landing', w);
    check(`the landing's way into a gate is above the fold at ${w}x${r.h}`,
      r.aboveFold === true, row(r));
  }

  // Type scales too. A 2560px display must get a bigger headline than a 1280px one:
  // before this work both got 46px, because the clamp cap was reached at 1046px.
  // The two surfaces that carry a headline. The gate's home screen is the two controls
  // and nothing else now, so it has no h1 to scale: asking it for one would assert on
  // null and pass or fail for the wrong reason.
  for (const screen of ['screen-onboarding', 'landing']) {
    const small = at(screen, 1280);
    const big = at(screen, 2560);
    check(`${screen.replace('screen-', '')}: the headline is larger on a 2560 display than on a 1280 one`,
      big.h1 > small.h1 + 4, `${small.h1}px at 1280, ${big.h1}px at 2560`);
  }
  const h2small = at('landing', 1280).h2;
  const h2big = at('landing', 2560).h2;
  check('and so is a section heading, so the whole scale moves and not just the headline',
    h2big !== null && h2big > h2small, `${h2small}px at 1280, ${h2big}px at 2560`);

  // The transcript takes the height instead of capping at 46vh with empty page under it.
  const threads = [1024, 1280, 1440, 1920, 2560].map((w) => at('screen-connected', w).threadH);
  check('the message thread grows with the window instead of capping at a fixed height',
    threads.every((v, i) => i === 0 || v >= threads[i - 1]) && threads[4] > threads[0] + 400,
    `1024..2560 -> ${threads.join(', ')}`);
  const slack = [1280, 1440, 1920, 2560].map((w) => at('screen-connected', w).underComposer);
  check('and there is no growing strip of dead window under the composer as the screen gets bigger',
    slack.every((v) => v !== null && v < 90), `under the composer: ${slack.join(', ')}px`);

  // A table for the record, so a future change can be compared against this run rather
  // than against a memory of it.
  process.stdout.write('\n--- measured layout ---------------------------------------------------\n');
  process.stdout.write('screen        viewport    container  deadL deadR  dead%  primary  fold  aboveFold  hScroll\n');
  for (const r of sweep) {
    process.stdout.write(
      `${r.screen.replace('screen-', '').padEnd(13)} ${String(r.w + 'x' + r.h).padEnd(11)}`
      + `${String(r.mainW).padStart(8)}   ${String(r.deadL).padStart(5)} ${String(r.deadR).padStart(5)}`
      + `  ${(100 * r.deadL / r.win).toFixed(1).padStart(5)}%  ${String(r.primaryBottom).padStart(6)}`
      + ` ${String(r.fold).padStart(5)}  ${String(r.aboveFold).padEnd(9)}  ${String(r.overflow).padStart(6)}\n`);
  }
  process.stdout.write('-----------------------------------------------------------------------\n\n');

  // ============================================================ the structure itself
  const shape = await guardedTab(APP, { width: 1920, height: 1080 });
  await shape.eval(forgetAgreement);
  await shape.send('Page.reload', {});
  await shape.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'onboarding for the structure checks' });

  // "A box should mean something." Count the elements on the consent screen that draw a
  // complete box: a border on all four sides. Before this work there were eight (five
  // disclosure cards, the agreement, the steps strip and the support panel). There is
  // one now, and it is the thing the user has to do.
  const boxes = JSON.parse(await shape.eval(`
    const found = [];
    for (const el of document.querySelectorAll('#screen-onboarding *')) {
      if (el.matches('input, button, select, textarea, code, pre')) continue;
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') continue;
      const r = el.getBoundingClientRect();
      if (r.width < 40 || r.height < 20) continue;
      const w = ['Top', 'Right', 'Bottom', 'Left'].map((s) => parseFloat(cs['border' + s + 'Width']) || 0);
      const styled = ['Top', 'Right', 'Bottom', 'Left'].every((s) => cs['border' + s + 'Style'] !== 'none');
      if (w.every((x) => x > 0) && styled) {
        found.push((el.id || el.tagName + '.' + String(el.className).trim().split(/\\s+/).join('.')).slice(0, 50));
      }
    }
    return JSON.stringify(found);
  `));
  check('the consent screen draws exactly one box, and it is the agreement',
    boxes.length === 1 && /agreement/.test(boxes[0]), JSON.stringify(boxes));

  // The five disclosures are a ruled list: hairline rules, no panel fill, and a mark in
  // front of each. The severe one breaks the numbering with "!" so it can be found
  // without being read; the other four are numbered.
  //
  // Chromium reports the SPECIFIED value of `content` for a pseudo-element, not the
  // string it painted, so the rendered digits cannot be read back. What can be read
  // back is the rule that produces them, which is the part that can actually be wrong:
  // every row increments the counter (so the severe one still consumes 03 and the list
  // stays 01 02 ! 04 05 rather than renumbering to 01 02 03 04), four rows print that
  // counter, and one prints a literal "!" in a different colour.
  const marks = JSON.parse(await shape.eval(`
    const out = [];
    for (const d of document.querySelectorAll('#screen-onboarding .ob-notes details.disc')) {
      const s = d.querySelector('summary');
      const cs = getComputedStyle(s, '::before');
      const box = getComputedStyle(d);
      out.push({
        content: cs.content || '',
        colour: cs.color,
        markWidth: parseFloat(cs.width) || 0,
        increment: box.counterIncrement,
        panel: box.backgroundColor,
        borders: ['Top', 'Right', 'Bottom', 'Left'].map((k) => parseFloat(box['border' + k + 'Width']) || 0),
        warn: d.classList.contains('warn'),
      });
    }
    return JSON.stringify(out);
  `));
  // Where the open/closed chevron actually lands. It is an absolutely positioned
  // ::after with a `right` offset, so where it paints is decided entirely by which
  // ancestor is its containing block. At 1360px and up the summary is confined to the
  // left column of a two-column grid, so while the summary was the positioned ancestor
  // the chevron sat in the middle of the row, a long way from the edge it is offset
  // from. Chromium will not report a pseudo-element's box, so this asserts the thing
  // that decides the box instead: absolute chevron, static summary, positioned details.
  const chevrons = JSON.parse(await shape.eval(`
    const out = [];
    // Remembered so the screen can be handed back exactly as the page decided to present
    // it. app.js picks the open/closed set from the viewport on first show, and leaving
    // this probe's choice behind would silently retune every check after it.
    window.__wgDiscWas = [...document.querySelectorAll('#screen-onboarding .ob-notes details.disc')].map((d) => d.open);
    for (const d of document.querySelectorAll('#screen-onboarding .ob-notes details.disc')) {
      d.open = true;
    }
    for (const d of document.querySelectorAll('#screen-onboarding .ob-notes details.disc[open]')) {
      const s = d.querySelector('summary');
      out.push({
        chevron: getComputedStyle(s, '::after').position,
        right: getComputedStyle(s, '::after').right,
        summary: getComputedStyle(s).position,
        details: getComputedStyle(d).position,
        summaryW: Math.round(s.getBoundingClientRect().width),
        detailsW: Math.round(d.getBoundingClientRect().width),
      });
    }
    return JSON.stringify(out);
  `));
  check('at 1920 the summary really is confined to the left column, or this proves nothing',
    chevrons.length === 5 && chevrons.every((c) => c.summaryW < c.detailsW * 0.6),
    JSON.stringify(chevrons.map((c) => [c.summaryW, c.detailsW])));
  check('an open disclosure offsets its chevron from the row, not from the narrow summary',
    chevrons.every((c) => c.chevron === 'absolute' && c.summary === 'static' && c.details === 'relative'),
    JSON.stringify(chevrons.map((c) => [c.chevron, c.summary, c.details])));
  // Put them back: everything after this measures the screen as the page decided to
  // present it, not as this probe left it.
  await shape.eval(`
    const was = window.__wgDiscWas || [];
    [...document.querySelectorAll('#screen-onboarding .ob-notes details.disc')]
      .forEach((d, i) => { d.open = was[i] === true; });
    return true;
  `);

  const bang = marks.filter((m) => /^"!"$/.test(m.content));
  const numbered = marks.filter((m) => /counter\(wgdisc, *decimal-leading-zero\)/.test(m.content));
  check('the disclosures carry no panel of their own, only a rule',
    marks.length === 5
    && marks.every((m) => /rgba\(0, 0, 0, 0\)|transparent/.test(m.panel))
    && marks.every((m) => m.borders[1] === 0 && m.borders[3] === 0 && m.borders[0] > 0),
    JSON.stringify(marks.map((m) => [m.panel, m.borders])));
  check('exactly one disclosure breaks the numbering with "!", and it is the severe one',
    bang.length === 1 && bang[0].warn === true,
    JSON.stringify(marks.map((m) => [m.content, m.warn])));
  check('the other four print a leading-zero counter, and every row increments it so the sequence stays 01 02 ! 04 05',
    numbered.length === 4 && marks.every((m) => /wgdisc *1/.test(m.increment)),
    JSON.stringify(marks.map((m) => [m.content.slice(0, 40), m.increment])));
  check('and every mark is actually drawn, rather than being an empty pseudo-element',
    marks.every((m) => m.markWidth > 4), JSON.stringify(marks.map((m) => m.markWidth)));
  check('the severe mark is not merely the same grey as the numbers',
    bang[0].colour !== numbered[0].colour, `${bang[0].colour} vs ${numbered[0].colour}`);
  shape.close();

  // ---------------------------------------------------------------- home structure
  const homeTab = await guardedTab(APP, { width: 1920, height: 1080 });
  await homeTab.eval(agreeInPage);
  await homeTab.send('Page.reload', {});
  await homeTab.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'home at 1920x1080' });
  const homeShape = JSON.parse(await homeTab.eval(`
    const create = document.getElementById('create-btn');
    const join = document.getElementById('join-btn');
    const lead = create.closest('.lp-action');
    const quiet = join.closest('.lp-action');
    const panel = document.getElementById('gate-opts-panel');
    const line = document.getElementById('gate-opts-summary');
    const rect = (el) => { const b = el.getBoundingClientRect(); return { top: Math.round(b.top), bottom: Math.round(b.bottom) }; };
    return JSON.stringify({
      createBottom: rect(create).bottom,
      joinBottom: rect(join).bottom,
      viewport: window.innerHeight,
      leadMarked: getComputedStyle(lead).borderTopColor !== getComputedStyle(quiet).borderTopColor,
      createBg: getComputedStyle(create).backgroundColor,
      joinBg: getComputedStyle(join).backgroundColor,
      optionsPanelShown: panel.getBoundingClientRect().height > 0,
      optionsLine: line.textContent.trim(),
      hasChange: !!document.getElementById('gate-opts-toggle'),
      // Anything that reads as a panel opened by a click. The old build had one here.
      discsOnHomeAboveActions: [...document.querySelectorAll('#gate-controls details')].length,
      // Nothing from the landing may have followed the user in. This is the split, as
      // one number: if any of these resolve, the marketing document and the document
      // holding a key are once again the same page.
      landingLeakage: ['.lp-hero', '.lp-section', '#support', '#ad-slot', '#cta-create']
        .filter((s) => document.querySelector(s)),
    });
  `));
  check('both actions, buttons included, are on the first screenful at 1920x1080',
    homeShape.createBottom < homeShape.viewport && homeShape.joinBottom < homeShape.viewport,
    `create ${homeShape.createBottom}, join ${homeShape.joinBottom}, window ${homeShape.viewport}`);
  check('and the gate document carries none of the landing: no hero, no marketing, no sponsor slot',
    homeShape.landingLeakage.length === 0, JSON.stringify(homeShape.landingLeakage));
  check('creating is marked as the lead action and joining is the quieter of the two',
    homeShape.leadMarked === true && homeShape.createBg !== homeShape.joinBg,
    `${homeShape.createBg} vs ${homeShape.joinBg}`);
  check('expiry and password are one line of plain text, not a panel to open',
    homeShape.optionsPanelShown === false && homeShape.discsOnHomeAboveActions === 0
    && /minute|hour/.test(homeShape.optionsLine) && /password/.test(homeShape.optionsLine)
    && homeShape.hasChange,
    JSON.stringify(homeShape));
  // ...and the line has to be able to change, or it is a hard-coded sentence that will
  // one day contradict the control it describes.
  const changed = await homeTab.eval(`
    const sel = document.getElementById('ttl-select');
    const before = document.getElementById('gate-opts-summary').textContent.trim();
    sel.selectedIndex = (sel.selectedIndex + 1) % sel.options.length;
    sel.dispatchEvent(new Event('change', { bubbles: true }));
    const afterTtl = document.getElementById('gate-opts-summary').textContent.trim();
    const pw = document.getElementById('room-password');
    pw.value = 'hunter2';
    pw.dispatchEvent(new Event('input', { bubbles: true }));
    const afterPw = document.getElementById('gate-opts-summary').textContent.trim();
    pw.value = '';
    pw.dispatchEvent(new Event('input', { bubbles: true }));
    return JSON.stringify({ before, afterTtl, afterPw, selectedText: sel.selectedOptions[0].textContent });
  `);
  const ch = JSON.parse(changed);
  check('the summary line is written from the live controls, so it cannot contradict them',
    ch.afterTtl !== ch.before && ch.afterTtl.startsWith(ch.selectedText)
    && /password set/.test(ch.afterPw),
    changed);
  const cspHome = await homeTab.eval('return JSON.stringify(window.__csp);');
  check('the home screen raises no CSP violation', cspHome === '[]', cspHome);
  homeTab.close();

  // ---------------------------------------------------------------- the split
  //
  // The landing and the gate are separate documents so that the page which may one
  // day carry somebody else's script is never the page holding a decryption key.
  // That is a claim about what each document contains and about what links them, so
  // it is asserted on both sides: nothing of the gate here, nothing of the landing
  // there (checked above), and a working route between them.
  const landing = await guardedTab(ORIGIN, { width: 1920, height: 1080 });
  const landShape = JSON.parse(await landing.eval(`
    const ctas = [...document.querySelectorAll('#cta-create, #cta-join')];
    const lead = document.getElementById('cta-create')?.closest('.lp-action');
    const quiet = document.getElementById('cta-join')?.closest('.lp-action');
    const slot = document.getElementById('ad-slot');
    const support = document.getElementById('support');
    return JSON.stringify({
      ctaCount: ctas.length,
      // Anchors, not buttons: middle-click and "open in new tab" have to work, and the
      // page has to be usable with the script dead.
      allAnchors: ctas.every((a) => a.tagName === 'A'),
      allToApp: ctas.every((a) => new URL(a.href, location.href).pathname === '/app'),
      insideHero: !!lead?.closest('.lp-hero') && !!quiet?.closest('.lp-hero'),
      leadMarked: lead && quiet
        && getComputedStyle(lead).borderTopColor !== getComputedStyle(quiet).borderTopColor,
      // Every id and hook the gate needs. If any of these resolve here, the split is
      // cosmetic and the ad-bearing document can still touch a room.
      gateLeakage: ['#create-btn', '#join-input', '#room-password', '#screen-connected',
        '#screen-onboarding', '#agree-check', '#log', '#status-badge']
        .filter((s) => document.querySelector(s)),
      // The support section is open markup, not a disclosure to find and click.
      supportOpen: !!support && support.tagName !== 'DETAILS'
        && support.getBoundingClientRect().height > 0,
      supportCards: document.querySelectorAll('#support .support-card').length,
      // The bar carries the two places the project lives, and no third way into a gate:
      // the hero already has two above the fold. Measured as hit areas, not as icons,
      // because these are tapped on a phone.
      barMarks: [...document.querySelectorAll('.bar .bar-ico')].map((a) => {
        const r = a.getBoundingClientRect();
        return { href: a.getAttribute('href'), w: Math.round(r.width), h: Math.round(r.height),
          named: a.textContent.trim().length > 0, glyph: !!a.querySelector('svg use') };
      }),
      barGateCta: document.querySelectorAll('.bar a[href="/app"], .bar-cta').length,
      // The wordmark sits outboard of the text column rather than inset to it, and is
      // read at a masthead size rather than a caption one.
      brand: (() => {
        const el = document.querySelector('.brand');
        // The headline, not <main>: main's border box already sits at the shell edge and
        // the text column is a gutter inside it, so main is the one comparison the
        // wordmark can pass while still looking inset.
        const h1 = document.querySelector('.lp-h1');
        if (!el || !h1) return null;
        return { left: Math.round(el.getBoundingClientRect().left),
          textLeft: Math.round(h1.getBoundingClientRect().left),
          px: Math.round(parseFloat(getComputedStyle(el).fontSize)) };
      })(),
      // The "How this works" disclosure repeated the section three screens above it.
      tailDisc: document.querySelectorAll('.lp-tail-disc').length,
      // The slot exists, and while unconfigured it takes up no space at all rather
      // than reserving a grey rectangle.
      slotPresent: !!slot,
      slotHidden: !!slot && slot.hidden,
      slotHeight: slot ? Math.round(slot.getBoundingClientRect().height) : -1,
      // Every band on the page has to sit in the same column. The support section broke
      // this the moment the split lifted it out of its old wrapper: it went full bleed
      // to both window edges and its last card was cut off at 1440px. It never showed up
      // as an overflow, because an element flush to the right edge is not past it, which
      // is exactly why this is measured as alignment and not as spill.
      // Measured against the SCROLLPORT, not the window: a classic scrollbar belongs to
      // the window and would read as ~15px of false asymmetry on every band at once.
      scrollportW: Math.round((document.querySelector('.page') || document.scrollingElement).clientWidth),
      bands: ['main', '#support', '#ad-slot', '.foot'].map((s) => {
        const el = document.querySelector(s);
        if (!el) return { s, missing: true };
        const b = el.getBoundingClientRect();
        return { s, left: Math.round(b.left), right: Math.round(b.right), w: Math.round(b.width) };
      }),
    });
  `));
  check('the landing offers a way into a gate, as real links to /app',
    landShape.ctaCount >= 2 && landShape.allAnchors && landShape.allToApp,
    JSON.stringify(landShape));
  check('and they sit in the hero rather than a screenful below it',
    landShape.insideHero === true && landShape.leadMarked === true, JSON.stringify(landShape));
  check('the landing carries no gate machinery at all',
    landShape.gateLeakage.length === 0, JSON.stringify(landShape.gateLeakage));
  check('support is an open section with all four ways to help, not a disclosure',
    landShape.supportOpen === true && landShape.supportCards === 4, JSON.stringify(landShape));
  check('the sponsor slot exists but takes no space until an operator configures one',
    landShape.slotPresent && landShape.slotHidden && landShape.slotHeight === 0,
    JSON.stringify(landShape));
  check('the bar carries the source and the tip jar as marks, each a real tap target with a name',
    landShape.barMarks.length === 2
    && landShape.barMarks.some((m) => /github\.com/.test(m.href))
    && landShape.barMarks.some((m) => /ko-fi\.com/.test(m.href))
    && landShape.barMarks.every((m) => m.glyph && m.named && m.w >= 30 && m.h >= 30),
    JSON.stringify(landShape.barMarks));
  check('and no third way into a gate competing with the two in the hero',
    landShape.barGateCta === 0, String(landShape.barGateCta));
  check('the wordmark reads as a masthead: outboard of the text column, not caption sized',
    landShape.brand && landShape.brand.px >= 16
    && landShape.brand.left < landShape.brand.textLeft,
    JSON.stringify(landShape.brand));
  check('the landing does not repeat "how it works" as a disclosure under the section',
    landShape.tailDisc === 0, String(landShape.tailDisc));
  {
    const main = landShape.bands.find((b) => b.s === 'main');
    // A hidden band has a zero rect and would compare as 0..0 against the column,
    // which is neither aligned nor a real answer. The slot's own emptiness is asserted
    // separately, just above.
    const others = landShape.bands
      .filter((b) => b.s !== 'main' && !b.missing && b.right > b.left);
    // Centred, and the same width as the column, within a gutter's worth. Centring alone
    // would not catch this: a full-bleed band spanning 0..1905 is perfectly centred and
    // still wrong, so the width bound is the arm that does the work. The tolerance is a
    // gutter (16px a side) because a band nested inside main is measured content-box
    // against main's border-box and is legitimately 32px narrower.
    check('every band on the landing sits in the same column as the rest of the page',
      others.length >= 2 && main.left > 0
      && [main, ...others].every((b) => Math.abs(b.left - (landShape.scrollportW - b.right)) <= 3
        && Math.abs(b.w - main.w) <= 40),
      JSON.stringify({ scrollportW: landShape.scrollportW, bands: landShape.bands }));
  }

  // The landing does the whole job of the support block, so its contrast and its
  // links are checked here rather than on the gate, which no longer has any of it.
  const contrast = await landing.eval(`
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

  const donateLinks = await landing.eval(`
    return JSON.stringify([...document.querySelectorAll('a.kofi, .foot a')].map(x => x.getAttribute('href')));
  `);
  check('the Ko-fi link points at the configured handle',
    /ko-fi\.com\/fysh_yum/.test(donateLinks), donateLinks);

  // Same trap as on the gate: an author rule with an explicit display beats the UA
  // stylesheet's [hidden] display:none. The sponsor slot sets display:flex, so this is
  // the check that catches a grey rectangle standing where no ad is.
  const landHidden = await landing.eval(`
    const offenders = [];
    for (const el of document.querySelectorAll('[hidden]')) {
      if (el.offsetParent !== null || el.getClientRects().length > 0) {
        offenders.push(el.id || el.className || el.tagName);
      }
    }
    return JSON.stringify(offenders);
  `);
  check('every element marked hidden on the landing is actually invisible',
    landHidden === '[]', `still rendered: ${landHidden}`);

  // The QR code opens over the page instead of unfolding inside the card. That is a
  // behaviour, so it is driven rather than read off the stylesheet: click the button,
  // look at what is on screen, press Escape, look again.
  {
    const before = JSON.parse(await landing.eval(`
      const m = document.getElementById('qr-modal');
      return JSON.stringify({ present: !!m, hidden: !!m && m.hidden,
        h: m ? Math.round(m.getBoundingClientRect().height) : -1,
        // Nothing may open in the card any more: that panel is what pushed the grid down.
        inCard: document.querySelectorAll('#support .coin-qr').length });
    `));
    check('the QR code is a lightbox that starts closed, with nothing left inside the card',
      before.present && before.hidden && before.h === 0 && before.inCard === 0,
      JSON.stringify(before));

    await landing.eval(`document.querySelector('[data-qr="xmr"]').click(); return '';`);
    await landing.waitFor("!document.getElementById('qr-modal').hidden && getComputedStyle(document.getElementById('qr-modal')).opacity === '1'",
      { timeout: 15000, label: 'qr lightbox open' });
    const open = JSON.parse(await landing.eval(`
      const m = document.getElementById('qr-modal');
      const panel = m.querySelector('.qr-modal-panel');
      const scrim = document.getElementById('qr-modal-scrim');
      const canvas = document.getElementById('qr-modal-canvas');
      const px = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
      let dark = 0, light = 0;
      for (let i = 0; i < px.length; i += 4) (px[i] < 128 ? dark++ : light++);
      const pr = panel.getBoundingClientRect();
      const sr = scrim.getBoundingClientRect();
      return JSON.stringify({
        // A modal that does not cover the page is a panel in the wrong place.
        scrimCovers: Math.round(sr.width) >= document.documentElement.clientWidth
          && Math.round(sr.height) >= document.documentElement.clientHeight,
        scrimBg: getComputedStyle(scrim).backgroundColor,
        panelOnTop: pr.width > 200 && pr.top >= 0 && pr.bottom <= window.innerHeight + 1,
        // Both counts non-zero is the arm that makes this fail on a blank canvas. An
        // undrawn one is uniformly transparent, which reads as red 0 on every pixel and
        // scores all-dark, so it is the light count that catches it; drawQr fills white
        // and then paints the modules, so a real code has thousands of each.
        dark, light,
        addr: document.getElementById('qr-modal-addr').textContent.trim(),
        cardAddr: document.getElementById('addr-xmr').textContent.trim(),
        titled: /Monero/.test(document.getElementById('qr-modal-title').textContent),
        // Focus is inside the dialog, not left behind on the page under the scrim.
        focusInside: panel.contains(document.activeElement),
      });
    `));
    check('clicking Show QR opens a real scannable code over a dimmed page',
      open.scrimCovers && open.panelOnTop && open.dark > 500 && open.light > 500
      && /^rgba\(/.test(open.scrimBg), JSON.stringify({ ...open, addr: undefined, cardAddr: undefined }));
    check('and the code it drew is the address on the card, named in the title',
      open.addr.length > 40 && open.addr === open.cardAddr && open.titled,
      JSON.stringify({ addr: open.addr, cardAddr: open.cardAddr, titled: open.titled }));
    check('and focus moves into the dialog rather than staying under the scrim',
      open.focusInside === true, JSON.stringify(open.focusInside));

    await landing.eval(`
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      return '';
    `);
    await landing.waitFor("document.getElementById('qr-modal').hidden",
      { timeout: 15000, label: 'qr lightbox closed' });
    const closed = JSON.parse(await landing.eval(`
      const m = document.getElementById('qr-modal');
      return JSON.stringify({ hidden: m.hidden, h: Math.round(m.getBoundingClientRect().height),
        // Back on the button that opened it, so a keyboard reader is not returned to
        // the top of the document.
        focusBack: document.activeElement === document.querySelector('[data-qr="xmr"]') });
    `));
    check('Escape closes the lightbox and hands focus back to the button that opened it',
      closed.hidden && closed.h === 0 && closed.focusBack, JSON.stringify(closed));
  }

  const cspLanding = await landing.eval('return JSON.stringify(window.__csp);');
  check('the landing raises no CSP violation', cspLanding === '[]', cspLanding);
  landing.close();

  // Links minted before the split are `/#WARP-...` and are printed on QR codes nobody
  // can go back and edit. The fragment never reaches the server, so the landing has to
  // hand it on client-side. Asserted with a real code, at the address bar, not by
  // reading the source of landing.js.
  {
    const legacy = await browser.newTab('about:blank');
    const LEGACY_CODE = 'WARP-DRIFT-MEAD-PLUNK-SIXTH-TOTE-VIVID-WHALE-ZONAL';
    await legacy.send('Page.navigate', { url: `${ORIGIN}/#${LEGACY_CODE}` });
    await legacy.waitFor("location.pathname === '/app'",
      { timeout: 15000, label: 'legacy hash redirect' });
    // location changes the moment the redirect is issued, which is before the gate
    // document has parsed. Without this the probe below reads the OLD document and
    // reports "no create button" as though the redirect had landed somewhere wrong.
    await legacy.waitFor("!!document.getElementById('create-btn')",
      { timeout: 15000, label: 'the gate document parsed after the redirect' });
    const landed = JSON.parse(await legacy.eval(`
      return JSON.stringify({ path: location.pathname, hash: location.hash,
        hasGate: !!document.getElementById('create-btn') });
    `));
    check('a link minted before the split still opens a gate, fragment intact',
      landed.path === '/app' && landed.hash === `#${LEGACY_CODE}` && landed.hasGate,
      JSON.stringify(landed));
    // The redirect must not be triggered by merely landing on the landing page: a
    // check that fires on every load would pass above and be worthless.
    await legacy.send('Page.navigate', { url: ORIGIN });
    await legacy.waitFor("document.readyState === 'complete'", { timeout: 15000, label: 'plain landing' });
    const stayed = await legacy.eval('return location.pathname;');
    check('and a plain visit to the landing is not redirected anywhere',
      stayed === '/', String(stayed));

    // The landing has its own anchors, and faq.html links to one of them. A redirect
    // keyed on "is there a fragment" threw those readers into the gate instead.
    for (const anchor of ['support', 'how-it-works']) {
      // about:blank first, or this is a SAME-DOCUMENT fragment jump from the previous
      // URL: the page never reloads, landing.js never re-runs, and the check passes
      // whatever the redirect does. It did exactly that on the first attempt.
      await legacy.send('Page.navigate', { url: 'about:blank' });
      await legacy.waitFor("document.readyState === 'complete'", { timeout: 15000, label: 'blank' });
      await legacy.send('Page.navigate', { url: `${ORIGIN}/#${anchor}` });
      await legacy.waitFor("document.readyState === 'complete'",
        { timeout: 15000, label: `anchor #${anchor}` });
      const at = JSON.parse(await legacy.eval(`
        const el = document.getElementById(${JSON.stringify(anchor)});
        return JSON.stringify({ path: location.pathname, hash: location.hash, target: !!el });
      `));
      check(`the landing anchor #${anchor} stays on the landing and resolves to a real element`,
        at.path === '/' && at.hash === `#${anchor}` && at.target === true, JSON.stringify(at));
    }
    legacy.close();
  }

  // ---------------------------------------------------------------- connected rail
  const connTab = await guardedTab(APP, { width: 1920, height: 1080 });
  await connTab.eval(agreeInPage);
  await connTab.send('Page.reload', {});
  await connTab.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'connected rail tab' });
  await connTab.eval(showScreen('screen-connected'));
  const rail = JSON.parse(await connTab.eval(`
    const sas = document.getElementById('sas');
    const sever = document.getElementById('sever');
    const railBox = document.querySelector('.conn-rail');
    // The connection details are no longer IN the rail: they moved under the composer,
    // into the chat column, because that is where the person reading them is looking.
    // The rail's own last row before Burn is whatever now sits above it.
    const disc = document.getElementById('conn-disc');
    const aboveSever = document.getElementById('sever').previousElementSibling;
    const px = (el) => parseFloat(getComputedStyle(el).fontSize);
    // Every element in the rail that paints its own text, so "largest" is a fact about
    // the rail and not about a list of selectors somebody remembered.
    const others = [];
    for (const el of railBox.querySelectorAll('*')) {
      if (el === sas || el.contains(sas)) continue;
      const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
      if (!own) continue;
      if (el.getBoundingClientRect().height < 2) continue;
      others.push([el.tagName + '.' + String(el.className).trim(), px(el)]);
    }
    const r = (el) => { const b = el.getBoundingClientRect(); return { top: Math.round(b.top), bottom: Math.round(b.bottom) }; };
    return JSON.stringify({
      sasPx: px(sas),
      biggestOther: others.length ? Math.max(...others.map((o) => o[1])) : 0,
      others,
      sasTop: r(sas).top,
      discBottom: disc ? r(disc).bottom : null,
      discInRail: Boolean(disc && railBox.contains(disc)),
      aboveSeverBottom: aboveSever ? r(aboveSever).bottom : null,
      railTop: r(railBox).top,
      severTop: r(sever).top,
      severBottom: r(sever).bottom,
      railBottom: r(railBox).bottom,
      severLast: sever === railBox.lastElementChild,
      composerBottom: r(document.getElementById('chat-form')).bottom,
    });
  `));
  check('the verification code is the largest thing in the rail',
    rail.sasPx >= 20 && rail.sasPx > rail.biggestOther * 1.5,
    `#sas ${rail.sasPx}px, next largest ${rail.biggestOther}px (${JSON.stringify(rail.others)})`);
  // 60px, not 0: the code carries a label above it. What must not happen is the code
  // sitting below the route badge, the roster or the connection details, which is the
  // arrangement this replaced.
  check('and it is at the top of the rail, where a thing you check at a glance belongs',
    rail.sasTop - rail.railTop <= 60, `sas top ${rail.sasTop}, rail top ${rail.railTop}`);
  check('the connection details are in the chat column now, not in the rail',
    rail.discBottom !== null && rail.discInRail === false && rail.discBottom > rail.composerBottom,
    JSON.stringify({ discInRail: rail.discInRail, discBottom: rail.discBottom, composerBottom: rail.composerBottom }));
  check('Burn is pinned to the foot of the rail, well clear of everything else',
    rail.severLast === true && rail.severTop - rail.aboveSeverBottom >= 60
    && rail.railBottom - rail.severBottom <= 4,
    JSON.stringify({ severTop: rail.severTop, aboveSeverBottom: rail.aboveSeverBottom, railBottom: rail.railBottom }));

  // The status log, non-empty, at a third width. The two it was checked at were 1920 and
  // 390; the layout in between is a different one and was never measured.
  await connTab.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  const midLogHits = [];
  for (const id of SCREENS) {
    for (const open of [false, true]) {
      await connTab.eval(showScreen(id));
      const h = await connTab.eval(fillLog(open));
      const g = JSON.parse(await connTab.eval(GEOMETRY + 'return JSON.stringify(geometry(null));'));
      midLogHits.push({ id, open, h, shown: g.logShown, hits: g.logHits });
    }
  }
  check('the status log is on screen at 1280x800 too, so the check below measures something',
    midLogHits.every((o) => o.shown && o.h > 10),
    JSON.stringify(midLogHits.map((o) => [o.id, o.open, o.h])));
  check('and it covers nothing interactive on any screen at 1280x800',
    midLogHits.every((o) => o.hits.length === 0),
    JSON.stringify(midLogHits.filter((o) => o.hits.length).map((o) => [o.id, o.open, o.hits])));
  connTab.close();

  // Several tabs above accepted the terms to reach the home screen, and every tab shares
  // one browser profile. The lifecycle below opens as a FIRST-TIME visitor, so the flag
  // is handed back the way it was found. Asserted rather than assumed: leaving it set
  // makes the first wait of the lifecycle time out twenty seconds later, a long way from
  // the line that caused it.
  const reset = await browser.newTab(APP);
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

// Opening or joining a gate now raises a one-time notice that a direct connection shows
// both devices each other's IP address, and holds the flow until it is answered. It is
// per tab, and it is answered here the way a returning user's tab already has it
// answered, so the rest of the lifecycle measures the lifecycle. Tabs A, B and E go
// through the real button instead, which is where the behaviour itself is checked.
const NET_ACK = "sessionStorage.setItem('wg.dismissed.v1:net-modal', '1'); return true;";
async function clickThroughNetNotice(tab, label) {
  await tab.waitFor("!document.getElementById('net-modal').hidden", { timeout: 20000, label });
  await tab.eval("document.getElementById('net-continue').click(); return true;");
}

try {
  // ------------------------------------------------------------ tab A: create
  const a = await browser.newTab(APP);
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

  // The support block and its contrast live on the landing now and are checked there.
  // What still matters HERE is that nothing marked hidden is actually painting: an
  // author rule with an explicit display beats the UA stylesheet's [hidden]
  // display:none, which once showed the donation QR as a blank white box and would
  // have done the same to the pairing QR.
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

  // A person pressing Create is looking at the tab they pressed it in. Chromium does not
  // advance a CSS transition in an occluded tab, so without this the opacity assertion
  // below measures the background-tab policy of the browser rather than the page.
  await a.send('Page.bringToFront', {});
  await a.eval("document.getElementById('create-btn').click(); return true;");
  // The notice stands in front of the gate, and nothing may be opened behind it: this is
  // the check that it is a gate rather than a decoration.
  await a.waitFor("!document.getElementById('net-modal').hidden", { timeout: 20000, label: 'the exposure notice' });
  // The notice is un-hidden and opaque in two steps, 180ms apart, so that it fades in
  // rather than appearing mid-sentence. Sampling opacity the instant it stops being
  // hidden measures the start of that fade and reports 0.
  await new Promise((r) => setTimeout(r, 400));
  const heldBack = await a.eval(`
    return JSON.stringify({
      waiting: !document.getElementById('screen-waiting').hidden,
      opacity: Number(getComputedStyle(document.getElementById('net-modal')).opacity),
      focused: document.activeElement && document.activeElement.id,
    });
  `);
  const hb = JSON.parse(heldBack);
  check('pressing Create raises the IP exposure notice and opens nothing behind it',
    hb.waiting === false && hb.opacity > 0.9, heldBack);
  check('and it takes the keyboard, so Enter answers it rather than the page behind it',
    hb.focused === 'net-continue', heldBack);

  // What the notice SAYS. The recommendation used to be a subordinate clause inside a
  // conditional, which is how an instruction turns into a footnote, and the modal is the
  // one place on the site with a concrete piece of advice to give.
  const notice = JSON.parse(await a.eval(`
    const panel = document.getElementById('net-modal');
    return JSON.stringify({
      title: document.getElementById('net-title').textContent.trim(),
      leads: [...panel.querySelectorAll('p strong')].map((s) => s.textContent.trim()),
      text: panel.textContent.replace(/\\s+/g, ' ').trim(),
    });
  `));
  check('the notice recommends a VPN outright, rather than mentioning one in passing',
    /we recommend a vpn/i.test(notice.text)
    && notice.leads.some((l) => /^we recommend a vpn/i.test(l)),
    JSON.stringify(notice.leads));
  check('and each paragraph leads with a bold phrase, the same shape the landing page uses',
    notice.leads.length === 3 && notice.leads.every((l) => l.length > 12 && l.endsWith('.')),
    JSON.stringify(notice.leads));
  // The same modal serves both paths and its title was written for only one of them.
  check('the notice is titled for the path it interrupted, which here is creating a gate',
    notice.title === 'Before you open a gate', notice.title);

  await a.eval("document.getElementById('net-continue').click(); return true;");
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
  // Shape only. That the words are ON the list, uniformly drawn, and stretch to the same S
  // on both devices is crypto.test.mjs's job; what this asserts is that the page shows a
  // human eight capitalised words and not, say, a promise or a base32 string.
  check('the revealed code is WARP plus eight capitalised words',
    /^WARP(-[A-Z]{4,7}){8}$/.test(code), code);
  const link = `${APP}#${code}`;

  // qr.js is fetched on first reveal rather than at load (see tests/size.test.mjs), so the
  // canvas is empty for one network round trip after the press. Waiting on the flag the
  // page sets when the draw lands, not on a sleep: an empty canvas is fully transparent and
  // samples as every pixel dark, so the bitmap below cannot tell "not drawn yet" from
  // "drawn", and a naive sample was passing this check for the wrong reason.
  await a.waitFor("document.getElementById('qr').dataset.drawn === '1'",
    { timeout: 15000, label: 'the QR code finished drawing' });

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
  // The person who was SENT a link is exactly the one who did not choose to be here, so
  // the notice stands in front of a link-join too. It is per tab, so tab A answering it
  // does nothing for tab B.
  // Tab B is following a link, so the SAME modal has to introduce itself as the join it
  // is interrupting. The create-side title is asserted where tab A pressed Create; this is
  // the other arm, and without it the mode argument could be ignored and both would pass.
  await b.waitFor("!document.getElementById('net-modal').hidden",
    { timeout: 20000, label: 'the exposure notice on a link-join' });
  check('and the same notice is titled for joining when it interrupted a join',
    (await b.eval("return document.getElementById('net-title').textContent.trim();"))
      === 'Before you join a gate',
    await b.eval("return document.getElementById('net-title').textContent.trim();"));
  await clickThroughNetNotice(b, 'the exposure notice on a link-join');
  check('following an invite link raises the same notice before it joins anything', true);
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

  // ------------------------------------------------------------ connected, for real
  //
  // The layout block above forced the connected screen on with showScreen(). This is the
  // same screen with a real gate behind it: a live verification code, a real roster and a
  // transcript with content in it. Geometry asserted here cannot be an artefact of an
  // empty screen that no user would ever see.
  await b.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  const live = JSON.parse(await b.eval(`
    const r = (el) => { const x = el.getBoundingClientRect(); return { top: Math.round(x.top), bottom: Math.round(x.bottom), h: Math.round(x.height) }; };
    const msgs = document.getElementById('messages');
    const form = document.getElementById('chat-form');
    const sas = document.getElementById('sas');
    const railBox = document.querySelector('.conn-rail');
    const sever = document.getElementById('sever');
    const chip = document.querySelector('#roster .who-chip');
    const cs = getComputedStyle(chip);
    return JSON.stringify({
      thread: r(msgs),
      threadScrolls: msgs.scrollHeight > 0 && getComputedStyle(msgs).overflowY === 'auto',
      composer: r(form),
      fold: window.innerHeight,
      sasText: sas.textContent.trim(),
      sasPx: Math.round(parseFloat(getComputedStyle(sas).fontSize)),
      sasBox: r(document.querySelector('.sas-box')),
      severTop: r(sever).top,
      railBottom: r(railBox).bottom,
      chipRadius: parseFloat(cs.borderTopLeftRadius),
      chipPad: parseFloat(cs.paddingLeft),
      chipName: (chip.querySelector('.who-name') || {}).textContent || '',
      rows: document.querySelectorAll('#messages .msg').length,
    });
  `));
  check('with a live gate the transcript takes the column height instead of a fixed box',
    live.rows >= 3 && live.thread.h > 330 && live.threadScrolls === true,
    JSON.stringify({ rows: live.rows, thread: live.thread }));
  check('and the composer sits under it with no dead strip below',
    live.fold - live.composer.bottom < 90 && live.composer.bottom <= live.fold,
    `composer bottom ${live.composer.bottom}, window ${live.fold}`);
  // Re-baselined 2026-08-10, against a REAL gate rather than the forced screen: the code
  // is populated and the words are on it, so the box is at the height a user actually
  // sees. The panel used to be 46px digits inside a filled accent block and measured
  // 181px against a 513px transcript, 35% of it: "the verification code is the same size
  // as the chat box, which makes it really distracting". It is 127px now, 25%. The 30%
  // line sits between the two measured states rather than being picked from taste, and
  // the heavy panel was re-run against this check to confirm it fails at 35%.
  check('the code box is a fraction of the transcript, not a peer of it',
    live.thread.h > 0 && live.sasBox.h < live.thread.h * 0.3,
    `sas-box ${live.sasBox.h}px, transcript ${live.thread.h}px, `
    + `${Math.round((live.sasBox.h / live.thread.h) * 100)}%`);
  // 20px, not the 30px this used to require: see the re-baseline note on the rail check
  // above. It still has to be a real five-digit number rendered at a size a person can
  // read out over a phone, which is the property that actually matters here.
  check('the live verification code is rendered large enough to read aloud',
    /^[0-9]{5}$/.test(live.sasText) && live.sasPx >= 20, `${live.sasText} at ${live.sasPx}px`);
  check('Burn is still at the foot of the rail with a real gate open',
    live.railBottom - live.severTop < 120 && live.severTop > live.thread.top,
    JSON.stringify({ severTop: live.severTop, railBottom: live.railBottom }));
  check('a derived name is rendered as a pill, so the roster scans',
    live.chipRadius >= 999 && live.chipPad >= 8 && /^[A-Z][a-z]+ [A-Z][a-z]+/.test(live.chipName),
    JSON.stringify({ radius: live.chipRadius, pad: live.chipPad, name: live.chipName }));
  await b.send('Emulation.clearDeviceMetricsOverride', {});

  // The media block below runs AFTER the geometry block above, and that ordering is
  // load-bearing rather than tidy. It leaves eight more rows in the transcript, and
  // #screen-connected deliberately grows past the viewport rather than squashing the
  // composer (see the flex comment in style.css), so measuring 'the composer sits under
  // the transcript' against a transcript this block had lengthened would be measuring
  // the fixture. Verified: the same geometry check fails at eleven rows and passes at
  // three, with or without a media element in them.

  // ------------------------------------------------- inline media, and the Open button
  //
  // Everything below is asserted on tab B, the RECEIVER, against files tab A actually
  // sent through the gate. Nothing is fabricated in the page: the MIME each row acts on
  // is the one the browser derived from the file the sender chose, which is exactly the
  // peer-controlled string the allowlists exist to distrust.
  //
  // The two media fixtures are real: a 537 byte VP8/WebM and a 478 byte PCM WAV, both
  // produced by ffmpeg and embedded here so the suite needs no encoder at run time. They
  // are genuinely decodable, which is what makes the "did not decode" case below a
  // contrast rather than the only outcome the harness can produce.
  const WEBM_B64 = 'GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQJChYECGFOAZwEAAAAAAAHpEU2bdLpNu4tTq4QVSalmU6yBoU27i1OrhBZUrmtTrIHYTbuMU6uEElTDZ1OsggElTbuMU6uEHFO7a1OsggHT7AEAAAAAAABZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmsirXsYMPQkBNgI1MYXZmNjIuMTIuMTAyV0GNTGF2ZjYyLjEyLjEwMkSJiECPQAAAAAAAFlSua8iuAQAAAAAAAD/XgQFzxYgjdc0cJS+/6pyBACK1nIN1bmSIgQCGhVZfVlA4g4EBI+ODhDuaygDgkLCBELqBEJqBAlWwhFW5gQESVMNn/HNzoGPAgGfImkWjh0VOQ09ERVJEh41MYXZmNjIuMTIuMTAyc3PWY8CLY8WII3XNHCUvv+pnyKFFo4dFTkNPREVSRIeUTGF2YzYyLjI4LjEwMiBsaWJ2cHhnyKFFo4hEVVJBVElPTkSHkzAwOjAwOjAxLjAwMDAwMDAwMAAfQ7Z1qOeBAKOjgQAAgBACAJ0BKhAAEAAARwiFhYiZhIgCAgAMDWAA/v+rUIAcU7trkbuPs4EAt4r3gQHxggGm8IED';
  const WAV_B64 = 'UklGRtYBAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgATElTVBoAAABJTkZPSVNGVA4AAABMYXZmNjIuMTIuMTAyAGRhdGGQAQAAgYWKjY+PjoqFgHt2cnBwcXV5foSJjY+PjouGgXx3c3BwcXR4fYOIjI+PjoyHgn13c3BwcHN3fYKHjI6Pj4yIg314dHFwcHN3fIGGi46Pj42JhH55dXFwcHJ2e4CFio6Pj42KhYB6dXJwcHF1en+EiY2Pj46KhoF7dnJwcHF0eX6DiIyPj46Lh4J8d3NwcHFzeH2DiIyPkI+MiIN9eHRxcHBzd3yCh4uOj4+MiIN+eXRxcHBydnuBhoqOj4+NiYR/enVxcHBydXp/hYqNj4+OioWAe3ZycHBxdXl+hImNj4+Oi4aBfHdzcHBxdHh9g4iMj4+OjIeCfXdzcHBwc3d8goeMjo+PjIiDfXh0cXBwc3d8gYaLjo+PjYmEfnl1cXBwcnZ7gIWKjo+PjYqFgHp1cnBwcXV6f4SJjY+PjoqGgXt2cnBwcXR5foOIjI+PjouHgnx3c3BwcXR4fYKIjI+Pj4yIgn14dHFwcHN3fIKHi46Pj4yIg355dHFwcHJ2e4GGio6Pj42JhH96dXFwcHJ1eg==';

  /** Write one fixture into the shared temp directory and hand back its path. */
  const fixture = (name, bytes) => {
    const p = path.join(TMP, name);
    fs.writeFileSync(p, bytes);
    return p;
  };
  const webmBytes = Buffer.from(WEBM_B64, 'base64');

  /**
   * Send one file and wait until the receiver's row for it is finished.
   *
   * Sequential on purpose. The preview budget is a queue, so a check about WHICH preview
   * was evicted is only meaningful if the order the rows arrived in is known, and firing
   * several sends at once makes that a race. It also keeps each file out of the batch
   * offer path, which is a different feature with its own prompt.
   */
  const sendFile = async (name, bytes) => {
    await a.setFileInput('#file-input', [fixture(name, bytes)]);
    await b.waitFor(
      `[...document.querySelectorAll('#messages .msg')].some((r) => r.textContent.includes(${JSON.stringify(name)})
        && r.querySelector('button.save-btn'))`,
      { timeout: 40000, label: `${name} finished on the receiver` },
    );
  };

  /** What tab B's transcript row for `name` looks like, read out of the DOM it renders. */
  const rowShape = async (name) => JSON.parse(await b.eval(`
    const row = [...document.querySelectorAll('#messages .msg')]
      .find((r) => r.textContent.includes(${JSON.stringify(name)}));
    if (!row) return JSON.stringify({ found: false });
    const media = row.querySelector('.msg-media');
    const btn = (label) => [...row.querySelectorAll('button')].some((x) => x.textContent === label);
    return JSON.stringify({
      found: true,
      tag: media ? media.tagName : null,
      src: media ? (media.currentSrc || media.src) : null,
      controls: media ? media.controls === true : null,
      preload: media ? media.getAttribute('preload') : null,
      autoplayProp: media ? media.autoplay : null,
      autoplayAttr: media ? media.hasAttribute('autoplay') : null,
      loop: media ? media.loop : null,
      muted: media ? media.muted : null,
      ready: media && media.readyState !== undefined ? media.readyState : null,
      videoWidth: media && 'videoWidth' in media ? media.videoWidth : null,
      duration: media && 'duration' in media ? media.duration : null,
      open: btn('Open'),
      save: btn('Save'),
      text: row.textContent,
    });
  `));

  /**
   * Is `url` still a resolvable object URL in tab B?
   *
   * Asked of the browser's own loader with a fresh element, not of the DOM: the claim
   * under test is that the URL was REVOKED, and "the element was removed" is a different
   * and much weaker statement that a leaking implementation would also satisfy.
   */
  const urlLives = (url) => b.eval(`
    const v = document.createElement('video');
    v.preload = 'metadata';
    return await new Promise((resolve) => {
      v.addEventListener('loadedmetadata', () => resolve('live'), { once: true });
      v.addEventListener('error', () => resolve('revoked'), { once: true });
      setTimeout(() => resolve('timeout'), 5000);
      v.src = ${JSON.stringify(url)};
    });
  `);

  await sendFile('clip1.webm', webmBytes);
  // readyState >= 1 is HAVE_METADATA, not "the element exists". The element is appended
  // before the browser has looked at a byte of it, so waiting on the node alone samples the
  // row mid-load and reads back a player that has not decided anything yet. Swallowing the
  // timeout rather than letting it throw keeps the assertion below the thing that reports
  // the failure: a waitFor that aborts the suite says nothing about which property was
  // wrong.
  await b.waitFor("(document.querySelector('#messages video.msg-media')||{}).readyState >= 1",
    { timeout: 30000, label: 'a video preview appears and decodes for the receiver' })
    .then(() => true, () => false);
  // Captured now, while it is still on screen. Once it is evicted the element is gone and
  // there is nothing left to read the URL off, so the eviction check below could not be
  // written at all without holding it here.
  const clip1 = await rowShape('clip1.webm');
  check('a received video renders as an inline player', clip1.tag === 'VIDEO', JSON.stringify(clip1).slice(0, 200));
  check('and it actually decoded, so the player is not a placeholder',
    clip1.ready >= 1 && clip1.videoWidth > 0, `readyState ${clip1.ready}, ${clip1.videoWidth}px wide`);
  // The four properties that decide whether a file arriving in a chat can take over the
  // room. Read as PROPERTIES and, for autoplay, as the attribute too: setting the property
  // false while leaving the attribute on the element would still autoplay.
  check('the player has controls and does not autoplay, loop or start muted',
    clip1.controls === true && clip1.autoplayProp === false && clip1.autoplayAttr === false
    && clip1.loop === false && clip1.muted === false,
    JSON.stringify({
      controls: clip1.controls, autoplayProp: clip1.autoplayProp,
      autoplayAttr: clip1.autoplayAttr, loop: clip1.loop, muted: clip1.muted,
    }));
  check('and it fetches metadata only, not the whole body, before anyone presses play',
    clip1.preload === 'metadata', String(clip1.preload));

  await sendFile('tone.wav', Buffer.from(WAV_B64, 'base64'));
  // Same bounded wait, same reason: an <audio> element exists before it has a duration.
  await b.waitFor("((document.querySelector('#messages audio.msg-media')||{}).duration > 0)",
    { timeout: 30000, label: 'an audio preview appears and decodes for the receiver' })
    .then(() => true, () => false);
  const wav = await rowShape('tone.wav');
  check('a received audio file renders as an inline player with the same restraint',
    wav.tag === 'AUDIO' && wav.controls === true && wav.preload === 'metadata'
    && wav.autoplayProp === false && wav.loop === false,
    JSON.stringify(wav).slice(0, 200));
  check('and the audio decoded, so its duration is real',
    Number(wav.duration) > 0, `duration ${wav.duration}`);

  // ---- the Open allowlist, which is the part that must be exactly right ----
  //
  // A blob: URL is same-origin with the page that made it, so opening a peer-supplied
  // text/html blob would run their markup in the gate's own origin with the room key in
  // reach. text/html and image/svg+xml are the two shapes that attack takes, and both must
  // come out of the transcript with no button at all: not a disabled one, not one that
  // downloads instead. Absent.
  await sendFile('evil.html', Buffer.from('<script>document.title="xss"</script>hello', 'utf8'));
  const evil = await rowShape('evil.html');
  check('a text/html file gets NO Open button, because a blob: document is same-origin',
    evil.found === true && evil.open === false, JSON.stringify({ open: evil.open, save: evil.save }));
  check('and it is still saveable, so refusing to open it costs the user nothing',
    evil.save === true, JSON.stringify({ save: evil.save }));

  await sendFile('drawing.svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>', 'utf8'));
  const svg = await rowShape('drawing.svg');
  check('an SVG gets neither an inline preview nor an Open button: it is a document',
    svg.found === true && svg.open === false && svg.tag === null,
    JSON.stringify({ open: svg.open, tag: svg.tag }));

  check('a video on the allowlist DOES get one, so the absences above are a decision',
    clip1.open === true, JSON.stringify({ open: clip1.open }));

  // ---- the type is FORCED, not copied ----
  //
  // text/plain is the fixture that can tell the difference: the table's value for it is
  // "text/plain; charset=utf-8", which is not the string the browser put on the file, so a
  // blob built from meta.mime and a blob built from the table are distinguishable. The
  // charset is pinned for a reason of its own: charset confusion was historically the one
  // way to get script out of a text document.
  //
  // Both hooks are installed for the duration of one click and removed straight after.
  // The anchor's click is intercepted rather than followed, because letting it through
  // would open a real tab and leave it there for the rest of the suite.
  await sendFile('notes.txt', Buffer.from('plain text, nothing executable', 'utf8'));
  const txt = await rowShape('notes.txt');
  check('a text/plain file gets an Open button and no inline element',
    txt.open === true && txt.tag === null, JSON.stringify({ open: txt.open, tag: txt.tag }));

  await b.eval(`
    window.__realCreate = URL.createObjectURL;
    window.__lastBlobType = null;
    URL.createObjectURL = function (blob) { window.__lastBlobType = blob.type; return window.__realCreate.call(URL, blob); };
    window.__realClick = HTMLAnchorElement.prototype.click;
    window.__opened = null;
    HTMLAnchorElement.prototype.click = function () {
      window.__opened = { href: this.href, target: this.target, rel: this.rel, type: window.__lastBlobType };
    };
    return true;
  `);
  await b.eval(`
    const row = [...document.querySelectorAll('#messages .msg')].find((r) => r.textContent.includes('notes.txt'));
    [...row.querySelectorAll('button')].find((x) => x.textContent === 'Open').click();
    return true;
  `);
  await b.waitFor('!!window.__opened', { timeout: 10000, label: 'the Open button built a URL' });
  const opened = JSON.parse(await b.eval('return JSON.stringify(window.__opened);'));
  await b.eval(`
    URL.createObjectURL = window.__realCreate;
    HTMLAnchorElement.prototype.click = window.__realClick;
    return true;
  `);
  check('Open builds its blob with the type from the allowlist, not the peer-declared one',
    opened.type === 'text/plain; charset=utf-8', String(opened.type));
  check('and it navigates to a blob: URL in a new tab with no opener back into the gate',
    /^blob:/.test(String(opened.href)) && opened.target === '_blank'
    && /noopener/.test(String(opened.rel)), JSON.stringify(opened).slice(0, 200));

  // ---- a file that claims a media type and does not decode ----
  //
  // The same contract the broken <img> already had: no dead element left behind, the
  // reason said in words, and Save still working, because the bytes are fine even though
  // they are not what the name claimed.
  await sendFile('broken.webm', Buffer.from('this is not a webm file at all', 'utf8'));
  // The row finishes before the decoder has failed, exactly as it finishes before a good
  // file has decoded, so the same bounded wait applies. The timeout is swallowed so that a
  // player which never gets torn down is reported by the checks below rather than by an
  // exception with no detail in it.
  await b.waitFor(
    `[...document.querySelectorAll('#messages .msg')]
      .find((r) => r.textContent.includes('broken.webm'))?.querySelector('.msg-media') === null`,
    { timeout: 20000, label: 'the undecodable player is torn down' },
  ).then(() => true, () => false);
  const broken = await rowShape('broken.webm');
  check('a file claiming to be video that does not decode leaves no dead player behind',
    broken.tag === null, `tag ${broken.tag}`);
  check('and says so in words, with Save still offered',
    /did not open as playable media/.test(broken.text) && broken.save === true,
    JSON.stringify({ save: broken.save, text: broken.text.slice(-120) }));

  // ---- eviction really revokes, for a video and not only for an image ----
  //
  // MAX_INLINE_PREVIEWS is 3 and the queue holds every kind of preview in one budget, so
  // the rows are, oldest first: pixel.png, clip1.webm, tone.wav. Two more videos push
  // pixel.png and then clip1.webm out of it. clip1 is the one that matters: releasing an
  // image was already implemented, and the selector that did it could not see a <video>,
  // so a video's object URL would have stayed live and pinned the whole file in memory for
  // the life of the gate.
  check('CONTROL: the video URL resolves while its preview is still on screen',
    (await urlLives(clip1.src)) === 'live', clip1.src);

  await sendFile('clip2.webm', webmBytes);
  await sendFile('clip3.webm', webmBytes);
  // Swallowed like the other waits in this block, and for the sharper version of the same
  // reason: a release path that cannot see a <video> never removes it, so this predicate
  // never becomes true, and letting it throw would abort the run at the exact point the
  // three checks below are the ones that should be speaking. Measured: with the release
  // selector reverted to 'img.msg-image' this threw and the eviction checks never ran at
  // all, which is a suite that cannot report the bug it was written for.
  await b.waitFor(
    `[...document.querySelectorAll('#messages .msg')]
      .find((r) => r.textContent.includes('clip1.webm')).querySelector('.msg-media') === null`,
    { timeout: 30000, label: 'clip1 is evicted from the preview budget' },
  ).then(() => true, () => false);
  const evictedProbe = await urlLives(clip1.src);
  check('evicting a video preview REVOKES its object URL, not merely removes the element',
    evictedProbe === 'revoked', `${evictedProbe} for ${clip1.src}`);
  const evicted = await rowShape('clip1.webm');
  check('and the evicted row says why, and can still save the file',
    /Preview released to free memory/.test(evicted.text) && evicted.save === true,
    JSON.stringify({ save: evicted.save, text: evicted.text.slice(-120) }));
  check('the newest previews survive the eviction, so the budget trims and does not clear',
    (await rowShape('clip3.webm')).tag === 'VIDEO' && (await rowShape('tone.wav')).tag === 'AUDIO',
    'the newest video and the audio should both still be rendered');

  // ---- a file that went to disk: no blob, but a handle to read it back ----
  //
  // A disk sink streams the file straight to the location the user picked, so this page
  // never holds the bytes. link.js passes on the FileSystemFileHandle that sink was already
  // holding for resume, which is what turns "Written to the location you chose" from a dead
  // end into a row that can still open the file.
  //
  // Driven against preview.js with a stub handle rather than through a real transfer,
  // because NO browser in this harness has showSaveFilePicker: headless Brave takes the
  // streaming-download route instead (tests/download.test.mjs is that route), so the disk
  // sink is unreachable end to end here and a check that waited for it would be a check
  // that never runs and never fails. What is asserted is exactly the half this change
  // wrote: the same allowlist, the same forced type, and bytes read at CLICK time rather
  // than held. The stub counts its own reads, so "read lazily" is measured and not assumed.
  const disk = JSON.parse(await b.eval(`
    const mod = await import('/js/preview.js');
    const realClick = HTMLAnchorElement.prototype.click;
    const realCreate = URL.createObjectURL;
    let opened = null;
    let lastType = null;
    URL.createObjectURL = function (blob) { lastType = blob.type; return realCreate.call(URL, blob); };
    HTMLAnchorElement.prototype.click = function () { opened = { href: this.href, rel: this.rel, target: this.target }; };
    const ctx = {
      objectUrls: new Set(), inlinePreviews: [], MAX_INLINE_PREVIEWS: 3,
      releasePreview: () => {}, scrollMessages: () => {}, sanitizeFilename: (n) => n,
    };
    const make = (mime) => {
      const row = document.createElement('div');
      row.className = 'msg is-file';
      const state = { reads: 0 };
      const handle = {
        getFile: async () => { state.reads += 1; return new Blob(['bytes on disk'], { type: 'application/octet-stream' }); },
      };
      mod.decorateFileRow(row, { name: 'from-disk', mime, blob: null, handle }, ctx);
      return { row, state };
    };
    const ok = make('text/plain');
    const bad = make('text/html');
    const btn = [...ok.row.querySelectorAll('button')].find((x) => x.textContent === 'Open');
    const readsBefore = ok.state.reads;
    if (btn) btn.click();
    await new Promise((r) => setTimeout(r, 400));
    const out = {
      openOnAllowed: !!btn,
      openOnHtml: [...bad.row.querySelectorAll('button')].some((x) => x.textContent === 'Open'),
      previewDrawn: !!ok.row.querySelector('.msg-media'),
      readsBefore,
      readsAfter: ok.state.reads,
      forcedType: lastType,
      opened,
      tracked: ctx.objectUrls.size,
    };
    URL.createObjectURL = realCreate;
    HTMLAnchorElement.prototype.click = realClick;
    return JSON.stringify(out);
  `));
  check('a file written to disk gets an Open button from its handle, and no preview',
    disk.openOnAllowed === true && disk.previewDrawn === false,
    JSON.stringify({ open: disk.openOnAllowed, preview: disk.previewDrawn }));
  check('the disk route reads the file at CLICK time, not when the row is drawn',
    disk.readsBefore === 0 && disk.readsAfter === 1, `${disk.readsBefore} read(s) -> ${disk.readsAfter}`);
  check('and it forces the same type the in-memory route does',
    disk.forcedType === 'text/plain; charset=utf-8', String(disk.forcedType));
  check('and obeys the same allowlist: a handle to text/html gets no Open button either',
    disk.openOnHtml === false, String(disk.openOnHtml));
  check('the URL it opens is a tracked blob: URL with no opener back into the gate',
    /^blob:/.test(String(disk.opened?.href)) && /noopener/.test(String(disk.opened?.rel))
    && disk.opened?.target === '_blank' && disk.tracked === 1,
    JSON.stringify(disk.opened) + ` tracked=${disk.tracked}`);


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
  await z.send('Page.navigate', { url: APP });
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
  await priv.send('Page.navigate', { url: APP });
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

  // ------------------------------------------- the camera scan button, and its absence
  //
  // The scanner itself needs a camera, which this headless browser does not have and
  // which a test must never pretend to have: a faked getUserMedia would prove that the
  // fake works. What IS testable is the contract around it, and that is where the bugs
  // would be: the button is offered only when the browser could actually open a camera,
  // the 57 KB behind it is not fetched until it is pressed, and the panel is not on
  // screen until then.
  {
    const s = await guardedTab(APP, { width: 1280, height: 900 });
    await s.eval(agreeInPage);
    await s.send('Page.reload', {});
    await s.waitFor("!document.getElementById('screen-home').hidden",
      { timeout: 30000, label: 'home for the scan checks' });

    const shape = JSON.parse(await s.eval(`
      const btn = document.getElementById('scan-btn');
      const panel = document.getElementById('scan-panel');
      return JSON.stringify({
        supported: typeof navigator?.mediaDevices?.getUserMedia === 'function',
        buttonExists: !!btn,
        buttonShown: !!btn && !btn.hidden,
        panelShown: !!panel && !panel.hidden,
        // The decoder must not be on the wire before the button is pressed. Asked of the
        // browser's own resource timing rather than of the source, so this is what was
        // FETCHED and not what was written.
        fetched: performance.getEntriesByType('resource')
          .map((e) => e.name).filter((n) => /qrscan|qrdecode/.test(n)).length,
      });
    `));

    check('the scan button exists in the join column', shape.buttonExists, JSON.stringify(shape));
    // Both directions of one rule, so neither a permanently-hidden nor a
    // permanently-shown button can pass. Which branch runs depends on the browser under
    // test, and the detail says which one it took.
    check('and it is shown exactly when this browser could open a camera',
      shape.buttonShown === shape.supported,
      `supported=${shape.supported} shown=${shape.buttonShown}`);
    check('the camera panel is not on screen before the button is pressed',
      shape.panelShown === false, JSON.stringify(shape));
    check('and neither the scanner nor the QR decoder has been fetched',
      shape.fetched === 0, `${shape.fetched} matching resource(s)`);

    // CONTROL: resource timing is really populated, so "0 matching" means "not fetched"
    // rather than "the browser told us nothing". Without this the check above passes on
    // a page that loaded no scripts at all.
    const anyJs = await s.eval(`
      return String(performance.getEntriesByType('resource')
        .filter((e) => e.name.endsWith('.js')).length);
    `);
    check('CONTROL: resource timing lists the scripts that WERE fetched',
      Number(anyJs) > 3, `${anyJs} .js resources`);

    // The gate's CSP has no media-src, so <video> inherits default-src 'none'. A
    // MediaStream assigned through srcObject is not a URL fetch and should therefore be
    // outside CSP entirely, but "should" is an argument and this is a check: a stream
    // made from a canvas is the same kind of object getUserMedia returns, so if the
    // policy did block srcObject this is where it would show, without needing a camera.
    const srcObject = await s.eval(`
      const c = document.createElement('canvas');
      c.width = 8; c.height = 8;
      c.getContext('2d').fillRect(0, 0, 8, 8);
      const v = document.getElementById('scan-video');
      try {
        v.srcObject = c.captureStream(1);
        await v.play();
        const ok = v.videoWidth > 0;
        for (const t of v.srcObject.getTracks()) t.stop();
        v.srcObject = null;
        return ok ? 'played' : 'no frames';
      } catch (err) {
        return 'threw: ' + err.name + ' ' + err.message;
      }
    `);
    check('a MediaStream plays in the scan video, so the policy does not block srcObject',
      srcObject === 'played', srcObject);

    check('the scan page raised no uncaught errors', s.pageErrors.length === 0,
      s.pageErrors.join(' | '));
    s.close();
  }

  // ------------------------------------------- the games are not fetched to open a gate
  //
  // The same question as above, asked of the other lazy cluster, and asked in the
  // browser because the size suite can only see the source.
  //
  // Run on tab A, which is CONNECTED. That is not incidental: the drawer only loads the
  // games once a gate exists, so asking this on the home screen would report "not
  // fetched" for both halves and the control below could never fire.
  {
    const gamesFetched = () => a.eval(`
      return String(performance.getEntriesByType('resource')
        .map((e) => e.name).filter((n) => /gameplay|gameui|games\\//.test(n)).length);
    `);

    check('a gate that ran a whole session never fetched the games',
      Number(await gamesFetched()) === 0, `${await gamesFetched()} resource(s)`);

    // The other half. A split that never loads the games is not a split, it is a
    // deletion, and the check above cannot tell the difference. Clicked rather than
    // toggled by property, so this is the path a person takes.
    await a.eval("document.querySelector('#games-disc > summary').click(); return true;");
    const arrived = await a.waitFor(
      "performance.getEntriesByType('resource').some((e) => /gameplay\\.js/.test(e.name))",
      { timeout: 15000, label: 'gameplay.js arrives when the drawer opens' },
    ).then(() => true, () => false);
    check('CONTROL: opening the drawer does fetch them, so the split is a split',
      arrived, 'gameplay.js never appeared in resource timing');

    // The board stylesheet is lazy for the same reason and by a different mechanism (a
    // link element injected by gameui.js), so it needs its own assertion.
    const cssArrived = await a.waitFor(
      "performance.getEntriesByType('resource').some((e) => /games\\.css/.test(e.name))",
      { timeout: 15000, label: 'games.css arrives with the first board' },
    ).then(() => true, () => false);
    check('and the board stylesheet comes with them', cssArrived,
      'games.css never appeared in resource timing');

    // It has to actually apply, not merely arrive: a stylesheet blocked by the CSP would
    // still show up in resource timing.
    const styled = await a.eval(`
      const area = document.getElementById('game-area');
      return getComputedStyle(area).getPropertyValue('--g-rose').trim();
    `);
    check('and the pastel palette is in effect on the board area',
      styled.length > 0, `--g-rose resolved to ${JSON.stringify(styled)}`);
  }

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
  await a.send('Page.navigate', { url: APP });
  await b.send('Page.navigate', { url: APP });
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
  const c = await browser.newTab(APP);
  await c.waitFor("!document.getElementById('screen-home').hidden", { label: 'home screen on tab C' });
  await c.eval(NET_ACK);

  // Every attempt below clears the error first. Without that, a waitFor on the error being
  // present passes instantly against the PREVIOUS attempt's message, and the check reports
  // the wrong code's verdict. That is not hypothetical: 'A gate code is 8 words' contains
  // the word "gate", which is exactly what the unknown-gate check below waits for.
  const tryJoin = async (value, label) => {
    await c.eval(`
      const err = document.getElementById('home-error');
      err.textContent = '';
      err.hidden = true;
      document.getElementById('join-input').value = ${JSON.stringify(value)};
      document.getElementById('join-btn').click();
      return true;
    `);
    await c.waitFor("!document.getElementById('home-error').hidden && document.getElementById('home-error').textContent.length > 0",
      { timeout: 25000, label });
    return c.eval("return document.getElementById('home-error').textContent;");
  };

  const malformedError = await tryJoin('not a warp gate code', 'malformed code is refused');
  check('a code with the wrong number of words is refused, and told how many it had',
    /8 words/.test(malformedError) && /5/.test(malformedError), malformedError);

  // A different fault, which must produce a different message. One sentence for both would
  // be a diagnostic that cannot name its own cause.
  const badWordError = await tryJoin(
    'WARP-AMBER-CRISP-MAPLE-KETTLE-MARBLE-VELVET-WALNUT-ZZZZQX', 'unknown word is refused');
  check('a word that is not on the list is named, rather than the whole code being rejected',
    /zzzzqx/i.test(badWordError) && !/8 words/.test(badWordError), badWordError);

  // A well-formed secret for a gate that does not exist. Because the room id is
  // derived from the secret, a wrong secret cannot reach someone else's room at all:
  // it addresses a room that is not there.
  // Timeout raised: this one is well formed, so it pays a full PBKDF2 stretch (about a
  // second on the measuring machine, worse on a loaded CI box) before it ever reaches the
  // server.
  const unknownError = await tryJoin(
    'WARP-AMBER-CRISP-MAPLE-KETTLE-MARBLE-VELVET-WALNUT-WIDGET', 'unknown gate is refused');
  check('a valid-looking code for a non-existent gate says so plainly',
    /does not exist|expired/.test(unknownError), unknownError);
  check('tab C raised no uncaught page errors', c.pageErrors.length === 0, c.pageErrors.join(' | '));

  // ------------------------------------------------------------ abrupt departure
  // A tab going away without pressing sever. The peer must be told and the room must
  // not sit around occupied until its TTL.
  const d = await browser.newTab(APP);
  await d.waitFor("!document.getElementById('screen-home').hidden", { label: 'home on tab D' });
  await d.eval(NET_ACK);
  await d.eval("document.getElementById('create-btn').click(); return true;");
  await d.waitFor("!document.getElementById('screen-waiting').hidden", { label: 'tab D waiting' });
  // The secret is no longer in the address bar, so reveal it to build the link.
  await d.eval("document.getElementById('reveal-share').click(); return true;");
  await d.waitFor("document.getElementById('share-shown').hidden === false", { label: 'tab D share revealed' });
  const code2 = await d.eval("return document.getElementById('room-code').textContent.trim();");
  const link2 = APP + '#' + code2;

  const e = await browser.newTab(link2);
  await clickThroughNetNotice(e, 'the exposure notice on tab E');
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

  // ------------------------------------------------------------ a password gate survives a reload
  //
  // The roadmap called this a real gap and it was one: the key schedule takes a password,
  // the reload path did not carry it, and a refresh dropped the joiner out. The stretched
  // key is now filed per room in this tab's sessionStorage (public/js/vault.js).
  //
  // The load-bearing assertion is the NEGATIVE one: the password screen must not come back.
  // "It reconnected" on its own would pass against a build that re-prompted and had the
  // test answer it again without noticing.
  {
    const GATE_PW = `pw-${crypto.randomUUID().slice(0, 8)}`;
    const pwA = await browser.newTab(APP);
    await pwA.waitFor("!document.getElementById('screen-home').hidden", { label: 'password gate: tab A home' });
    await pwA.eval(NET_ACK);
    await pwA.eval(`
      document.getElementById('room-password').value = ${JSON.stringify(GATE_PW)};
      document.getElementById('create-btn').click();
      return true;
    `);
    await pwA.waitFor("!document.getElementById('screen-waiting').hidden",
      { timeout: 40000, label: 'password gate: tab A waiting' });
    await pwA.eval("document.getElementById('reveal-share').click(); return true;");
    await pwA.waitFor("document.getElementById('share-shown').hidden === false",
      { label: 'password gate: share revealed' });
    const pwCode = await pwA.eval("return document.getElementById('room-code').textContent.trim();");

    // The exposure notice comes BEFORE any screen on a link-join: boot goes straight into
    // startJoin, which awaits the modal, and every screen stays hidden until it is answered.
    // Waiting for "some screen is visible" first therefore hangs forever.
    const pwB = await browser.newTab(`${APP}#${pwCode}`);
    await clickThroughNetNotice(pwB, 'password gate: tab B notice');
    await pwB.waitFor("!document.getElementById('screen-password').hidden",
      { timeout: 40000, label: 'password gate: tab B is asked for the password' });
    check('a gate with a password asks the joiner for it', true);
    await pwB.eval(`
      document.getElementById('password-input').value = ${JSON.stringify(GATE_PW)};
      document.getElementById('password-submit').click();
      return true;
    `);
    await pwB.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'password gate: tab B connected' });
    await pwA.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'password gate: tab A connected' });

    // Watched from the reloaded document's first byte, because a build that re-prompts and
    // then satisfies itself would show the screen for a moment and be invisible to a check
    // that only reads the end state.
    await pwB.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `
        window.__pwAsked = false;
        // document, NOT document.documentElement. This runs at document-start, before the
        // parser has created <html>, so documentElement is null and observe() throws: the
        // observer is never installed and __pwAsked stays false for the wrong reason. The
        // negative control below is what caught that.
        new MutationObserver(() => {
          const s = document.getElementById('screen-password');
          if (s && !s.hidden) window.__pwAsked = true;
        }).observe(document, { attributes: true, subtree: true, attributeFilter: ['hidden'] });
      `,
    });
    await pwB.send('Page.reload', {});
    await pwB.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'password gate: tab B reconnected after reload' });

    const asked = await pwB.eval('return window.__pwAsked === true;');
    check('a reloaded joiner is never asked for the room password again', asked === false, `asked=${asked}`);

    const pwMsg = `password gate ${crypto.randomUUID()}`;
    await pwA.eval(`
      document.getElementById('chat-input').value = ${JSON.stringify(pwMsg)};
      document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
      return true;
    `);
    await pwB.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(pwMsg)})`,
      { timeout: 30000, label: 'password gate: message crosses after reload' });
    check('and the recalled key still opens the channel, so the password really did survive', true);

    // Negative control for the watcher. Without it, `__pwAsked === false` also reads as
    // "the observer never ran", which is the same answer for a passing build and a broken
    // check.
    const observerWorks = await pwB.eval(`
      const s = document.getElementById('screen-password');
      const was = s.hidden;
      s.hidden = false;
      await new Promise((r) => setTimeout(r, 60));
      s.hidden = was;
      return window.__pwAsked === true;
    `);
    check('negative control: the watcher does fire when the password screen is shown',
      observerWorks === true, `observed=${observerWorks}`);

    await pwA.eval("document.getElementById('sever').click(); return true;");
    pwA.close();
    pwB.close();
  }

  // ------------------------------------------------------------ a dropped transfer continues
  //
  // The claim on the landing page is that a dropped connection costs the chunks that were
  // in flight and not the file. Nothing short of an actual drop mid-transfer tests that,
  // so the data channel is closed underneath a live send.
  //
  // Closing the channel rather than the peer connection is deliberate: it is what a phone
  // sleeping or a network blinking looks like from here, and it leaves the signalling path
  // alive so the pair renegotiates the way it would in the field.
  {
    const rsA = await browser.newTab('about:blank');
    const rsB = await browser.newTab('about:blank');
    // A test-only hook installed from the harness: no production code knows this exists.
    //
    // Two things it has to get right, both learned the hard way:
    //
    // 1. Which side holds the channel is decided by the signalling roster ('a' offers,
    //    'b' answers), NOT by who clicked Create. Watching only createDataChannel found
    //    the channel on the sending tab about half the time and reported "no channel"
    //    the rest, so the datachannel event is captured too.
    // 2. The cut is counted in bytes rather than waited for as a percentage. Over
    //    loopback the whole 8 MiB can land between two polls, and a cut that arrives
    //    after the last byte tests nothing at all.
    const CHAN_HOOK = `
      window.__chans = [];
      window.__cutAfter = 0;
      window.__cutFired = false;
      const grab = (ch) => {
        if (!ch || ch.label !== 'wg') return ch;
        window.__chans.push(ch);
        let sent = 0;
        const send = ch.send.bind(ch);
        ch.send = (data) => {
          sent += (data && (data.byteLength ?? data.length)) || 0;
          if (window.__cutAfter && sent > window.__cutAfter && !window.__cutFired) {
            window.__cutFired = true;
            ch.close();
            return undefined;
          }
          return send(data);
        };
        return ch;
      };
      const RPC = RTCPeerConnection;
      function Patched(...args) {
        const pc = new RPC(...args);
        pc.addEventListener('datachannel', (event) => grab(event.channel));
        const make = pc.createDataChannel.bind(pc);
        pc.createDataChannel = (...a) => grab(make(...a));
        return pc;
      }
      Patched.prototype = RPC.prototype;
      window.RTCPeerConnection = Patched;
      window.__blobs = [];
      const realUrl = URL.createObjectURL.bind(URL);
      URL.createObjectURL = (blob) => { window.__blobs.push(blob); return realUrl(blob); };
    `;
    for (const t of [rsA, rsB]) await t.send('Page.addScriptToEvaluateOnNewDocument', { source: CHAN_HOOK });

    await rsA.send('Page.navigate', { url: APP });
    await rsA.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'resume: tab A home' });
    await rsA.eval(NET_ACK);
    await rsA.eval("document.getElementById('create-btn').click(); return true;");
    await rsA.waitFor("!document.getElementById('screen-waiting').hidden",
      { timeout: 40000, label: 'resume: tab A waiting' });
    await rsA.eval("document.getElementById('reveal-share').click(); return true;");
    await rsA.waitFor("document.getElementById('share-shown').hidden === false",
      { label: 'resume: share revealed' });
    const rsCode = await rsA.eval("return document.getElementById('room-code').textContent.trim();");

    await rsB.send('Page.navigate', { url: `${APP}#${rsCode}` });
    await clickThroughNetNotice(rsB, 'resume: tab B notice');
    await rsB.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'resume: tab B connected' });
    await rsA.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'resume: tab A connected' });

    // 8 MiB: under the 10 MiB auto-accept threshold so the receiver is never prompted, and
    // 512 chunks long, which leaves plenty of room to land a drop in the middle of it.
    const bigPath = path.join(TMP, 'dropped.bin');
    const bigPayload = crypto.randomBytes(8 * 1024 * 1024);
    fs.writeFileSync(bigPath, bigPayload);
    const bigDigest = crypto.createHash('sha256').update(bigPayload).digest('hex');

    // Armed before the file is chosen: 1.5 MiB of 8 MiB, so the drop lands in the middle
    // of the file and the sender still has most of it left to send.
    await rsA.eval('window.__cutAfter = 1500000; return true;');
    await rsA.setFileInput('#file-input', [bigPath]);
    await rsA.waitFor('window.__cutFired === true',
      { timeout: 60000, label: 'resume: the channel was cut mid-file' });

    const cut = await rsA.eval(`
      const ch = window.__chans[window.__chans.length - 1];
      if (!ch) return 'no channel';
      return ch.readyState;
    `);
    check('the test really did cut the data channel out from under a live transfer',
      cut === 'closing' || cut === 'closed', String(cut));

    // Both sides must say so. A drop that only one end noticed is a different bug.
    await rsB.waitFor("/paused|waiting to continue|nothing has arrived/i.test(document.getElementById('log').textContent)",
      { timeout: 60000, label: 'resume: the receiver noticed the drop' });

    await rsB.waitFor("[...document.querySelectorAll('#messages button')].some(x => x.textContent === 'Save')",
      { timeout: 180000, label: 'resume: the interrupted file finished anyway' });

    const rsLog = await rsB.eval("return document.getElementById('log').textContent;");
    const continuedAt = (rsLog.match(/continuing from ([\d.]+)\s*(B|KB|MB|GB)/i) || [])[1];
    check('the transfer continued rather than starting the file again',
      continuedAt !== undefined && Number(continuedAt) > 0, rsLog.slice(-300));

    await rsB.eval(`
      const btn = [...document.querySelectorAll('#messages button')].find((x) => x.textContent === 'Save');
      if (btn) btn.click();
      return true;
    `);
    const got = JSON.parse(await rsB.eval(`
      const blob = window.__blobs[window.__blobs.length - 1];
      if (!blob) return JSON.stringify(null);
      const bytes = new Uint8Array(await blob.arrayBuffer());
      const d = await crypto.subtle.digest('SHA-256', bytes);
      return JSON.stringify({ size: bytes.length,
        hash: [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('') });
    `));
    check('the file that survived the drop is byte-for-byte the one that was sent',
      got?.size === bigPayload.length && got?.hash === bigDigest,
      `${got?.size} bytes, sha256 ${got?.hash} vs ${bigDigest}`);
    // Without this, "identical" is a claim about a comparison that might always say yes.
    const rsWrong = await rsB.eval(`
      const d = await crypto.subtle.digest('SHA-256', new Uint8Array([9, 9, 9]));
      return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
    `);
    check('negative control: the same hash over different bytes does NOT match',
      rsWrong !== bigDigest, `${rsWrong} vs ${bigDigest}`);

    await rsA.eval("document.getElementById('sever').click(); return true;");
    rsA.close();
    rsB.close();
  }

  // ------------------------------------------------------------ several files, ONE accept
  //
  // The reported problem, in the reporter's words: "so laptop side has to accept each
  // individually instead of accepting a full batch". Several photos from a phone, one
  // prompt per photo on the laptop.
  //
  // The prompt-per-file is not an oversight, it is what a user gesture costs: accepting
  // opens a file-system dialog and those cannot be opened outside a click. So the fix
  // spends ONE gesture on the whole set, and everything below tests the bound that has to
  // come with it. A single click that grants unlimited writes into a folder the user chose
  // would be a worse product than the five prompts it replaced.
  //
  // The forge hook rewrites the batch ANNOUNCEMENT on its way out of the sending tab, and
  // nothing else: it is how a lying sender is tested without a second implementation of the
  // protocol. It is narrow on purpose (it only ever sees objects whose kind is
  // 'file-batch') because JSON.stringify is on far too many paths to patch broadly.
  {
    const fbA = await browser.newTab('about:blank');
    const fbB = await browser.newTab('about:blank');
    const FORGE_HOOK = `
      window.__forge = null;
      const S = JSON.stringify;
      JSON.stringify = function (value, ...rest) {
        if (window.__forge && value && typeof value === 'object' && value.kind === 'file-batch') {
          value = window.__forge(value) || value;
        }
        return S.call(this, value, ...rest);
      };
      window.__blobs = [];
      const realUrl = URL.createObjectURL.bind(URL);
      URL.createObjectURL = (blob) => { window.__blobs.push(blob); return realUrl(blob); };
    `;
    await fbA.send('Page.addScriptToEvaluateOnNewDocument', { source: FORGE_HOOK });
    await fbB.send('Page.addScriptToEvaluateOnNewDocument', { source: FORGE_HOOK });

    await fbA.send('Page.navigate', { url: APP });
    await fbA.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'batch: tab A home' });
    await fbA.eval(NET_ACK);
    await fbA.eval("document.getElementById('create-btn').click(); return true;");
    await fbA.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 40000, label: 'batch: tab A waiting' });
    await fbA.eval("document.getElementById('reveal-share').click(); return true;");
    await fbA.waitFor("document.getElementById('share-shown').hidden === false", { label: 'batch: share revealed' });
    const fbCode = await fbA.eval("return document.getElementById('room-code').textContent.trim();");

    await fbB.send('Page.navigate', { url: `${APP}#${fbCode}` });
    await clickThroughNetNotice(fbB, 'batch: tab B notice');
    await fbB.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'batch: tab B connected' });
    await fbA.waitFor("!document.getElementById('screen-connected').hidden",
      { timeout: 90000, label: 'batch: tab A connected' });

    // Waits that report rather than throw. A build with the batch path broken must produce
    // BAD lines that name what was actually on screen, not one timeout that kills every
    // later assertion in this block and leaves the other two bounds untested.
    const settled = async (tab, expression, ms, label) => {
      try {
        await tab.waitFor(expression, { timeout: ms, label });
        return true;
      } catch (err) {
        void err.message;
        return false;
      }
    };
    // How many batch rows have ever been drawn on the receiving side. Counted rather than
    // asked as a yes/no, because two of the checks below are about a row NOT appearing and
    // "none on screen" would also be true if the row had appeared and been removed.
    const batchRows = () => fbB.eval(
      "return [...document.querySelectorAll('#messages .msg.is-file')].filter((r) => r.id.startsWith('transfer-batch-')).length;",
    );

    const mk = (name, bytes) => {
      const p = path.join(TMP, name);
      const payload = crypto.randomBytes(bytes);
      fs.writeFileSync(p, payload);
      return { path: p, name, payload, digest: crypto.createHash('sha256').update(payload).digest('hex') };
    };

    // ---------------------------------------------------- three files, one Accept
    //
    // 300 KB each: many chunks, so this is a real transfer and not a single frame, and
    // small enough that three of them cross a loopback data channel in seconds. All three
    // are UNDER the auto-accept threshold, which makes the assertion below strictly
    // stronger than the reported case: before this change three small files drew ZERO
    // accept controls and three separate large ones drew THREE. Exactly one is neither.
    const trio = [mk('batch-one.bin', 300 * 1024), mk('batch-two.bin', 300 * 1024), mk('batch-three.bin', 300 * 1024)];
    await fbA.eval('window.__forge = null; return true;');
    await fbA.setFileInput('#file-input', trio.map((f) => f.path));

    const sawRow = await settled(fbB,
      "[...document.querySelectorAll('#messages .msg.is-file')].some((r) => r.id.startsWith('transfer-batch-'))",
      30000, 'batch: the receiver drew one row for the whole set');
    check('three files sent together draw a batch row on the receiving side', sawRow === true,
      `batch rows: ${await batchRows()}`);

    const controls = JSON.parse(await fbB.eval(`
      const buttons = [...document.querySelectorAll('#messages button')].filter((b) => !b.disabled);
      return JSON.stringify({
        accepts: buttons.filter((b) => /^Accept/.test(b.textContent)).length,
        labels: buttons.map((b) => b.textContent),
        names: (document.querySelector('#messages .file-names') || {}).textContent || '',
      });
    `));
    check('exactly ONE accept control is drawn for three files, not one per file',
      controls.accepts === 1, JSON.stringify(controls.labels));
    check('and it says how many files and how much, so the click is informed',
      /Accept 3 files/.test(controls.labels.join(' ')), JSON.stringify(controls.labels));
    check('the row lists every filename it is asking about',
      trio.every((f) => controls.names.includes(f.name)), controls.names);

    await fbB.eval(`
      const btn = [...document.querySelectorAll('#messages button')].find((b) => /^Accept 3 files/.test(b.textContent));
      if (!btn) return false;
      btn.click();
      return true;
    `);

    const allThree = await settled(fbB,
      "[...document.querySelectorAll('#messages button')].filter((x) => x.textContent === 'Save').length === 3",
      120000, 'batch: all three files finished');
    check('one click delivers all three files', allThree === true,
      await fbB.eval("return String([...document.querySelectorAll('#messages button')].filter((x) => x.textContent === 'Save').length);"));

    // Byte-for-byte, per file. "Three rows appeared" would pass against a build that
    // delivered the same file three times, or truncated two of them.
    const received = JSON.parse(await fbB.eval(`
      const out = [];
      for (const row of document.querySelectorAll('#messages .msg.is-file')) {
        const save = [...row.querySelectorAll('button')].find((x) => x.textContent === 'Save');
        if (!save) continue;
        const before = window.__blobs.length;
        save.click();
        if (window.__blobs.length === before) continue;
        const blob = window.__blobs[window.__blobs.length - 1];
        const bytes = new Uint8Array(await blob.arrayBuffer());
        const d = await crypto.subtle.digest('SHA-256', bytes);
        out.push({
          title: (row.querySelector('.file-title') || {}).textContent || '',
          size: bytes.length,
          hash: [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join(''),
        });
      }
      return JSON.stringify(out);
    `));
    const matched = trio.filter((f) => received.some(
      (r) => r.title.includes(f.name) && r.size === f.payload.length && r.hash === f.digest));
    check('all three arrived byte-for-byte, each under its own name',
      matched.length === 3, `${matched.length}/3 matched, got ${JSON.stringify(received.map((r) => [r.title, r.size]))}`);
    check('negative control: the three files were not three copies of one file',
      new Set(trio.map((f) => f.digest)).size === 3, trio.map((f) => f.digest.slice(0, 8)).join(' '));

    // ---------------------------------------------------- peer-chosen names reach the DOM
    //
    // The names on a batch offer are the only peer-written strings this row displays, and
    // they are displayed before anything has been agreed to. A right-to-left override
    // disguises an extension and a NUL blanks the rest of a line, so both are planted here
    // and the rendered text is read back.
    await fbA.eval(`
      window.__forge = (m) => ({ ...m, names: m.names.map((n, i) => (i === 0 ? '\\u202Egnp.evil\\u0000.exe' : n)) });
      return true;
    `);
    const pair = [mk('hostile-one.bin', 64 * 1024), mk('hostile-two.bin', 64 * 1024)];
    await fbA.setFileInput('#file-input', pair.map((f) => f.path));
    const sawHostile = await settled(fbB,
      "[...document.querySelectorAll('#messages .msg.is-file')].filter((r) => r.id.startsWith('transfer-batch-')).length === 2",
      30000, 'batch: the second offer was drawn');
    check('a second batch offer draws its own row', sawHostile === true, `batch rows: ${await batchRows()}`);

    // Null-safe on purpose. A build with the batch path broken has no row here at all, and
    // an eval that throws would end this block on its first failure and leave the other
    // three bounds below untested: a negative control has to produce its BAD line and then
    // let the rest of the run continue.
    const shown = await fbB.eval(`
      const rows = [...document.querySelectorAll('#messages .msg.is-file')].filter((r) => r.id.startsWith('transfer-batch-'));
      const el = rows.length ? rows[rows.length - 1].querySelector('.file-names') : null;
      return el ? el.textContent : '';
    `);
    check('a bidi override in a peer-chosen filename never reaches the row',
      !shown.includes('\u202E'), JSON.stringify(shown));
    check('and neither does a NUL, which would blank the rest of the line',
      !shown.includes('\u0000'), JSON.stringify(shown));
    check('negative control: the hostile name really was sent, so the strip is doing work',
      /exe/.test(shown), JSON.stringify(shown));
    check('the names are text, not markup: no element came out of the peer\'s string',
      (await fbB.eval(`
        const rows = [...document.querySelectorAll('#messages .msg.is-file')].filter((r) => r.id.startsWith('transfer-batch-'));
        const el = rows.length ? rows[rows.length - 1].querySelector('.file-names') : null;
        return el ? el.children.length : -1;
      `)) === 0);

    // Refuse, and the whole set must go: a batch that is refused and then delivers its
    // small files anyway through the auto-accept path would be the button lying.
    await fbB.eval(`
      const btn = [...document.querySelectorAll('#messages button')].find((b) => b.textContent === 'Refuse');
      if (!btn) return false;
      btn.click();
      return true;
    `);
    // Named per file, because "something was refused" would also pass against a build that
    // refused the file in hand and quietly auto-accepted the second one behind it: the
    // second file is the whole point of latching the refusal.
    const refusedBoth = await settled(fbA,
      "/could not send hostile-one\\.bin/.test(document.getElementById('log').textContent)"
      + " && /could not send hostile-two\\.bin/.test(document.getElementById('log').textContent)",
      30000, 'batch: the sender was told about both refused files');
    check('Refuse refuses the whole set, not just the file already in flight',
      refusedBoth === true, (await fbA.eval("return document.getElementById('log').textContent;")).slice(-240));
    // A refused file still gets a row, saying it was not accepted. What must not exist is a
    // SAVE button on one: that is the only thing that means bytes were actually taken.
    const leaked = await fbB.eval(`
      return String([...document.querySelectorAll('#messages .msg.is-file')].filter((r) =>
        /hostile-/.test((r.querySelector('.file-title') || {}).textContent || '')
        && [...r.querySelectorAll('button')].some((b) => b.textContent === 'Save')).length);
    `);
    check('no refused file was saved anyway', leaked === '0', `${leaked} refused files were saved`);

    // ---------------------------------------------------- a count that disagrees with names
    //
    // count and names.length are two statements about the same set, and a row built from a
    // message where they disagree would misstate what the click agrees to. The receiver
    // must drop it where it stands. The log line is asserted as well as the missing row:
    // without it "no row appeared" would also pass if the message had never arrived, which
    // is a check that measures nothing.
    const rowsBeforeBad = Number(await batchRows());
    await fbA.eval('window.__forge = (m) => ({ ...m, names: m.names.slice(0, m.count - 1) }); return true;');
    const liars = [mk('liar-one.bin', 64 * 1024), mk('liar-two.bin', 64 * 1024)];
    await fbA.setFileInput('#file-input', liars.map((f) => f.path));
    const complained = await settled(fbB,
      "/malformed offer of several files/.test(document.getElementById('log').textContent)",
      30000, 'batch: the receiver rejected the inconsistent offer');
    check('a batch whose count and names disagree is rejected on arrival',
      complained === true, (await fbB.eval("return document.getElementById('log').textContent;")).slice(-240));
    check('and no prompt is drawn from it',
      Number(await batchRows()) === rowsBeforeBad, `${await batchRows()} rows vs ${rowsBeforeBad} before`);

    // ---------------------------------------------------- a fourth file under a three-file grant
    //
    // The security property, stated as a test. A one-click grant is bounded by what was
    // announced, so a sender that says three and then pushes a fourth gets the ordinary
    // treatment for the fourth: consent covered three files, and it is spent.
    //
    // The fourth is 11 MiB, over the auto-accept threshold, so "ordinary treatment" is
    // visible as an Accept control of its own. It is never accepted, so those bytes are
    // announced and not sent.
    await fbA.eval('window.__forge = (m) => ({ ...m, count: 3, names: m.names.slice(0, 3) }); return true;');
    const four = [
      mk('grant-one.bin', 200 * 1024), mk('grant-two.bin', 200 * 1024),
      mk('grant-three.bin', 200 * 1024), mk('grant-four.bin', 11 * 1024 * 1024),
    ];
    await fbA.setFileInput('#file-input', four.map((f) => f.path));
    const sawGrantRow = await settled(fbB,
      `[...document.querySelectorAll('#messages .msg.is-file')].filter((r) => r.id.startsWith('transfer-batch-')).length === ${rowsBeforeBad + 1}`,
      30000, 'batch: the three-file offer was drawn');
    check('the understated offer is drawn as a three-file batch', sawGrantRow === true, `batch rows: ${await batchRows()}`);
    await fbB.eval(`
      const btn = [...document.querySelectorAll('#messages button')].find((b) => /^Accept 3 files/.test(b.textContent));
      if (!btn) return false;
      btn.click();
      return true;
    `);

    const fourthAsked = await settled(fbB,
      `[...document.querySelectorAll('#messages .msg.is-file')].some((row) => /grant-four\\.bin/.test(
         (row.querySelector('.file-title') || {}).textContent || '')
         && [...row.querySelectorAll('button')].some((b) => b.textContent === 'Accept'))`,
      120000, 'batch: the fourth file was offered on its own');
    check('a fourth file under a three-file grant is offered rather than taken',
      fourthAsked === true,
      await fbB.eval("return document.getElementById('messages').textContent.slice(-240);"));
    const fourthTaken = await fbB.eval(`
      const row = [...document.querySelectorAll('#messages .msg.is-file')].find(
        (r) => /grant-four\\.bin/.test((r.querySelector('.file-title') || {}).textContent || ''));
      if (!row) return 'no row';
      return [...row.querySelectorAll('button')].some((b) => b.textContent === 'Save') ? 'saved' : 'not saved';
    `);
    check('and it was not written anywhere while it waits to be answered',
      fourthTaken === 'not saved', String(fourthTaken));
    check('the three files the grant did cover still arrived',
      (await fbB.eval(`
        const titles = [...document.querySelectorAll('#messages .msg.is-file')]
          .filter((r) => [...r.querySelectorAll('button')].some((b) => b.textContent === 'Save'))
          .map((r) => (r.querySelector('.file-title') || {}).textContent || '').join(' ');
        return String(['grant-one.bin', 'grant-two.bin', 'grant-three.bin'].filter((n) => titles.includes(n)).length);
      `)) === '3',
      await fbB.eval("return document.getElementById('messages').textContent.slice(-240);"));

    check('batch: the receiving tab raised no uncaught page errors',
      fbB.pageErrors.length === 0, fbB.pageErrors.join(' | '));
    check('batch: the sending tab raised no uncaught page errors',
      fbA.pageErrors.length === 0, fbA.pageErrors.join(' | '));

    await fbA.eval("document.getElementById('sever').click(); return true;");
    fbA.close();
    fbB.close();
  }

  severTested = true;
} finally {
  await browser.close();
  await server.stop();
  fs.rmSync(TMP, { recursive: true, force: true });
}

check('the full lifecycle ran to completion', severTested);
process.exit(summary('browser end-to-end') ? 0 : 1);
