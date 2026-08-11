// Warp Gate user interface.
//
// This file owns the DOM and nothing else. All protocol and cryptography lives in
// session.js, crypto.js, peer.js and signal.js.

// EXTENSION COPY of public/js/app.js. Every change is marked `EXTENSION PATCH` and is
// listed in extension/README.md. It is produced by extension/sync-from-public.mjs and
// checked by extension/drift-check.mjs, so diff this against public/js/app.js and the only
// hunks should be the ones named there.
//
// The copy exists because the web client writes its requests as absolute PATHS, which
// resolve against `chrome-extension://<id>` here and reach nothing. The upstream change
// that would delete this copy is written up in extension/README.md.

import {
  generateGateCode, decodeGateCode, tryDecodeGateCode, deriveSecret, clearSecretCache,
  GateCodeError, deriveRoomId,
} from './crypto.js';
// EXTENSION PATCH: this page is not served by the signalling server, so neither the API
// origin nor the shareable gate link can be read off `location`. See js/endpoint.js.
import { signalOrigin, gateLink, DEFAULT_ORIGIN } from './endpoint.js';
import { fetchConfig, checkRoom } from './signal.js';
import { Session, STATE } from './session.js';
import { checkWebRtcCapability, hostSuppressedAdvice } from './peer.js';
import {
  describeLimit, canAccept, formatBytes, saveBlob, sanitizeFilename, revokeAllObjectUrls,
  canStreamToDisk,
} from './transfer.js';
// qr.js and share.js are reached through import() rather than a static import, so neither
// is fetched to open a gate. See loadQr() and the initShare() call at the foot of this
// file for why each is off the critical path.

// common.js, not support.js. Both documents need these two; only the landing has the
// donation cards and the modal markup that the rest of support.js drives, so importing it
// here fetched 7.2 KB of UI this document cannot display. See common.js.
import { applySourceLink, copyText as writeClipboard } from './common.js';
import { forgetPasswordKey, forgetAllPasswordKeys } from './vault.js';
// gameplay.js, gameui.js and the four engines are ~88 KB and none of it can run until
// somebody decides to play. They are therefore NOT imported here: see loadGames().
// saswords.js is likewise not imported here: see loadSasWords(), which starts the fetch
// the moment a gate exists.

/**
 * Fetch the QR encoder, once, the first time somebody asks to see a code.
 *
 * qr.js is 13 KB of encoder and generator polynomials that nothing needs in order to open
 * or join a gate: the only two things that draw with it are the share panel, which is
 * revealed by a press and deliberately renders nothing until then, and the donation modal
 * in support.js. Both are decisions made after the page is usable, which is exactly the
 * rule tests/size.test.mjs applies to everything else it keeps off the eager graph.
 *
 * The module namespace is cached rather than the promise being re-awaited per call so
 * that a second reveal is synchronous in everything but name.
 */
let qrMod = null;
async function loadQr() {
  if (!qrMod) qrMod = await import('./qr.js');
  return qrMod;
}

const $ = (id) => document.getElementById(id);
const SCREENS = ['onboarding', 'home', 'password', 'waiting', 'connected', 'severed', 'failed'];
// Bumping the version re-prompts everyone, which is the point if the terms change.
const AGREEMENT_KEY = 'wg.agreed.v1';
// Set once, from describeLimit(), when this browser cannot stream a received file
// straight to disk. Empty means there is nothing to say and the note stays hidden.
let receiveNoteText = '';
// Bounded by what one data channel message can carry. 32k characters is 128 KB even if
// every one of them is a 4-byte emoji, which stays clear of the SCTP ceiling.
const MAX_MESSAGE_CHARS = 16000;

let session = null;
let config = null;
// A file the operating system shared into this gate before there was a gate to share it
// into. It waits here until a peer connects, then goes out like any other attachment.
let pendingShare = [];
// The game layer, built once per gate in wire(). Null until then.
let games = null;
let gameUi = null;
let gamesLoading = null;
// Messages that arrived while the module was still in flight, replayed in order once it
// lands. Bounded: a peer that floods `game` frames at a device with no games loaded must
// not be able to grow this without limit, and a real match never queues more than the
// invite plus a move or two.
const gameBacklog = [];
const GAME_BACKLOG_MAX = 32;
let ttlTimer = null;
let diag = { candidates: [], ice: null, full: null };
// True once this gate reached STATE.CONNECTED, which is the whole test for whether the
// product worked for this person. It gates the one and only ask for money, and it is set
// in exactly one place. Nothing on the failure paths can set it, by construction.
let everConnected = false;

// The transcript is deliberately retained past sever, so it is the one list in this page
// with no natural end. Without a cap a peer looping messages grows the DOM until the tab
// dies. #log has had this discipline since it was written; #messages needs it too.
const MAX_MESSAGES = 200;

// Inline previews are the expensive kind of row: each one pins a decoded bitmap or a
// demuxed media header plus the blob behind an object URL, and session.js accepts anything
// under 10 MB with no prompt at all. Only the newest few stay rendered; older ones become
// Save-only. Images, video and audio share this one budget on purpose: the cost being
// bounded is memory, and memory does not care which tag is holding it.
const MAX_INLINE_PREVIEWS = 3;

// A participant's display name is derived here rather than received (session.js), so it
// cannot be hostile and cannot be long. This clamp is not defence against the peer, it is
// defence against a future where some other string reaches these two functions: a label
// that arrives at a message row or a roster pill is bounded before it is rendered, full
// stop, and there is no path where a longer one is allowed through instead.
const MAX_NAME_CHARS = 32;

// The MIME allowlists, the inline elements and the Open button all live in preview.js,
// which is fetched only once a file has actually been received. See the head of that file
// for why, and renderFilePreview() below for the call site.

// How many local sends are in flight. renderProgress consults this so it can refuse to
// CREATE a row for an outbound transfer this side never started (see H7).
let localSends = 0;
// The transfer id of the send sendFilesNow is currently awaiting, learned from the offer row
// link.js draws before it waits for acceptance. Null until that offer goes out.
let offeredRowId = null;

// The drag veil's state lives at module level so show() and the Escape/dragend resets can
// clear it. A drag cancelled in a browser that emits no balancing dragleave otherwise
// leaves a full-screen panel with nothing able to dismiss it.
let dragDepth = 0;
function resetDrag() {
  dragDepth = 0;
  const veil = $('drop-veil');
  if (veil) veil.hidden = true;
}

// Slot persistence. Without this a page reload is fatal: re-joining a gate you already
// occupy is correctly refused as full, so the session could never be recovered.
//
// The room secret is held here too, because it is deliberately no longer in the address
// bar. sessionStorage is scoped to this tab and discarded when the tab closes, which is
// a far higher bar than a URL anyone can read over your shoulder. It is removed the
// moment the gate ends. Note that some browsers write sessionStorage to disk for crash
// recovery, so this is a short-lived convenience, not a vault.
const slotKey = (roomId) => `wg.slot.${roomId}`;
const SECRET_KEY = 'wg.secret';

function rememberSecret(formatted) {
  try { sessionStorage.setItem(SECRET_KEY, formatted); } catch (err) { void err; }
}

function recallSecret() {
  try { return sessionStorage.getItem(SECRET_KEY); } catch (err) { return null; }
}

function forgetSecret() {
  try { sessionStorage.removeItem(SECRET_KEY); } catch (err) { void err; }
}

function rememberSlot(roomId, slot) {
  try {
    sessionStorage.setItem(slotKey(roomId), JSON.stringify(slot));
  } catch (err) { void err; }
}

function recallSlot(roomId) {
  try {
    const raw = sessionStorage.getItem(slotKey(roomId));
    return raw ? JSON.parse(raw) : null;
  } catch (err) { return null; }
}

function forgetSlot(roomId) {
  try {
    if (roomId) sessionStorage.removeItem(slotKey(roomId));
    else for (const k of Object.keys(sessionStorage)) if (k.startsWith('wg.slot.')) sessionStorage.removeItem(k);
    forgetSecret();
    // S is stretched once and held in a module-level map in crypto.js so a reload does not
    // pay PBKDF2 again. That map outlives the session object, so the gate ending has to say
    // so explicitly: otherwise the derived key is still in this tab's heap after the code
    // it came from was forgotten.
    clearSecretCache();
  } catch (err) { void err; }
  // The stretched room password is filed per tab under the room id so that a reload does
  // not have to ask for it again (public/js/vault.js). Session.teardown() drops it, but
  // three paths here abandon a slot with no session left to tear down: a room the server
  // says is gone, a resume that threw, and the unreachable handler, which nulls `session`
  // outright. Same choke point, same lifetime, so it is dropped here too.
  //
  // Outside the try above on purpose: those sessionStorage calls can throw as a group and
  // skip everything after them, and this is the one thing here that must not be skipped.
  // vault.js catches on every access, so it cannot throw out of forgetSlot.
  if (roomId) forgetPasswordKey(roomId);
  else forgetAllPasswordKeys();
}

// ---------------------------------------------------------------- chrome

// Set the moment a session asks for a room password, cleared when one is supplied or the
// gate is abandoned. Both the join and the resume flow emit password-required from inside
// the very call whose success path then shows the waiting screen, so without this the
// prompt is drawn and immediately covered over, and the handshake blocks forever on a
// password the user was never given the chance to type.
let promptingForPassword = false;

// Banners the user has closed. sessionStorage, not localStorage: "I have read this"
// is true for this tab and this visit, and a capability warning that stays dismissed
// forever would hide a genuinely new failure on a later visit. A tab that refuses
// storage (private mode with the quota at zero, an embedded webview) simply keeps
// showing the banners, which is the safe direction to fail in.
const DISMISSED_KEY = 'wg.dismissed.v1';

function isDismissed(id) {
  try {
    return sessionStorage.getItem(`${DISMISSED_KEY}:${id}`) === '1';
  } catch (err) {
    void err;
    return false;
  }
}

function markDismissed(id) {
  try {
    sessionStorage.setItem(`${DISMISSED_KEY}:${id}`, '1');
  } catch (err) {
    // Not worth a log line. The banner still closes for this view; it just comes back
    // on the next screen change, and the alternative is failing to close it at all.
    void err;
  }
}

/**
 * Wire every [data-dismiss] close button to the banner it names.
 *
 * The attribute carries the element id rather than relying on the button's position,
 * because show() and runCapabilityCheck() both decide these banners' visibility by id
 * and the two have to agree about what was dismissed.
 */
function wireDismissables() {
  for (const btn of document.querySelectorAll('[data-dismiss]')) {
    btn.addEventListener('click', () => {
      const id = btn.dataset.dismiss;
      const target = $(id);
      // Fade and a 4px lift, then hide. Deliberately NOT a height collapse: these banners
      // sit above a screen that may be running a live transfer, and animating a height
      // relayouts the whole page under it on every frame.
      //
      // markDismissed runs immediately, not on animationend. What was dismissed is a fact
      // the moment the button was pressed, and it must survive a reload landing in the
      // middle of the 150ms.
      if (target) {
        // A banner that never hides because an animationend did not arrive is a worse
        // outcome than one that hides abruptly, so the timer is a floor rather than a
        // nicety: whichever lands first wins and the second call is a no-op.
        const done = () => {
          target.classList.remove('is-leaving');
          target.hidden = true;
        };
        target.classList.add('is-leaving');
        target.addEventListener('animationend', done, { once: true });
        setTimeout(done, FADE_MS + 200);
      }
      markDismissed(id);
    });
  }
}

// How long the fade out runs before the modal is hidden outright. Must match the
// transition in .wg-modal, or the panel snaps away mid-fade.
//
// Read out of the token rather than held as a literal. This was `180`, duplicating the
// `0.18s` in the stylesheet, and the two were free to drift: nothing connected them and
// nothing would have said so. The fallback is the token's own value, for the case where
// the stylesheet did not load at all, where a modal that hides 150ms late is not the
// problem anyone has.
const FADE_MS = parseFloat(
  getComputedStyle(document.documentElement).getPropertyValue('--motion-small'),
) || 150;

/**
 * Make a .wg-modal opaque, one layout after it stopped being display:none.
 *
 * The obvious way to write this is requestAnimationFrame, and it is wrong here: rAF does
 * not run in a tab that is not being painted. The ask is raised on BOTH sides of a gate
 * the instant it is burned, and the other side is very often a phone with the screen off
 * or a tab in the background, where the callback never fires. That left a modal at
 * opacity 0 covering the whole viewport: invisible, and still swallowing every click.
 *
 * Reading offsetHeight forces the layout synchronously instead, which the engine does
 * whether or not it intends to paint, so the transition has a start value either way.
 */
function revealModal(modal) {
  void modal.offsetHeight;
  modal.classList.add('wg-modal-open');
}

/**
 * Ask for a tip, once per tab, and only after a gate that actually worked.
 *
 * Two conditions, both of which have to hold, and neither of which is a heuristic:
 *
 *  - `everConnected`. Set on STATE.CONNECTED and nowhere else. A pair that never
 *    connected reaches #screen-failed, which does not call this at all, and a pair that
 *    connected and then dropped stays on #screen-connected (link.js holdOpen), so it does
 *    not reach here either. The ask cannot appear on the back of a failure.
 *  - not already dismissed this tab. Somebody who closed it once has answered.
 *
 * It is a nag, so it fails silently and closes on anything: the button, the scrim, Escape.
 */
function maybeAskForSupport() {
  if (!everConnected) return;
  if (isDismissed('donate-modal')) return;
  const modal = $('donate-modal');
  if (!modal) return;

  const close = () => {
    modal.classList.remove('wg-modal-open');
    document.removeEventListener('keydown', onKey);
    markDismissed('donate-modal');
    setTimeout(() => { modal.hidden = true; }, FADE_MS);
    // Back to the screen underneath, which is the one with "Open a new gate" on it.
    $('restart')?.focus();
  };
  function onKey(event) {
    if (event.key === 'Escape') close();
  }

  $('donate-close').addEventListener('click', close, { once: true });
  $('donate-scrim').addEventListener('click', close, { once: true });
  document.addEventListener('keydown', onKey);

  modal.hidden = false;
  revealModal(modal);
  $('donate-close').focus();
}

/**
 * Say out loud, once per tab, that a direct connection exposes both IP addresses, and
 * give the user the chance to go and turn a VPN on before anything is opened.
 *
 * Resolves true to carry on, false to abandon the flow. It deliberately does NOT claim to
 * have checked anything: see the comment on #net-modal in app.html for why a real VPN
 * check is not available to this document and is not going to be.
 *
 * Awaited from inside startCreate() and startJoin() rather than from the button handlers,
 * because boot's auto-join follows a link straight into startJoin() without passing
 * through runFlow, and a warning the link path skips is a warning most people never see.
 */
function confirmNetworkExposure(mode) {
  if (isDismissed('net-modal')) return Promise.resolve(true);
  const modal = $('net-modal');
  // No markup, no gate. This must never be the thing that stops somebody connecting.
  if (!modal) return Promise.resolve(true);

  // One modal serves both paths, and the title was written for only one of them: somebody
  // following a link was told "Before you open a gate" while joining one. The body is the
  // same either way, because the exposure is the same either way.
  $('net-title').textContent = mode === 'join'
    ? 'Before you join a gate'
    : 'Before you open a gate';

  return new Promise((resolve) => {
    const finish = (proceed) => {
      modal.classList.remove('wg-modal-open');
      document.removeEventListener('keydown', onKey);
      $('net-continue').removeEventListener('click', onYes);
      $('net-cancel').removeEventListener('click', onNo);
      $('net-scrim').removeEventListener('click', onNo);
      setTimeout(() => { modal.hidden = true; }, FADE_MS);
      // Only a Continue records the acknowledgement. Backing out is not an answer to
      // "have you read this", so the next attempt asks again.
      if (proceed) markDismissed('net-modal');
      resolve(proceed);
    };
    const onYes = () => finish(true);
    const onNo = () => finish(false);
    function onKey(event) {
      // Escape is a cancel here, not a dismissal: this one holds up an action.
      if (event.key === 'Escape') finish(false);
    }

    $('net-continue').addEventListener('click', onYes);
    $('net-cancel').addEventListener('click', onNo);
    $('net-scrim').addEventListener('click', onNo);
    document.addEventListener('keydown', onKey);

    modal.hidden = false;
    revealModal(modal);
    $('net-continue').focus();
  });
}

/** show(), unless a password prompt is up and waiting for the user. */
function showUnlessPrompting(name) {
  if (promptingForPassword) return;
  show(name);
}

/**
 * The screens that get an entrance, and the three that deliberately do not.
 *
 * 'severed' and 'failed' report a bad outcome, where a decorative arrival reads as
 * flippant and delays text somebody needs to read right now. 'password' holds up an
 * action and would put 300ms between the screen appearing and focus landing in
 * #password-input. All three arrive in one frame instead.
 */
const ENTERING = new Set(['onboarding', 'home', 'waiting', 'connected']);

function show(name) {
  for (const screen of SCREENS) $(`screen-${screen}`).hidden = screen !== name;
  // The outgoing screen is hidden in the SAME frame as the incoming one appears: this is
  // an entrance, never a crossfade. Fading one out and then the next in costs 450ms
  // before the user sees the screen they asked for, and that does not read as polish, it
  // reads as latency.
  //
  // No forced layout, no rAF, no double flush. An element leaving display:none restarts
  // its CSS animations by itself, which is exactly why this is a @keyframes and not a
  // transition: revealModal() has to do `void modal.offsetHeight` for that reason and
  // that pattern is not copied here.
  if (ENTERING.has(name)) {
    const el = $(`screen-${name}`);
    el.dataset.enter = '';
    el.addEventListener('animationend', () => { delete el.dataset.enter; }, { once: true });
  }
  // Any screen change ends whatever drag was in progress; the veil must not survive it.
  resetDrag();
  // #extras used to be toggled here, because it was a page-level band that had to be
  // shown on onboarding, home and severed and hidden everywhere else. It is a cell of
  // the home screen's own grid now, so the <section class="screen"> around it already
  // governs when it paints and a second switch here could only ever disagree with the
  // first one. Removed rather than left as a no-op: a line that sets `hidden` on an
  // element inside an already-hidden ancestor is a rule nobody can test.
  // The status badge describes a gate, so it appears once there is one to describe.
  // On the consent screen and the front page there is no gate and nothing has gone
  // wrong, so "idle" in the corner is chrome reporting the absence of an event.
  // 'severed' keeps it: "burned" is the outcome of the gate you just had.
  const statusBadge = $('status-badge');
  if (statusBadge) statusBadge.hidden = ['onboarding', 'home'].includes(name);
  // What this browser can RECEIVE is worth stating while you are still deciding to open
  // a gate, and is noise once one is open.
  const receive = $('receive-note');
  if (receive && receiveNoteText) {
    receive.hidden = isDismissed('receive-note') || !['onboarding', 'home'].includes(name);
  }
  if (name === 'onboarding') fitDisclosures();
  scrollPageToTop();
}

/**
 * Put the scroll position back at the top of the page.
 *
 * The document itself no longer scrolls: `.page` is the scroll container, so that the
 * status log can be a layout row at the bottom of the viewport instead of a fixed panel
 * painting over the last 60px of every screen. Both are scrolled here because engines
 * without :has() keep the old document-level scrolling, and a screen change has to land
 * at the top on either.
 */
function watchLogHeight() {
  const box = $('log');
  const page = document.querySelector('.page');
  if (!box || !page || typeof ResizeObserver !== 'function') return;
  // The connected screen sizes itself against the viewport, and the log is a row of that
  // viewport, so the screen has to know how tall the row currently is. Publishing the
  // real height beats reserving the 26vh maximum, which left a dead strip under the
  // composer whenever the log held a single line. CSSOM, not a style attribute: the CSP
  // forbids the latter, not this.
  const publish = () => {
    const h = box.textContent.trim() ? Math.round(box.getBoundingClientRect().height) : 0;
    document.documentElement.style.setProperty('--log-h', `${h}px`);
  };
  new ResizeObserver(publish).observe(box);
  publish();
}

function scrollPageToTop() {
  const page = document.querySelector('.page');
  if (page) page.scrollTop = 0;
  window.scrollTo(0, 0);
}

/**
 * The onboarding disclosures ship OPEN, and are collapsed here on a narrow viewport.
 *
 * They are the informed half of informed consent, so the no-script and unknown-viewport
 * outcome has to be "all of it is on the page". A phone cannot show five open panels
 * without burying the agreement under 3000px of scrolling, so on a narrow screen they
 * become the accordion they have always been. Only ever runs while the onboarding screen
 * is being shown, and never re-runs on resize: reaching in to close a panel somebody
 * deliberately opened would be worse than either layout.
 */
/**
 * Fade a disclosure body in when the USER opens it, and only then.
 *
 * Keyed off a class this listener sets rather than off [open], and that distinction is
 * the whole reason this function exists. The onboarding disclosures ship OPEN, so a
 * `details.disc[open] > .disc-body` rule would replay on all five of them every time
 * show('onboarding') runs and fitDisclosures() touches them. A toggle event is the only
 * signal that says a person did this.
 *
 * Open only. Closing is instant: a panel somebody has decided to be rid of should be
 * gone, not lingering while it is animated away.
 */
function wireDisclosureMotion() {
  for (const disc of document.querySelectorAll('details.disc')) {
    const body = disc.querySelector('.disc-body');
    if (!body) continue;
    disc.addEventListener('toggle', () => {
      if (!disc.open) {
        disc.classList.remove('is-opening');
        return;
      }
      disc.classList.add('is-opening');
      body.addEventListener('animationend', () => disc.classList.remove('is-opening'), { once: true });
    });
  }
}

let disclosuresFitted = false;
function fitDisclosures() {
  if (disclosuresFitted) return;
  disclosuresFitted = true;
  if (window.innerWidth >= 1024) return;
  for (const disc of document.querySelectorAll('#screen-onboarding details.disc')) {
    disc.open = false;
  }
}

/**
 * Test whether this browser can do peer-to-peer, and if not, say exactly how to fix it.
 *
 * `manual` is true when the user pressed Re-check, which is the one case where a
 * successful result deserves to be announced rather than passing silently.
 */
async function runCapabilityCheck(manual) {
  const banner = $('webrtc-warning');
  const recheck = $('webrtc-recheck');
  if (manual) {
    recheck.disabled = true;
    recheck.textContent = 'Checking...';
  }

  let result;
  try {
    result = await checkWebRtcCapability(config?.iceServers ?? []);
  } catch (err) {
    log(`could not check WebRTC support: ${err.message}`, 'warn');
    return;
  } finally {
    recheck.disabled = false;
    recheck.textContent = 'Re-check';
  }

  // Capable, and local addresses available: nothing to say.
  if (result.capable && result.via !== 'srflx') {
    banner.hidden = true;
    banner.classList.remove('note');
    if (manual) log('WebRTC is working now. You can open or join a gate.', 'ok');
    return;
  }

  // Capable, but only over the public address. Cross-network works; same-network may
  // not, because that would need the router to hairpin. Worth saying, quietly.
  const advice = result.capable ? hostSuppressedAdvice() : result;
  banner.classList.toggle('note', Boolean(result.capable));

  $('webrtc-warning-title').textContent = result.capable
    ? 'Same-network connections may not work'
    : (advice.browser ? `${advice.browser} is blocking direct connections` : 'This browser cannot make direct connections');
  $('webrtc-warning-text').textContent = advice.headline ?? '';

  const steps = $('webrtc-steps');
  steps.replaceChildren();
  for (const step of advice.steps ?? []) {
    const li = document.createElement('li');
    li.textContent = step;
    steps.appendChild(li);
  }

  // Shown as copyable text, not a link: browsers block pages from navigating to their
  // own settings pages, so a link would just look broken.
  const hasPath = Boolean(advice.settingsPath);
  $('webrtc-path-row').hidden = !hasPath;
  $('webrtc-path-note').hidden = !hasPath;
  if (hasPath) $('webrtc-settings-path').textContent = advice.settingsPath;

  $('webrtc-reassurance').textContent = advice.reassurance ?? '';
  // A manual re-check is somebody asking for the answer, so it overrides a dismissal:
  // otherwise the button they just pressed would appear to do nothing.
  banner.hidden = !manual && isDismissed('webrtc-warning');
  if (result.capable) {
    if (manual) log('WebRTC works. Local addresses are hidden, so same-network pairs may fail.', 'warn');
  } else if (manual) {
    log('Still blocked. The setting may not have been applied yet.', 'warn');
  } else {
    log(advice.headline ?? 'This browser cannot make direct connections.', 'bad');
  }
}

/**
 * Move the conversation onto the severed screen so it stays readable.
 *
 * The point is the case this was reported for: transporting a password when the
 * connection drops. Having to run the whole gate cycle again to re-read something you
 * already received is pure friction, and keeping it costs nothing in privacy: the
 * plaintext is already in this page's memory. It is never written to storage, so
 * "gone when the tab closes" remains exactly true.
 */
function showTranscript() {
  const messages = $('messages');
  const holder = $('transcript-holder');
  const mount = $('transcript-mount');
  if (!messages || !holder || !mount) return;
  if (!messages.children.length) return; // nothing was exchanged
  mount.appendChild(messages);
  messages.classList.add('transcript');
  holder.hidden = false;
}

function clearTranscript() {
  releaseAllPreviews();
  // Empty the LIST, not the mount. showTranscript() MOVES #messages into
  // #transcript-mount, so replaceChildren() on the mount deleted #messages itself and
  // every later bubble(), scrollMessages(), addMessage() and fileRow() would throw on
  // null the moment anything tried to render again.
  $('messages').replaceChildren();
  $('transcript-holder').hidden = true;
  log('Transcript cleared.', 'ok');
}

// The donation cards moved to the landing document with the rest of the marketing,
// and their wiring went with them: see support.js, which landing.js loads. This
// document deliberately loads no code it does not need while a key is in memory.

// The last line written, so an identical repeat can be folded into it instead of pushing
// a ninth copy of the same sentence. A reconnect loop emits the SAME three messages every
// backoff round, and at 40 retained lines that meant the entire log was one loop's noise:
// the user's screenshot of a stuck gate showed "The other device never answered the
// connection offer" seven times and nothing else. Repeats are information about COUNT, not
// about sequence, so they belong on one line with a tally.
let lastLine = null;
let lastLineText = '';
let lastLineLevel = '';
let lastLineCount = 0;

/** Empty the log and put the dock away. Called when the thing it describes is gone. */
function clearLog() {
  $('log').replaceChildren();
  lastLine = null;
  lastLineText = '';
  lastLineLevel = '';
  lastLineCount = 0;
  $('log-latest').textContent = '';
  $('log-more').textContent = '';
  $('log-dock').hidden = true;
  $('log-dock').removeAttribute('data-open');
  $('log-toggle').setAttribute('aria-expanded', 'false');
}

function log(message, level = '') {
  const box = $('log');

  if (lastLine && message === lastLineText && level === lastLineLevel) {
    lastLineCount += 1;
    // The message stays whole and the count is appended, rather than the message being
    // rewritten: a line that says "x7" after the text is still greppable and still reads
    // as the sentence it is.
    lastLine.textContent = `${message}  (x${lastLineCount})`;
  } else {
    const line = document.createElement('div');
    if (level) line.className = level;
    line.textContent = message;
    box.appendChild(line);
    lastLine = line;
    lastLineText = message;
    lastLineLevel = level;
    lastLineCount = 1;
    while (box.children.length > 40) {
      // If the pruned node IS the one repeats are being folded into, the reference has to
      // go too. Otherwise the next duplicate would rewrite a node that is no longer in the
      // document and the message would vanish instead of appearing.
      const dropped = box.removeChild(box.firstChild);
      if (dropped === lastLine) { lastLine = null; lastLineText = ''; lastLineCount = 0; }
    }
  }

  box.scrollTop = box.scrollHeight;

  // The closed dock shows the newest line and, when it has been repeating, how many times.
  const dock = $('log-dock');
  dock.hidden = false;
  $('log-latest').textContent = message;
  $('log-latest').className = `log-latest${level ? ` ${level}` : ''}`;
  $('log-more').textContent = lastLineCount > 1 ? `x${lastLineCount}` : '';
}

function armLogDock() {
  const dock = $('log-dock');
  const toggle = $('log-toggle');
  toggle.addEventListener('click', () => {
    const open = dock.hasAttribute('data-open');
    if (open) dock.removeAttribute('data-open');
    else dock.setAttribute('data-open', '');
    toggle.setAttribute('aria-expanded', open ? 'false' : 'true');
    if (!open) { const box = $('log'); box.scrollTop = box.scrollHeight; }
  });
}

function badge(text, kind) {
  const el = $('status-badge');
  el.textContent = text;
  el.className = `badge badge-${kind}`;
}

const STATE_LABELS = {
  [STATE.IDLE]: ['idle', 'idle'],
  [STATE.CREATING]: ['creating gate', 'work'],
  [STATE.WAITING]: ['waiting for peer', 'work'],
  [STATE.EXCHANGING]: ['exchanging keys', 'work'],
  [STATE.NEGOTIATING]: ['negotiating', 'work'],
  [STATE.CONNECTING]: ['establishing direct connection', 'work'],
  [STATE.CONFIRMING]: ['verifying secret', 'work'],
  [STATE.CONNECTED]: ['connected', 'direct'],
  [STATE.RECONNECTING]: ['waiting for the other device', 'work'],
  [STATE.AUTH_FAILED]: ['verification failed', 'bad'],
  [STATE.UNREACHABLE]: ['could not connect', 'bad'],
  [STATE.SEVERED]: ['severed', 'idle'],
};

function startTtl(expiresAt) {
  stopTtl();
  const el = $('ttl');
  el.hidden = false;
  const tick = () => {
    const left = Math.max(0, expiresAt - Date.now());
    const mins = Math.floor(left / 60000);
    const secs = Math.floor((left % 60000) / 1000);
    el.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
    if (left <= 0) stopTtl();
  };
  tick();
  ttlTimer = setInterval(tick, 1000);
}

function stopTtl() {
  if (ttlTimer) clearInterval(ttlTimer);
  ttlTimer = null;
  $('ttl').hidden = true;
}

// ---------------------------------------------------------------- camera scan

/**
 * Wire the "scan with the camera" button.
 *
 * All this does is decide whether the button may exist and, if it is pressed, fetch the
 * panel that does the work. The panel, the camera plumbing and the QR decoder behind it are
 * ~60 KB in scanui.js and qrscan.js, and none of it is reachable until somebody chooses to
 * scan rather than type: see the header of scanui.js for why that is the line.
 *
 * The camera check itself stays here because it needs no module, is one property lookup,
 * and has to run on every load: a device that cannot open a camera must not be shown a
 * button that can only fail. It mirrors scanSupported() in qrscan.js, which is the
 * authority once the module is loaded.
 *
 * @param {() => void} joinNow the same join path the button and the Enter key use, handed
 *   through to scanui.js so a scanned code cannot take a second, less validated route in.
 */
function armScanner(joinNow) {
  const btn = $('scan-btn');
  if (typeof navigator?.mediaDevices?.getUserMedia !== 'function') return;
  btn.hidden = false;

  btn.addEventListener('click', async () => {
    const panel = $('scan-panel');
    // Painted BEFORE the await, restored in review on 2026-08-10. These three lines used to
    // live here and moved wholesale into scanui.js when the panel was split out, which put
    // the entire fetch of that module and its ~60 KB of QR decoder between the press and any
    // change on screen. On a slow connection that is a button that visibly does nothing, and
    // a button that does nothing is a button people press again. scanui.js still sets the
    // same three itself, so this is the same state written twice rather than a second source
    // of truth: the module cannot rely on a caller having done it.
    btn.hidden = true;
    panel.hidden = false;
    $('scan-note').textContent = 'Starting the camera...';
    try {
      const mod = await import('./scanui.js');
      await mod.scanIntoField({ $, log, joinNow });
    } catch (err) {
      // The panel never opened, so the button has to come back or the press leaves the page
      // with nothing on it to press. Reported rather than swallowed: a button that does
      // nothing at all reads as a broken page, not as a failed fetch.
      panel.hidden = true;
      btn.hidden = false;
      log(`the scanner could not be loaded: ${err.message}`, 'bad');
    }
  });
}

// ---------------------------------------------------------------- the spoken wordlist

let sasWordsLoading = null;

/**
 * Fetch the wordlist that turns the verification digits into two spoken words.
 *
 * The saving here is CPU rather than bytes: the wordlist itself (words.js) stays eager
 * because crypto.js needs it to decode a typed gate code. What defers is saswords.js's
 * module-eval work, which filters and phonetically de-collides all 7776 entries to build
 * the spoken list, and on a phone that is main-thread time spent before the home screen
 * paints for a value nobody sees until a peer connects.
 *
 * It still needs justifying more carefully than the games, because it IS on the security
 * path. Three things make deferring it safe:
 *
 *   - The digits are the verification value. They are written to the screen from the
 *     event itself, synchronously, and never wait on this. The words are a reading aid
 *     laid beside them.
 *   - The fetch is started by wire(), which runs when a gate is CREATED. A peer cannot
 *     connect for at least a network round trip after that, so by the time an `sas` event
 *     exists the list has had seconds, not milliseconds.
 *   - If it never arrives, the screen shows digits and no words. That is the mechanism
 *     this site shipped with, and it is still sound: two people reading five digits at
 *     each other verify exactly as much as two people reading two words.
 *
 * What it must never do is show words derived from a different list than the peer's. It
 * cannot: the derivation is pure and the list is pinned by SHA-256 in saswords.js.
 */
function loadSasWords() {
  if (!sasWordsLoading) {
    sasWordsLoading = import('./saswords.js').catch((err) => {
      // Cleared so a later gate retries rather than inheriting one bad fetch forever.
      sasWordsLoading = null;
      log(`spoken words unavailable, verify by digits: ${err.message}`, 'warn');
      return null;
    });
  }
  return sasWordsLoading;
}

// ---------------------------------------------------------------- games, on demand

/**
 * Bring the games in, once, for this gate.
 *
 * The four engines plus the match layer plus the board renderer are ~88 KB, and a gate
 * whose two people never open a board should not pay for a chess move generator. More to
 * the point for an auditor: none of that code is on the security path, and shipping it
 * ahead of the verification words puts entertainment bytes in front of the one screen
 * that has to be right.
 *
 * Two things trigger it: this device opening the drawer, or the other device sending an
 * invite. Whichever comes first wins; the second finds `gamesLoading` already set.
 *
 * A failed import is reported and left non-fatal. Chess not loading must never take the
 * transfer down with it, so this is deliberately not awaited by anything that matters.
 */
function loadGames(active) {
  if (gamesLoading) return gamesLoading;
  const area = $('game-area');
  if (!area.childElementCount) area.textContent = 'Loading games...';

  gamesLoading = Promise.all([import('./gameplay.js'), import('./gameui.js')])
    .then(([play, ui]) => {
      // The gate this load was started for may already be gone: a burn, a severed link
      // or a second create all replace `session` while the fetch is in flight. Wiring a
      // board to a dead link would send its moves nowhere and never say so.
      if (session !== active) return;
      const built = new play.GameSession({
        send: (peerId, payload) => active.sendGameTo(peerId, payload),
      });
      gameUi = new ui.GameUI({
        root: area,
        games: built,
        // Asked for on every render rather than captured once: people join and leave a
        // gate, and a stale partner list offers a game to somebody who is not here.
        partners: () => (session === active ? active.gamePartners() : []),
        // Neutral, not 'warn'. This channel now carries "X wants to play Chess", which is
        // an invitation and not a problem, and styling it as a warning next to real ones
        // teaches people to discount the colour.
        onNotice: (text) => log(text),
      });
      // Drain BEFORE publishing `games`, and drain synchronously, so an invite that
      // arrived during the fetch is applied ahead of any message that arrives after it.
      // Setting `games` first would let a later frame overtake the queued one.
      for (const held of gameBacklog) built.receive(held.peer, held.payload);
      gameBacklog.length = 0;
      games = built;
      gameUi.render();
    })
    .catch((err) => {
      gamesLoading = null;
      gameBacklog.length = 0;
      area.textContent = 'Games could not be loaded.';
      log(`games unavailable: ${err.message}`, 'warn');
    });
  return gamesLoading;
}

// ---------------------------------------------------------------- session wiring

function wire(active) {
  diag = { candidates: [], ice: null, full: null };
  // Per gate, not per page: two gates in one tab are two separate answers to "did this
  // actually work for you". Reset here rather than at boot for that reason.
  everConnected = false;

  // The games live for exactly one gate. A new gate is a new board, and a GameSession
  // carried over from the last one would hold a match id and a peer that no longer exist.
  // Cleared here rather than reloaded: the module stays in the browser's module map, so
  // a second gate pays for the fetch once and the constructor again.
  games = null;
  gameUi = null;
  gamesLoading = null;
  gameBacklog.length = 0;

  // Started here, at gate creation, rather than when the first `sas` event fires. A peer
  // is at minimum a signalling round trip away, so this has the whole handshake to land
  // in and the words are already there when the screen that shows them appears.
  loadSasWords();
  // Somebody who opened the drawer during the last gate has it open now, and an empty
  // panel would read as "no games here".
  if ($('games-disc').open) loadGames(active);

  // session.js forwards a link's object events with the peer id stamped on, so the whole
  // detail IS the payload plus that stamp. The stamp is applied after the spread, so a
  // peer cannot forge which board its own move belongs to by sending a `peer` field.
  active.addEventListener('game', (event) => {
    // An invite is the other half of the trigger: a peer can start a game on a device
    // that has never opened the drawer, and dropping their invite while the module
    // fetched would look like the invite was never sent.
    if (!games) {
      if (gameBacklog.length >= GAME_BACKLOG_MAX) return;
      gameBacklog.push({ peer: event.detail.peer, payload: event.detail });
      loadGames(active);
      return;
    }
    games.receive(event.detail.peer, event.detail);
  });

  active.addEventListener('state', (event) => {
    const [label, kind] = STATE_LABELS[event.detail.state] ?? [event.detail.state, 'work'];
    badge(label, kind);
    if (event.detail.state === STATE.CONNECTED) {
      everConnected = true;
      show('connected');
      // While both devices are here the server keeps pushing the expiry forward, so a
      // countdown would be misleading. It resumes if the other side leaves.
      stopTtl();
      const ttl = $('ttl');
      ttl.hidden = false;
      ttl.textContent = 'live';
      // Lede into the summary, detail into the disclosure's body. One string into one
      // element made the body empty, and an empty body under a line clamp is a control that
      // hides pixels while a screen reader still reads every word: see describeLimit().
      const limit = describeLimit();
      $('compose-hint').textContent = limit.lede;
      $('compose-hint-detail').textContent = limit.detail;
      // Whatever the operating system shared into this page before a gate existed goes
      // out now. Cleared first, so a second connection does not send it twice.
      if (pendingShare.length) {
        const queued = pendingShare;
        pendingShare = [];
        sendFiles(queued);
      }
      // The partner list only becomes non-empty here, so the menu has to be redrawn.
      if (gameUi) gameUi.render();
    }
    // Only a genuine key-confirmation failure says "could not verify". A connectivity
    // stall has its own state and its own far more specific message, set by the
    // unreachable handler below; overwriting it here produced the wrong title.
    if (event.detail.state === STATE.AUTH_FAILED) {
      // The gate has ended, so the room secret must go with it. Without this it stayed
      // in sessionStorage for the life of the tab, and the reload behind "Start again"
      // recalled it and auto-rejoined a room that is already gone.
      forgetSlot(active.roomId);
      $('failed-title').textContent = 'Could not verify the other device';
      // Not "the connection dropped". Reaching here means the bytes arrived and did not
      // authenticate, which is either the wrong gate code or somebody in the middle. It
      // gets its own sentence for that reason.
      $('failed-oops').textContent = 'The other device answered but could not prove it holds '
        + 'this gate code. Nothing was sent to it. Check that both devices are using the same '
        + 'code, and if they are, do not use this gate.';
      $('failed-detail').textContent = event.detail.detail ?? '';
      $('failed-diag').textContent = diagnosticText();
      show('failed');
    }
    if (event.detail.detail) log(`${label}: ${event.detail.detail}`);
  });

  active.addEventListener('sas', (event) => {
    const digits = event.detail;
    $('sas').textContent = digits;
    // The words are derived, not sent, and the derivation is a few hundred microseconds
    // of SHA-256. It is still async, so the answer is only written if the code on screen
    // is still the one it was derived from: a gate that re-keyed while this was in flight
    // must not end up showing one peer's digits beside another peer's words.
    const holder = $('sas-words');
    if (!holder) return;
    holder.textContent = '';
    loadSasWords().then((mod) => {
      if (!mod) return; // digits only, and that is a complete verification on its own
      return mod.sasPhrase(digits).then((phrase) => {
        if ($('sas').textContent === digits) holder.textContent = phrase;
      });
    }).catch((err) => { void err; });
  });

  active.addEventListener('roster', (event) => {
    renderRoster(event.detail ?? {});
    if (games) games.reconcile(active.gamePartners().map((p) => p.peer));
    if (gameUi) gameUi.render();
  });

  active.addEventListener('route', (event) => {
    const route = event.detail;
    const el = $('route-badge');
    if (route === 'relay') {
      el.textContent = 'RELAYED (still encrypted)';
      el.className = 'badge badge-relay';
    } else if (route) {
      el.textContent = `DIRECT P2P (${route})`;
      el.className = 'badge badge-direct';
      log(`connected directly, candidate type ${route}`, 'ok');
    } else {
      el.textContent = 'CONNECTED';
      el.className = 'badge badge-direct';
    }
  });

  active.addEventListener('chat', (event) => addMessage(event.detail));
  active.addEventListener('secret', (event) => addSecret({ ...event.detail, who: event.detail?.label ?? null }));

  active.addEventListener('progress', (event) => {
    const d = event.detail;
    if (d.kind === 'candidates' || d.kind === 'gathering-complete') diag.candidates = d.types;
    if (d.kind === 'ice') diag.ice = d.state;
    renderDiagnostics();
  });

  active.addEventListener('diagnostics', (event) => {
    diag.full = event.detail;
    renderDiagnostics();
  });

  active.addEventListener('unreachable', (event) => {
    // Stop the countdown first. It used to run for the life of the page, ticking down a
    // gate that had already failed, because only the severed handler ever stopped it.
    stopTtl();
    cancelClipboardWipe();
    $('failed-title').textContent = 'Could not connect the two devices';
    $('failed-oops').textContent = 'Oops. Looks like the connection dropped by accident. '
      + 'Please try again, or give us a heads up at warpgate@fysh.site.';
    $('failed-detail').textContent = event.detail;
    $('failed-diag').textContent = diagnosticText();
    forgetSlot(active.roomId);
    // Drop the reference so no later handler, Accept button or send acts on a dead one.
    if (session === active) session = null;
    show('failed');
  });

  active.addEventListener('auth-failed', (event) => log(event.detail, 'bad'));
  active.addEventListener('intruder', () => log('A device in this room could not be decrypted: it does not hold the room secret.', 'bad'));
  active.addEventListener('frame-rejected', (event) => log(`frame rejected: ${event.detail}`, 'bad'));
  active.addEventListener('warning', (event) => log(event.detail, 'warn'));
  active.addEventListener('peer-left', (event) => {
    const detail = event.detail;
    log(typeof detail === 'string' ? detail : detail.message, 'warn');
    // The gate is idle again, so show how long it has left.
    if (detail && detail.expiresAt) startTtl(detail.expiresAt);
    // Reconciled against who is actually left rather than against this event's detail,
    // which is a sentence for the log and does not always name a peer.
    if (games) games.reconcile(active.gamePartners().map((p) => p.peer));
    if (gameUi) gameUi.render();
  });

  active.addEventListener('severed', (event) => {
    // The gate has ended, so the room secret goes with it, whichever side ended it.
    // Only the local Sever button used to do this, so when the PEER severed, when the
    // TTL expired or when the room closed, the secret sat in sessionStorage for the
    // life of the tab: exactly the window the severed screen invites the user to leave
    // open, and browsers persist sessionStorage to disk for crash recovery. It also
    // made "Open a new gate" reload into a stale secret and auto-rejoin a dead room.
    forgetSlot(active.roomId);
    stopTtl();
    cancelClipboardWipe();
    // The transcript TEXT stays readable until the tab closes or the user clears it,
    // which is the whole point of the severed screen. The image previews do not: each
    // one pins a decoded bitmap and a blob with nothing to release it, so they are
    // demoted to Save-only rows here rather than held until pagehide.
    releaseAllPreviews();
    // A board belongs to a gate. The transcript survives a burn so it can be read; a
    // half-finished game cannot be played on, and leaving it on screen with dead buttons
    // reads as a gate that is still live.
    if (games) games.reset();
    // The batch models go with the gate, for the reason link.js gives where it nulls
    // pendingBatch, batchGrant and refusedBatch on close: consent does not survive the gate it
    // was given in. batchui.js's own map was never cleared at all, so peer-supplied filenames
    // lived for the life of the page and a later gate reusing a batch id would have found
    // them. Guarded because the module is only fetched when a batch was actually announced.
    if (batchUiMod) batchUiMod.forgetBatches();
    // Any transfer still running is over. Without this the row froze mid-progress with
    // no explanation, which reads as "still going" on a screen that says the gate ended.
    for (const bar of document.querySelectorAll('#messages progress')) {
      const row = bar.closest('.msg');
      bar.remove();
      if (row) rowStatus(row, 'Stopped: the gate was burned before this finished.', 'error small');
    }
    showTranscript();
    badge('burned', 'idle');
    // The heading already says "Gate burned.", so the local burn's own reason string is
    // the same sentence printed twice, one line apart. Every other reason (expired, the
    // other device burned it, the hard ceiling) says something the heading does not.
    const reason = event.detail ?? '';
    $('severed-reason').textContent = reason === 'Gate burned.' ? '' : reason;
    history.replaceState(null, '', location.pathname);
    show('severed');
    // The log described a gate that no longer exists. It used to survive the burn and sit
    // across the bottom of the severed screen still reciting the reconnect attempts of a
    // dead session, which reads as a gate that is somehow still trying. Everything it held
    // was about the connection, and the connection is what just ended.
    clearLog();
    // Last, and only after show(): the ask sits over the severed screen, so the screen has
    // to exist underneath it first.
    maybeAskForSupport();
  });

  // --- file events
  active.addEventListener('file-offered', (event) => renderOffer(event.detail));
  active.addEventListener('files-offered', (event) => renderBatchOffer(event.detail));
  active.addEventListener('file-refused', (event) => {
    const d = event.detail ?? {};
    log(`refused incoming file: ${d.reason}`, 'bad');
    noteFileOutcome('them', d.name, `Not accepted: ${d.reason ?? 'refused.'}`);
    noteBatchFile(d, 'refused', d.reason);
  });
  active.addEventListener('file-rejected', (event) => {
    const d = event.detail ?? {};
    log(`the other device refused the file: ${d.reason}`, 'bad');
    // Updated IN PLACE when a row exists. link.close reports a severed send through here, and
    // leaving that row alone while writing a second bubble under it is how one dead transfer
    // came to sit in two places, the older still showing a bar that would never move again.
    if (endRow(document.getElementById(`transfer-${d.id}`), d.reason ?? 'Not delivered.')) return;
    noteFileOutcome('me', d.name, `Not delivered: ${d.reason ?? 'refused.'}`);
  });
  active.addEventListener('file-accepted', (event) => {
    const d = event.detail ?? {};
    log('the other device accepted the file', 'ok');
    // The offer row said "waiting for it to be accepted there". This is the answer to that
    // sentence, and without it the row kept saying it was waiting for the whole transfer.
    const row = document.getElementById(`transfer-${d.id}`);
    if (row) rowStatus(row, 'Accepted on the other device. Sending.', 'muted small');
  });
  active.addEventListener('file-progress', (event) => renderProgress(event.detail));
  active.addEventListener('file-failed', (event) => {
    const d = event.detail ?? {};
    log(`transfer failed: ${d.reason}`, 'bad');
    endRow(document.getElementById(`transfer-${d.id}`), d.reason ?? 'The transfer failed.');
    noteBatchFile(d, 'failed', d.reason);
  });

  // --- interrupted transfers
  //
  // A dropped connection is not a failed transfer. Nothing is torn down on either side:
  // the receiver keeps its sink open and its byte count, the sender keeps its file, and
  // the row says so instead of disappearing.
  active.addEventListener('file-stalled', (event) => {
    const d = event.detail ?? {};
    const row = document.getElementById(`transfer-${d.id}`)
      ?? fileRow(d.id, d.direction === 'out' ? 'me' : 'them', d.label);
    if (!rowTitle(row).textContent) {
      rowTitle(row).textContent = `${sanitizeFilename(d.name, 'file')} (${formatBytes(d.total ?? 0)})`;
    }
    setProgress(row, d.sent ?? 0, d.total ?? 1);
    // Three things arrive on this one event and must not read as one. `offered` is a file
    // waiting for a human to say yes: ordinary, not a warning. `retrying` is a transfer still
    // being chased and has to look unmistakably unlike one that has given up, which is the
    // error-level row file-failed writes. "It only stopped moving" is what was reported, so
    // the distinction is the fix rather than decoration.
    const offered = d.kind === 'offered';
    // Which row belongs to the send sendFilesNow is currently awaiting. link.js mints the
    // transfer id and session.sendFile does not hand it back, so this is the only place the
    // id and the file the loop is on are known to be the same thing.
    if (offered && d.direction === 'out') offeredRowId = d.id;
    rowStatus(row, d.message ?? 'Paused. Waiting to continue.', offered ? 'muted small' : 'warn small');
    log(d.message ?? `${sanitizeFilename(d.name, 'file')}: paused`, offered ? '' : 'warn');
  });

  active.addEventListener('file-resumed', (event) => {
    const d = event.detail ?? {};
    const row = document.getElementById(`transfer-${d.id}`);
    if (row) rowStatus(row, `Continuing from ${formatBytes(d.offset ?? 0)}.`, 'muted small');
    log(`${sanitizeFilename(d.name, 'file')}: continuing from ${formatBytes(d.offset ?? 0)}`, 'ok');
  });

  active.addEventListener('file-reselect-needed', (event) => renderReselect(event.detail ?? {}));

  active.addEventListener('file-reselect-refused', (event) => {
    const d = event.detail ?? {};
    log(`refused to continue: ${d.reason}. Nothing was written, because joining two different `
      + 'files together would produce a corrupt file that still looks the right size.', 'bad');
  });

  active.addEventListener('inbound-recoverable', (event) => renderRecoverInbound(event.detail ?? {}));

  active.addEventListener('inbound-lost', (event) => {
    const d = event.detail ?? {};
    log(`${sanitizeFilename(d.name, 'file')} cannot be continued: ${d.reason}`, 'bad');
    const row = fileRow(d.id, 'them', d.label);
    rowTitle(row).textContent = `${sanitizeFilename(d.name)} (${formatBytes(d.size ?? 0)})`;
    rowStatus(row, d.reason ?? 'This transfer has to start again.', 'error small');
  });

  // The gate was up and is not up now. NOT a failure: nothing is torn down, the transcript
  // stays, any transfer is held, and the page says the true thing instead of accusing the
  // user's network of a NAT problem that a working connection has already disproved.
  active.addEventListener('holding', (event) => {
    const d = event.detail ?? {};
    const banner = $('conn-hint');
    if (banner) banner.textContent = d.peerLeft ? 'other device away, waiting' : 'reconnecting';
    const el = $('route-badge');
    if (el) {
      el.textContent = 'RECONNECTING';
      el.className = 'badge badge-work';
    }
    log(d.detail ?? 'The connection dropped. Waiting for the other device.', 'warn');
    if (d.transferInFlight) log('The transfer is being held where it stopped and will carry on by itself.', 'warn');
  });

  active.addEventListener('transfer-waiting', (event) => {
    log(`Still trying to reconnect; the paused transfer is being held. ${event.detail?.detail ?? ''}`, 'warn');
  });

  active.addEventListener('gate-deadline', (event) => {
    const d = event.detail ?? {};
    if (!d.expiring) return;
    const left = Math.max(0, (d.absoluteExpiresAt ?? 0) - Date.now());
    log(`This gate reaches the longest a single gate may live in about ${Math.round(left / 60000)} minutes, `
      + 'and will end then even if it is in use. Finish up, or open a new gate for the rest.', 'warn');
  });
  active.addEventListener('file-received', (event) => {
    const meta = event.detail;
    log(`received ${sanitizeFilename(meta.name)} (${meta.human})`, 'ok');
    finishFileRow(fileRow(meta.id, 'them', meta.label), meta, 'them');
    noteBatchFile(meta, 'done');
  });

  // Emitted by acceptIncoming and previously dropped on the floor. It carries the one
  // thing the user must be told: that the save dialog was unavailable and the file is
  // accumulating in RAM rather than streaming to the location they believe they picked.
  active.addEventListener('file-accepted-local', (event) => {
    const meta = event.detail;
    const name = sanitizeFilename(meta?.name);
    if (meta?.note) log(`${name}: ${meta.note}`, 'warn');
    else if (meta?.sink === 'memory') log(`${name} is being held in memory until it is complete.`, 'warn');
  });

  // Also previously unhandled: the peer's confirmation that it finished receiving.
  active.addEventListener('file-complete', (event) => {
    const d = event.detail ?? {};
    log(`the other device finished receiving the file (${formatBytes(d.bytes ?? 0)})`, 'ok');
  });

  active.addEventListener('connection-state', (event) => {
    const state = event.detail;
    if (state === 'failed' || state === 'disconnected') log(`peer connection ${state}`, 'warn');
    else log(`peer connection ${state}`);
  });

  active.addEventListener('file-incoming', (event) => {
    const meta = event.detail;
    const row = fileRow(meta.id, 'them', meta.label);
    rowTitle(row).textContent = `${sanitizeFilename(meta.name)} (${formatBytes(meta.size)})`;
    noteBatchFile(meta, 'receiving');
  });

  active.addEventListener('file-sent', (event) => {
    const meta = event.detail;
    finishFileRow(fileRow(meta.id, 'me'), { ...meta, human: formatBytes(meta.size) }, 'me');
  });

  active.addEventListener('password-required', () => {
    promptingForPassword = true;
    $('password-error').hidden = true;
    show('password');
    $('password-input').focus();
  });

  active.addEventListener('deriving', (event) => log(event.detail, 'warn'));
}

// ---------------------------------------------------------------- rendering

const CANDIDATE_MEANING = {
  host: 'host: a local network address, works on the same network only',
  srflx: 'srflx: your public address, this is what crosses networks',
  prflx: 'prflx: an address discovered during connectivity checks',
  relay: 'relay: a relayed address via TURN',
};

function diagnosticText() {
  const lines = [];
  const d = diag.full;
  const types = d?.local ?? diag.candidates;

  // Whether the two sides ever exchanged an offer and answer comes first: if they did
  // not, ICE never ran, and everything below it is meaningless rather than damning.
  if (d) {
    lines.push(`offer sent          : ${d.sentDescription ? 'yes' : 'no'}`);
    lines.push(`answer received     : ${d.gotDescription ? 'yes' : 'no'}`);
  }
  lines.push(`my address types    : ${types.length ? types.join(', ') : 'none yet'}`);
  for (const type of types) if (CANDIDATE_MEANING[type]) lines.push(`  ${CANDIDATE_MEANING[type]}`);
  if (d) lines.push(`peer address types  : ${d.remote.length ? d.remote.join(', ') : 'none received'}`);
  lines.push(`ice state           : ${d?.iceConnection ?? diag.ice ?? 'not started'}`);
  if (d) lines.push(`ice gathering       : ${d.iceGathering}`);
  const cross = types.includes('srflx') || types.includes('relay');
  lines.push(`cross-network able  : ${cross ? 'yes' : 'no, same network only'}`);
  return lines.join('\n');
}

/**
 * Show who is in the gate.
 *
 * One pill per participant including this device, each named. The name is DERIVED from the
 * room secret and that participant's slot id (session.js), so every device in the gate
 * prints the same name for the same person and nobody typed or transmitted anything. Our
 * own pill is marked "(you)" rather than being the only one without a name: the whole value
 * of the name is that the others are calling us that too.
 *
 * Each peer pill also carries that pair's own verification code: with a full mesh there is
 * no single code for the room, because every pair derives its own. A participant that is
 * present but not connected right now is shown faded rather than dropped, so "waiting for
 * them" and "they are gone" do not look alike.
 *
 * Names are derived, never received, so they cannot be hostile. They are still written with
 * textContent and never as markup, because the rule here is that nothing reaches the DOM as
 * markup, and a rule with an exception in it is not a rule.
 *
 * The roster is hidden outright when nobody else is here, which keeps a waiting gate quiet.
 */
// slot id -> last known connected flag. Bounded by the gate's participant count, which is
// bounded by the server's slot limit, so this cannot grow without end. Never cleared on
// an empty roster: a peer that drops and comes back is the same person returning, not a
// new arrival, and re-animating them would say otherwise.
const rosterSeen = new Map();

function renderRoster({ self = null, selfName = null, peers = [] } = {}) {
  const el = $('roster');
  if (!el) return;
  el.replaceChildren();
  if (!peers.length) {
    el.hidden = true;
    return;
  }
  const me = document.createElement('span');
  me.className = 'who-chip self';
  // Plain "you" until the name has been derived, which takes one HKDF and is over before
  // the first link connects. "you (you)" is what a nameless pill would otherwise read as.
  if (selfName) me.append(nameSpan(selfName), ' (you)');
  else me.textContent = 'you';
  if (self) me.title = `slot ${self}, this device`;
  el.appendChild(me);
  for (const peer of peers) {
    const chip = document.createElement('span');
    chip.className = `who-chip ${peer.connected ? 'live' : 'away'}`;
    // Arrival and departure, keyed off the slot id rather than off the element.
    //
    // This function rebuilds the whole roster with replaceChildren on EVERY render, and a
    // render happens on any peer state change, so an entrance rule written against the
    // chip itself would replay across the entire roster whenever one person's SAS was
    // derived. rosterSeen is what tells a genuinely new participant apart from the same
    // participant re-rendered. For the same reason "away" is an animation and not a
    // transition on .away: there is no surviving element for a transition to run on.
    const wasConnected = rosterSeen.get(peer.id);
    if (wasConnected === undefined) chip.classList.add('is-new');
    else if (wasConnected && !peer.connected) chip.classList.add('is-dimming');
    rosterSeen.set(peer.id, Boolean(peer.connected));
    chip.appendChild(nameSpan(peer.name ?? peer.label));
    if (peer.sas) {
      const code = document.createElement('span');
      code.className = 'who-sas';
      code.textContent = peer.sas;
      // A real space, not a CSS gap: the pill's text content is read by assistive
      // technology and asserted by the tests, and a margin is invisible to both.
      chip.append(' ', code);
    }
    // The slot id is routing information, not a secret, so it is safe to show; it is
    // here rather than in the pill because a name is what people can read out.
    chip.title = `slot ${peer.id}, ${peer.state}`;
    el.appendChild(chip);
  }
  el.hidden = false;
}

/** A participant's name, bounded and set as text. Never markup, never unbounded. */
function nameSpan(name) {
  const el = document.createElement('span');
  el.className = 'who-name';
  el.textContent = String(name ?? '').slice(0, MAX_NAME_CHARS);
  return el;
}

function renderDiagnostics() {
  const el = $('conn-detail');
  if (el) el.textContent = diagnosticText();
  const hint = $('conn-hint');
  if (hint) {
    const cross = diag.candidates.includes('srflx') || diag.candidates.includes('relay');
    hint.textContent = cross ? 'direct, cross-network capable' : 'same network only';
  }
}

const objectUrls = new Set();

// Rows currently showing an inline preview, oldest first. Held so the newest few can be
// kept and the rest released without walking the whole transcript.
const inlinePreviews = [];

// EVERY inline preview element carries this class, whatever its tag. This was
// 'img.msg-image', which could not release anything that was not an image: adding <video>
// without changing it would leave the object URL live, and a live object URL pins the
// ENTIRE file in memory for the life of the gate. One class, one selector.
const PREVIEW_SELECTOR = '.msg-media';

/**
 * Release the inline preview a row is holding: revoke its object URL and swap the element
 * for a line saying so. The Save button is untouched, so the file is still recoverable.
 */
function releasePreview(row) {
  const el = row.querySelector?.(PREVIEW_SELECTOR);
  if (!el) return;
  // Read the URL BEFORE tearing the element down: clearing the source below empties .src.
  const url = el.currentSrc || el.src;
  // A detached <video>/<audio> keeps playing in Chromium, so removing the node does not
  // stop it: a player still audible after its row says the preview was released is worse
  // than the memory that bought. pause, drop the source, load() to let go of the blob.
  if (typeof el.pause === 'function') {
    el.pause();
    el.removeAttribute('src');
    el.load();
  }
  el.remove();
  if (url) {
    URL.revokeObjectURL(url);
    objectUrls.delete(url);
  }
  const note = document.createElement('div');
  note.className = 'muted small';
  note.textContent = 'Preview released to free memory. Use Save to open the file.';
  row.appendChild(note);
}

function releaseAllPreviews() {
  for (const row of inlinePreviews.splice(0)) releasePreview(row);
  // Belt and braces: anything that escaped the list is still revoked.
  for (const url of objectUrls) URL.revokeObjectURL(url);
  objectUrls.clear();
  // saveBlob keeps its own URLs alive for 60 seconds so the download can start. Those
  // are this page's too, and severing should not have to wait out that timer.
  revokeAllObjectUrls();
}

/** Drop an evicted row's object URL, otherwise trimming the list would leak it. */
function discardRow(row) {
  const i = inlinePreviews.indexOf(row);
  if (i !== -1) inlinePreviews.splice(i, 1);
  // Not 'img[src^="blob:"]': a video or an audio element holds exactly the same kind of
  // URL and would have been walked straight past. Any element with a blob: source, and a
  // media element is stopped first so it cannot outlive its own row.
  for (const el of row.querySelectorAll?.('[src^="blob:"]') ?? []) {
    const url = el.src;
    if (typeof el.pause === 'function') {
      el.pause();
      el.removeAttribute('src');
      el.load();
    }
    URL.revokeObjectURL(url);
    objectUrls.delete(url);
  }
}

/**
 * One row in the single message stream. Everything lands here: text, secrets, files.
 *
 * `label` says WHICH participant a row came from: the sender's derived display name, which
 * every device in the gate computes identically for that slot. Our own rows stay "you",
 * because "you" is shorter and clearer than our own name on our own screen, and the roster
 * is where the name we answer to is shown.
 *
 * "them" is the fallback for a row whose sender the session could not name, which in a
 * settled gate does not happen. It is not the two-party case any more: a two-party gate
 * shows the one name it has, which is no more cluttered than "them" and stays true when a
 * third person arrives mid-conversation.
 */
function bubble(from, extraClass = '', label = null) {
  const wrap = document.createElement('div');
  wrap.className = `msg ${from === 'me' ? 'me' : ''} ${extraClass}`.trim();
  const who = document.createElement('span');
  who.className = from === 'me' ? 'who' : 'who from-peer';
  who.textContent = from === 'me' ? 'you' : String(label || 'them').slice(0, MAX_NAME_CHARS);
  wrap.appendChild(who);
  const list = $('messages');
  list.appendChild(wrap);
  // Same discipline as #log: this list is retained past sever and has no other end, so
  // a peer looping messages would otherwise grow the DOM until the tab dies. Evicting
  // has to release the row's object URL or trimming the list would trade one leak for
  // another.
  while (list.children.length > MAX_MESSAGES) {
    const evicted = list.firstElementChild;
    if (!evicted) break;
    discardRow(evicted);
    list.removeChild(evicted);
  }
  markArrival(wrap);
  list.scrollTop = list.scrollHeight;
  return wrap;
}

// A burst guard, not a rate limit. Three rows in a 200ms window is more than anyone
// reads; past that the animation is not telling anybody anything and every extra row is
// another element on the compositor, on the same main thread a transfer is using. A peer
// replaying history, or a transfer emitting status rows faster than they can be read,
// would otherwise put the whole burst up at once.
const BURST_WINDOW_MS = 200;
const BURST_MAX = 3;
let burstStart = 0;
let burstCount = 0;

/**
 * Mark a row as newly arrived, so the stylesheet fades it in.
 *
 * No will-change: #messages holds up to MAX_MESSAGES rows and a layer per row is memory
 * held for the life of the gate. MDN is explicit that will-change "should not be used to
 * anticipate performance problems".
 */
function markArrival(el) {
  const now = performance.now();
  if (now - burstStart > BURST_WINDOW_MS) {
    burstStart = now;
    burstCount = 0;
  }
  burstCount += 1;
  if (burstCount > BURST_MAX) return;
  el.classList.add('is-new');
  // Removed on the way out, so a row that is still on screen an hour later is not
  // carrying an animation the compositor has to keep a record of.
  el.addEventListener('animationend', () => el.classList.remove('is-new'), { once: true });
}

function scrollMessages() {
  const list = $('messages');
  list.scrollTop = list.scrollHeight;
}

function addMessage({ from, text, label = null }) {
  const wrap = bubble(from, '', label);
  const body = document.createElement('span');
  body.className = 'msg-text';
  body.textContent = text;
  wrap.appendChild(body);
  scrollMessages();
}

// `who` rather than `label`: the masked-secret bubble already uses `label` for its
// accessible description, and shadowing that produced a duplicate declaration.
function addSecret({ from, text, who = null }) {
  const wrap = bubble(from, 'is-secret', who);

  const tag = document.createElement('span');
  tag.className = 'chip';
  tag.textContent = 'secret';
  wrap.appendChild(tag);

  // The plaintext is deliberately NOT in the DOM while masked. The CSS mask hides it
  // from the eye, from Select-All and from innerText, but textContent still put it in
  // the accessibility tree, and #messages is aria-live="polite": a screen reader read
  // an arriving secret out loud before the recipient had chosen to reveal it, which is
  // precisely the shoulder-surfing the mask exists to prevent. The plaintext lives in
  // this closure and is written into the node only while revealed, so the placeholder
  // does not depend on the blur holding up either.
  const label = from === 'me' ? 'secret sent' : 'secret received';
  const placeholder = `${'•'.repeat(Math.min(text.length, 32))} ${text.length} characters`;
  const value = document.createElement('div');
  value.className = 'secret-value masked';
  const setMasked = (masked) => {
    value.textContent = masked ? placeholder : text;
    if (masked) value.setAttribute('aria-hidden', 'true');
    else value.removeAttribute('aria-hidden');
    wrap.setAttribute('aria-label', `${label}, ${masked ? 'hidden' : 'revealed'}`);
  };
  setMasked(true);
  wrap.appendChild(value);

  const actions = document.createElement('div');
  actions.className = 'secret-actions';

  const reveal = document.createElement('button');
  reveal.className = 'secondary';
  reveal.textContent = 'Reveal';
  reveal.addEventListener('click', () => {
    const masked = value.classList.toggle('masked');
    setMasked(masked);
    reveal.textContent = masked ? 'Reveal' : 'Hide';
  });

  const copy = document.createElement('button');
  copy.className = 'secondary';
  copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    if (!await copyText(text)) return;
    copy.textContent = 'Copied';
    scheduleClipboardWipe(text, () => { copy.textContent = 'Copy'; });
  });

  actions.append(reveal, copy);
  wrap.appendChild(actions);
  scrollMessages();
}

// One implementation, in common.js, because the landing needs it too. The only
// difference here is where a refusal is reported: this document has a status log.
async function copyText(text) {
  return writeClipboard(text, log);
}

// The pending clipboard wipe. It used to be an unstored setTimeout per Copy click, so
// nothing could cancel it: the user copied a secret, severed, copied something unrelated
// from another application, and up to 45 seconds later this page silently wiped THAT.
// One handle, cancelled on a repeat click and whenever the gate ends.
let clipboardTimer = null;
const CLIPBOARD_WIPE_MS = 45000;

function cancelClipboardWipe() {
  if (clipboardTimer) clearTimeout(clipboardTimer);
  clipboardTimer = null;
}

/**
 * Clear the clipboard 45 seconds after a secret was copied, but only if it still holds
 * that secret. Best effort in both directions: no browser guarantees a clipboard can be
 * cleared, and a clipboard that cannot be READ is left alone rather than wiped blind.
 */
function scheduleClipboardWipe(secret, restoreLabel) {
  cancelClipboardWipe();
  clipboardTimer = setTimeout(async () => {
    clipboardTimer = null;
    restoreLabel();
    let current = null;
    try {
      current = await navigator.clipboard.readText();
    } catch (err) {
      log(`Left the clipboard alone: could not read it to check it still held the secret (${err.message}).`, 'warn');
      return;
    }
    if (current !== secret) {
      log('Left the clipboard alone: it no longer holds the secret.', 'ok');
      return;
    }
    await copyText('');
    log('Attempted to clear the clipboard. This is best effort and not guaranteed.', 'warn');
  }, CLIPBOARD_WIPE_MS);
}

/** Get or create the row for a transfer, so progress updates land in one place. */
function fileRow(id, from, label = null) {
  let row = document.getElementById(`transfer-${id}`);
  if (!row) {
    row = bubble(from, 'is-file', label);
    row.id = `transfer-${id}`;
    const title = document.createElement('div');
    title.className = 'file-title';
    row.appendChild(title);
  }
  return row;
}

const rowTitle = (row) => row.querySelector('.file-title');

/**
 * One status line per transfer row, replaced in place rather than appended.
 *
 * A stalled transfer can reconnect many times, and appending would turn one paused
 * transfer into a wall of near-identical lines that buries the row's actual state.
 */
// Pending status writes, coalesced to one paint. This is the one hot path in the file
// that fights everything else: a transfer calls rowStatus() many times a second, on a row
// inside a scrolling container, and every call was one style invalidation. Writing the
// same text twice between two frames buys nothing, so the last value per row wins and the
// intermediate ones are dropped. The Map is keyed by the row element and emptied on every
// flush, so it holds at most one entry per transfer in flight.
const pendingStatus = new Map();
let statusFrame = 0;
let statusTimer = 0;

function flushStatus() {
  if (statusFrame) cancelAnimationFrame(statusFrame);
  if (statusTimer) clearTimeout(statusTimer);
  statusFrame = 0;
  statusTimer = 0;
  for (const [row, { line, text, level }] of pendingStatus) {
    void row;
    line.className = `file-status ${level}`;
    line.textContent = text;
  }
  pendingStatus.clear();
}

/**
 * Ask for a flush on the next frame, with a timer as the floor.
 *
 * rAF alone would be wrong here for the same reason it is wrong in revealModal(): a tab
 * that is not being painted never fires one. A transfer runs perfectly well in a
 * background tab, and its status line silently freezing until the tab is looked at again
 * would be a real regression sold as an optimisation. Whichever of the two lands first
 * flushes and cancels the other, so a visible tab still gets exactly one write per frame.
 */
function scheduleStatusFlush() {
  if (statusFrame || statusTimer) return;
  statusFrame = requestAnimationFrame(flushStatus);
  statusTimer = setTimeout(flushStatus, 32);
}

function rowStatus(row, text, level = 'muted small') {
  let line = row.querySelector('.file-status');
  if (!line) {
    line = document.createElement('div');
    line.className = 'file-status';
    row.appendChild(line);
  }
  // .warn is only styled inside #log, so a warning colour here used to be written as
  // line.style.color on every single call. It is a class now: an inline style write is a
  // style invalidation whether or not the value changed, and the colour comes from the
  // stylesheet's own token either way, so nothing about the rendered result differs.
  pendingStatus.set(row, { line, text, level });
  scheduleStatusFlush();
  return line;
}

function clearRowStatus(row) {
  // Drop the queued write first. A flush landing after the element was removed would
  // write the status that was just cleared back into a detached node, and the next
  // rowStatus() for that row would find no .file-status and build a second one.
  pendingStatus.delete(row);
  row.querySelector('.file-status')?.remove();
}

/**
 * Offer the user a way to hand a file back after this tab reloaded mid-send.
 *
 * The File object behind an <input> or a drop cannot survive a navigation, full stop, so
 * there is no way to do this without asking. The pick is checked against the fingerprint
 * the transfer started with before a single byte is sent at an offset, so choosing the
 * wrong file is refused rather than spliced.
 */
function renderReselect({ id, name, size, received, peer = null }) {
  const row = fileRow(id, 'me');
  if (!rowTitle(row).textContent) {
    rowTitle(row).textContent = `${sanitizeFilename(name)} (${formatBytes(size ?? 0)})`;
  }
  setProgress(row, received ?? 0, size ?? 1);
  rowStatus(
    row,
    `Paused at ${formatBytes(received ?? 0)}. This page reloaded, so the file has to be chosen `
    + 'again to continue. It must be the same file.',
    'warn small',
  );
  if (row.querySelector('.reselect-btn')) return;

  const picker = document.createElement('input');
  picker.type = 'file';
  picker.hidden = true;
  const button = document.createElement('button');
  button.className = 'primary reselect-btn';
  button.textContent = `Choose ${sanitizeFilename(name)} again`;
  button.addEventListener('click', () => picker.click());
  picker.addEventListener('change', async () => {
    const file = picker.files?.[0];
    picker.value = '';
    if (!file || !session) return;
    button.disabled = true;
    button.textContent = 'Checking the file...';
    // renderProgress refuses to CREATE an outbound row unless this side really is sending.
    localSends += 1;
    try {
      await session.resumeOutbound(file, peer);
      button.remove();
      picker.remove();
    } catch (err) {
      log(`could not continue sending: ${err.message}`, 'bad');
      rowStatus(row, err.message, 'error small');
      button.disabled = false;
      button.textContent = `Choose ${sanitizeFilename(name)} again`;
    } finally {
      localSends -= 1;
    }
  });
  row.append(button, picker);
  scrollMessages();
}

/**
 * Offer to pick up an incoming transfer that a reload interrupted.
 *
 * Behind a button because it has to be: re-granting write permission on a stored file
 * handle prompts, and a prompt outside a user gesture is refused by the browser.
 */
function renderRecoverInbound(meta) {
  const row = fileRow(meta.id, 'them', meta.label);
  rowTitle(row).textContent = `${sanitizeFilename(meta.name)} (${formatBytes(meta.size ?? 0)})`;
  setProgress(row, meta.received ?? 0, meta.size ?? 1);
  rowStatus(row, `Interrupted at ${meta.human ?? formatBytes(meta.received ?? 0)}. `
    + 'It can carry on into the same file you already chose.', 'warn small');
  if (row.querySelector('.recover-btn')) return;
  const button = document.createElement('button');
  button.className = 'primary recover-btn';
  button.textContent = 'Continue receiving';
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      // Must run inside this click: requestPermission needs a user gesture.
      const at = await session.adoptInbound();
      button.remove();
      rowStatus(row, `Continuing from ${formatBytes(at)}.`, 'muted small');
    } catch (err) {
      log(`could not continue receiving: ${err.message}`, 'bad');
      rowStatus(row, err.message, 'error small');
      button.disabled = false;
    }
  });
  row.appendChild(button);
  scrollMessages();
}

function setProgress(row, sent, total) {
  let bar = row.querySelector('progress');
  if (!bar) {
    bar = document.createElement('progress');
    row.appendChild(bar);
  }
  bar.max = total || 1;
  bar.value = sent;
}

// The inline preview and the Open button live in preview.js, fetched only once a file has
// actually been received. Same rule as the batch prompt above: unreachable by a gate used
// for chat alone, so it is not weight every gate pays. See the head of tests/size.test.mjs.
let previewMod = null;

/**
 * Grow a finished row's preview and Open button, if its type earns either.
 *
 * Called AFTER the Save button exists and never awaited. Save is the guarantee: a failed
 * fetch, or a throw while drawing, still leaves a row whose file is recoverable, which is
 * why the failure below is a note in the row rather than a rethrow nobody would catch.
 */
async function renderFilePreview(row, meta) {
  try {
    if (!previewMod) previewMod = await import('./preview.js');
    previewMod.decorateFileRow(row, meta, {
      objectUrls, inlinePreviews, MAX_INLINE_PREVIEWS, releasePreview, scrollMessages, sanitizeFilename,
    });
  } catch (err) {
    // The caller discards this promise, so without this a failed fetch would drop the
    // preview and the Open button in silence, indistinguishable from a type that gets none.
    const note = document.createElement('div');
    note.className = 'muted small';
    note.textContent = `The preview could not be prepared (${err.message}). Save still works.`;
    row.appendChild(note);
  }
  scrollMessages();
}

/** Show a preview inline once the file has arrived; everything gets a save button. */
function finishFileRow(row, meta, from) {
  row.querySelector('progress')?.remove();
  // A finished transfer must not keep showing "paused, waiting to continue" from the last
  // drop it survived, and must not keep offering a button to hand it a file.
  clearRowStatus(row);
  row.querySelector('.reselect-btn')?.remove();
  row.querySelector('.recover-btn')?.remove();
  // The name arrives exactly as the other side wrote it. Show the same sanitised name
  // that saveBlob will actually write under, so the row cannot advertise one name and
  // the download produce another.
  const name = sanitizeFilename(meta.name);
  rowTitle(row).textContent = `${name} (${meta.human ?? formatBytes(meta.size ?? 0)})`;

  // Branch on WHO the row belongs to, not on whether a blob came with it. file-sent
  // carries no blob, so the sender's own row used to claim the file had been written to
  // a location they never chose: that message belongs only to a received disk transfer.
  if (from === 'me') {
    const done = document.createElement('div');
    done.className = 'muted small';
    done.textContent = 'Sent.';
    row.appendChild(done);
    return;
  }

  if (!meta.blob) {
    const done = document.createElement('div');
    done.className = 'muted small';
    // Two sinks arrive with no blob and they put the file in two different places. The
    // stream sink hands it to the browser's own download manager, which picked the
    // downloads folder; telling the user they chose that location is simply untrue.
    done.textContent = meta.sink === 'stream'
      ? 'Saved by this browser to your downloads folder.'
      : 'Written to the location you chose.';
    row.appendChild(done);
    // A disk sink kept the handle for the file the user picked and link.js passes it here,
    // so Open can read those bytes back on demand. No inline preview on this route: the
    // file went to disk precisely so it would not be held in memory, and drawing it would
    // pull the whole thing back in. The stream sink has no handle and cannot be opened,
    // which is why its wording above stays a dead end.
    // Called for the stream sink too, which has no handle and gets neither a preview nor an
    // Open button. It is still a file this device received from someone else, and preview.js
    // carries the scan caution: a route that skipped it would be a received file with no
    // caution on it, which is the one case where the user is most likely to open the file
    // from their own downloads folder instead of from here.
    void renderFilePreview(row, meta);
    return;
  }

  const save = document.createElement('button');
  // save-btn is not decoration: preview.js anchors the inline element above it and the
  // Open button after it, so the row reads content, Open, Save whichever of the three
  // this file's type earns.
  save.className = 'secondary save-btn';
  save.textContent = 'Save';
  save.addEventListener('click', () => saveBlob(meta.blob, meta.name));
  row.appendChild(save);
  void renderFilePreview(row, meta);
  scrollMessages();
}

/** Only large transfers ask; small ones are accepted automatically. */
function renderOffer(meta) {
  const row = fileRow(meta.id, 'them', meta.label);
  rowTitle(row).textContent = `${sanitizeFilename(meta.name)} (${formatBytes(meta.size)})`;

  const verdict = canAccept(meta.size);
  if (!verdict.ok) {
    const why = document.createElement('div');
    why.className = 'error small';
    why.textContent = verdict.reason;
    row.appendChild(why);
    return;
  }

  // canAccept's note is the only warning that a save dialog is about to open and that
  // dismissing it cancels the transfer. Dropping it meant the one browser that opens a
  // dialog was also the one browser that never said it was going to.
  if (verdict.note) {
    const note = document.createElement('div');
    note.className = 'muted small';
    note.textContent = verdict.note;
    row.appendChild(note);
  }

  const accept = document.createElement('button');
  accept.className = 'primary';
  accept.textContent = 'Accept';
  accept.addEventListener('click', async () => {
    accept.disabled = true;
    try {
      // Must run inside this click: showSaveFilePicker requires a user gesture.
      await session.acceptIncoming(meta.peer ?? null);
      accept.remove();
    } catch (err) {
      log(`could not start receiving: ${err.message}`, 'bad');
      accept.disabled = false;
    }
  });
  row.appendChild(accept);
}

// The batch accept row lives in batchui.js and is fetched only when a peer actually offers
// several files at once. It is the drawing half of the batch feature: the protocol half
// (parse, validate, bound the grant) is in link.js and stays on the boot path, because a
// control frame arrives whether or not this module was ever fetched. See the head of
// tests/size.test.mjs for why anything reachable only after an unmade decision is loaded
// this way.
let batchUiMod = null;

// Move one file of an accepted batch along in the batch's own row. The model, the drawing
// and the reasoning are all in batchui.js, which is not fetched until a peer has actually
// announced several files at once; this is the one line of it that has to be on the boot
// path, because these events arrive whether or not that module was ever loaded. Silent on a
// miss, which is every single-file send.
function noteBatchFile(meta, state, detail = null) {
  if (!meta || typeof meta.batch !== 'string' || !batchUiMod) return;
  batchUiMod.noteBatchFile({
    batch: meta.batch, id: meta.id, name: meta.name, state, detail,
  }, { fileRow, rowTitle, rowStatus, log, scrollMessages, session });
}

async function renderBatchOffer(d) {
  try {
    if (!batchUiMod) batchUiMod = await import('./batchui.js');
    batchUiMod.renderBatchOffer(d, {
      fileRow, rowTitle, rowStatus, log, scrollMessages, session,
    });
  } catch (err) {
    // Nothing above this catches: the event listener that calls this discards the promise,
    // so a failed fetch or a throw while drawing would lose the offer in silence and leave
    // the sender waiting on an accept this side was never able to ask for.
    log(`could not draw the prompt for these ${d.count} files: ${err.message}`, 'bad');
  }
}

function renderProgress({ direction, id, sent, total, name, label = null }) {
  // fileRow() CREATES on a miss, so an outbound row must be looked up, never minted: a
  // forged file-progress control from the peer otherwise put a bubble labelled "you",
  // carrying a filename of their choosing, into this side's transcript. An outbound row
  // is only created while this side actually has a send in flight.
  let row = document.getElementById(`transfer-${id}`);
  if (!row) {
    if (direction === 'out' && localSends === 0) return;
    row = fileRow(id, direction === 'out' ? 'me' : 'them', label);
  }
  if (!rowTitle(row).textContent) {
    rowTitle(row).textContent = `${sanitizeFilename(name, 'file')} (${formatBytes(total ?? 0)})`;
  }
  setProgress(row, sent, total);
}

/** Send whatever the user attached, pasted or dropped, one after another. */
// Two separate calls can overlap: attaching while a drop is in flight, or dropping
// twice. Each call awaited its own files but nothing serialised the CALLS, so the
// second batch hit "another file is already being sent" and vanished with no transcript
// row, no queue and no retry. The only trace was a line in the collapsible log.
// Chaining makes a concurrent batch wait its turn instead of being thrown away.
let outboundChain = Promise.resolve();

async function sendFiles(files) {
  const list = [...files].filter(Boolean);
  if (!list.length || !session) return undefined;
  const run = outboundChain.then(() => sendFilesNow(list), () => sendFilesNow(list));
  // Keep the chain alive whatever happens, or one failure wedges every later send.
  outboundChain = run.catch(() => {});
  return run;
}

/**
 * Wait for at least one connected link, waking the ones that are not.
 *
 * THE BUG THIS EXISTS FOR, and it is the phone case the user reported: tapping Attach
 * opens the OS file picker, which freezes this tab. Both mobile engines reclaim an
 * RTCPeerConnection from a frozen tab, so however long the user spends choosing files is
 * time the link spends dead and backing off. The picker's `change` event then fires the
 * INSTANT they tap Done, which is the one moment the link is guaranteed not to be back
 * yet. requireConnected() threw, and from the user's side the gate refused a send for no
 * visible reason immediately after they had done exactly what it asked.
 *
 * Picking files is not a request to send them within the next 40 milliseconds. It is a
 * request to send them. So: ask every link to retry now rather than at the back of its
 * backoff, then wait, and only give up if the gate really does not come back.
 *
 * Polled rather than event-driven on purpose. The connected state is derived from several
 * links and several state machines, `connectedLinks()` is the one place that decides it,
 * and a 250ms poll of a getter cannot disagree with it the way a second event subscription
 * could. Twelve polls a second cost nothing next to a file transfer.
 */
async function waitForLink(timeoutMs = 30000) {
  if (!session) return false;
  if (session.connectedLinks().length) return true;

  session.wakeAll('a file is waiting to be sent');
  log('Waiting for the gate to come back before sending.', 'warn');

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => { setTimeout(r, 250); });
    if (!session) return false;
    if (session.connectedLinks().length) {
      log('The gate is back. Sending now.', 'ok');
      return true;
    }
  }
  return false;
}

async function sendFilesNow(list) {
  if (!session) return;
  if (!(await waitForLink())) {
    // Named per file rather than once for the batch: the row in the transcript is where
    // the user looks for what happened to a particular file, and a single line in the log
    // does not tell them which of the four they picked went nowhere.
    for (const file of list) {
      log(`could not send ${file.name}: the gate did not reconnect`, 'bad');
      noteFileOutcome('me', file.name, 'Not sent: the gate did not reconnect');
    }
    return;
  }
  // Announce the whole set BEFORE the first FILE_START, so the other side draws one Accept
  // for all of them instead of one per file. Only for more than one: a single send
  // announces nothing, carries no batch id, and behaves exactly as it did.
  let batch = null;
  if (list.length > 1) {
    try {
      batch = await session.announceFileBatch(list);
    } catch (err) {
      // Never fatal: without the announcement the receiver asks per file, which is what it
      // did before this, so the files still go. Only the convenience is lost, and losing it
      // quietly is what would be wrong.
      log(`could not offer these ${list.length} files as one batch, so the other device will `
        + `ask about each one: ${err.message}`, 'warn');
      batch = null;
    }
  }
  for (const file of list) {
    if (!session) return;
    // Cleared per file, so a failure that never got as far as an offer cannot borrow the
    // previous file's row and report itself as already handled.
    offeredRowId = null;
    // renderProgress reads this to tell a send this side started from a forged one.
    localSends += 1;
    try {
      await session.sendFile(file, batch);
    } catch (err) {
      log(`could not send ${file.name}: ${err.message}`, 'bad');
      // EVERY rejection resolves the row, not only the ones that emit an event. This used to
      // suppress itself whenever an offer row existed, on the stated assumption that
      // "file-rejected has already written the reason into it". That assumption was false for
      // link.js's resetForRenegotiation, which rejects the pending accept with "the connection
      // restarted before the transfer was accepted" and emits NOTHING. Measured: send a file
      // over AUTO_ACCEPT_BYTES, the offer row is drawn, the connection renegotiates before the
      // receiver taps Accept, sendFile rejects, the row exists, nothing is written, and the row
      // says "Offered to the other device. Waiting for it to be accepted there" for ever. That
      // is the stranded row this whole change set exists to remove, reintroduced by the check
      // meant to avoid duplicating a message.
      //
      // endRow is what makes saying it unconditionally safe: a row an event already resolved
      // keeps that event's wording, which is the more specific of the two. `offeredRowId` is
      // this send's id and nothing else's: sendFilesNow awaits one file at a time and
      // outboundChain serialises the callers.
      const row = offeredRowId ? document.getElementById(`transfer-${offeredRowId}`) : null;
      if (!endRow(row, `Not sent: ${err.message}`)) {
        noteFileOutcome('me', file.name, `Not sent: ${err.message}`);
      }
    } finally {
      localSends -= 1;
    }
  }
}

// Reading scrollHeight after writing height forces a synchronous layout, and this ran
// on EVERY input event. Coalescing into one frame means a burst of keystrokes, or a
// paste, pays for one layout instead of one per character.
const growPending = new WeakSet();

function autoGrow(el) {
  if (growPending.has(el)) return;
  growPending.add(el);
  requestAnimationFrame(() => {
    growPending.delete(el);
    const next = (() => {
      el.style.height = 'auto';
      return `${Math.min(el.scrollHeight, 220)}px`;
    })();
    if (el.style.height !== next) el.style.height = next;
  });
}

/**
 * Say the last thing about one transfer row, once, and remember that it has been said.
 *
 * Two callers both have to be able to resolve the same row and neither can see the other:
 * the `file-rejected` and `file-failed` listeners write whatever the link established, and
 * sendFilesNow's catch has to resolve a row that NO event ever spoke for. Without the mark
 * the second writer either overwrites a specific cause with a vaguer one (link.close emits a
 * full severance sentence and then rejects sendFile with "the gate was burned during the
 * transfer") or, if it defers, leaves the row unresolved on every path that emits nothing.
 * First writer wins, because the first writer is the one closest to the cause.
 *
 * Returns false only when there is no row, which is the caller's signal to write a bubble
 * instead. It returns TRUE for a row that was already ended: the row is resolved either way,
 * and a second bubble under it is the duplicate this was built to stop.
 */
function endRow(row, text) {
  if (!row) return false;
  if (row.dataset.ended === '1') return true;
  row.dataset.ended = '1';
  row.querySelector('progress')?.remove();
  rowStatus(row, text, 'error small');
  return true;
}

/**
 * Record a file outcome where the user is actually looking.
 *
 * Refusals used to exist only in the collapsible diagnostic log, so a file that was
 * never delivered left no trace at all in the transcript the UI presents as the record
 * of what was exchanged. Silence is the worst possible answer to "did that send?".
 */
function noteFileOutcome(from, name, text) {
  const row = bubble(from, 'is-file');
  const title = document.createElement('div');
  title.className = 'file-title';
  title.textContent = sanitizeFilename(name || 'file');
  row.appendChild(title);
  rowStatus(row, text, 'error small');
  scrollMessages();
  return row;
}

// ---------------------------------------------------------------- flows

/**
 * Tear down whatever session is currently held before another replaces it.
 *
 * Reassigning `session` only orphans the old object: its listeners keep firing badge(),
 * show() and startTtl() against the live UI, and its room is never severed.
 */
async function discardSession() {
  const old = session;
  promptingForPassword = false; // whatever prompt was up belonged to the gate being dropped
  if (!old) return;
  session = null;
  stopTtl();
  forgetSlot(old.roomId);
  try {
    await old.sever();
  } catch (err) {
    log(`could not close the previous gate: ${err.message}`, 'warn');
  }
}

async function startCreate() {
  if (!(await confirmNetworkExposure('create'))) return;
  await discardSession();

  // Reset the waiting screen this is about to use. The join, resume and password paths
  // all hide the share panel and retitle the screen with no counterpart anywhere, so a
  // Create after any of them in the same page load showed a waiting screen with no
  // code, no QR and no copy buttons: the gate could not be shared at all.
  $('waiting-title').textContent = 'Waiting for the other device';
  $('share-hidden').hidden = false;
  $('share-shown').hidden = true;
  $('qr-wrap').hidden = false;
  $('room-code').textContent = '';

  const minutes = Number($('ttl-select').value);
  const password = $('room-password').value || null;
  // The code is minted first and S derived from it, not the other way round: the code is
  // the only thing that travels, and S is a one-way function of it. PBKDF2 at 600,000
  // iterations is a one to four second pause, which is why it happens once, here. runFlow
  // already has the button disabled and reading "Working..." for the duration.
  const formatted = generateGateCode();
  const secret = await deriveSecret(formatted);

  session = new Session({ secret, iceServers: config.iceServers, password });
  wire(session);
  try {
    const room = await session.create(minutes);
    rememberSlot(session.roomId, { token: room.token, role: 'a', expiresAt: room.expiresAt });
    rememberSecret(formatted);
    // EXTENSION PATCH. Upstream this is `${location.origin}${location.pathname}#...`,
    // which on this page produces `chrome-extension://<id>/app.html#...`: a URL naming a
    // package on THIS machine, useless on the other device, and different per install.
    // The link has to name the signalling origin's web client, because that is what the
    // other device can open. gateLink() carries the full reasoning, including the honest
    // consequence: a peer without the extension runs code that origin served them.
    const link = gateLink(formatted);
    // Deliberately NOT putting the secret in the address bar. It would otherwise sit
    // there in plain sight for the whole session, readable by anyone who can see the
    // screen or a screenshot. It lives in memory, and the link is produced on demand.

    // Rendered only when the user asks for it, so nothing sensitive is on screen by
    // default.
    let drawn = false;
    const revealShare = () => {
      // The code itself is written synchronously and the panel is revealed synchronously.
      // Only the canvas waits for the encoder, because the readable code is the thing the
      // press asked for and the QR is the convenience beside it: making the whole reveal
      // await a fetch would put a network round trip between the press and the words.
      $('room-code').textContent = formatted;
      $('share-hidden').hidden = true;
      $('share-shown').hidden = false;
      if (drawn) return;
      // Set before the await, not after: two fast presses would otherwise both pass the
      // check and draw the same code twice.
      drawn = true;
      loadQr().then(({ encodeQr, drawQr }) => {
        drawQr($('qr'), encodeQr(link));
        // Set only after the pixels are actually on the canvas. An empty canvas reads as
        // fully transparent, which samples as every pixel dark, so "is there a code here
        // yet" cannot be answered from the bitmap alone: this is the signal that says the
        // draw landed, for anything waiting on it.
        $('qr').dataset.drawn = '1';
      }).catch((err) => {
        drawn = false;
        delete $('qr').dataset.drawn;
        log(`could not render a QR code: ${err.message}. Use the link instead.`, 'warn');
      });
    };
    const hideShare = () => {
      $('room-code').textContent = '';
      $('share-shown').hidden = true;
      $('share-hidden').hidden = false;
    };
    $('reveal-share').onclick = revealShare;
    $('hide-share').onclick = hideShare;

    const copyLink = (btn) => copyText(link).then((ok) => { if (ok) btn.textContent = 'Copied'; });
    $('copy-link').onclick = () => copyLink($('copy-link'));
    $('copy-link-2').onclick = () => copyLink($('copy-link-2'));
    $('copy-code').onclick = () => copyText(formatted).then((ok) => { if (ok) $('copy-code').textContent = 'Copied'; });

    startTtl(room.expiresAt);
    show('waiting');
    if (!config.iceServers.length) {
      log('No STUN server is configured, so only same-network connections will work.', 'warn');
    }
  } catch (err) {
    showHomeError(`Could not create the gate: ${describeError(err)}`);
    session = null;
  }
}

async function startJoin(text) {
  await discardSession();

  // Decoding is synchronous and cheap; it is the stretch that is expensive. Splitting them
  // keeps the order the comment below asks for AND keeps a bad code from costing a second
  // of PBKDF2 before it is rejected.
  let parsed;
  try {
    parsed = decodeGateCode(text);
  } catch (err) {
    if (!(err instanceof GateCodeError)) throw err;
    // The message names the actual fault: the wrong number of words, a word that is not on
    // the list, the word it was probably meant to be, or an old-format code. One generic
    // sentence instead would throw all of that away.
    showHomeError(err.message);
    return;
  }

  // After the code is known to be well formed, so a typo gets the typo message rather than
  // a privacy notice it has no way to act on.
  if (!(await confirmNetworkExposure('join'))) return;

  // Only now pay for the stretch. Cached in crypto.js, so the resume path below and a later
  // reload of this tab do not pay it again.
  const secret = await deriveSecret(parsed.code);

  // If this tab already holds a slot in this gate, re-attach instead of joining again.
  // Joining twice is correctly refused as full, which is what makes a reload fatal.
  const roomId = await deriveRoomId(secret);
  const held = recallSlot(roomId);
  if (held) {
    // A thrown checkRoom is a NETWORK failure; a null return is the server saying the
    // room is gone. Conflating them dropped a valid slot and re-joined a gate this tab
    // already occupies, which is then correctly refused as full: the exact failure the
    // slot cache exists to prevent. So a transport error keeps the slot and stops here.
    let still = null;
    try {
      still = await checkRoom(roomId, held.token);
    } catch (err) {
      log(`could not check the gate this tab already holds: ${err.message}`, 'warn');
      showHomeError(`Could not reach the server to check the gate this tab already holds: ${err.message}. Check your connection and try again.`);
      return;
    }
    if (still) {
      // A resumed gate needs the room password again: it is never persisted, so after a
      // reload the only copy is whatever the user has just typed, which on a reload is
      // nothing. Hand over what we have; resume prompts through the password screen when
      // that is empty and the gate wants one.
      const typed = $('join-password').value || null;
      session = new Session({ secret, iceServers: config.iceServers, password: typed });
      wire(session);
      try {
        await session.resume({
          token: held.token,
          role: still.role,
          expiresAt: still.expiresAt,
          password: typed,
          requiresPassword: still.requiresPassword === true,
        });
        startTtl(still.expiresAt);
        showUnlessPrompting('waiting');
        $('waiting-title').textContent = 'Reconnecting to the other device';
        $('share-hidden').hidden = true;
        $('share-shown').hidden = true;
        log('Resumed the gate after a reload.', 'ok');
        // A transfer this tab was receiving when it reloaded. This only looks for it and
        // reports; adopting it needs a user gesture, so it happens behind a button.
        session.recoverInbound().catch((err) => log(`could not check for an interrupted transfer: ${err.message}`, 'warn'));
        return;
      } catch (err) {
        log(`could not resume: ${err.message}`, 'warn');
        session = null;
      }
    }
    forgetSlot(roomId);
  }

  session = new Session({ secret, iceServers: config.iceServers, password: $('join-password').value || null });
  wire(session);
  try {
    const room = await session.join();
    rememberSlot(session.roomId, { token: room.token, role: 'b', expiresAt: room.expiresAt });
    rememberSecret(parsed.code);
    startTtl(room.expiresAt);
    badge('negotiating', 'work');
    showUnlessPrompting('waiting');
    // The joiner has no need to display the code at all.
    $('share-hidden').hidden = true;
    $('share-shown').hidden = true;
    $('waiting-title').textContent = 'Connecting to the other device';
  } catch (err) {
    showHomeError(`Could not join: ${describeError(err)}`);
    session = null;
    show('home');
  }
}

function describeError(err) {
  const map = {
    no_room: 'that gate does not exist, or it has already expired',
    room_full: `that gate is full (it seats ${config?.maxParticipants ?? 2} devices)`,
    room_exists: 'a gate with that code already exists, try again',
    rate_limited: 'too many attempts, wait a few minutes',
    // Distinct from rate_limited on purpose: this one is not fixed by waiting, it is
    // fixed by closing a gate, and telling the user to wait would be telling them to do
    // the one thing that cannot help.
    too_many_rooms: 'you already have as many gates open as one device may hold, close one and try again',
    capacity: 'the server is at capacity, try again shortly',
    bad_room_id: 'that code is malformed',
    bad_join_proof: 'that code does not match this gate, check you pasted the whole link or code',
  };
  return map[err.message] ?? err.message;
}

function showHomeError(message) {
  const el = $('home-error');
  el.textContent = message;
  el.hidden = false;
  show('home');
}

// Guards Create and Join against re-entry: a second click while the first is still in
// flight, or a click on Join while Create is running.
let flowBusy = false;

async function runFlow(button, fn) {
  if (flowBusy) return;
  flowBusy = true;
  const label = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = 'Working...';
  }
  try {
    await fn();
  } catch (err) {
    log(`could not complete that: ${err.message}`, 'bad');
  } finally {
    flowBusy = false;
    if (button) {
      button.disabled = false;
      button.textContent = label;
    }
  }
}

async function severNow() {
  cancelClipboardWipe();
  // Cancelling the passphrase prompt lands here, so the flag must not outlive the gate
  // it belonged to.
  promptingForPassword = false;
  if (!session) { show('home'); return; }
  forgetSlot(session.roomId);
  try {
    await session.sever();
  } catch (err) {
    log(`burning the gate failed: ${err.message}`, 'bad');
  }
  session = null;
}

// ---------------------------------------------------------------- boot

/**
 * Opening the drawer is a decision to play, and it is the point at which the games are
 * worth their bytes. Registered once at boot rather than per gate: `wire()` runs on every
 * create and join, and a listener added there would stack.
 */
function armGamesDrawer() {
  $('games-disc').addEventListener('toggle', (event) => {
    if (!event.target.open || !session) return;
    loadGames(session);
  });
}

/**
 * Refuse to arm the gate when the browser has not given this page the Web Crypto API.
 *
 * `crypto.subtle` exists in a secure context only: TLS, or one of the loopback addresses.
 * A self-hosted copy reached at `http://192.168.x.x` therefore serves a byte-identical
 * `/app` whose cryptography is missing, and the old behaviour was an uncaught TypeError
 * out of `crypto.js` partway through opening a gate. `qrscan.js` and `download.js` already
 * test `isSecureContext` and disappear quietly, which made the remaining failure harder to
 * read rather than easier: the page looked merely reduced instead of broken.
 *
 * Tested through `globalThis.crypto?.subtle` rather than `isSecureContext` alone, because
 * the thing that must exist is the API, and a browser that reports a secure context but
 * withholds `subtle` should still be refused instead of trusted into a throw.
 *
 * Returns true when the page is usable.
 */
function requireSecureContext() {
  if (globalThis.crypto?.subtle) return true;

  const banner = $('insecure-warning');
  if (banner) {
    // Named explicitly. "Not secure" on its own reads as a warning about the site; the
    // address in the bar is the whole cause, so it is the whole message.
    const origin = globalThis.location?.origin ?? 'this address';
    $('insecure-warning-text').textContent = `${origin} was not served over HTTPS and is not `
      + 'a loopback address, so this browser withheld the encryption API from the page.';
    banner.hidden = false;
  }

  for (const id of ['create-btn', 'join-btn']) {
    const btn = $(id);
    if (!btn) continue;
    btn.disabled = true;
    btn.title = 'Unavailable: this page cannot encrypt over a plain HTTP address.';
  }

  log('This page is not a secure context, so it cannot encrypt. Use HTTPS or localhost.', 'bad');
  return false;
}

async function boot() {
  // Before the config fetch, so that an insecure origin says so immediately rather than
  // after a network round trip, and before anything can reach a crypto call.
  if (!requireSecureContext()) {
    show('home');
    return;
  }

  try {
    config = await fetchConfig();
  } catch (err) {
    config = { iceServers: [], sessionMinutes: [10, 30, 60], defaultSessionMinutes: 30 };
    log(`could not load server config: ${err.message}`, 'bad');
  }

  // A served config that parses is not a served config that is COMPLETE. A missing
  // sessionMinutes threw out of boot() and left the page with no screen visible at all,
  // so every field this file reads is normalised here rather than trusted.
  config = {
    ...config,
    iceServers: Array.isArray(config?.iceServers) ? config.iceServers : [],
    sessionMinutes: Array.isArray(config?.sessionMinutes) && config.sessionMinutes.length
      ? config.sessionMinutes.filter((m) => Number.isFinite(Number(m)))
      : [10, 30, 60],
    defaultSessionMinutes: Number(config?.defaultSessionMinutes) || 30,
    // How many devices one gate seats. Only used to explain a refusal, so a server that
    // does not say falls back to the two-party answer rather than inventing a number.
    maxParticipants: Number(config?.maxParticipants) || 2,
  };
  if (!config.sessionMinutes.length) config.sessionMinutes = [10, 30, 60];

  // How many devices a gate seats is a deployment setting, so the sentence that states it
  // is written from the server's own answer rather than hard-coded in the markup: an
  // operator who changes WG_MAX_PARTICIPANTS must not end up with a page that lies.
  const capNote = $('cap-note');
  if (capNote && config.maxParticipants >= 2) {
    capNote.textContent = `A gate holds up to ${config.maxParticipants} devices. Once it is full, `
      + 'any further device is refused.';
  }

  // AGPL-3.0 section 13: users interacting over a network must be offered the source.
  // Shared with the landing document, which has to do the same from its own fetch.
  applySourceLink(config.sourceUrl);

  const select = $('ttl-select');
  for (const minutes of config.sessionMinutes) {
    const option = document.createElement('option');
    option.value = String(minutes);
    option.textContent = minutes >= 60 ? `${minutes / 60} hour` : `${minutes} minutes`;
    if (minutes === config.defaultSessionMinutes) option.selected = true;
    select.appendChild(option);
  }

  // Expiry and room password are one line of plain text plus a change link, rather than
  // a disclosure panel that has to be opened before it can be understood. The line is
  // written from the LIVE values of the two controls, so it always states what pressing
  // Create will actually do; a hard-coded "30 minutes" would go silently wrong the
  // moment an operator changed WG_SESSION_MINUTES or the user picked something else.
  const optsPanel = $('gate-opts-panel');
  const optsToggle = $('gate-opts-toggle');
  const optsSummary = $('gate-opts-summary');
  const roomPassword = $('room-password');
  const describeOptions = () => {
    const ttl = select.selectedOptions[0]?.textContent || `${config.defaultSessionMinutes} minutes`;
    optsSummary.textContent = `${ttl} · ${roomPassword.value ? 'password set' : 'no password'}`;
  };
  describeOptions();
  select.addEventListener('change', describeOptions);
  roomPassword.addEventListener('input', describeOptions);
  optsToggle.addEventListener('click', () => {
    const open = optsPanel.hidden;
    optsPanel.hidden = !open;
    optsToggle.setAttribute('aria-expanded', String(open));
    optsToggle.textContent = open ? 'done' : 'change';
    if (open) select.focus();
  });

  // Clickwrap: the button stays disabled until the box is ticked, and what was agreed
  // to is recorded with a version and a timestamp.
  const agreeCheck = $('agree-check');
  const agreeBtn = $('onboarding-done');
  agreeCheck.addEventListener('change', () => {
    agreeBtn.disabled = !agreeCheck.checked;
    $('agree-hint').hidden = agreeCheck.checked;
  });
  agreeBtn.addEventListener('click', () => {
    if (!agreeCheck.checked) return;
    try {
      localStorage.setItem(AGREEMENT_KEY, JSON.stringify({ version: 1, acceptedAt: new Date().toISOString() }));
    } catch (err) { void err; }
    afterAgreement();
  });

  // Say plainly which instance this is. A hostile host would simply delete this, which
  // is exactly why the text says the trust question can only be settled by self-hosting.
  // warpgate.fysh.site is canonical. wg.fysh.site is the original name and stays
  // trusted: old links and QR codes still carry it, and it redirects here, so treating
  // it as unofficial would flash a scary warning at people following a valid link.
  // EXTENSION PATCH: this block asks a different question here, so it answers one.
  //
  // Upstream it reads `location.hostname` and warns when the page came from a host that is
  // not the official instance, because upstream the host that served the page IS the party
  // controlling the encrypting code. That is no longer true here, and the check would be
  // actively misleading: `location.hostname` is the extension id, so the original code
  // prints "You are on hgkl...jej, which is not the official instance" and opens a red
  // warning on the one delivery path that does not have the problem the warning describes.
  //
  // What is worth saying instead is the split. The CODE came from the extension package and
  // the store's signed update channel. The SIGNALLING went to whatever origin is configured,
  // and installing something changes nothing about that: the server still sees the metadata
  // in THREAT-MODEL.md and is still not trusted with a key.
  const origin = signalOrigin();
  $('instance-title').textContent = 'Where this code came from, and where it signals';
  $('instance-origin').textContent = origin;
  if (origin !== DEFAULT_ORIGIN) $('instance-origin-note').hidden = false;

  // Ask up front whether this browser can do peer-to-peer at all, rather than letting
  // the user set up a gate and wait 25 seconds to find out it never could. The probe
  // uses no ICE servers, so it contacts nobody.
  $('webrtc-copy-path').addEventListener('click', async () => {
    const btn = $('webrtc-copy-path');
    const ok = await copyText($('webrtc-settings-path').textContent.trim());
    btn.textContent = ok ? 'Copied' : 'Select it';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2500);
  });
  $('webrtc-recheck').addEventListener('click', () => runCapabilityCheck(true));
  runCapabilityCheck(false);
  watchLogHeight();
  wireDismissables();
  wireDisclosureMotion();
  armGamesDrawer();

  // Say up front what this browser can RECEIVE, before a gate is opened, rather than
  // letting someone set one up and find out mid-transfer. Sending is unaffected either way.
  //
  // describeLimit() is the ONLY place that knows the answer, because it is the only place
  // that checks whether the streaming-download path is available. A second copy of the
  // sentence here stated a 500 MB memory cap that the service worker had already removed,
  // so the front page understated the product on every Firefox and Safari that loaded it.
  // A standing fact about this browser, not an event. It used to be written into the
  // status log, which is a fixed panel at the bottom of the window: on every browser
  // without showSaveFilePicker that made the log permanently non-empty and permanently
  // over the bottom of the page. The sentence is unchanged and still comes from
  // describeLimit(), which remains the only place that knows the answer.
  if (!canStreamToDisk()) {
    const limit = describeLimit();
    // The LEDE is what receiveNoteText holds, because its only other job is to decide
    // whether the banner has anything to say at all (see the screen switch above).
    receiveNoteText = limit.lede;
    $('receive-note-text').textContent = limit.lede;
    $('receive-note-detail').textContent = limit.detail;
    $('receive-note').hidden = isDismissed('receive-note');
  }
  // Create and Join build a Session, hold a room slot and open a signalling connection.
  // Two clicks built two of them: the first was orphaned by the reassignment but kept
  // firing badge(), show() and startTtl() against the live UI and its room was never
  // severed. One flow at a time, and the buttons say so while it runs.
  $('create-btn').addEventListener('click', () => runFlow($('create-btn'), startCreate));
  const joinNow = () => runFlow($('join-btn'), () => startJoin($('join-input').value));
  $('join-btn').addEventListener('click', joinNow);
  $('join-input').addEventListener('keydown', (e) => {
    // isComposing: on an IME the Enter that COMMITS a candidate arrives as Enter, and
    // acting on it submits half-composed text.
    if (e.key === 'Enter' && !e.isComposing) joinNow();
  });
  armScanner(joinNow);
  armLogDock();
  $('sever').addEventListener('click', severNow);
  $('waiting-sever').addEventListener('click', severNow);
  $('clear-transcript').addEventListener('click', clearTranscript);
  window.addEventListener('pagehide', () => {
    cancelClipboardWipe();
    releaseAllPreviews();
  });

  // The tab coming back is the strongest signal available that the network picture has
  // changed, and this document had no handler for it at all: recovery was left entirely
  // to EventSource's own reconnect plus Link's exponential backoff, which by design gets
  // slower the longer things have been wrong.
  //
  // That is exactly backwards for the case that made this necessary. A phone opening the
  // OS file picker freezes this tab, the peer connection is reclaimed underneath it, and
  // the backoff walks out to its 30s ceiling while nobody is watching. The picker then
  // returns and fires `change` immediately, so the send met a link that was half a minute
  // from even trying. Waking here closes that gap to zero.
  //
  // `pageshow` as well as `visibilitychange`, because a back/forward-cache restore does
  // not always produce the latter, and a restored page is precisely one whose connections
  // are gone. Both paths are no-ops on a healthy link.
  const wakeLinks = (why) => {
    if (document.visibilityState !== 'visible') return;
    try {
      session?.wakeAll(why);
    } catch (err) {
      log(`could not retry the connection on returning to the page: ${err.message}`, 'warn');
    }
  };
  document.addEventListener('visibilitychange', () => wakeLinks('the page is back in front'));
  window.addEventListener('pageshow', (e) => {
    if (e.persisted) wakeLinks('the page was restored from the cache');
  });
  $('restart').addEventListener('click', () => { location.href = location.pathname; });
  $('failed-restart').addEventListener('click', () => { location.href = location.pathname; });

  // ---- one composer for everything
  const input = $('chat-input');
  const fileInput = $('file-input');

  input.addEventListener('input', () => {
    // A 400 KiB single-token paste locked the tab for over 30 seconds laying out one
    // unbreakable line, and could never have been delivered anyway: it is far past what
    // a single data channel message carries, so it failed on send after the freeze.
    // Clamping is both the fix and the honest behaviour. maxlength covers real typing
    // and pasting; this covers anything that sets the value directly.
    if (input.value.length > MAX_MESSAGE_CHARS) {
      input.value = input.value.slice(0, MAX_MESSAGE_CHARS);
      // Its OWN element, not #compose-hint. Both messages used to go through that one span,
      // so a 65-character transient notice inherited the standing note's disclosure and got a
      // "Read the rest" control that revealed nothing. A control that does nothing teaches
      // the user that the control does nothing, and then they do not press it on the note
      // where it matters.
      const trim = $('compose-trim');
      trim.textContent =
        `Trimmed to ${MAX_MESSAGE_CHARS.toLocaleString()} characters. Send longer text as a file instead.`;
      trim.hidden = false;
    }
    autoGrow(input);
  });
  input.addEventListener('keydown', (e) => {
    // Enter sends, Shift+Enter makes a new line. Matches every chat app.
    //
    // isComposing is not optional here: on any IME (Japanese, Chinese, Korean, and the
    // predictive keyboards on Android and iOS) the Enter that COMMITS a candidate
    // arrives as key 'Enter' with isComposing true, and sending on it transmitted the
    // half-composed text instead of committing it.
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      $('chat-form').requestSubmit();
    }
  });

  $('chat-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = input.value;
    if (!text.trim() || !session) return;
    const asSecret = $('secret-toggle').checked;
    // Do NOT clear the composer until the send has actually succeeded. Clearing first
    // meant a failed send destroyed the text with no bubble to recover it from: a
    // message over the SCTP limit vanished entirely, which for a typed-out secret is
    // the worst possible failure.
    try {
      if (asSecret) await session.sendSecret(text);
      else await session.sendChat(text);
      input.value = '';
      autoGrow(input);
    } catch (err) {
      log(`could not send, your text is still in the box: ${err.message}`, 'bad');
    }
  });

  $('attach-btn').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const files = [...fileInput.files];
    fileInput.value = '';
    await sendFiles(files);
  });

  // Paste an image or a file straight into the conversation.
  input.addEventListener('paste', async (e) => {
    const items = [...(e.clipboardData?.items ?? [])];
    const files = items.filter((i) => i.kind === 'file').map((i) => i.getAsFile()).filter(Boolean);
    if (!files.length) return; // ordinary text paste
    e.preventDefault();
    await sendFiles(files);
  });

  // Drag and drop anywhere on the connected screen.
  const veil = $('drop-veil');
  window.addEventListener('dragenter', (e) => {
    if (!session || $('screen-connected').hidden) return;
    if (![...(e.dataTransfer?.types ?? [])].includes('Files')) return;
    dragDepth += 1;
    veil.hidden = false;
  });
  window.addEventListener('dragover', (e) => {
    if (!veil.hidden) e.preventDefault();
  });
  window.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) veil.hidden = true;
  });
  window.addEventListener('drop', async (e) => {
    if (veil.hidden) return;
    e.preventDefault();
    resetDrag();
    await sendFiles(e.dataTransfer?.files ?? []);
  });
  // dragenter increments only after two guards while dragleave decrements
  // unconditionally, and some browsers emit no balancing dragleave for a cancelled
  // drag, so the veil could be left up with nothing able to take it down.
  window.addEventListener('dragend', resetDrag);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') resetDrag(); });

  // ---- password prompt
  $('password-submit').addEventListener('click', () => {
    const value = $('password-input').value;
    if (!value) {
      $('password-error').textContent = 'Enter the password, or cancel.';
      $('password-error').hidden = false;
      return;
    }
    $('password-input').value = '';
    promptingForPassword = false;
    session?.setPassword(value);
    show('waiting');
    $('waiting-title').textContent = 'Connecting to the other device';
    $('qr-wrap').hidden = true;
  });
  $('password-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.isComposing) $('password-submit').click();
  });
  $('password-cancel').addEventListener('click', severNow);

  // Deliberately NOT calling bye() on pagehide. pagehide fires on reload as well as on
  // close, and deleting the room there destroyed the gate for both devices whenever
  // either one refreshed. The server reaps a room once both sides have been gone for a
  // grace period, which frees abandoned gates without punishing a reload.

  // Take the secret out of the address bar HERE, before anything is shown, rather than
  // in afterAgreement. On a first visit the onboarding path runs instead of
  // afterAgreement, so the secret used to sit in the address bar for the whole of the
  // one screen a new user is most likely to be shown by the person who sent them the
  // link. It is captured first because it is still needed to join.
  arrivalHash = location.hash.slice(1);
  if (arrivalHash) history.replaceState(null, '', location.pathname);

  let agreed = false;
  try { agreed = Boolean(JSON.parse(localStorage.getItem(AGREEMENT_KEY) || 'null')); } catch (err) { void err; }
  if (agreed) afterAgreement();
  else show('onboarding');
}

// The secret as it arrived in the fragment, held from boot until the user has agreed.
let arrivalHash = '';

function afterAgreement() {
  const hash = arrivalHash;
  arrivalHash = '';

  // A fresh arrival brings the secret in the link. A reload has no link any more, so
  // fall back to the copy held for this tab, which is what makes refresh survivable.
  // tryDecodeGateCode, not deriveSecret: this is a yes/no question and deriveSecret returns
  // a promise, which is always truthy. Using it here would treat every fragment on the page
  // as a gate code, and pay a second of PBKDF2 on every load to do it.
  const fromLink = hash && tryDecodeGateCode(hash) ? hash : null;
  const stored = fromLink ? null : recallSecret();

  // startJoin resumes an existing slot if this tab already holds one, so a reload of
  // either side lands back in the same gate rather than being refused as full.
  if (fromLink) runFlow($('join-btn'), () => startJoin(fromLink));
  else if (stored && tryDecodeGateCode(stored)) runFlow($('join-btn'), () => startJoin(stored));
  else show('home');
}

// Registers the download worker at load, which is what makes this page installable and
// gives it a share target at all, and picks up anything the operating system shared into
// it. Nothing about a shared file touches the network: it comes back out of the Cache
// Storage the worker put it in. Deliberately not awaited and never fatal, so a browser
// with none of this loads the gate exactly as before.
// Reached by import() rather than a static import for the same reason it was already not
// awaited: nothing here is needed to open or join a gate, so it must not be one of the
// files a browser fetches before the page is usable. The behaviour is unchanged, because
// the result was only ever consumed in a .then().
import('./share.js').then(({ initShare }) => initShare()).then((files) => {
  if (!files.length) return;
  pendingShare = files;
  log(files.length === 1
    ? `${sanitizeFilename(files[0].name)} is attached and will send as soon as a gate opens.`
    : `${files.length} files are attached and will send as soon as a gate opens.`);
}).catch((err) => { void err; });

// Without this, any throw inside boot left the page with NO screen visible and nothing
// logged: a blank app and no way to tell why.
boot().catch((err) => {
  try { log(`could not start: ${err.message}`, 'bad'); } catch (inner) { void inner; }
  try { show('home'); } catch (inner) { void inner; }
});
