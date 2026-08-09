// Warp Gate user interface.
//
// This file owns the DOM and nothing else. All protocol and cryptography lives in
// session.js, crypto.js, peer.js and signal.js.

import { generateSecret, formatSecret, parseSecret, deriveRoomId } from './crypto.js';
import { fetchConfig, checkRoom } from './signal.js';
import { Session, STATE } from './session.js';
import { checkWebRtcCapability, hostSuppressedAdvice } from './peer.js';
import { describeLimit, canAccept, formatBytes, saveBlob } from './transfer.js';
import { encodeQr, drawQr } from './qr.js';

const $ = (id) => document.getElementById(id);
const SCREENS = ['onboarding', 'home', 'password', 'waiting', 'connected', 'severed', 'failed'];
// Bumping the version re-prompts everyone, which is the point if the terms change.
const AGREEMENT_KEY = 'wg.agreed.v1';

let session = null;
let config = null;
let ttlTimer = null;
let diag = { candidates: [], ice: null, full: null };

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
  } catch (err) { void err; }
}

// ---------------------------------------------------------------- chrome

function show(name) {
  for (const screen of SCREENS) $(`screen-${screen}`).hidden = screen !== name;
  // The extras fill the space on the quiet screens, and stay out of the way while a
  // gate is actually open.
  const extras = $('extras');
  if (extras) extras.hidden = !['onboarding', 'home', 'severed'].includes(name);
  window.scrollTo(0, 0);
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
  banner.hidden = false;
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
  for (const url of objectUrls) URL.revokeObjectURL(url);
  objectUrls.clear();
  $('transcript-mount').replaceChildren();
  $('transcript-holder').hidden = true;
  log('Transcript cleared.', 'ok');
}

/** Copy buttons and lazily-rendered QR codes for the donation addresses. */
function setupSupport() {
  for (const btn of document.querySelectorAll('[data-copy]')) {
    btn.addEventListener('click', async () => {
      const source = $(btn.dataset.copy);
      if (!source) return;
      const label = btn.textContent;
      const copied = await copyText(source.textContent.trim());
      btn.textContent = copied ? 'Copied' : 'Select it manually';
      setTimeout(() => { btn.textContent = label; }, 2500);
    });
  }

  for (const btn of document.querySelectorAll('[data-qr]')) {
    btn.addEventListener('click', () => {
      const which = btn.dataset.qr;
      const box = $(`qrbox-${which}`);
      const canvas = $(`qr-${which}`);
      const address = $(`addr-${which}`)?.textContent.trim();
      if (!box || !canvas || !address) return;

      if (!box.hidden) {
        box.hidden = true;
        btn.textContent = 'Show QR';
        return;
      }
      if (!canvas.dataset.rendered) {
        try {
          drawQr(canvas, encodeQr(address));
          canvas.dataset.rendered = '1';
        } catch (err) {
          // Never leave a blank white box implying a scannable code.
          log(`could not render the ${which.toUpperCase()} QR code: ${err.message}. Copy the address instead.`, 'warn');
          return;
        }
      }
      box.hidden = false;
      btn.textContent = 'Hide QR';
    });
  }
}

function log(message, level = '') {
  const line = document.createElement('div');
  if (level) line.className = level;
  line.textContent = message;
  const box = $('log');
  box.appendChild(line);
  while (box.children.length > 40) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
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

// ---------------------------------------------------------------- session wiring

function wire(active) {
  diag = { candidates: [], ice: null, full: null };
  active.addEventListener('state', (event) => {
    const [label, kind] = STATE_LABELS[event.detail.state] ?? [event.detail.state, 'work'];
    badge(label, kind);
    if (event.detail.state === STATE.CONNECTED) {
      show('connected');
      // While both devices are here the server keeps pushing the expiry forward, so a
      // countdown would be misleading. It resumes if the other side leaves.
      stopTtl();
      const ttl = $('ttl');
      ttl.hidden = false;
      ttl.textContent = 'live';
      $('compose-hint').textContent = describeLimit();
    }
    // Only a genuine key-confirmation failure says "could not verify". A connectivity
    // stall has its own state and its own far more specific message, set by the
    // unreachable handler below; overwriting it here produced the wrong title.
    if (event.detail.state === STATE.AUTH_FAILED) {
      $('failed-title').textContent = 'Could not verify the other device';
      $('failed-detail').textContent = event.detail.detail ?? '';
      $('failed-diag').textContent = diagnosticText();
      show('failed');
    }
    if (event.detail.detail) log(`${label}: ${event.detail.detail}`);
  });

  active.addEventListener('sas', (event) => { $('sas').textContent = event.detail; });

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
  active.addEventListener('secret', (event) => addSecret(event.detail));

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
    $('failed-title').textContent = 'Could not connect the two devices';
    $('failed-detail').textContent = event.detail;
    $('failed-diag').textContent = diagnosticText();
    forgetSlot(active.roomId);
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
  });

  active.addEventListener('severed', (event) => {
    stopTtl();
    // Deliberately NOT revoking the preview URLs here: the transcript below stays
    // readable until the tab closes or the user clears it.
    showTranscript();
    badge('severed', 'idle');
    $('severed-reason').textContent = event.detail ?? '';
    history.replaceState(null, '', location.pathname);
    show('severed');
  });

  // --- file events
  active.addEventListener('file-offered', (event) => renderOffer(event.detail));
  active.addEventListener('file-refused', (event) => log(`refused incoming file: ${event.detail.reason}`, 'bad'));
  active.addEventListener('file-rejected', (event) => log(`the other device refused the file: ${event.detail.reason}`, 'bad'));
  active.addEventListener('file-accepted', () => log('the other device accepted the file', 'ok'));
  active.addEventListener('file-progress', (event) => renderProgress(event.detail));
  active.addEventListener('file-failed', (event) => log(`transfer failed: ${event.detail.reason}`, 'bad'));
  active.addEventListener('file-received', (event) => {
    const meta = event.detail;
    log(`received ${meta.name} (${meta.human})`, 'ok');
    finishFileRow(fileRow(meta.id, 'them'), meta);
  });

  active.addEventListener('file-incoming', (event) => {
    const meta = event.detail;
    const row = fileRow(meta.id, 'them');
    rowTitle(row).textContent = `${meta.name} (${formatBytes(meta.size)})`;
  });

  active.addEventListener('file-sent', (event) => {
    const meta = event.detail;
    finishFileRow(fileRow(meta.id, 'me'), { ...meta, human: formatBytes(meta.size) });
  });

  active.addEventListener('password-required', () => {
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

/** One row in the single message stream. Everything lands here: text, secrets, files. */
function bubble(from, extraClass = '') {
  const wrap = document.createElement('div');
  wrap.className = `msg ${from === 'me' ? 'me' : ''} ${extraClass}`.trim();
  const who = document.createElement('span');
  who.className = 'who';
  who.textContent = from === 'me' ? 'you' : 'them';
  wrap.appendChild(who);
  const list = $('messages');
  list.appendChild(wrap);
  list.scrollTop = list.scrollHeight;
  return wrap;
}

function scrollMessages() {
  const list = $('messages');
  list.scrollTop = list.scrollHeight;
}

function addMessage({ from, text }) {
  const wrap = bubble(from);
  const body = document.createElement('span');
  body.className = 'msg-text';
  body.textContent = text;
  wrap.appendChild(body);
  scrollMessages();
}

function addSecret({ from, text }) {
  const wrap = bubble(from, 'is-secret');

  const tag = document.createElement('span');
  tag.className = 'chip';
  tag.textContent = 'secret';
  wrap.appendChild(tag);

  const value = document.createElement('div');
  value.className = 'secret-value masked';
  value.textContent = text;
  wrap.appendChild(value);

  const actions = document.createElement('div');
  actions.className = 'secret-actions';

  const reveal = document.createElement('button');
  reveal.className = 'secondary';
  reveal.textContent = 'Reveal';
  reveal.addEventListener('click', () => {
    value.classList.toggle('masked');
    reveal.textContent = value.classList.contains('masked') ? 'Reveal' : 'Hide';
  });

  const copy = document.createElement('button');
  copy.className = 'secondary';
  copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    if (!await copyText(text)) return;
    copy.textContent = 'Copied';
    // Best effort only. No browser guarantees a clipboard can be cleared, and another
    // application may already have taken a copy.
    setTimeout(async () => {
      await copyText('');
      copy.textContent = 'Copy';
      log('Attempted to clear the clipboard. This is best effort and not guaranteed.', 'warn');
    }, 45000);
  });

  actions.append(reveal, copy);
  wrap.appendChild(actions);
  scrollMessages();
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    log(`clipboard unavailable: ${err.message}. Select and copy manually.`, 'warn');
    return false;
  }
}

/** Get or create the row for a transfer, so progress updates land in one place. */
function fileRow(id, from) {
  let row = document.getElementById(`transfer-${id}`);
  if (!row) {
    row = bubble(from, 'is-file');
    row.id = `transfer-${id}`;
    const title = document.createElement('div');
    title.className = 'file-title';
    row.appendChild(title);
  }
  return row;
}

const rowTitle = (row) => row.querySelector('.file-title');

function setProgress(row, sent, total) {
  let bar = row.querySelector('progress');
  if (!bar) {
    bar = document.createElement('progress');
    row.appendChild(bar);
  }
  bar.max = total || 1;
  bar.value = sent;
}

/** Show an image inline once it has arrived; anything else gets a save button. */
function finishFileRow(row, meta) {
  row.querySelector('progress')?.remove();
  rowTitle(row).textContent = `${meta.name} (${meta.human ?? formatBytes(meta.size ?? 0)})`;

  if (!meta.blob) {
    const done = document.createElement('div');
    done.className = 'muted small';
    done.textContent = 'Written to the location you chose.';
    row.appendChild(done);
    return;
  }

  if ((meta.mime || '').startsWith('image/')) {
    const url = URL.createObjectURL(meta.blob);
    objectUrls.add(url);
    const img = document.createElement('img');
    img.className = 'msg-image';
    img.alt = meta.name;
    img.src = url;
    img.addEventListener('load', scrollMessages);
    row.appendChild(img);
  }

  const save = document.createElement('button');
  save.className = 'secondary';
  save.textContent = 'Save';
  save.addEventListener('click', () => saveBlob(meta.blob, meta.name));
  row.appendChild(save);
  scrollMessages();
}

/** Only large transfers ask; small ones are accepted automatically. */
function renderOffer(meta) {
  const row = fileRow(meta.id, 'them');
  rowTitle(row).textContent = `${meta.name} (${formatBytes(meta.size)})`;

  const verdict = canAccept(meta.size);
  if (!verdict.ok) {
    const why = document.createElement('div');
    why.className = 'error small';
    why.textContent = verdict.reason;
    row.appendChild(why);
    return;
  }

  const accept = document.createElement('button');
  accept.className = 'primary';
  accept.textContent = 'Accept';
  accept.addEventListener('click', async () => {
    accept.disabled = true;
    try {
      // Must run inside this click: showSaveFilePicker requires a user gesture.
      await session.acceptIncoming();
      accept.remove();
    } catch (err) {
      log(`could not start receiving: ${err.message}`, 'bad');
      accept.disabled = false;
    }
  });
  row.appendChild(accept);
}

function renderProgress({ direction, id, sent, total, name }) {
  const row = fileRow(id, direction === 'out' ? 'me' : 'them');
  if (!rowTitle(row).textContent) {
    rowTitle(row).textContent = `${name ?? 'file'} (${formatBytes(total ?? 0)})`;
  }
  setProgress(row, sent, total);
}

/** Send whatever the user attached, pasted or dropped, one after another. */
async function sendFiles(files) {
  const list = [...files].filter(Boolean);
  if (!list.length || !session) return;
  for (const file of list) {
    try {
      await session.sendFile(file);
    } catch (err) {
      log(`could not send ${file.name}: ${err.message}`, 'bad');
    }
  }
}

function autoGrow(el) {
  el.style.height = 'auto';
  el.style.height = `${Math.min(el.scrollHeight, 220)}px`;
}

// ---------------------------------------------------------------- flows

async function startCreate() {
  const minutes = Number($('ttl-select').value);
  const password = $('room-password').value || null;
  const secret = generateSecret();
  const formatted = formatSecret(secret);

  session = new Session({ secret, iceServers: config.iceServers, password });
  wire(session);
  try {
    const room = await session.create(minutes);
    rememberSlot(session.roomId, { token: room.token, role: 'a', expiresAt: room.expiresAt });
    rememberSecret(formatted);
    const link = `${location.origin}${location.pathname}#${formatted}`;
    // Deliberately NOT putting the secret in the address bar. It would otherwise sit
    // there in plain sight for the whole session, readable by anyone who can see the
    // screen or a screenshot. It lives in memory, and the link is produced on demand.

    // Rendered only when the user asks for it, so nothing sensitive is on screen by
    // default.
    let drawn = false;
    const revealShare = () => {
      $('room-code').textContent = formatted;
      if (!drawn) {
        try {
          drawQr($('qr'), encodeQr(link));
          drawn = true;
        } catch (err) {
          log(`could not render a QR code: ${err.message}. Use the link instead.`, 'warn');
        }
      }
      $('share-hidden').hidden = true;
      $('share-shown').hidden = false;
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
  const secret = parseSecret(text);
  if (!secret) {
    showHomeError('That does not look like a Warp Gate code. Paste the whole link or the WARP- code.');
    return;
  }

  // If this tab already holds a slot in this gate, re-attach instead of joining again.
  // Joining twice is correctly refused as full, which is what makes a reload fatal.
  const roomId = await deriveRoomId(secret);
  const held = recallSlot(roomId);
  if (held) {
    const still = await checkRoom(roomId, held.token).catch(() => null);
    if (still) {
      session = new Session({ secret, iceServers: config.iceServers });
      wire(session);
      try {
        await session.resume({ token: held.token, role: still.role, expiresAt: still.expiresAt });
        startTtl(still.expiresAt);
        show('waiting');
        $('waiting-title').textContent = 'Reconnecting to the other device';
        $('share-hidden').hidden = true;
        $('share-shown').hidden = true;
        log('Resumed the gate after a reload.', 'ok');
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
    rememberSecret(formatSecret(secret));
    startTtl(room.expiresAt);
    badge('negotiating', 'work');
    show('waiting');
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
    room_full: 'that gate already has two devices in it',
    room_exists: 'a gate with that code already exists, try again',
    rate_limited: 'too many attempts, wait a few minutes',
    capacity: 'the server is at capacity, try again shortly',
    bad_room_id: 'that code is malformed',
  };
  return map[err.message] ?? err.message;
}

function showHomeError(message) {
  const el = $('home-error');
  el.textContent = message;
  el.hidden = false;
  show('home');
}

async function severNow() {
  if (!session) { show('home'); return; }
  forgetSlot(session.roomId);
  try {
    await session.sever();
  } catch (err) {
    log(`sever encountered an error: ${err.message}`, 'bad');
  }
  session = null;
}

// ---------------------------------------------------------------- boot

async function boot() {
  try {
    config = await fetchConfig();
  } catch (err) {
    config = { iceServers: [], sessionMinutes: [10, 30, 60], defaultSessionMinutes: 30 };
    log(`could not load server config: ${err.message}`, 'bad');
  }

  // AGPL-3.0 section 13: users interacting over a network must be offered the source.
  if (config.sourceUrl) {
    const link = $('source-link');
    link.href = config.sourceUrl;
    link.hidden = false;
  }

  const select = $('ttl-select');
  for (const minutes of config.sessionMinutes) {
    const option = document.createElement('option');
    option.value = String(minutes);
    option.textContent = minutes >= 60 ? `${minutes / 60} hour` : `${minutes} minutes`;
    if (minutes === config.defaultSessionMinutes) option.selected = true;
    select.appendChild(option);
  }

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
  $('show-onboarding').addEventListener('click', () => show('onboarding'));
  setupSupport();

  // Say plainly which instance this is. A hostile host would simply delete this, which
  // is exactly why the text says the trust question can only be settled by self-hosting.
  const OFFICIAL_HOST = 'wg.fysh.site';
  const host = location.hostname;
  const isOfficial = host === OFFICIAL_HOST;
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  if (!isOfficial && !isLocal) {
    $('instance-title').textContent = `You are on ${host}, which is not the official instance`;
    $('instance-disc').classList.add('warn');
    $('instance-disc').open = true;
  } else if (isLocal) {
    $('instance-title').textContent = 'You are running your own copy';
  }

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
  $('create-btn').addEventListener('click', startCreate);
  $('join-btn').addEventListener('click', () => startJoin($('join-input').value));
  $('join-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') startJoin($('join-input').value); });
  $('sever').addEventListener('click', severNow);
  $('waiting-sever').addEventListener('click', severNow);
  $('clear-transcript').addEventListener('click', clearTranscript);
  window.addEventListener('pagehide', () => {
    for (const url of objectUrls) URL.revokeObjectURL(url);
    objectUrls.clear();
  });
  $('restart').addEventListener('click', () => { location.href = location.pathname; });
  $('failed-restart').addEventListener('click', () => { location.href = location.pathname; });

  // ---- one composer for everything
  const input = $('chat-input');
  const fileInput = $('file-input');

  input.addEventListener('input', () => autoGrow(input));
  input.addEventListener('keydown', (e) => {
    // Enter sends, Shift+Enter makes a new line. Matches every chat app.
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      $('chat-form').requestSubmit();
    }
  });

  $('chat-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = input.value;
    if (!text.trim() || !session) return;
    const asSecret = $('secret-toggle').checked;
    input.value = '';
    autoGrow(input);
    try {
      if (asSecret) await session.sendSecret(text);
      else await session.sendChat(text);
    } catch (err) {
      log(`could not send: ${err.message}`, 'bad');
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
  let dragDepth = 0;
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
    dragDepth = 0;
    veil.hidden = true;
    await sendFiles(e.dataTransfer?.files ?? []);
  });

  // ---- password prompt
  $('password-submit').addEventListener('click', () => {
    const value = $('password-input').value;
    if (!value) {
      $('password-error').textContent = 'Enter the password, or cancel.';
      $('password-error').hidden = false;
      return;
    }
    $('password-input').value = '';
    session?.setPassword(value);
    show('waiting');
    $('waiting-title').textContent = 'Connecting to the other device';
    $('qr-wrap').hidden = true;
  });
  $('password-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('password-submit').click();
  });
  $('password-cancel').addEventListener('click', severNow);

  // Deliberately NOT calling bye() on pagehide. pagehide fires on reload as well as on
  // close, and deleting the room there destroyed the gate for both devices whenever
  // either one refreshed. The server reaps a room once both sides have been gone for a
  // grace period, which frees abandoned gates without punishing a reload.

  let agreed = false;
  try { agreed = Boolean(JSON.parse(localStorage.getItem(AGREEMENT_KEY) || 'null')); } catch (err) { void err; }
  if (agreed) afterAgreement();
  else show('onboarding');
}

function afterAgreement() {
  const hash = location.hash.slice(1);
  // Strip it immediately: the secret has done its job by arriving, and leaving it in
  // the address bar means it is readable for the rest of the session by anyone who can
  // see the screen, and by anything that screenshots or records it.
  if (hash) history.replaceState(null, '', location.pathname);

  // A fresh arrival brings the secret in the link. A reload has no link any more, so
  // fall back to the copy held for this tab, which is what makes refresh survivable.
  const fromLink = hash && parseSecret(hash) ? hash : null;
  const stored = fromLink ? null : recallSecret();

  // startJoin resumes an existing slot if this tab already holds one, so a reload of
  // either side lands back in the same gate rather than being refused as full.
  if (fromLink) startJoin(fromLink);
  else if (stored && parseSecret(stored)) startJoin(stored);
  else show('home');
}

boot();
