// Warp Gate user interface.
//
// This file owns the DOM and nothing else. All protocol and cryptography lives in
// session.js, crypto.js, peer.js and signal.js.

import { generateSecret, formatSecret, parseSecret, deriveRoomId } from './crypto.js';
import { fetchConfig, checkRoom } from './signal.js';
import { Session, STATE } from './session.js';
import { checkWebRtcCapability } from './peer.js';
import { describeLimit, canAccept, formatBytes, saveBlob } from './transfer.js';
import { encodeQr, drawQr } from './qr.js';

const $ = (id) => document.getElementById(id);
const SCREENS = ['onboarding', 'home', 'waiting', 'connected', 'severed', 'failed'];
// Bumping the version re-prompts everyone, which is the point if the terms change.
const AGREEMENT_KEY = 'wg.agreed.v1';

let session = null;
let config = null;
let ttlTimer = null;
let diag = { candidates: [], ice: null, full: null };

// Slot persistence. Without this a page reload is fatal: re-joining a gate you already
// occupy is correctly refused as full, so the session could never be recovered.
const slotKey = (roomId) => `wg.slot.${roomId}`;

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
      $('file-capability').textContent = describeLimit();
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
  active.addEventListener('peer-left', (event) => log(event.detail, 'warn'));

  active.addEventListener('severed', (event) => {
    stopTtl();
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
  active.addEventListener('file-sent', (event) => log(`sent ${event.detail.name} (${formatBytes(event.detail.size)})`, 'ok'));
  active.addEventListener('file-failed', (event) => log(`transfer failed: ${event.detail.reason}`, 'bad'));
  active.addEventListener('file-received', (event) => {
    const meta = event.detail;
    log(`received ${meta.name} (${meta.human})`, 'ok');
    const row = transferRow(meta.id);
    row.replaceChildren();
    const title = document.createElement('div');
    title.textContent = `${meta.name} received (${meta.human})`;
    row.appendChild(title);
    if (meta.blob) {
      const save = document.createElement('button');
      save.className = 'secondary';
      save.textContent = 'Save file';
      save.addEventListener('click', () => saveBlob(meta.blob, meta.name));
      row.appendChild(save);
    } else {
      const done = document.createElement('div');
      done.className = 'muted small';
      done.textContent = 'Written straight to the location you chose.';
      row.appendChild(done);
    }
  });
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

function addMessage({ from, text }) {
  const wrap = document.createElement('div');
  wrap.className = `msg ${from === 'me' ? 'me' : ''}`;
  const who = document.createElement('span');
  who.className = 'who';
  who.textContent = from === 'me' ? 'you' : 'them';
  const body = document.createElement('span');
  body.textContent = text;
  wrap.append(who, body);
  const list = $('messages');
  list.appendChild(wrap);
  list.scrollTop = list.scrollHeight;
}

function addSecret({ from, text }) {
  const item = document.createElement('div');
  item.className = 'secret-item';

  const label = document.createElement('div');
  label.className = 'muted small';
  label.textContent = from === 'me' ? 'sent' : 'received';

  const value = document.createElement('div');
  value.className = 'secret-value masked';
  value.textContent = text;

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
    const wrote = await copyText(text);
    if (!wrote) return;
    copy.textContent = 'Copied';
    // Best effort only. No browser guarantees a clipboard can be cleared, and other
    // applications may already have taken a copy.
    setTimeout(async () => {
      await copyText('');
      copy.textContent = 'Copy';
      log('Attempted to clear the clipboard. This is best effort and not guaranteed.', 'warn');
    }, 45000);
  });

  const drop = document.createElement('button');
  drop.className = 'secondary';
  drop.textContent = 'Remove';
  drop.addEventListener('click', () => item.remove());

  actions.append(reveal, copy, drop);
  item.append(label, value, actions);
  $('secret-list').prepend(item);
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

function transferRow(id) {
  let row = document.getElementById(`transfer-${id}`);
  if (!row) {
    row = document.createElement('div');
    row.id = `transfer-${id}`;
    row.className = 'transfer-item';
    $('transfers').prepend(row);
  }
  return row;
}

function renderOffer(meta) {
  const row = transferRow(meta.id);
  row.replaceChildren();
  const title = document.createElement('div');
  title.textContent = `Incoming: ${meta.name} (${formatBytes(meta.size)})`;
  row.appendChild(title);

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
    } catch (err) {
      log(`could not start receiving: ${err.message}`, 'bad');
      accept.disabled = false;
    }
  });
  row.appendChild(accept);
}

function renderProgress({ direction, id, sent, total, name }) {
  const row = transferRow(id);
  let bar = row.querySelector('progress');
  if (!bar) {
    row.replaceChildren();
    const title = document.createElement('div');
    title.textContent = `${direction === 'out' ? 'Sending' : 'Receiving'} ${name ?? ''}`;
    bar = document.createElement('progress');
    row.append(title, bar);
  }
  bar.max = total || 1;
  bar.value = sent;
  bar.textContent = `${formatBytes(sent)} of ${formatBytes(total)}`;
}

// ---------------------------------------------------------------- flows

async function startCreate() {
  const minutes = Number($('ttl-select').value);
  const secret = generateSecret();
  const formatted = formatSecret(secret);

  session = new Session({ secret, iceServers: config.iceServers });
  wire(session);
  try {
    const room = await session.create(minutes);
    rememberSlot(session.roomId, { token: room.token, role: 'a', expiresAt: room.expiresAt });
    history.replaceState(null, '', `${location.pathname}#${formatted}`);
    const link = `${location.origin}${location.pathname}#${formatted}`;

    $('room-code').textContent = formatted;
    try {
      const qr = encodeQr(link);
      drawQr($('qr'), qr);
    } catch (err) {
      log(`could not render a QR code: ${err.message}. Use the link instead.`, 'warn');
    }

    $('copy-link').onclick = () => copyText(link).then((ok) => { if (ok) $('copy-link').textContent = 'Copied'; });
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
        $('qr-wrap').hidden = true;
        $('room-code').textContent = formatSecret(secret);
        log('Resumed the gate after a reload.', 'ok');
        return;
      } catch (err) {
        log(`could not resume: ${err.message}`, 'warn');
        session = null;
      }
    }
    forgetSlot(roomId);
  }

  session = new Session({ secret, iceServers: config.iceServers });
  wire(session);
  try {
    const room = await session.join();
    rememberSlot(session.roomId, { token: room.token, role: 'b', expiresAt: room.expiresAt });
    startTtl(room.expiresAt);
    badge('negotiating', 'work');
    show('waiting');
    $('room-code').textContent = formatSecret(secret);
    $('qr-wrap').hidden = true;
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

  // Ask up front whether this browser can do peer-to-peer at all, rather than letting
  // the user set up a gate and wait 25 seconds to find out it never could. The probe
  // uses no ICE servers, so it contacts nobody.
  checkWebRtcCapability().then((result) => {
    if (result.capable) return;
    $('webrtc-warning-text').textContent = result.hint;
    $('webrtc-warning').hidden = false;
    log(result.hint, 'bad');
  }).catch((err) => log(`could not check WebRTC support: ${err.message}`, 'warn'));
  $('create-btn').addEventListener('click', startCreate);
  $('join-btn').addEventListener('click', () => startJoin($('join-input').value));
  $('join-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') startJoin($('join-input').value); });
  $('sever').addEventListener('click', severNow);
  $('waiting-sever').addEventListener('click', severNow);
  $('restart').addEventListener('click', () => { location.href = location.pathname; });
  $('failed-restart').addEventListener('click', () => { location.href = location.pathname; });

  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      for (const other of document.querySelectorAll('.tab')) other.classList.toggle('active', other === tab);
      for (const name of ['chat', 'secret', 'file']) $(`tab-${name}`).hidden = name !== tab.dataset.tab;
    });
  }

  $('chat-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('chat-input');
    const text = input.value.trim();
    if (!text || !session) return;
    input.value = '';
    try { await session.sendChat(text); } catch (err) { log(`could not send: ${err.message}`, 'bad'); }
  });

  $('secret-send').addEventListener('click', async () => {
    const box = $('secret-input');
    const text = box.value;
    if (!text.trim() || !session) return;
    box.value = '';
    try { await session.sendSecret(text); } catch (err) { log(`could not send: ${err.message}`, 'bad'); }
  });

  $('file-send').addEventListener('click', async () => {
    const file = $('file-input').files?.[0];
    if (!file || !session) return;
    try { await session.sendFile(file); } catch (err) { log(`could not send file: ${err.message}`, 'bad'); }
  });

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
  // startJoin resumes an existing slot if this tab already holds one, so a reload of
  // either side lands back in the same gate rather than being refused as full.
  if (hash && parseSecret(hash)) startJoin(hash);
  else show('home');
}

boot();
