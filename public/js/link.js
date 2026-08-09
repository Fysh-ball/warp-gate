// One link: everything that is true of ONE pair of participants.
//
// A gate used to be a pair, so all of this lived in session.js. A gate is now a full mesh
// of up to config.maxParticipants participants, and every pair in that mesh runs its own
// RTCPeerConnection, its own ECDH, its own Channel and its own replay counters. Nothing is
// shared between pairs except the room secret, which enters each pair's key schedule as a
// pre-shared key: one pair's session keys are useless against another's frames, and a
// participant cannot read traffic it is not a party to.
//
// session.js owns the room (the secret, the signalling stream, the roster) and fans work
// out across these. This file owns a single peer-to-peer conversation from key agreement
// to teardown, and it is the ONLY place that touches a Channel.

import {
  generateKeyPair, deriveSession, Channel,
  b64u, TYPE, equalCt, decodeJson, decodeText, encodeText, typeName,
} from './crypto.js';
import { Peer } from './peer.js';
import {
  CHUNK_BYTES, readChunks, createSink, canAccept, formatBytes,
  fingerprintFile, compareFingerprints, saveResume, loadResume, clearResume,
} from './transfer.js';

export const STATE = {
  IDLE: 'idle',
  CREATING: 'creating',
  WAITING: 'waiting-for-peer',
  EXCHANGING: 'exchanging-keys',
  NEGOTIATING: 'negotiating',
  CONNECTING: 'connecting',
  CONFIRMING: 'confirming',
  CONNECTED: 'connected',
  // Was connected, is not now, and is waiting for the other device to come back. NOT a
  // failure state: the gate is intact, any transfer is held, and nothing is torn down.
  RECONNECTING: 'reconnecting',
  AUTH_FAILED: 'auth-failed',
  UNREACHABLE: 'unreachable',
  SEVERED: 'severed',
};

const CONFIRM_TIMEOUT_MS = 8000;

// Anything at or below this is accepted without asking. Pasting an image should feel
// like sending a message, not like agreeing to a download. Larger transfers still ask,
// which is also what lets the receiver choose a save location.
const AUTO_ACCEPT_BYTES = 10 * 1024 * 1024;
const MAX_AUTH_FAILURES = 3;
// Reconnect backoff while a transfer is paused. The owner's rule is that one side still
// being present keeps the gate waiting, so there is no attempt ceiling: only a cap on how
// often trying costs anything. The room's own hard 24h limit is what finally ends it.
const RESTART_BASE_MS = 2000;
const RESTART_MAX_MS = 30_000;
// How long a fresh handshake is left alone before another restart may be stacked on it.
// Both sides react to a dropped channel at once, so restarts cross as a matter of course;
// what must not happen is a third restart landing on a handshake that is still running,
// because that throws away a key pair the peer is in the middle of answering.
const RESTART_SETTLE_MS = 8000;
// What one sealed frame costs on the wire beyond its plaintext: the 10-byte header
// (version, type, 64-bit counter) plus the 16-byte AES-GCM tag. Subtracted from the SCTP
// maximum message size, because a message over that limit is rejected outright.
const FRAME_OVERHEAD_BYTES = 10 + 16;
// Frames held while the key schedule is still running. Small: the only thing that can
// legitimately arrive in that window is the peer's key confirmation.
const MAX_EARLY_FRAMES = 16;

/**
 * Address every relay this link sends at exactly one peer.
 *
 * Peer only ever calls signal.send(), and it must not have to know about slot ids. This
 * wrapper is what turns "send an offer" into "send an offer TO this participant": the
 * server refuses an unaddressed relay outright, so there is no path by which one pair's
 * SDP can reach a third participant.
 */
class LinkSignal {
  constructor(signal, to) {
    this.signal = signal;
    this.to = to;
  }

  send(message) {
    return this.signal.send(message, this.to);
  }
}

/** Did this relay fail because the room no longer seats the participant it was aimed at? */
const targetIsGone = (err) => /no_peer/.test(err?.message ?? '');

export class Link extends EventTarget {
  /**
   * @param session   the Session that owns the room
   * @param peerId    the other participant's slot id
   * @param peerRole  their seat letter. Display only, and only as the fallback label
   *                  before the session has derived this slot's name.
   * @param initiator true when THIS side makes the offer
   */
  constructor({ session, peerId, peerRole, initiator }) {
    super();
    this.session = session;
    this.peerId = peerId;
    this.peerRole = peerRole ?? null;
    // The side with the lexicographically smaller slot id offers. Deterministic on both
    // sides from two public strings, so there is no glare to resolve and no rollback to
    // implement; and it is the SAME comparison that fixes `role` below, so the direction
    // constants in the nonce and the transcript ordering cannot disagree across the pair.
    this.initiator = Boolean(initiator);
    this.role = this.initiator ? 'a' : 'b';
    this.signal = new LinkSignal(session.signal, peerId);

    this.state = STATE.IDLE;
    this.closed = false;

    this.channel = null;
    this.peer = null;
    this.keyPair = null;
    this.peerPublicRaw = null;
    this.sessionKeys = null;
    this.confirmedByPeer = false;
    this.confirmSent = false;
    this.confirmTimer = null;
    this.incoming = null;
    this.sendQueue = Promise.resolve();
    // Frames are delivered from an event listener, so without a queue two of them are
    // decrypted and applied concurrently and their order is whatever the event loop
    // decides. Everything that touches inbound state goes through this chain.
    this.recvQueue = Promise.resolve();
    // Set synchronously by connect(); this.keyPair only exists two awaits later.
    this.handshaking = false;
    // The in-flight key derivation, so two callers share one instead of racing.
    this.deriving = null;
    // Frames the peer sent before this side had a channel to open them with.
    this.earlyFrames = [];
    // Our record of the transfer THIS side started towards THIS peer: {id, name, size}.
    // The peer's progress reports are matched against it and never trusted for anything
    // else. One in flight per peer, so a slow peer cannot block the others.
    this.outbound = null;
    // Resolves when the peer accepts the outbound transfer, rejects if it refuses.
    this.pendingAccept = null;
    // Reconnect bookkeeping. A dropped link with a transfer in flight is not a failure to
    // report, it is a wait to keep, so these drive retries instead of an error screen.
    this.restartTimer = null;
    this.restartAttempt = 0;
    this.restarting = false;
    this.iceRestartDone = false;
    this.lastRenegotiationAt = 0;
    this.watchdog = null;
    // Has this link ever actually been up? Everything about how a stall is reported hangs
    // on this one bit.
    this.everConnected = false;
    // What the SIGNALLING channel last told us about the other side, which is a different
    // and usually more truthful fact than anything ICE knows.
    this.peerGone = false;
    // Set when this page reloaded: the peer still holds a connection to the page we
    // navigated away from and will ignore a new public key while it thinks it has one.
    this.needsRestart = Boolean(session.needsRestart);
  }

  /**
   * A short human label, used in the transcript and the roster.
   *
   * Delegated to the session, which owns the derived display names: the name comes from
   * the room secret and the peer's SLOT ID, so it is the same on every device in the gate,
   * and it is not this link's to compute. Deriving it from anything this link holds is the
   * mistake that looks obvious and is not: each pair has its own ephemeral key material, so
   * a name taken from that would differ for every observer of the same participant.
   */
  get label() {
    return this.session.labelFor(this);
  }

  emit(name, detail) { this.dispatchEvent(new CustomEvent(name, { detail })); }

  get severed() { return this.closed || this.session.severed; }

  setState(state, detail) {
    if (this.state === state) return;
    this.state = state;
    this.emit('link-state', { state, detail });
    if (state === STATE.CONNECTED) {
      // Latched for the life of the link. After this, a lost connection is a peer that
      // went away, never a pair of devices that could not find each other, and the two must
      // never again be reported as the same thing.
      this.everConnected = true;
      this.restartAttempt = 0;
      this.iceRestartDone = false;
      this.clearRestartTimer();
      // The link is back. Anything that was paused by the drop picks up here, and this is
      // the only place it happens, so a first connection and a reconnection take the same
      // path and cannot diverge.
      this.afterReconnect().catch((err) => this.emit('warning', `could not continue the paused transfer: ${err.message}`));
    }
  }

  // ------------------------------------------------------------ staying connected

  clearRestartTimer() {
    if (this.restartTimer) { clearTimeout(this.restartTimer); this.restartTimer = null; }
  }

  /** Drop all peer and key state so a fresh handshake can run over the same pair. */
  resetForRenegotiation() {
    // Stamped for both the self-initiated and the peer-initiated path, so the settle guard
    // in restartConnection cannot be dodged by whichever side happened to ask first.
    this.lastRenegotiationAt = Date.now();
    this.clearWatchdog();
    if (this.confirmTimer) { clearTimeout(this.confirmTimer); this.confirmTimer = null; }
    try { this.peer?.close(); } catch (err) { void err; }
    this.peer = null;
    // ------------------------------------------------------------------------------
    // INVARIANT, and it is the one that keeps this file confidential:
    //
    //   the key pair and the session keys are dropped TOGETHER, and a new Channel is
    //   only ever built after a FRESH ECDH.
    //
    // A Channel starts its send counter at zero. The nonce is the direction constant
    // concatenated with that counter, so a second Channel over the SAME derived session
    // reuses (key, nonce) exactly: two frames sealed at the same counter satisfy
    // ct1 XOR ct2 == p1 XOR p2, and AES-GCM offers nothing at all after that. It is total
    // loss of confidentiality for every frame either side sends, not a degradation.
    //
    // crypto.js refuses a second Channel over the same CryptoKey objects, but that guard
    // is on object identity: deriving the same session twice from the same inputs yields
    // equal key BYTES in fresh objects and walks straight past it. Regenerating the key
    // pair is what makes the next derivation produce different keys, so it is the real
    // protection and it lives here.
    //
    // If you are here to remove the generateKeyPair() call on the renegotiation path
    // because the old pair "is still perfectly good": it is not. That is the bug.
    // ------------------------------------------------------------------------------
    this.keyPair = null;
    this.peerPublicRaw = null;
    this.sessionKeys = null;
    this.channel = null;
    this.confirmSent = false;
    this.confirmedByPeer = false;
    // Held frames belong to the dead session's keys and can never be opened now.
    this.earlyFrames = [];
    this.deriving = null;
    // The session this handshake belonged to is gone, so it must not keep the latch and
    // block the fresh handshake that renegotiation exists to run.
    this.handshaking = false;

    // this.incoming is deliberately NOT dropped. The sink is open, the bytes are already
    // in the user's own file or in this page's memory, and destroying that because the
    // network blinked is the exact behaviour resuming exists to remove. Only a transfer
    // that never got a sink is discarded: nothing was committed, so nothing is lost.
    if (this.incoming) {
      if (!this.incoming.sink) this.incoming = null;
      else {
        this.incoming.stalled = true;
        // Chunks buffered before a sink existed belong to the dead channel's byte stream.
        this.incoming.early = null;
        this.incoming.earlyBytes = 0;
      }
    }

    if (this.pendingAccept) {
      const pending = this.pendingAccept;
      const id = pending.id;
      this.pendingAccept = null;
      // This transfer never started streaming, so there is no partial state to protect and
      // nothing to resume from: it is genuinely over.
      if (this.outbound?.id === id) {
        this.outbound.active = false;
        this.forgetOutboundIntent();
      }
      pending.reject(new Error('the connection restarted before the transfer was accepted'));
    }
    // A send that WAS streaming keeps everything it has: which file, how far, and its
    // fingerprint. It just stops until the receiver says where to continue from.
    if (this.outbound?.active) {
      this.outbound.stalled = true;
      this.outbound.streaming = false;
    }
  }

  /**
   * A link that has been up and is not up now. Keep it, say something TRUE, keep trying.
   *
   * This is the whole of the owner's rule in one method: regardless of what caused the
   * drop, as long as one of the parties is still here the gate keeps waiting. Nothing is
   * torn down, no failure screen is shown, no partial file is discarded, and the only
   * thing that changes is the badge and a line of text.
   *
   * It also fixes what the previous code said. `disconnected` is frequently transient in
   * the W3C model and returns to `connected` on its own; only `failed` is terminal, and
   * even `failed` after a successful connection means the peer went away rather than that
   * no path exists. Both used to land on the same screen with the same wrong explanation.
   */
  holdOpen(reason) {
    if (this.severed || !this.everConnected) return false;
    const detail = this.peer
      ? this.peer.explainStall({ peerLeft: this.peerGone })
      : 'The other device is not reachable at the moment.';
    if (this.state !== STATE.RECONNECTING) this.setState(STATE.RECONNECTING, reason);
    this.emit('holding', {
      reason,
      detail,
      peerLeft: this.peerGone,
      transferInFlight: this.hasTransferInFlight(),
    });
    this.markTransfersStalled(reason);
    this.scheduleRestart(reason);
    return true;
  }

  /** Is there anything in flight worth holding the connection open for? */
  hasTransferInFlight() {
    const pending = this.session.pendingInbound;
    // A record with no peerId was written before slot ids existed, so it can only belong to
    // this link if this link is the only one. Matching it unconditionally would make every
    // link in a mesh claim the same recovered transfer.
    const pendingIsOurs = Boolean(pending)
      && (pending.peerId ? pending.peerId === this.peerId : this.session.links.size === 1);
    return Boolean(this.incoming?.sink || this.outbound?.active || pendingIsOurs);
  }

  /**
   * Mark everything in flight as paused. Returns true if anything was.
   *
   * The point is what it does NOT do: no sink is aborted, no byte count is reset and no
   * File reference is released. A paused transfer is a transfer, not a failed one.
   */
  markTransfersStalled(why) {
    let any = false;
    if (this.incoming?.sink && !this.incoming.stalled) {
      this.incoming.stalled = true;
      any = true;
      this.emit('file-stalled', {
        direction: 'in',
        id: this.incoming.meta.id,
        name: this.incoming.meta.name,
        sent: this.incoming.received,
        total: this.incoming.meta.size,
        message: `Paused after ${formatBytes(this.incoming.received)}: ${why}. Waiting to continue.`,
      });
    }
    if (this.outbound?.active && !this.outbound.stalled) {
      this.outbound.stalled = true;
      this.outbound.streaming = false;
      any = true;
      this.emit('file-stalled', {
        direction: 'out',
        id: this.outbound.id,
        name: this.outbound.name,
        sent: this.outbound.sent,
        total: this.outbound.size,
        message: `Paused after ${formatBytes(this.outbound.sent)}: ${why}. Waiting to continue.`,
      });
    }
    return any || this.hasTransferInFlight();
  }

  /**
   * Arm the next reconnect attempt, backing off.
   *
   * Deliberately unbounded in attempts. "As long as one of the parties is still up it
   * should keep waiting" is the requirement, so the only thing that ends this is the gate
   * itself ending: a sever, the room's idle TTL with nobody attached, or its 24h cap.
   */
  scheduleRestart(reason) {
    if (this.severed || this.restartTimer) return;
    const delay = Math.min(RESTART_BASE_MS * (2 ** this.restartAttempt), RESTART_MAX_MS);
    this.restartAttempt += 1;
    this.emit('warning', `${reason}. Reconnecting in ${Math.round(delay / 1000)}s (attempt ${this.restartAttempt}).`);
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      this.restartConnection().catch((err) => {
        // A relay refused with no_peer says the room no longer seats this participant.
        // That is terminal for this link, and retrying it would burn the shared reject
        // budget until every route answers 429.
        if (targetIsGone(err)) { this.session.onLinkTargetGone(this); return; }
        this.emit('warning', `could not reconnect: ${err.message}`);
        this.scheduleRestart('the reconnect attempt failed');
      });
    }, delay);
  }

  /**
   * Get the data path back, cheapest option first.
   *
   * Tier one is an ICE restart, which re-runs connectivity checks over the SAME DTLS and
   * SCTP association: keys, frame counters and the data channel all survive, so nothing
   * has to be resent and no fingerprint has to be re-proved.
   *
   * Tier two throws the session away and handshakes again. That gives a new channel with a
   * new frame counter, which is exactly when the receiver has to say where it got to.
   */
  async restartConnection() {
    if (this.severed || this.restarting) return;
    // It may have come back by itself while the timer was pending.
    if (this.state === STATE.CONNECTED && this.peer?.channel?.readyState === 'open') return;
    // A handshake that started moments ago has not had a chance to succeed yet, and both
    // sides restart on the same event, so without this the two of them tear down each
    // other's fresh key pairs in turn and neither handshake ever completes.
    if (Date.now() - (this.lastRenegotiationAt ?? 0) < RESTART_SETTLE_MS) {
      this.scheduleRestart('a handshake is already in progress');
      return;
    }
    this.restarting = true;
    try {
      const channelAlive = this.peer?.channel?.readyState === 'open';
      if (channelAlive && !this.iceRestartDone && this.peer && !this.peer.closed) {
        this.iceRestartDone = true;
        this.emit('warning', 'Re-running the direct connection without renegotiating keys.');
        // Only the offering side may offer. The answering side asks.
        if (this.initiator) await this.peer.makeOffer(true);
        else await this.signal.send({ t: 'ice-restart' });
        // Escalate if that does not bring it back.
        this.scheduleRestart('waiting for the direct connection to come back');
        return;
      }
      this.iceRestartDone = false;
      this.emit('warning', 'Renegotiating the connection from the start.');
      // Tell the peer to drop its half before dropping ours, or it keeps waiting on a
      // public key it will never accept because it thinks it already has one.
      await this.signal.send({ t: 'restart' });
      this.resetForRenegotiation();
      await this.connect();
    } finally {
      this.restarting = false;
    }
  }

  /**
   * Pick up whatever the drop interrupted, now that the link is back.
   *
   * The RECEIVER drives this, always: it is the only side that knows how many bytes it
   * actually committed. The sender never assumes an offset.
   */
  async afterReconnect() {
    if (this.severed) return;

    // A transfer whose data cannot come back has to be closed out rather than left for a
    // sender that would otherwise hold its file open indefinitely.
    const lost = this.session.lostInbound;
    if (lost && (!lost.peerId || lost.peerId === this.peerId)) {
      this.session.lostInbound = null;
      await this.control({
        kind: 'file-resume-deny',
        id: lost.id,
        code: 'memory_sink_reload',
        reason: 'the receiving browser was holding this file in memory, and reloading the page discarded it, '
          + 'so the transfer has to start again from the beginning',
      });
    }

    const inbound = this.incoming;
    if (inbound?.sink && inbound.stalled) await this.requestResume(inbound);

    const out = this.outbound;
    if (out?.active && out.stalled && !out.file) {
      // Our own page reloaded: the File is gone and only the user can give it back.
      this.emit('file-reselect-needed', {
        id: out.id, name: out.name, size: out.size, received: out.sent,
      });
    }
  }

  /** Ask the sender to continue from exactly where this side's sink is positioned. */
  async requestResume(inbound) {
    const received = inbound.sink?.position ?? inbound.received;
    // The sink's own position is the authority: after a reload it is clamped to what the
    // file on disk actually contains, which can be less than the count we remembered.
    inbound.received = received;
    this.emit('file-stalled', {
      direction: 'in',
      id: inbound.meta.id,
      name: inbound.meta.name,
      sent: received,
      total: inbound.meta.size,
      message: `Asking the other device to continue from ${formatBytes(received)}.`,
    });
    await this.control({
      kind: 'file-resume',
      id: inbound.meta.id,
      received,
      chunks: inbound.chunks,
      crossedReload: Boolean(inbound.crossedReload),
      fingerprint: inbound.meta.fingerprint ?? null,
    });
  }

  /**
   * Give up waiting after a bounded time and say precisely why.
   *
   * Browsers can sit in ICE checking for 30 seconds or more before declaring failure,
   * and sometimes never declare it at all, which is what "it just spins forever" is.
   * A watchdog turns that into a specific, actionable message.
   */
  startWatchdog(ms = 25000) {
    this.clearWatchdog();
    this.watchdog = setTimeout(() => {
      this.watchdog = null;
      if (this.severed || this.state === STATE.CONNECTED) return;
      // A link that has been up keeps waiting, whether or not a file is moving. This is the
      // owner's rule and it has no exceptions: one party still being here is enough.
      if (this.everConnected) {
        this.emit('transfer-waiting', {
          detail: this.peer
            ? this.peer.explainStall({ peerLeft: this.peerGone })
            : 'The connection has not come back yet.',
        });
        this.holdOpen('the connection has not come back yet');
        this.startWatchdog(ms);
        return;
      }
      const detail = this.peer ? this.peer.explainStall({ peerLeft: this.peerGone }) : 'The connection never started.';
      // Report the connection's own state, not just what the UI happened to observe.
      this.emit('diagnostics', this.peer ? this.peer.diagnostics() : null);
      this.emit('unreachable', detail);
      this.setState(STATE.UNREACHABLE, detail);
    }, ms);
  }

  clearWatchdog() {
    if (this.watchdog) { clearTimeout(this.watchdog); this.watchdog = null; }
  }

  // ------------------------------------------------------------ key agreement

  async connect() {
    // this.keyPair is the "already under way" marker but it is not set until two awaits
    // later, so on its own it is not a guard at all: hello and peer-joined can both fire
    // inside that window and run two handshakes, each generating a key pair and sending
    // its own public key. Latch synchronously, before the first await.
    if (this.handshaking || this.keyPair || this.severed) return;
    this.handshaking = true;
    try {
      // Never derive keys before the password is known, or the first attempt would
      // always be made without it and always fail.
      await this.session.passwordGate;
      if (this.severed) return;
      this.setState(STATE.EXCHANGING);
      this.startWatchdog();
      this.keyPair = await generateKeyPair();
      if (this.keyPair.privateExtractable) {
        this.emit('warning', 'This browser would not create a non-extractable key; key hygiene is degraded.');
      }
      this.peer = new Peer({ role: this.role, iceServers: this.session.iceServers, signal: this.signal });
      this.wirePeer();
      if (this.needsRestart) {
        this.needsRestart = false;
        await this.signal.send({ t: 'restart' });
      }
      await this.signal.send({ t: 'pk', pk: b64u.encode(this.keyPair.publicRaw) });

      // The peer's public key can arrive before generateKeyPair() above resolves. In that
      // case onSignalMessage stored it and returned without deriving, because we had no
      // key of our own yet. Deriving here covers that ordering; deriveKeys is idempotent.
      await this.deriveKeys();

      if (this.initiator) {
        this.setState(STATE.NEGOTIATING);
        await this.peer.start();
      }
    } finally {
      // Released either way. On success this.keyPair now holds the guard; on an early
      // return or a throw the handshake must stay retryable.
      this.handshaking = false;
    }
  }

  wirePeer() {
    this.peer.addEventListener('channel-open', () => {
      this.setState(STATE.CONFIRMING);
      this.maybeConfirm();
    });
    this.peer.addEventListener('channel-close', () => {
      if (this.severed) return;
      // A closed channel is a pause, not an end. Nothing is torn down here: any sink stays
      // open and any byte count stays exactly where it is.
      if (this.holdOpen('the data channel closed')) return;
      if (this.state === STATE.CONNECTED) this.emit('warning', 'The data channel closed.');
    });
    this.peer.addEventListener('frame', (event) => this.onFrame(event.detail));
    this.peer.addEventListener('connection-state', (event) => {
      this.emit('connection-state', event.detail);
      if (event.detail === 'connecting' && this.state === STATE.NEGOTIATING) this.setState(STATE.CONNECTING);
      // An ICE restart keeps the keys and the data channel, so no fresh key confirmation
      // arrives and nothing else would ever move the state back. Without this the gate
      // recovers on the wire and stays greyed out on screen forever.
      if (event.detail === 'connected' && this.state === STATE.RECONNECTING
        && this.confirmedByPeer && this.peer?.channel?.readyState === 'open') {
        this.setState(STATE.CONNECTED);
      }
      // 'disconnected' is frequently TRANSIENT in the W3C model: it can and often does
      // return to 'connected' on its own, so it must never be terminal. It only ARMS the
      // backoff here, and the first attempt re-checks the state and does nothing if it
      // recovered in the meantime.
      //
      // 'closed' is here because a peer connection can be closed out from under us (a
      // browser reclaiming a backgrounded tab's resources, or the OS tearing down the
      // socket) and that emits no channel 'close' event at all: webrtc-pc 4.4.3 says
      // pc.close() closes its data channels WITHOUT dispatching one. Peer.close() is
      // silent after teardown, so this only ever sees a close we did not ask for.
      if (this.severed) return;
      if (['disconnected', 'failed', 'closed'].includes(event.detail)) {
        this.holdOpen(`the connection went ${event.detail}`);
      }
    });
    this.peer.addEventListener('failed', (event) => {
      if (this.severed) return;
      // A link that has been up is never declared unreachable. Declaring it drops the
      // session in app.js, which throws away any partial file the other side is still
      // perfectly able to finish sending, and it puts a NAT-traversal explanation on
      // screen for a connection that demonstrably traversed the NAT already.
      if (this.holdOpen('the direct connection failed')) return;
      // Never connected. Now the diagnosis below is the right one and is worth showing.
      const detail = this.peer ? this.peer.explainStall({ peerLeft: this.peerGone }) : event.detail;
      this.emit('diagnostics', this.peer ? this.peer.diagnostics() : null);
      this.emit('unreachable', detail);
      this.setState(STATE.UNREACHABLE, detail);
    });
    this.peer.addEventListener('warning', (event) => this.emit('warning', event.detail));
    // Progress the user can actually see while ICE works.
    this.peer.addEventListener('candidate', (event) => this.emit('progress', {
      kind: 'candidates', types: event.detail.types,
    }));
    this.peer.addEventListener('gathering-complete', (event) => this.emit('progress', {
      kind: 'gathering-complete', types: event.detail.types,
    }));
    this.peer.addEventListener('ice-state', (event) => this.emit('progress', {
      kind: 'ice', state: event.detail,
    }));
  }

  /** A decrypted signalling message addressed to this link. */
  async onSignalMessage(message) {
    if (!message || typeof message.t !== 'string') return;
    if (message.t === 'pk') {
      if (this.peerPublicRaw) return;
      this.peerPublicRaw = b64u.decode(message.pk);
      await this.deriveKeys();
      return;
    }
    if (message.t === 'sever') {
      this.session.teardown('The other device burned the gate.');
      return;
    }
    if (message.t === 'restart') {
      // The peer reloaded, or asked for a full renegotiation. Discard our half of the dead
      // session and handshake again. resetForRenegotiation keeps any transfer in flight.
      this.emit('warning', 'The other device reconnected. Renegotiating.');
      this.resetForRenegotiation();
      await this.connect();
      return;
    }
    if (message.t === 'ice-restart') {
      // The answering side cannot offer, so it asks. An ICE restart keeps the keys and the
      // data channel, which is the cheap way back from a network change.
      if (this.initiator && this.peer && !this.peer.closed) {
        this.emit('warning', 'The other device asked to re-run the direct connection.');
        await this.peer.makeOffer(true);
      }
      return;
    }
    if (!this.peer) await this.connect();
    await this.peer?.handleMessage(message);
  }

  /**
   * Derive this pair's session keys, exactly once.
   *
   * Both connect() and the 'pk' handler call this, and the peer's public key can land in
   * the window between them. The guard below is read before an await, so on its own it is
   * not a guard at all: both calls got past it and ran the whole schedule twice. The
   * slower of the two then replaced a Channel the faster had already sealed a frame on.
   */
  async deriveKeys() {
    if (this.deriving) return this.deriving;
    if (!this.keyPair || !this.peerPublicRaw || this.sessionKeys) return undefined;
    this.deriving = this.deriveKeysOnce();
    try {
      return await this.deriving;
    } finally {
      this.deriving = null;
    }
  }

  /** The body of deriveKeys(). Never call this directly: deriveKeys() holds the latch. */
  async deriveKeysOnce() {
    try {
      // Stretching the room password is deliberately slow, and it is the SAME password for
      // every link, so the session stretches it once and every link waits on that one
      // result rather than each paying 600,000 iterations of its own.
      const passwordKey = await this.session.ensurePasswordKey();
      // `role` here is the per-PAIR role from the slot-id comparison, not a seat label.
      // It orders the two public keys in the transcript hash and picks the direction
      // constants, and both sides compute it from the same two strings, so they cannot
      // disagree: if they could, the two sides would derive different keys and the
      // failure would present as a crypto fault rather than a routing one.
      this.sessionKeys = await deriveSession({
        secret: this.session.secret,
        passwordKey,
        privateKey: this.keyPair.privateKey,
        publicRaw: this.keyPair.publicRaw,
        peerPublicRaw: this.peerPublicRaw,
        role: this.role,
        roomId: this.session.roomId,
      });
    } catch (err) {
      this.setState(STATE.AUTH_FAILED, `key agreement failed: ${err.message}`);
      return;
    }
    this.channel = new Channel(this.sessionKeys);
    // Anything the peer sent while this was still running can be opened now. Queued, so
    // it is replayed in arrival order and ahead of whatever arrives next.
    this.flushEarlyFrames();
    this.emit('sas', this.sessionKeys.sas);
    this.maybeConfirm();
    return undefined;
  }

  /** Replay frames that arrived before there was a channel to open them with. */
  flushEarlyFrames() {
    if (!this.earlyFrames.length) return;
    const held = this.earlyFrames;
    this.earlyFrames = [];
    for (const raw of held) this.onFrame(raw);
  }

  /** Send our key confirmation once both the keys and the channel are ready. */
  async maybeConfirm() {
    if (this.confirmSent || !this.channel || !this.peer?.channel) return;
    if (this.peer.channel.readyState !== 'open') return;
    this.confirmSent = true;
    try {
      await this.peer.send(await this.channel.sealJson(TYPE.CONTROL, {
        kind: 'confirm',
        value: b64u.encode(this.sessionKeys.confirmMine),
      }));
    } catch (err) {
      this.setState(STATE.AUTH_FAILED, `could not send key confirmation: ${err.message}`);
      return;
    }
    this.confirmTimer = setTimeout(() => {
      if (!this.confirmedByPeer) {
        this.setState(STATE.AUTH_FAILED, 'The other device did not confirm the shared secret in time.');
        this.emit('auth-failed', 'No key confirmation received. The other device may not have the same link.');
      }
    }, CONFIRM_TIMEOUT_MS);
  }

  /**
   * Report how the connection is actually routed.
   *
   * The selected candidate pair is not always present in getStats() the instant key
   * confirmation completes, so sampling once makes the UI fall back to a vague
   * "CONNECTED" perhaps a third of the time. Telling the user their data is flowing
   * directly is a stated goal, not decoration, so poll until the answer is real.
   */
  async reportRoute(deadlineMs = 8000) {
    const until = Date.now() + deadlineMs;
    for (;;) {
      if (this.severed || !this.peer) return;
      const route = await this.peer.routeType();
      if (route) { this.emit('route', route); return; }
      if (Date.now() >= until) {
        // Still unknown: say so rather than implying a direct path we cannot confirm.
        this.emit('route', null);
        return;
      }
      await new Promise((resolve) => { setTimeout(resolve, 250); });
    }
  }

  // ------------------------------------------------------------ frames

  /**
   * Serialise everything that touches inbound state, in arrival order.
   *
   * The peer's 'frame' listener calls this without awaiting, so before the queue two
   * frames could be decrypted at once. That is what made the replay counter in
   * Channel.open regressable, and it also let a chunk be written to the sink out of
   * order. One frame at a time, in the order the DataChannel delivered them.
   */
  enqueueInbound(task) {
    const run = this.recvQueue.then(task, task);
    // The chain itself must never stay rejected, or one bad frame would take the queue
    // down with it; callers still see their own task's rejection.
    this.recvQueue = run.then(() => undefined, () => undefined);
    return run;
  }

  onFrame(raw) {
    // Nothing awaits this: it is called from the DataChannel listener. Keep the reason.
    return this.enqueueInbound(() => this.handleFrame(raw))
      .catch((err) => this.emit('warning', `could not handle a frame: ${err.message}`));
  }

  async handleFrame(raw) {
    if (!this.channel) {
      // Not garbage: the DataChannel can open, and the peer's key confirmation can
      // arrive, while this side is still stretching the room password. PBKDF2 is
      // deliberately slow, so that window is seconds wide on a resumed gate where the
      // peer reconnects from a warm ICE state. Dropping the frame loses the confirmation
      // outright, nothing retransmits it, and the gate fails verification eight seconds
      // later reporting that the peer never confirmed. Hold it until there are keys.
      if (this.severed) return;
      if (this.earlyFrames.length >= MAX_EARLY_FRAMES) {
        this.emit('warning', 'the other device sent more than expected before the keys were ready; dropping a frame');
        return;
      }
      this.earlyFrames.push(raw);
      return;
    }
    let opened;
    try {
      opened = await this.channel.open(raw);
    } catch (err) {
      this.emit('frame-rejected', err.message);
      if (this.channel.authFailures >= MAX_AUTH_FAILURES) {
        this.emit('auth-failed', `${this.channel.authFailures} frames failed authentication. Severing.`);
        await this.session.sever();
      }
      return;
    }

    const { type, plaintext } = opened;
    try {
      if (type === TYPE.CONTROL) return await this.onControl(decodeJson(plaintext));
      if (type === TYPE.CHAT) return this.emit('chat', { from: 'peer', text: decodeText(plaintext) });
      if (type === TYPE.SECRET) return this.emit('secret', { from: 'peer', text: decodeText(plaintext) });
      if (type === TYPE.FILE_START) return await this.onFileStart(decodeJson(plaintext));
      if (type === TYPE.FILE_CHUNK) return await this.onFileChunk(plaintext);
      if (type === TYPE.FILE_END) return await this.onFileEnd(decodeJson(plaintext));
      this.emit('warning', `ignored unknown frame type ${typeName(type)}`);
    } catch (err) {
      this.emit('warning', `could not handle a ${typeName(type)} frame: ${err.message}`);
    }
    return undefined;
  }

  async onControl(control) {
    if (control.kind === 'confirm') {
      const expected = this.sessionKeys?.confirmPeer;
      // A confirmation that is not decodable is a FAILED confirmation, and it has to be
      // reported as one here. Letting b64u.decode throw into the generic frame handler did
      // fail closed, but only via the eight-second confirm timeout, so the user saw a vague
      // warning and then an unexplained failure; a genuine mismatch says so at once. The
      // decode reason is kept rather than swallowed, because "malformed" and "wrong" are
      // different things to be told.
      let offered = null;
      let why = null;
      try {
        if (typeof control.value !== 'string') throw new Error('no confirmation value was sent');
        offered = b64u.decode(control.value);
      } catch (err) {
        why = err.message;
      }
      if (!expected || !offered || !equalCt(offered, expected)) {
        this.setState(STATE.AUTH_FAILED, why ? `malformed key confirmation: ${why}` : 'key confirmation mismatch');
        this.emit('auth-failed', why
          ? `The other device sent a key confirmation this device could not read (${why}). Verification failed.`
          : (this.session.password
            ? 'Verification failed. The room password does not match, or the other device used a different link.'
            : 'The other device does not hold the same link. Verification failed.'));
        await this.session.sever();
        return;
      }
      this.confirmedByPeer = true;
      if (this.confirmTimer) { clearTimeout(this.confirmTimer); this.confirmTimer = null; }
      this.clearWatchdog();
      this.setState(STATE.CONNECTED);
      this.reportRoute();
      return;
    }
    if (control.kind === 'sever') { this.session.teardown('The other device burned the gate.'); return; }
    if (control.kind === 'file-accept' || control.kind === 'file-reject') {
      const out = this.outbound;
      if (!out || control.id !== out.id) {
        this.emit('warning', `ignored a ${control.kind} for a transfer this device did not start`);
        return;
      }
      if (control.kind === 'file-accept') {
        this.settleAcceptance(out.id, null);
        this.emit('file-accepted', { id: out.id, name: out.name });
        return;
      }
      const reason = typeof control.reason === 'string' ? control.reason : 'the other device refused the transfer';
      this.settleAcceptance(out.id, reason);
      this.emit('file-rejected', { id: out.id, name: out.name, reason });
      return;
    }
    if (control.kind === 'file-progress') {
      const row = this.outboundRow(control);
      if (row) this.emit('file-progress', row);
      return;
    }
    if (control.kind === 'file-complete') {
      const row = this.outboundRow(control);
      if (row) this.emit('file-complete', row);
      return;
    }
    if (control.kind === 'file-resume') { await this.onResumeRequest(control); return; }
    if (control.kind === 'file-resume-ok') { await this.onResumeAccepted(control); return; }
    if (control.kind === 'file-resume-wait') { this.onResumeWait(control); return; }
    if (control.kind === 'file-resume-deny') { await this.onResumeDenied(control); return; }
    if (control.kind === 'file-abort') { await this.onPeerAbort(control); return; }
    this.emit('warning', `ignored unknown control message "${control.kind}"`);
  }

  // ------------------------------------------------------------ resume protocol

  /**
   * SENDER side. The receiver has told us where it got to; decide whether we can serve it.
   *
   * Three answers, and the difference between them matters to the user:
   *   file-resume-ok    we are continuing now, from this exact offset
   *   file-resume-wait  we are still here but need the user to do something first
   *   file-resume-deny  we cannot ever serve this, stop waiting and say why
   *
   * A deny is what stops the receiver hanging. A wait is what stops it giving up on a
   * sender who only needs to be handed the file again.
   */
  async onResumeRequest(control) {
    const id = typeof control.id === 'string' ? control.id : null;
    const received = Number(control.received);
    if (!id || !Number.isSafeInteger(received) || received < 0) {
      await this.control({
        kind: 'file-resume-deny', id: id ?? '', code: 'bad_request',
        reason: 'the request to continue the transfer was malformed',
      });
      return;
    }

    let out = this.outbound;
    if (!out || out.id !== id || !out.active) {
      // Our page may have reloaded. The File itself cannot survive that, but what the
      // transfer WAS survives, which is enough to ask the user for the file again.
      const intent = this.recallOutboundIntent();
      if (!intent || intent.id !== id) {
        await this.control({
          kind: 'file-resume-deny', id, code: 'no_transfer',
          reason: 'this device is no longer sending that file',
        });
        return;
      }
      out = {
        ...intent,
        file: null,
        sent: received,
        chunks: 0,
        active: true,
        stalled: true,
        streaming: false,
        settle: null,
      };
      this.outbound = out;
    }

    out.resumeOffset = received;
    out.resumeChunks = Number(control.chunks);
    out.peerFingerprint = control.fingerprint ?? null;

    if (!out.file) {
      await this.control({
        kind: 'file-resume-wait', id, code: 'needs_reselect',
        reason: 'the sending device reloaded and has to be given the file again',
      });
      this.emit('file-reselect-needed', { id, name: out.name, size: out.size, received });
      return;
    }

    if (received > Number(out.size)) {
      await this.control({
        kind: 'file-resume-deny', id, code: 'bad_offset',
        reason: `the other device claims ${received} bytes of a ${out.size} byte file`,
      });
      return;
    }

    await this.serveResume(out, received);
  }

  /**
   * Prove the file is still the same file, then continue from `offset`.
   *
   * The fingerprint is recomputed from the live File EVERY time, not read from our own
   * cached copy, and it is checked against what the RECEIVER recorded at FILE_START rather
   * than only against our own record. A sender comparing its cache to its cache proves
   * nothing; a sender that reloaded and was handed the wrong file has a cache that agrees
   * with itself perfectly. Recomputing is one 64 KiB read, so there is no reason to skip it
   * on the cheap resumes either.
   */
  async serveResume(out, offset) {
    let fresh;
    try {
      fresh = await fingerprintFile(out.file);
    } catch (err) {
      await this.control({
        kind: 'file-resume-deny', id: out.id, code: 'unreadable',
        reason: `the file could not be read to check it is the same one: ${err.message}`,
      });
      this.abandonOutbound(out, `could not re-read ${out.name}: ${err.message}`);
      return false;
    }

    const against = out.peerFingerprint ?? out.fingerprint;
    const verdict = compareFingerprints(against, fresh);
    if (!verdict.ok) {
      // Never splice. Resuming a different file at an offset produces a corrupt result
      // that passes every length check on both sides, so this refuses rather than repairs.
      await this.control({
        kind: 'file-resume-deny', id: out.id, code: 'fingerprint_mismatch',
        reason: `${verdict.reason}. The transfer has to start again from the beginning rather than `
          + 'joining two different files together.',
      });
      this.emit('file-reselect-refused', { id: out.id, name: out.name, reason: verdict.reason });
      this.abandonOutbound(out, verdict.reason);
      return false;
    }

    out.sent = offset;
    const claimedChunks = Number(out.resumeChunks);
    // Adopt the receiver's chunk count so the two sides' FILE_END totals are consistent.
    // This does weaken the chunk-count check across a resume, which is why meta.size stays
    // the independent end-to-end check: it was taken from the File before any reading.
    out.chunks = Number.isSafeInteger(claimedChunks) && claimedChunks >= 0 ? claimedChunks : 0;
    out.stalled = false;
    out.fingerprint = fresh;
    await this.control({ kind: 'file-resume-ok', id: out.id, offset, fingerprint: fresh });
    this.emit('file-resumed', {
      direction: 'out', id: out.id, name: out.name, offset, total: out.size,
    });
    this.driveOutbound(offset);
    return true;
  }

  /** RECEIVER side. The sender is about to continue; check it before accepting a byte. */
  async onResumeAccepted(control) {
    const inbound = this.incoming;
    if (!inbound || inbound.meta.id !== control.id) return; // a late reply for a dead transfer
    const offset = Number(control.offset);

    if (offset !== inbound.received) {
      await this.failInbound(
        inbound,
        `the other device offered to continue from ${offset} bytes but ${inbound.received} have been written here`,
      );
      return;
    }

    // The second half of the splice guard: the sender proved the file to itself, and now
    // it has to prove it to the side that holds the partial copy.
    const verdict = compareFingerprints(inbound.meta.fingerprint ?? null, control.fingerprint ?? null);
    if (!verdict.ok) {
      await this.control({
        kind: 'file-resume-deny', id: control.id, code: 'fingerprint_mismatch', reason: verdict.reason,
      });
      await this.failInbound(inbound, `refused to continue: ${verdict.reason}`);
      return;
    }

    inbound.stalled = false;
    inbound.crossedReload = false;
    inbound.resumes = (inbound.resumes ?? 0) + 1;
    this.emit('file-resumed', {
      direction: 'in', id: inbound.meta.id, name: inbound.meta.name, offset, total: inbound.meta.size,
    });
  }

  /** RECEIVER side. The sender is still there but needs the user to act. Keep waiting. */
  onResumeWait(control) {
    const inbound = this.incoming;
    if (!inbound || inbound.meta.id !== control.id) return;
    this.emit('file-stalled', {
      direction: 'in',
      id: inbound.meta.id,
      name: inbound.meta.name,
      sent: inbound.received,
      total: inbound.meta.size,
      message: typeof control.reason === 'string'
        ? `Still waiting: ${control.reason}.`
        : 'Still waiting for the other device.',
    });
  }

  /** Either side. The transfer cannot be continued; end it cleanly rather than hang. */
  async onResumeDenied(control) {
    const reason = typeof control.reason === 'string' && control.reason
      ? control.reason
      : 'the other device could not continue the transfer';
    const inbound = this.incoming;
    if (inbound && inbound.meta.id === control.id) {
      await this.failInbound(inbound, reason);
      return;
    }
    const out = this.outbound;
    if (out && out.id === control.id && out.active) {
      this.abandonOutbound(out, reason);
      return;
    }
    this.emit('warning', `ignored a refusal to continue a transfer this device does not have: ${reason}`);
  }

  /** Give up on an inbound transfer: release the sink, forget the record, say why. */
  async failInbound(inbound, reason) {
    if (this.incoming === inbound) this.incoming = null;
    try { await inbound.sink?.abort(reason); } catch (err) { this.emit('warning', `could not close the partial file: ${err.message}`); }
    await this.forgetInboundRecord();
    this.emit('file-failed', { ...inbound.meta, reason });
  }

  /**
   * Give up on an outbound transfer: release the File, forget the intent, say why.
   *
   * The peer MUST be told. Without the control frame below, a sender-side read failure
   * was completely invisible on the other device: its row sat with no status and no
   * progress indefinitely, and because `incoming` was never cleared that pair's whole
   * file path stayed wedged, refusing every later file with "another transfer is
   * already in progress". `serveResume` already had this right with `file-resume-deny`.
   *
   * Deliberately fire-and-forget: the reason we are abandoning is often that the
   * channel is unhappy, and this must not itself throw into the caller's failure path.
   */
  abandonOutbound(out, reason) {
    out.active = false;
    out.stalled = false;
    out.streaming = false;
    out.file = null;
    this.forgetOutboundIntent();
    this.control({ kind: 'file-abort', id: out.id, reason: String(reason).slice(0, 300) })
      .catch((err) => this.emit('warning', `could not tell the other device the transfer stopped: ${err.message}`));
    this.emit('file-rejected', { id: out.id, name: out.name, reason });
    const settle = out.settle;
    out.settle = null;
    if (settle) settle.reject(new Error(reason));
  }

  /**
   * The sender gave up. Release the inbound side so the link is usable again, and tell
   * the user why the row stopped moving rather than leaving it frozen.
   */
  async onPeerAbort(control) {
    const inbound = this.incoming;
    if (!inbound || typeof control.id !== 'string' || inbound.meta.id !== control.id) return;
    const why = typeof control.reason === 'string' && control.reason
      ? control.reason.slice(0, 300)
      : 'the other device stopped sending';
    await this.failInbound(inbound, `the other device stopped sending: ${why}`);
  }

  /**
   * Build an OUTBOUND progress row out of a peer control message.
   *
   * `{ direction: 'out', ...control }` spread unvalidated peer JSON over the direction,
   * so the peer chose `direction`, `id`, `name`, `sent` and `total`. The UI creates a
   * row from that and labels it "you", and the row survives into the transcript the UI
   * presents as the record of what was exchanged: a peer could therefore write a line
   * saying this device sent a file it never sent, under a name the peer picked.
   *
   * So: accept a report only for the transfer this side actually started with THIS peer,
   * and take everything except the byte count from our own record of it.
   */
  outboundRow(control) {
    const out = this.outbound;
    // Silently, not as a warning: a late report for a superseded transfer is ordinary.
    if (!out || typeof control.id !== 'string' || control.id !== out.id) return null;
    const claimed = Number(control.bytes ?? control.sent);
    const sent = Number.isFinite(claimed) ? Math.min(Math.max(claimed, 0), out.size) : out.size;
    // `bytes` as well as `sent`: the completion listener reads `bytes`, and without it
    // every finished send was reported to the sender as "(0 B)", including a 157 MB one.
    return { direction: 'out', id: out.id, name: out.name, total: out.size, sent, bytes: sent };
  }

  /** Release sendFile's wait for acceptance. `reason` null means accepted. */
  settleAcceptance(id, reason) {
    const pending = this.pendingAccept;
    if (!pending || id !== pending.id) return;
    this.pendingAccept = null;
    if (reason === null) pending.resolve();
    else pending.reject(new Error(reason));
  }

  // ------------------------------------------------------------ sending

  /** Serialise sends so a file transfer cannot interleave its own frames. */
  enqueue(task) {
    this.sendQueue = this.sendQueue.then(task, task);
    return this.sendQueue;
  }

  get connected() {
    return this.state === STATE.CONNECTED && this.peer?.channel?.readyState === 'open';
  }

  requireConnected() {
    if (this.state !== STATE.CONNECTED) throw new Error('the gate is not connected');
  }

  async sendChat(text) {
    this.requireConnected();
    return this.enqueue(async () => {
      await this.peer.send(await this.channel.seal(TYPE.CHAT, encodeText(text)));
    });
  }

  async sendSecret(text) {
    this.requireConnected();
    return this.enqueue(async () => {
      await this.peer.send(await this.channel.seal(TYPE.SECRET, encodeText(text)));
    });
  }

  // What this side is sending to THIS peer, minus the File, so a reload knows what it was
  // doing. sessionStorage, not IndexedDB: it is tab-scoped, it is discarded when the tab
  // closes, and it holds no file content, only the name, size and fingerprint of the file
  // the user themselves picked in this tab moments ago. Keyed per peer, because a mesh can
  // legitimately be sending a different file to each of them.
  outboundKey() { return `wg.out.${this.session.roomId}.${this.peerId}`; }

  rememberOutboundIntent(out) {
    try {
      globalThis.sessionStorage?.setItem(this.outboundKey(), JSON.stringify({
        id: out.id, name: out.name, size: out.size, mime: out.mime,
        chunkSize: out.chunkSize, fingerprint: out.fingerprint,
      }));
    } catch (err) { this.emit('warning', `could not remember what is being sent: ${err.message}`); }
  }

  recallOutboundIntent() {
    try {
      const raw = globalThis.sessionStorage?.getItem(this.outboundKey());
      return raw ? JSON.parse(raw) : null;
    } catch (err) {
      this.emit('warning', `could not read what this tab was sending: ${err.message}`);
      return null;
    }
  }

  forgetOutboundIntent() {
    try { globalThis.sessionStorage?.removeItem(this.outboundKey()); } catch (err) { void err; }
  }

  /**
   * Send one file to this peer.
   *
   * `id` comes from the caller so that a file fanned out to several peers is ONE row in
   * the transcript rather than one per peer. The guard below is per link, which is the
   * point: one file in flight per peer, never one globally, so a peer on a slow link
   * cannot hold up everybody else's copy.
   */
  async sendFile(file, id, fingerprint) {
    this.requireConnected();
    if (this.outbound?.active) throw new Error('another file is already being sent to this device');
    // Ask the connection how big a frame it will actually carry rather than assuming the
    // 16 KiB floor. At 16 KiB a 30 GiB file is about 1.97 million AEAD seals; at 256 KiB it
    // is about 123 thousand. Fixed for the life of THIS transfer even across a resume: the
    // resume offset is a byte count, so the two sides may not agree on chunk size and it
    // still works, but changing it mid-file buys nothing and complicates the arithmetic.
    const chunkSize = this.peer?.maxChunkBytes(FRAME_OVERHEAD_BYTES, CHUNK_BYTES) ?? CHUNK_BYTES;
    // Kept after the transfer finishes too, because the receiver's file-complete arrives
    // once we have stopped sending; it is replaced when the next transfer starts.
    this.outbound = {
      id,
      name: file.name,
      size: file.size,
      mime: file.type || 'application/octet-stream',
      chunkSize,
      file,
      fingerprint,
      sent: 0,
      chunks: 0,
      active: true,
      stalled: false,
      streaming: false,
      settle: null,
    };
    const out = this.outbound;
    this.rememberOutboundIntent(out);

    // Registered BEFORE the offer goes out: an auto-accepted transfer is accepted the
    // moment FILE_START lands, so a wait created afterwards would miss it and hang.
    const accepted = new Promise((resolve, reject) => {
      this.pendingAccept = { id, resolve, reject };
    });
    // Mark it handled straight away. A refusal can land while FILE_START is still in the
    // send queue, before the await below exists, and that would surface as an unhandled
    // rejection; awaiting it later still sees the rejection.
    accepted.catch(() => {});

    // Settled only by a terminal outcome: the whole file went, or the transfer was refused,
    // denied or burned. A dropped connection does NOT settle it, because a dropped
    // connection is a pause, and the caller waiting is what "keep waiting" means.
    const finished = new Promise((resolve, reject) => { out.settle = { resolve, reject }; });
    finished.catch(() => {});

    try {
      await this.enqueue(async () => {
        // Name, MIME type, size and fingerprint travel inside the ciphertext. The server
        // never sees any of them (DESIGN.md 1.4, section 8).
        await this.peer.send(await this.channel.sealJson(TYPE.FILE_START, {
          id, name: out.name, mime: out.mime, size: out.size, chunkSize: out.chunkSize, fingerprint,
        }));
      });

      // Awaited OUTSIDE the send queue, so chat still flows while the other side decides,
      // and streaming never begins before there is a sink to stream into. Without this
      // the receiver holds chunks in a bounded buffer and drops the whole transfer once
      // it overflows.
      await accepted;

      this.driveOutbound(0);
      return await finished;
    } catch (err) {
      // Refused, or never got off the ground. Either way there is nothing to resume.
      if (this.outbound?.id === id) {
        this.outbound.active = false;
        this.outbound.file = null;
      }
      this.forgetOutboundIntent();
      throw err;
    } finally {
      if (this.pendingAccept?.id === id) this.pendingAccept = null;
    }
  }

  /**
   * Stream the current outbound file from `offset` to the end.
   *
   * Re-entrant by design: it is called once when the transfer starts and again for every
   * resume, always with the offset the RECEIVER asked for. `streaming` is the latch, so a
   * resume that arrives while a previous run is still unwinding cannot double-send.
   *
   * A read error and a send error are handled differently on purpose. A file that cannot
   * be read is terminal: no amount of reconnecting fixes it, and pretending otherwise would
   * leave the receiver waiting on a sender that can never deliver. A send error is a
   * dropped link: keep everything and wait to be told where to continue from.
   */
  driveOutbound(offset) {
    const out = this.outbound;
    if (!out || !out.file || !out.active || out.streaming) return;
    out.streaming = true;
    // Deliberately NOT wrapping the whole loop in enqueue(). Doing so made the send
    // queue exclusive to this transfer for its entire duration, so a chat message typed
    // 16.7 MB into a 157 MB send did not arrive until the transfer finished, 20 seconds
    // later. Each FRAME is enqueued individually instead: that still keeps seal-then-send
    // atomic, which matters because the AEAD counter has to increment in the same order
    // the frames go out or the peer's replay guard rejects them, while letting chat
    // interleave between chunks.
    (async () => {
      const iterator = readChunks(out.file, out.chunkSize, offset)[Symbol.asyncIterator]();
      try {
        for (;;) {
          if (this.severed) throw new Error('gate burned during transfer');
          // Superseded by a newer transfer, or abandoned. Stop without touching anything.
          if (this.outbound !== out || !out.active) return;

          let step;
          try {
            step = await iterator.next();
          } catch (err) {
            this.abandonOutbound(out, `${out.name} could not be read: ${err.message}`);
            return;
          }
          if (step.done) break;

          try {
            await this.enqueue(async () => {
              await this.peer.send(await this.channel.seal(TYPE.FILE_CHUNK, step.value));
            });
          } catch (err) {
            if (this.severed) throw err;
            out.stalled = true;
            this.emit('file-stalled', {
              direction: 'out',
              id: out.id,
              name: out.name,
              sent: out.sent,
              total: out.size,
              message: `Paused after ${formatBytes(out.sent)}: ${err.message}. Waiting to continue.`,
            });
            this.scheduleRestart(`sending ${out.name} was interrupted`);
            return;
          }
          out.sent += step.value.byteLength;
          out.chunks += 1;
          if (out.chunks % 32 === 0) {
            this.emit('file-progress', { direction: 'out', id: out.id, sent: out.sent, total: out.size, name: out.name });
          }
        }

        await this.enqueue(async () => {
          await this.peer.send(await this.channel.sealJson(TYPE.FILE_END, {
            id: out.id, bytes: out.sent, chunks: out.chunks,
          }));
        });
        out.active = false;
        out.file = null;
        this.forgetOutboundIntent();
        this.emit('file-progress', { direction: 'out', id: out.id, sent: out.sent, total: out.size, name: out.name });
        this.emit('file-sent', { id: out.id, name: out.name, size: out.size });
        const settle = out.settle;
        out.settle = null;
        settle?.resolve();
      } catch (err) {
        // Only a burned gate reaches here: everything else is handled above.
        out.active = false;
        out.file = null;
        this.forgetOutboundIntent();
        const settle = out.settle;
        out.settle = null;
        if (settle) settle.reject(err);
        else this.emit('warning', `the transfer ended: ${err.message}`);
      } finally {
        out.streaming = false;
        try { await iterator.return?.(); } catch (err) { void err; }
      }
    })();
  }

  /**
   * Hand the sender its file back after a reload, and continue.
   *
   * This is the single most dangerous entry point in the file: the user is choosing a file
   * to splice onto bytes the other side already holds. serveResume refuses anything whose
   * fingerprint does not match, so a wrong pick restarts rather than corrupts.
   */
  async resumeOutbound(file) {
    const out = this.outbound;
    if (!out || !out.active) throw new Error('there is no paused transfer to continue');
    if (out.file) throw new Error('that transfer already has its file');
    out.file = file;
    const finished = new Promise((resolve, reject) => { out.settle = { resolve, reject }; });
    finished.catch(() => {});
    const served = await this.serveResume(out, Number(out.resumeOffset ?? 0));
    if (!served) {
      // serveResume has already denied, told the peer and settled this one.
      throw new Error(`that is not the file this transfer began with, so ${out.name} has to be sent again from the start`);
    }
    return finished;
  }

  // ------------------------------------------------------------ receiving files

  async onFileStart(meta) {
    if (this.incoming) {
      await this.control({ kind: 'file-reject', id: meta.id, reason: 'another transfer is already in progress' });
      return;
    }
    const verdict = canAccept(meta.size);
    if (!verdict.ok) {
      await this.control({ kind: 'file-reject', id: meta.id, reason: verdict.reason });
      this.emit('file-refused', { ...meta, reason: verdict.reason });
      return;
    }
    // meta.fingerprint is recorded exactly as it arrived and is never recomputed here: it
    // is the receiver's independent record of what the transfer claimed to be at the start,
    // and comparing it to itself later is the whole splice guard. A FILE_START with no
    // fingerprint is still accepted, but compareFingerprints fails closed on a missing one,
    // so such a transfer simply cannot be resumed at an offset.
    this.incoming = {
      meta, received: 0, chunks: 0, sink: null, stalled: false, crossedReload: false, resumes: 0,
    };

    if (meta.size <= AUTO_ACCEPT_BYTES) {
      // No user gesture here, so never try to open a save dialog: straight to memory.
      try {
        this.incoming.sink = await createSink(meta, { preferMemory: true });
        await this.flushEarly(this.incoming);
        await this.rememberInboundRecord(this.incoming);
        await this.control({ kind: 'file-accept', id: meta.id });
        this.emit('file-incoming', meta);
        return;
      } catch (err) {
        this.emit('warning', `could not start receiving ${meta.name}: ${err.message}`);
        this.incoming = null;
        await this.control({ kind: 'file-reject', id: meta.id, reason: err.message });
        return;
      }
    }
    this.emit('file-offered', meta);
  }

  /** Called by the UI, from a user gesture, so showSaveFilePicker is allowed. */
  async acceptIncoming() {
    if (!this.incoming) throw new Error('no incoming file to accept');
    const inbound = this.incoming;
    const { meta } = inbound;
    try {
      inbound.sink = await createSink(meta);
    } catch (err) {
      // Cancelling the save dialog lands here and is an ordinary path, not an anomaly.
      // Leaving this.incoming set with a null sink and saying nothing left the sender
      // streaming into the bounded `early` buffer until the transfer was dropped with
      // no explanation on either side, so tell the peer and clear the state.
      this.incoming = null;
      await this.control({ kind: 'file-reject', id: meta.id, reason: err.message });
      this.emit('file-refused', { ...meta, reason: err.message });
      throw err;
    }
    await this.rememberInboundRecord(inbound);
    await this.control({ kind: 'file-accept', id: meta.id });
    this.emit('file-accepted-local', {
      ...meta,
      sink: inbound.sink.kind,
      note: inbound.sink.note ?? null,
    });
    // Flush what arrived before the sink existed, now, rather than waiting for the next
    // chunk to push it: the last buffered chunk may be the last chunk of the file, and
    // nothing would ever arrive to flush it. Queued behind the inbound frames so a chunk
    // that lands mid-flush cannot overtake the buffered ones.
    await this.enqueueInbound(() => (this.incoming === inbound ? this.flushEarly(inbound) : undefined));
  }

  /** Write anything that arrived before there was a sink, in arrival order. */
  async flushEarly(inbound) {
    if (!inbound?.sink || !inbound.early?.length) return;
    const held = inbound.early;
    inbound.early = null;
    inbound.earlyBytes = 0;
    for (const chunk of held) {
      await inbound.sink.write(chunk);
      inbound.received += chunk.byteLength;
      inbound.chunks += 1;
    }
  }

  // -------------------------------------------- surviving a reload on the receiving side

  /**
   * Record enough about an interrupted incoming transfer to pick it up after a reload.
   *
   * A disk sink stores its FileSystemFileHandle, which is a REFERENCE to the file the user
   * chose, not its contents. A memory sink stores no handle at all and is marked
   * unresumable: the partial data is in this page's heap and a reload destroys it, and the
   * alternative (writing the user's file content into IndexedDB) is exactly the thing this
   * product exists not to do. The record is deleted the moment the transfer ends.
   *
   * `peerId` rides along so a recovered transfer is offered back to the participant that
   * was actually sending it, rather than to whoever happens to connect first.
   */
  async rememberInboundRecord(inbound) {
    if (!this.session.roomId || !inbound?.sink) return;
    try {
      await saveResume(this.session.roomId, {
        roomId: this.session.roomId,
        peerId: this.peerId,
        id: inbound.meta.id,
        meta: inbound.meta,
        received: inbound.sink.position ?? inbound.received,
        chunks: inbound.chunks,
        sinkKind: inbound.sink.kind,
        handle: inbound.sink.handle ?? null,
        savedAt: Date.now(),
      });
    } catch (err) {
      // Not fatal: it only costs the ability to survive a reload, which the user should
      // know about rather than discover later.
      this.emit('warning', `this transfer will not survive a page reload: ${err.message}`);
    }
  }

  async forgetInboundRecord() {
    if (!this.session.roomId) return;
    try { await clearResume(this.session.roomId); } catch (err) { this.emit('warning', `could not clear the resume record: ${err.message}`); }
  }

  /**
   * Adopt a transfer recovered from storage into this link.
   *
   * MUST be called from a user gesture: re-granting write permission on a stored handle
   * prompts, and a prompt outside a gesture is refused.
   */
  async adoptInbound(record) {
    if (this.incoming) throw new Error('another transfer is already in progress');
    // startOffset is a request; the sink clamps it to what the file actually contains,
    // because everything written and not committed before the reload was discarded.
    const sink = await createSink(record.meta, { handle: record.handle, startOffset: record.received });
    const at = sink.position;
    this.incoming = {
      meta: record.meta,
      received: at,
      // Chunks are written whole and the sink commits on a chunk boundary, so this is
      // exact. It is also sent to the sender, which adopts it, so the two cannot diverge.
      chunks: Math.ceil(at / (Number(record.meta.chunkSize) || CHUNK_BYTES)),
      sink,
      stalled: true,
      crossedReload: true,
      resumes: 0,
    };
    await this.rememberInboundRecord(this.incoming);
    this.emit('file-incoming', record.meta);
    this.emit('file-progress', {
      direction: 'in', id: record.meta.id, sent: at, total: record.meta.size, name: record.meta.name,
    });
    if (this.state === STATE.CONNECTED) await this.requestResume(this.incoming);
    return at;
  }

  async onFileChunk(bytes) {
    const inbound = this.incoming;
    if (!inbound) { this.emit('warning', 'received a file chunk with no transfer in progress'); return; }
    if (inbound.stalled) {
      // The sender must not write at an offset this side has not agreed to. Nothing has
      // been agreed until file-resume-ok has been checked, so this drops rather than
      // guesses; the sender restarts from our reported offset either way.
      this.emit('warning', 'ignored a file chunk that arrived before the transfer was resumed');
      return;
    }
    if (!inbound.sink) {
      // Chunks arrived before the user accepted. Hold a bounded amount rather than
      // dropping them, so an eager sender does not corrupt the transfer.
      inbound.early = inbound.early ?? [];
      inbound.earlyBytes = (inbound.earlyBytes ?? 0) + bytes.byteLength;
      if (inbound.earlyBytes > 4 * 1024 * 1024) {
        this.emit('warning', 'sender began before the transfer was accepted; dropping the transfer');
        this.incoming = null;
        return;
      }
      inbound.early.push(bytes);
      return;
    }
    await this.flushEarly(inbound);
    await inbound.sink.write(bytes);
    inbound.received += bytes.byteLength;
    inbound.chunks += 1;
    if (inbound.chunks % 32 === 0) {
      this.emit('file-progress', { direction: 'in', id: inbound.meta.id, sent: inbound.received, total: inbound.meta.size, name: inbound.meta.name });
    }
    // Commit periodically so a reload has something to resume ONTO. Without this the
    // handle stored in IndexedDB points at a file that is still empty, because a
    // FileSystemWritableFileStream only lands on the real file when it is closed.
    if (inbound.sink.wantsCheckpoint) {
      try {
        await inbound.sink.checkpoint();
        await this.rememberInboundRecord(inbound);
      } catch (err) {
        // The write path is already dead if this threw; let onFileEnd's length check
        // report it rather than silently continuing to count bytes into a broken sink.
        this.emit('warning', `could not commit the partial file: ${err.message}`);
      }
    }
  }

  async onFileEnd(end) {
    const inbound = this.incoming;
    if (!inbound) return;
    this.incoming = null;
    if (!inbound.sink) { this.emit('warning', 'transfer ended before it was accepted'); return; }

    // Every chunk was individually authenticated and sequence-bound by the AEAD, so
    // there is no whole-file hash to check (DESIGN.md 1.14). What is worth checking is
    // that we reassembled exactly what was sent AND exactly what was promised.
    //
    // end.bytes is the sender's own running total, so comparing only against it means a
    // truncating read on the sender produces a short file that both ends agree is
    // complete. meta.size came from the File object before any reading happened, so it
    // is the independent number: a mismatch there is a real truncation.
    const declared = Number(inbound.meta?.size);
    const failures = [];
    if (inbound.received !== end.bytes || inbound.chunks !== end.chunks) {
      failures.push(`expected ${end.bytes} bytes in ${end.chunks} chunks, reassembled ${inbound.received} in ${inbound.chunks}`);
    }
    if (!Number.isFinite(declared) || inbound.received !== declared) {
      failures.push(`the file was announced as ${inbound.meta?.size} bytes but ${inbound.received} arrived`);
    }
    if (failures.length) {
      await inbound.sink.abort('length mismatch');
      await this.forgetInboundRecord();
      this.emit('file-failed', { ...inbound.meta, reason: failures.join('; ') });
      return;
    }

    const blob = await inbound.sink.finish();
    // The file is whole and closed, so there is nothing left to resume and the record must
    // not outlive it: a stale handle would offer to continue a transfer that is finished.
    await this.forgetInboundRecord();
    await this.control({ kind: 'file-complete', id: inbound.meta.id, bytes: inbound.received });
    this.emit('file-received', { ...inbound.meta, blob, sink: inbound.sink.kind, human: formatBytes(inbound.received) });
  }

  async control(message) {
    if (!this.channel || !this.peer?.channel || this.peer.channel.readyState !== 'open') return;
    await this.enqueue(async () => {
      await this.peer.send(await this.channel.sealJson(TYPE.CONTROL, message));
    });
  }

  // ------------------------------------------------------------ teardown

  /** Tell this one peer the gate is being burned. Best effort; teardown follows anyway. */
  async sendSever() {
    if (!this.channel || this.peer?.channel?.readyState !== 'open') return;
    await this.peer.send(await this.channel.sealJson(TYPE.CONTROL, { kind: 'sever' }));
  }

  /**
   * Drop every reference to this pair's key material and stop all its timers.
   *
   * The AES keys are non-extractable CryptoKey objects, so their bytes were never in the
   * JS heap; releasing the reference is the strongest erasure a browser offers
   * (DESIGN.md 1.11). Only THIS pair is affected: every other link keeps its own keys,
   * its own counters and its own transfers.
   */
  close(reason) {
    if (this.closed) return;
    this.closed = true;
    this.clearWatchdog();
    this.clearRestartTimer();
    if (this.confirmTimer) { clearTimeout(this.confirmTimer); this.confirmTimer = null; }
    try { this.peer?.close(); } catch (err) { void err; }
    if (this.incoming?.sink) {
      this.incoming.sink.abort(reason ?? 'the link closed').catch(() => {});
    }
    this.forgetOutboundIntent();
    // A send waiting for the peer to accept would otherwise wait for a peer that no
    // longer exists.
    if (this.pendingAccept) {
      const pending = this.pendingAccept;
      this.pendingAccept = null;
      pending.reject(new Error('the gate was burned before the transfer was accepted'));
    }
    if (this.outbound) {
      this.outbound.active = false;
      this.outbound.file = null;
      const settle = this.outbound.settle;
      this.outbound.settle = null;
      // Otherwise sendFile parks forever on a link that no longer exists.
      if (settle) settle.reject(new Error(`the gate was burned during the transfer: ${reason ?? 'closed'}`));
    }
    // Same invariant as resetForRenegotiation: these three go together, always. A closed
    // link that kept its session keys and later built a second Channel over them would
    // restart the frame counter and reuse (key, nonce), which is total loss of
    // confidentiality rather than a weakening. Nothing may reconnect this link; a new one
    // runs a new ECDH from scratch.
    this.sessionKeys = null;
    this.channel = null;
    this.keyPair = null;
    this.peerPublicRaw = null;
    this.incoming = null;
    this.earlyFrames = [];
    this.deriving = null;
    this.peer = null;
    this.state = STATE.SEVERED;
  }
}

/** Read whatever interrupted inbound transfer this room left behind. */
export async function readInboundRecord(roomId) {
  return loadResume(roomId);
}

/** Forget it. Exported so the session can clear it without owning a link. */
export async function dropInboundRecord(roomId) {
  return clearResume(roomId);
}
