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
  generateKeyPair, deriveSession, Channel, commitPublicKey,
  b64u, TYPE, equalCt, decodeJson, decodeText, encodeText, typeName,
} from './crypto.js';
import { Peer } from './peer.js';
import {
  CHUNK_BYTES, readChunkRanges, createSink, primeSink, canAccept, formatBytes,
  fingerprintFile, compareFingerprints, saveResume, listResume, clearResume, clearRoomResume,
} from './transfer.js';
// The frame layout and the chunk arithmetic: needed at module evaluation time and once per
// chunk in the send loop, so static.
import {
  CHUNK_INDEX_BYTES, chunkCount, expectedChunkBytes, frameChunk, unframeChunk,
} from './chunkwire.js';

/**
 * How many bytes of the FILE the sender has covered, indexed by chunk.
 *
 * THE BUG THIS EXISTS FOR, measured on a real 434 MB transfer that arrived perfectly and
 * was then thrown away. `out.sent` used to be a running total of bytes PUSHED, incremented
 * once per chunk sent. A resume rebased it to what the receiver already held and then
 * re-drove the file. When a resume landed while the previous run was still unwinding, the
 * rebase happened anyway (it sits before the `streaming` latch that stops the double
 * send), and the old loop went on adding to the rebased figure. FILE_END then declared
 * 832,087,527 bytes for a 455,030,247 byte file: exactly the 377,057,280 the receiver
 * already had, plus the whole file again. The receiver had every chunk, in the right
 * order, with the right length and the right total, and failed the transfer on the
 * sender's arithmetic alone.
 *
 * Counting coverage per index instead makes the total idempotent: re-sending a chunk adds
 * nothing, because the slot already holds that chunk's length. Overlapping runs, a resume
 * mid-unwind and a re-send of a range the receiver already had all become harmless, which
 * is the property the latch was trying to provide and could not.
 *
 * A Uint32Array rather than a Set or a Map: one slot per chunk, 4 bytes each. A 30 GiB
 * file at the 16 KiB floor is 7.9 MB, and at the 256 KiB a real connection negotiates it
 * is 492 KB. Lengths rather than bits, so the total is a byte count and can be compared
 * with the file's size directly.
 *
 * What it does NOT do, and the comment here used to claim it did: catch a truncating read.
 * readChunkRanges throws on a short read (transfer.js) rather than yielding one, so a short
 * chunk never reaches this map, and abandonOutbound ends the transfer there. That guard is
 * the one to keep; do not delete it believing this replaces it.
 */
function newCoverage(size, chunkSize) {
  return new Uint32Array(chunkCount(size, chunkSize));
}

/**
 * The resume NEGOTIATION half of chunk-level resume, fetched the first time a transfer
 * needs it.
 *
 * 22 KB of ledger, indexed sink, token and control-message handling that nothing can reach
 * until a file has been offered in one direction or the other. Keeping it off the static
 * graph is what took the gate back under its byte budget after this session's work; see the
 * header of chunkwire.js for why the split falls where it does.
 *
 * Every consumer below takes the loaded namespace as an explicit argument rather than
 * reading a module-level cache. That is deliberate: adoptSink() runs immediately after a
 * check that `this.incoming` is still the transfer it was called for, and putting an await
 * between the two would open a window, however small, in which a dropped connection could
 * swap the transfer under it. Passing the namespace in keeps every one of those consumers
 * synchronous and makes it impossible to call one before the module is there.
 */
let resumeMod = null;
function loadResume() {
  // Not `await import()` in an async function: returning the same promise means N
  // concurrent transfers share one fetch instead of racing to assign the cache.
  if (!resumeMod) {
    resumeMod = import('./resume.js').catch((err) => {
      // Cleared so a transient failure is retried by the next transfer rather than
      // poisoning resume for the rest of the session.
      resumeMod = null;
      throw new Error(`could not load the resume machinery: ${err.message}`);
    });
  }
  return resumeMod;
}

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
// How long the responder waits for the initiator to REVEAL the public key it committed to.
//
// The commitment splits what used to be one message into two, and every added wait is a
// new way to deadlock: a peer that sends {t:'pkc'} and then nothing at all would otherwise
// leave this side holding a key pair, a commitment and no route out, because none of the
// existing timers watch that window. The watchdog does not cover it either: it reports an
// unreachable PEER, and a peer that is demonstrably talking to us is not that.
//
// Same size as CONFIRM_TIMEOUT_MS on purpose. It is the same kind of wait (a specific
// message from a peer that has already proved it can reach us) and the same kind of
// answer (say what did not arrive, and stop), so two different numbers would only be two
// different things to explain.
const REVEAL_TIMEOUT_MS = CONFIRM_TIMEOUT_MS;

// How many times a handshake timeout may be forgiven for having elapsed while this page
// was not running. Three, so a user who taps through two or three apps mid-handshake is
// not punished for it, and a peer that is genuinely absent still fails in bounded time
// rather than never.
const BACKGROUND_GRACE_MAX = 3;

// ------------------------------------------------- was this page even awake to hear it?
//
// A handshake timeout is evidence of one specific thing: the other device did not answer
// WITHIN the window. That inference is only sound if this page was running for the
// window. It was not, on the case that made this necessary: a phone freezes the tab
// behind the OS file picker or behind a tap into another app, every pending setTimeout
// lands in a heap the moment it thaws, and the two auth timers below then declared
// AUTH_FAILED, which unlike every other failure path here does NOT call holdOpen or
// scheduleRestart. The link was left terminal with only a log line, and the gate never
// came back.
//
// So the deadlines are still deadlines, but they are only counted against a page that was
// present to observe them. `document.visibilityState` is the only signal available for
// this: the Page Lifecycle `freeze` event is Chromium-only and is not delivered at all in
// the case that matters most, an iOS tab suspended behind the picker.
//
// Guarded on `document` because this module is also loaded by the node test suites, where
// there is no document and nothing is ever backgrounded.
let lastVisibleAt = Date.now();
if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') lastVisibleAt = Date.now();
  });
}

/**
 * Was this page out of the foreground at any point in the last `ms` milliseconds?
 *
 * Hidden right now counts, and so does having become visible only moments ago: a timer
 * that fires immediately on thaw is exactly the one whose window this page slept through.
 */
function sleptThrough(ms) {
  if (typeof document === 'undefined') return false;
  if (document.visibilityState !== 'visible') return true;
  return Date.now() - lastVisibleAt < ms;
}

// Anything at or below this is accepted without asking. Pasting an image should feel
// like sending a message, not like agreeing to a download. Larger transfers still ask,
// which is also what lets the receiver choose a save location.
const AUTO_ACCEPT_BYTES = 10 * 1024 * 1024;
// How much a sender may run ahead of the accept before this side gives up holding it. The
// buffer exists because chunks can arrive while the save dialog is open; it is bounded
// because those bytes are in this page's memory and nothing has agreed to take them yet.
const EARLY_LIMIT_BYTES = 4 * 1024 * 1024;
// The largest game message this side will look at. A chess move serialises to a few dozen
// bytes and the longest thing a game sends is a starting position, so this is generous by
// two orders of magnitude and still small enough that a peer cannot use the game channel
// as a way to make this page allocate.
const GAME_MESSAGE_LIMIT = 4096;
// The most files one batch offer may name. Two bounds in one number: what a single click
// may consent to, which is the security property the grant exists for, and how many
// peer-chosen names one message may put on screen. A sender with more files announces a
// second batch, which gets its own row and its own click.
export const MAX_BATCH_FILES = 64;
// The only shape a batch id may have: base64url of the 8 random bytes the sender mints.
// Checked as a charset and not just a length because this string is used as a key and put
// into an element id by the UI. Both ends are this codebase, so nothing legitimate is
// excluded and a peer cannot smuggle whitespace or markup through it.
const BATCH_ID_SHAPE = /^[A-Za-z0-9_-]{1,64}$/;
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
// How long an accepted transfer may go without a single chunk before the receiver says so.
//
// peer.js has DRAIN_TIMEOUT_MS for the sending side and there was no counterpart here, so a
// sender that stopped sending WITHOUT the channel closing was invisible: a phone whose
// screen locks or whose tab is backgrounded stops feeding the data channel while the
// connection stays up, and the receiver sat at 0% forever with nothing on screen to read.
//
// Longer than peer.js's 30s on purpose. This one accuses the other device of having gone
// quiet, and a receiver that cries stall while the sender is merely slow is worse than
// silence. It is also only a message: nothing is aborted, because the resume design says a
// quiet link is a pause and not an end.
const INBOUND_QUIET_MS = 45_000;
// What one sealed frame costs on the wire beyond its plaintext: the 10-byte header
// (version, type, 64-bit counter), the 16-byte AES-GCM tag, and the 4-byte chunk index that
// now rides inside the sealed plaintext. Subtracted from the SCTP maximum message size,
// because a message over that limit is rejected outright. The index has to come out of the
// payload budget for the same reason: a chunk sized to the SCTP maximum without counting it
// is four bytes too long and the send fails rather than being fragmented.
const FRAME_OVERHEAD_BYTES = 10 + 16 + CHUNK_INDEX_BYTES;
// Frames held while the key schedule is still running. Small: the only thing that can
// legitimately arrive in that window is the peer's key confirmation.
const MAX_EARLY_FRAMES = 16;
// How many chunks may be held while the accept dialog is open, counted as ENTRIES rather
// than as bytes.
//
// EARLY_LIMIT_BYTES on its own was not a bound at all. A chunk frame's plaintext was
// allowed to be exactly the four index bytes and no body, so its payload counted zero
// against the byte limit while still costing about 100 bytes of heap for the {index, bytes}
// entry and the array slot: earlyBytes stayed at 0 for ever and the array grew until the
// tab died, at 30 bytes per frame on the wire, while a save dialog sat on screen. Zero
// length is now refused in unframeChunk, which closes the free case, and this closes the
// cheap one: a one-byte body would otherwise still buy four million entries inside 4 MiB.
//
// 1024 is generous rather than tight. A sender running ahead at the 16 KiB chunk floor
// fills EARLY_LIMIT_BYTES with 256 entries and at a negotiated 256 KiB with 16, so no
// legitimate transfer comes near this, and 1024 entries is about 100 KiB of bookkeeping.
// resume.js's MAX_AHEAD_CHUNKS is the same idea for the post-accept buffer and caps both
// count and bytes for exactly this reason.
const MAX_EARLY_CHUNKS = 1024;

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

/**
 * The whole file as one chunk range, and NO ranges at all when the file is empty.
 *
 * A zero-byte file is a legal transfer: canAccept takes it and the old byte-offset path
 * streamed it as zero chunks without noticing. `[[0, 0]]` is not the same thing: an empty
 * range is rejected by readChunkRanges, correctly, because a range that covers nothing is
 * how a sender declares a file complete it never read. So an empty file gets an empty list
 * and goes straight to FILE_END, which is what the receiver's ledger already expects.
 */
const wholeFileRanges = (size, chunkSize) => {
  const total = chunkCount(size, chunkSize);
  return total > 0 ? [[0, total]] : [];
};

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
    // Commit-then-reveal state. See crypto.js commitPublicKey for the attack.
    //
    //   initiator: {t:'pkc', h}  ->
    //                            <-  {t:'pk', pk: pk_B}       responder
    //   initiator: {t:'pk', pk: pk_A} ->                      checked against h
    //
    // peerCommitment is what the RESPONDER holds between those two messages: the digest it
    // must check the reveal against. pkSent latches our own reveal so neither side can be
    // made to send its public key twice under one commitment.
    this.peerCommitment = null;
    this.pkSent = false;
    this.revealTimer = null;
    this.sessionKeys = null;
    this.confirmedByPeer = false;
    this.confirmSent = false;
    this.confirmTimer = null;
    this.incoming = null;
    // {batch, count, bytes, names}: a batch the peer ANNOUNCED and this side has not agreed
    // to. Holds no consent at all, it is only what the UI draws one row from. Cleared when
    // it is accepted or refused and on close, so a batch nobody answered leaves nothing
    // behind for a later transfer to inherit.
    this.pendingBatch = null;
    // {batch, files, bytes, directory}: a batch the user HAS agreed to, and the two counters
    // that bound the agreement. Both are spent down per file and the whole grant is dropped
    // when either runs out, so one click never becomes permission for the next forty files
    // or the next four gigabytes.
    this.batchGrant = null;
    // The id of the last batch this side said Refuse to. One string, replaced by the next
    // announcement: a latch, not a growing list of grudges.
    this.refusedBatch = null;
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
    // How many times each handshake deadline has been forgiven for elapsing while this
    // page was in the background. Bounded by BACKGROUND_GRACE_MAX so a peer that is truly
    // absent still fails, just not because the user changed apps. See sleptThrough().
    this.revealGrace = 0;
    this.confirmGrace = 0;
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
    this.clearRevealTimer();
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
    // The commitment belonged to the key pair that just died. Carrying it into the fresh
    // handshake would check the NEW reveal against the OLD digest and abort every
    // renegotiation as an attack; dropping it without dropping pkSent would let the fresh
    // pk go out with nothing committed to it, which is the whole hole back again. They go
    // together, like the key pair and the session keys above.
    this.peerCommitment = null;
    this.pkSent = false;
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
      // Either way this transfer stops being watched for quiet. A dropped channel is
      // already explained by markTransfersStalled, and leaving the timer running would
      // land a second, worse account of the same event 45 seconds later.
      this.clearInboundQuiet(this.incoming);
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
  /**
   * Start (or restart) the receiver's quiet timer for an accepted transfer.
   *
   * Called on every arriving chunk, including a duplicate one: a duplicate is not progress
   * but it IS proof the other device is still sending, which is the only thing this timer
   * asks about.
   */
  armInboundQuiet(inbound) {
    if (!inbound?.sink) return;
    this.clearInboundQuiet(inbound);
    inbound.quietTimer = setTimeout(() => {
      inbound.quietTimer = null;
      // Two ways to already know: the transfer moved on, or the channel dropped and
      // markTransfersStalled has already said so in better words. Neither needs a second
      // message from here.
      if (this.incoming !== inbound || inbound.stalled || inbound.quietWarned) return;
      // Deliberately NOT `inbound.stalled`. That flag means "an offset has to be agreed
      // before another byte may be written", and onFileChunk DROPS chunks while it is set.
      // A sender that is merely slow is still sending at the offset we last agreed, so
      // setting it here would turn a warning about quiet into the thing that breaks the
      // transfer it was warning about. This flag only governs what has been said.
      inbound.quietWarned = true;
      this.emit('file-stalled', {
        direction: 'in',
        id: inbound.meta.id,
        name: inbound.meta.name,
        sent: inbound.received,
        total: inbound.meta.size,
        message: `Nothing has arrived for ${Math.round(INBOUND_QUIET_MS / 1000)} seconds, stopped at `
          + `${formatBytes(inbound.received)} of ${formatBytes(inbound.meta.size)}. The other device may `
          + 'have locked its screen or switched away from this page. It continues on its own if they '
          + 'come back.',
      });
    }, INBOUND_QUIET_MS);
  }

  /** Stop the quiet timer. Safe to call on an inbound that never had one. */
  clearInboundQuiet(inbound) {
    if (inbound?.quietTimer) {
      clearTimeout(inbound.quietTimer);
      inbound.quietTimer = null;
    }
  }

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
   * The page is back in front of the user. Retry NOW, not at the back of the backoff.
   *
   * THE BUG THIS EXISTS FOR. On a phone, tapping Attach opens the OS file picker and the
   * browser freezes the tab behind it. Both mobile engines reclaim an
   * `RTCPeerConnection` from a frozen tab, so by the time the picker returns the link is
   * down and scheduleRestart() has been through several rounds: 2s, 4s, 8s, 16s, 30s. The
   * `change` event from the picker, meanwhile, fires the instant the user taps Done. It
   * therefore arrived at a link that was still up to thirty seconds away from its next
   * attempt, requireConnected() threw, and the send failed for what looked to the user
   * like no reason at all: they had picked the files and the gate said it was not
   * connected.
   *
   * The backoff itself is right. What was wrong was applying it to a tab that had just
   * been given back the foreground, which is the strongest possible signal that the
   * network situation has changed. So: cancel the pending timer, put the backoff back to
   * zero, and go. If this attempt fails, scheduleRestart takes over again from the
   * beginning, which is what should happen after a genuine change of circumstances.
   *
   * Idempotent and cheap: a connected link returns immediately, so wiring this to every
   * visibilitychange costs nothing on the overwhelmingly common path.
   */
  wake(reason) {
    if (this.severed) return false;
    if (this.state === STATE.CONNECTED && this.peer?.channel?.readyState === 'open') return false;
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }
    this.restartAttempt = 0;
    this.emit('warning', `${reason}: trying the connection again now.`);
    this.restartConnection().catch((err) => {
      if (targetIsGone(err)) { this.session.onLinkTargetGone(this); return; }
      this.emit('warning', `could not reconnect: ${err.message}`);
      this.scheduleRestart('the reconnect attempt failed');
    });
    return true;
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
    if (!inbound.token) {
      // No token means no sink was ever created for this transfer, so there is nothing on
      // this side to continue and nothing the sender may splice onto.
      await this.failInbound(inbound, 'this transfer was never accepted here, so it cannot be continued');
      return;
    }
    const R = await loadResume();
    await this.control(R.buildResumeRequest({
      id: inbound.meta.id,
      token: inbound.token,
      indexed: inbound.sink,
      fingerprint: inbound.meta.fingerprint ?? null,
      crossedReload: Boolean(inbound.crossedReload),
    }));
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
      // COMMIT-THEN-REVEAL. The initiator publishes only a digest of its public key here;
      // the key itself does not go out until the responder's key has arrived. The
      // responder sends nothing at all until it holds that digest. crypto.js
      // commitPublicKey has the attack this ordering exists to stop.
      if (this.initiator) {
        await this.signal.send({ t: 'pkc', h: b64u.encode(await commitPublicKey(this.keyPair.publicRaw)) });
      }
      // Whichever half of the exchange this side is now owed may already have arrived:
      // onSignalMessage stored it and returned without acting, because we had no key pair
      // of our own yet. Both of these are idempotent and cover that ordering.
      await this.maybeSendPublicKey();
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

  // ------------------------------------------------- commit, then reveal

  clearRevealTimer() {
    if (this.revealTimer) { clearTimeout(this.revealTimer); this.revealTimer = null; }
  }

  /**
   * Start the clock on the initiator's reveal. Responder only.
   *
   * The initiator is never waiting on a second message from the responder, so it has
   * nothing to time here; the existing watchdog already covers "the peer said nothing at
   * all", which is the only wait the initiator has.
   */
  armRevealTimer() {
    this.clearRevealTimer();
    if (this.peerPublicRaw || this.severed) return;
    this.revealTimer = setTimeout(() => {
      this.revealTimer = null;
      if (this.peerPublicRaw || this.severed || this.sessionKeys) return;
      // This page was asleep for some of that window, so nothing has been proved about
      // the other device. Serve the sentence again rather than convicting on it.
      if (sleptThrough(REVEAL_TIMEOUT_MS) && this.revealGrace < BACKGROUND_GRACE_MAX) {
        this.revealGrace += 1;
        this.emit('warning', 'this page was in the background while waiting for the key: waiting again.');
        this.armRevealTimer();
        return;
      }
      this.setState(STATE.AUTH_FAILED, 'the other device committed to a key and never revealed it');
      this.emit('auth-failed',
        'The other device promised a key and never sent it, so this gate could not be verified. '
        + 'Nothing was exchanged.');
    }, REVEAL_TIMEOUT_MS);
  }

  /**
   * Send our own public key, once, and only when it is this side's turn.
   *
   * Idempotent and order-independent, because the two inputs it waits on (our key pair,
   * and whichever half of the peer's exchange we are owed) can land in either order:
   * generateKeyPair() takes two awaits and a relayed message can arrive inside that window.
   */
  async maybeSendPublicKey() {
    if (this.pkSent || this.severed || !this.keyPair) return;
    // The initiator reveals only once the responder's key is in hand; the responder speaks
    // only once the initiator's commitment is in hand. Neither may go first, and that is
    // the whole security property: see crypto.js commitPublicKey.
    if (this.initiator ? !this.peerPublicRaw : !this.peerCommitment) return;
    this.pkSent = true;
    try {
      await this.signal.send({ t: 'pk', pk: b64u.encode(this.keyPair.publicRaw) });
    } catch (err) {
      // Nothing was revealed, so this must stay retryable: latching pkSent on a failed
      // relay would wedge the handshake with a key neither side ever received.
      this.pkSent = false;
      throw err;
    }
    if (!this.initiator) this.armRevealTimer();
  }

  /**
   * Stop the key exchange because something about it was not honest, and say what.
   *
   * Severs, exactly as a key confirmation mismatch does. A commitment that does not open
   * is not a fault to retry around: it is the signature of somebody sitting between the
   * two devices, and continuing would hand them a session.
   */
  async failKeyExchange(detail, human) {
    this.clearRevealTimer();
    this.setState(STATE.AUTH_FAILED, detail);
    this.emit('auth-failed', human);
    await this.session.sever();
  }

  /** A decrypted signalling message addressed to this link. */
  async onSignalMessage(message) {
    if (!message || typeof message.t !== 'string') return;
    if (message.t === 'pkc') {
      // Only the responder is ever owed a commitment. An initiator that receives one is
      // either talking to a build that disagrees about who offers, or to something trying
      // to invert the roles so that IT is the side allowed to see a key before binding
      // itself to one. Neither is a message to act on.
      if (this.initiator) {
        this.emit('warning', 'ignored a key commitment from the device that is meant to be answering');
        return;
      }
      // First commitment wins, for the same reason the first public key used to: a second
      // one is either a replay or an attempt to re-aim a handshake already under way.
      if (this.peerCommitment) return;
      let digest = null;
      try {
        if (typeof message.h !== 'string') throw new Error('no commitment value was sent');
        digest = b64u.decode(message.h);
      } catch (err) {
        await this.failKeyExchange(
          `malformed key commitment: ${err.message}`,
          `The other device sent a key commitment this device could not read (${err.message}). `
          + 'The gate was not opened.',
        );
        return;
      }
      // SHA-256 is 32 bytes. A commitment of any other length cannot be the digest it
      // claims to be, and accepting one would mean comparing against something that can
      // never match, which reads as a timeout rather than as the refusal it is.
      if (digest.length !== 32) {
        await this.failKeyExchange(
          `key commitment was ${digest.length} bytes, not 32`,
          'The other device sent a key commitment of the wrong size. The gate was not opened.',
        );
        return;
      }
      this.peerCommitment = digest;
      await this.maybeSendPublicKey();
      return;
    }
    if (message.t === 'pk') {
      if (this.peerPublicRaw) return;
      let offered = null;
      try {
        if (typeof message.pk !== 'string') throw new Error('no public key was sent');
        offered = b64u.decode(message.pk);
      } catch (err) {
        await this.failKeyExchange(
          `malformed public key: ${err.message}`,
          `The other device sent a public key this device could not read (${err.message}). `
          + 'The gate was not opened.',
        );
        return;
      }
      // THE CHECK. Only the responder holds a commitment, and only because only the
      // initiator has to be bound: the responder answers before it has ever seen the
      // initiator's key, so it has nothing to grind against and nothing to commit to.
      // Binding the one side that COULD choose after seeing the other is what collapses
      // the birthday search (crypto.js commitPublicKey) to a single blind guess.
      if (!this.initiator) {
        if (!this.peerCommitment) {
          await this.failKeyExchange(
            'the peer sent a public key with no commitment in front of it',
            'The other device sent its key without first committing to it, which is what an attempt to '
            + 'sit between these two devices looks like. The gate was not opened.',
          );
          return;
        }
        let got = null;
        try {
          got = await commitPublicKey(offered);
        } catch (err) {
          await this.failKeyExchange(
            `could not check the key against its commitment: ${err.message}`,
            `The other device sent a key that is not a usable public key (${err.message}). `
            + 'The gate was not opened.',
          );
          return;
        }
        if (!equalCt(got, this.peerCommitment)) {
          await this.failKeyExchange(
            'the revealed public key does not match the commitment',
            'The other device revealed a different key from the one it committed to. Somebody is '
            + 'sitting between these two devices. The gate was not opened and nothing was sent.',
          );
          return;
        }
      }
      this.clearRevealTimer();
      this.peerPublicRaw = offered;
      // The initiator owes its own reveal now that the responder's key has arrived.
      await this.maybeSendPublicKey();
      await this.deriveKeys();
      return;
    }
    if (message.t === 'sever') {
      this.session.teardown('The other device burned the gate.');
      return;
    }
    if (message.t === 'restart') {
      // The SAME settle guard restartConnection has, which this path did not: a handshake
      // that started moments ago has not had a chance to succeed yet, and tearing it down
      // throws away a key pair the peer may be in the middle of answering. Self-initiated
      // restarts were guarded and peer-initiated ones were not, so a peer that repeated
      // 'restart' drove an unbounded renegotiation loop through here, and after R2 that is
      // a message only the genuine peer can send but still one it can send repeatedly.
      //
      // Deferred rather than dropped, exactly as restartConnection defers it: the request
      // may be the only thing that gets this link moving again, so it is re-armed behind
      // the backoff instead of being thrown away.
      if (Date.now() - (this.lastRenegotiationAt ?? 0) < RESTART_SETTLE_MS) {
        this.scheduleRestart('a handshake is already in progress');
        return;
      }
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
    // Named and re-armed by name. `arguments.callee` would be the obvious way to say
    // "run me again" and it is a SyntaxError here: this is an ES module, so strict mode
    // is not optional.
    const onConfirmTimeout = () => {
      if (this.confirmedByPeer) return;
      // Same reasoning as armRevealTimer: a deadline this page slept through says nothing
      // about the peer. See sleptThrough() for why AUTH_FAILED in particular must not be
      // reached this way.
      if (sleptThrough(CONFIRM_TIMEOUT_MS) && this.confirmGrace < BACKGROUND_GRACE_MAX) {
        this.confirmGrace += 1;
        this.emit('warning', 'this page was in the background while waiting for confirmation: waiting again.');
        this.confirmTimer = setTimeout(onConfirmTimeout, CONFIRM_TIMEOUT_MS);
        return;
      }
      this.setState(STATE.AUTH_FAILED, 'The other device did not confirm the shared secret in time.');
      this.emit('auth-failed', 'No key confirmation received. The other device may not have the same link.');
    };
    this.confirmTimer = setTimeout(onConfirmTimeout, CONFIRM_TIMEOUT_MS);
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
    // NOTHING but CONTROL may be acted on before the peer has proved it holds the same key
    // schedule. The send side has always been gated (requireConnected), the receive side
    // was not, so a peer that had opened a data channel and never completed the key
    // confirmation could push chat, secrets and file offers straight into this session:
    // the frames authenticate, because a peer that got this far agreed a session, but
    // agreeing a session is not the same as having proved it holds the room secret.
    //
    // Per branch and not at function entry, because CONTROL carries the confirmation
    // itself and a gate at the top would refuse the one frame that opens the gate.
    // onControl gates its own remaining branches for the same reason, one step further in.
    if (type !== TYPE.CONTROL && !this.confirmedByPeer) {
      this.emit('warning', `ignored a ${typeName(type)} frame that arrived before the other device confirmed the shared secret`);
      return undefined;
    }
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
    // Everything from here down is an ordinary capability, not part of the key exchange, so
    // it waits for the confirmation exactly as the non-CONTROL frame types do. `sever` is
    // deliberately BELOW this line and not above it: a peer that has not proved it holds
    // the room secret must not be able to end this device's gate, and a game invite rides
    // this channel too, so an ungated CONTROL would have left both of those open.
    if (!this.confirmedByPeer) {
      this.emit('warning',
        `ignored a "${control.kind}" message that arrived before the other device confirmed the shared secret`);
      return;
    }
    if (control.kind === 'sever') { this.session.teardown('The other device burned the gate.'); return; }
    if (control.kind === 'file-batch') { this.onBatchOffer(control); return; }
    if (control.kind === 'file-accept' || control.kind === 'file-reject') {
      const out = this.outbound;
      if (!out || control.id !== out.id) {
        this.emit('warning', `ignored a ${control.kind} for a transfer this device did not start`);
        return;
      }
      if (control.kind === 'file-accept') {
        // The receiver minted this when it created its sink. It names this transfer
        // INSTANCE, where the id only names the file and is shared across every peer in a
        // fan-out, and every later resume has to echo it.
        out.resumeToken = typeof control.token === 'string' ? control.token : null;
        this.rememberOutboundIntent(out);
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
    if (control.kind === 'game') {
      // Games ride the control channel rather than a frame type of their own: a move is a
      // few bytes and a new frame type would need its own counter, its own size rules and
      // its own place in the resume protocol for no gain.
      //
      // Nothing here understands the rules, on purpose. This is the other device's word
      // about what it did, so it is passed up as data and the game layer validates it
      // against its own engine before anything changes. A link that knew the rules would
      // be a second implementation of them, and the two would drift.
      const payload = control.payload;
      if (!payload || typeof payload !== 'object' || typeof payload.t !== 'string') {
        this.emit('warning', 'ignored a malformed game message');
        return;
      }
      // A move is tens of bytes. Anything approaching this is not a game, and the cost of
      // finding out is a JSON.stringify of something the peer chose the size of, so the
      // cheap length check comes first.
      if (JSON.stringify(payload).length > GAME_MESSAGE_LIMIT) {
        this.emit('warning', 'ignored an oversized game message');
        return;
      }
      this.emit('game', payload);
      return;
    }
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
    // Loaded before the first refusal rather than beside the first use: every path out of
    // this method either sends a resume control message or denies with the frozen refusal,
    // and both are this module's.
    const R = await loadResume();
    const id = typeof control.id === 'string' ? control.id : null;
    if (!id) {
      await this.control({
        kind: 'file-resume-deny', id: '', code: 'bad_request',
        reason: 'the request to continue the transfer was malformed',
      });
      return;
    }

    let out = this.outbound;
    // Whether `out` is a live transfer or a shell rebuilt from sessionStorage. A rebuilt one
    // is deliberately not installed as this.outbound until the request has been accepted.
    let recovered = false;
    if (!out || out.id !== id || !out.active) {
      // Our page may have reloaded. The File itself cannot survive that, but what the
      // transfer WAS survives, which is enough to ask the user for the file again.
      const intent = this.recallOutboundIntent();
      if (!intent || intent.id !== id) {
        await this.control({ kind: 'file-resume-deny', id, code: R.RESUME_REFUSED.code, reason: R.RESUME_REFUSED.reason });
        return;
      }
      out = {
        ...intent,
        file: null,
        sent: 0,
        chunks: 0,
        active: true,
        stalled: true,
        streaming: false,
        settle: null,
      };
      recovered = true;
    }

    // Every check on the peer's numbers lives in planResumeResponse: the token, the range
    // list, and the agreement between the byte count and the ranges. It refuses with the
    // one frozen message for anything that could tell the peer which state this side is in.
    const plan = R.planResumeResponse(control, {
      id, size: out.size, chunkSize: out.chunkSize, token: out.resumeToken ?? null,
    });
    if (!plan.ok) {
      // The refusal goes out BEFORE a recovered intent is installed, and a refused request
      // therefore leaves no mark on this side at all. A frozen refusal that still moved this
      // device into "sending that file again" would say by its effect what it refused to say
      // in its text, and the next request would get a different answer.
      await this.control({ kind: 'file-resume-deny', id, code: plan.code, reason: plan.reason });
      return;
    }
    if (recovered) this.outbound = out;

    out.resumeOffset = plan.offset;
    out.resumeRanges = plan.ranges;
    out.resumeBytes = plan.bytes;
    out.peerFingerprint = control.fingerprint ?? null;

    if (!out.file) {
      await this.control({
        kind: 'file-resume-wait', id, code: 'needs_reselect',
        reason: 'the sending device reloaded and has to be given the file again',
      });
      this.emit('file-reselect-needed', { id, name: out.name, size: out.size, received: plan.offset });
      return;
    }

    await this.serveResume(out, plan.offset, plan.ranges, plan.bytes);
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
  async serveResume(out, offset, ranges, remaining) {
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

    // What the receiver already holds, so the running total still ends at the file's size.
    // Nothing is adopted from the peer's own counter: `remaining` came from ranges this
    // side validated, and FILE_END's chunk count is derived from the size and chunk size
    // fixed at FILE_START. Be honest about what the seeded slots are: for a chunk this run
    // never reads, the length written here comes from the declared size, not from the
    // disk. It is the only figure available, the receiver's own size check is the
    // independent guard, and the receiver's indexed sink refuses a wrong-length chunk on
    // arrival, so it can never report holding one that is short.
    //
    // Seeded into the coverage map rather than assigned to the total. The old line set
    // `out.sent` directly, which was correct only if nothing was still sending: this runs
    // BEFORE driveOutbound consults its `streaming` latch, so a resume arriving while the
    // previous run was still unwinding rebased the figure and then let that run keep
    // adding to it. Marking the chunks the receiver already has as covered gets the same
    // starting total and stays right no matter how the two runs overlap, because every
    // chunk can only ever contribute its own length once.
    // Seeding ADDS what the receiver reports it already holds. It never takes coverage
    // away, and that distinction cost a test: replacing the map wholesale also erased the
    // chunks the still-running send had already pushed, so a resume asking for a range the
    // old loop had passed under-declared by exactly those chunks. Coverage is a record of
    // what was actually read and sent; only a read can write it, and only upwards.
    const total = chunkCount(out.size, out.chunkSize);
    if (!out.coverage || out.coverage.length !== total) out.coverage = newCoverage(out.size, out.chunkSize);
    const wanted = new Uint8Array(total);
    for (const [from, to] of ranges) {
      for (let i = from; i < to && i < total; i += 1) wanted[i] = 1;
    }
    let covered = 0;
    for (let i = 0; i < total; i += 1) {
      // Outside the requested ranges the receiver has the chunk, so it counts at its full
      // length. Inside them it counts only for what this side has actually read, which is
      // how a truncating read still shows up as a shortfall at FILE_END.
      if (!wanted[i]) out.coverage[i] = expectedChunkBytes(i, out.chunkSize, out.size);
      covered += out.coverage[i];
    }
    out.sent = covered;
    // A per-run counter now, used only to throttle progress events. The count that goes on
    // the wire at FILE_END is derived from the file, not counted from this run.
    out.chunks = 0;
    out.stalled = false;
    out.fingerprint = fresh;
    await this.control({
      kind: 'file-resume-ok', id: out.id, token: out.resumeToken ?? null, offset, ranges, fingerprint: fresh,
    });
    this.emit('file-resumed', {
      direction: 'out', id: out.id, name: out.name, offset, total: out.size,
    });
    this.driveOutbound(ranges);
    return true;
  }

  /** RECEIVER side. The sender is about to continue; check it before accepting a byte. */
  async onResumeAccepted(control) {
    const R = await loadResume();
    const inbound = this.incoming;
    // Everything that could distinguish "no such transfer" from "wrong token" answers with
    // one frozen refusal, and this side sends NOTHING back for it: a reply is itself a
    // signal, and a resume offer must not be usable to probe what this device holds.
    const verdict = R.judgeResumeResponse(inbound, control);
    if (!verdict.ok) {
      if (verdict.code === R.RESUME_REFUSED.code) return;
      await this.control({ kind: 'file-resume-deny', id: control.id, code: verdict.code, reason: verdict.reason });
      await this.failInbound(inbound, verdict.reason);
      return;
    }
    const offset = verdict.offset;

    // The second half of the splice guard: the sender proved the file to itself, and now
    // it has to prove it to the side that holds the partial copy.
    const sameFile = compareFingerprints(inbound.meta.fingerprint ?? null, control.fingerprint ?? null);
    if (!sameFile.ok) {
      await this.control({
        kind: 'file-resume-deny', id: control.id, code: 'fingerprint_mismatch', reason: sameFile.reason,
      });
      await this.failInbound(inbound, `refused to continue: ${sameFile.reason}`);
      return;
    }

    inbound.stalled = false;
    inbound.crossedReload = false;
    inbound.resumes = (inbound.resumes ?? 0) + 1;
    // Chunks are about to start again, so the quiet clock starts again with them. Without
    // this a resumed transfer runs with no watchdog at all: the timer was cleared when the
    // link dropped and only an arriving chunk re-arms it, which is the one thing a sender
    // that goes quiet immediately after resuming never does.
    inbound.quietWarned = false;
    this.armInboundQuiet(inbound);
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
    this.clearInboundQuiet(inbound);
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
        // Without this a sender that reloaded could not recognise its own receiver's
        // resume, and every reload would restart the file rather than continue it. It is
        // not a secret against this peer: the peer is the party that minted it.
        resumeToken: out.resumeToken ?? null,
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
   *
   * `batch` names the announcement this file belongs to, and is null for a single-file
   * send. Null is not sent: see the FILE_START below.
   */
  async sendFile(file, id, fingerprint, batch = null) {
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
      // Byte coverage of the file, per chunk index. `sent` is its running sum, so the two
      // are updated together in driveOutbound and nowhere else.
      coverage: newCoverage(file.size, chunkSize),
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
        const start = {
          id, name: out.name, mime: out.mime, size: out.size, chunkSize: out.chunkSize, fingerprint,
        };
        // ADDED, never written as `batch: null`. A single-file send has to put exactly the
        // bytes on the wire it always did, so the one-file path is unchanged rather than
        // merely equivalent.
        if (batch) start.batch = batch;
        await this.peer.send(await this.channel.sealJson(TYPE.FILE_START, start));
      });

      // Awaited OUTSIDE the send queue, so chat still flows while the other side decides,
      // and streaming never begins before there is a sink to stream into. Without this
      // the receiver holds chunks in a bounded buffer and drops the whole transfer once
      // it overflows.
      await accepted;

      this.driveOutbound(wholeFileRanges(out.size, out.chunkSize));
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
   * Stream the chunk RANGES the receiver asked for, in order.
   *
   * Was a single byte offset, which can only express a suffix. A receiver that holds 0 to 4
   * and also 6, which is what a drop leaves behind once anything was in flight, could only
   * be served by re-sending 6, and the receiver had no index on the wire with which to
   * notice the duplicate.
   *
   * Re-entrant by design: it is called once when the transfer starts and again for every
   * resume, always with the ranges the RECEIVER asked for. `streaming` is the latch, so a
   * resume that arrives while a previous run is still unwinding cannot double-send.
   *
   * A read error and a send error are handled differently on purpose. A file that cannot
   * be read is terminal: no amount of reconnecting fixes it, and pretending otherwise would
   * leave the receiver waiting on a sender that can never deliver. A send error is a
   * dropped link: keep everything and wait to be told where to continue from.
   */
  driveOutbound(ranges) {
    const out = this.outbound;
    if (!out || !out.file || !out.active) return;
    // PARKED, never dropped. The latch used to be a bare `return`, and the ranges the
    // caller was holding went with it. serveResume had already sent `file-resume-ok` by
    // then, so a resume that landed while the previous run was still unwinding told the
    // receiver "continuing from here" and then sent nothing: if the requested chunks were
    // behind the running iterator's cursor, which is exactly the case when the receiver
    // lost frames from the middle of the window, they never arrived and the transfer died
    // on the quiet timer. Correct arithmetic on a transfer that never finishes is not a
    // fix, so the ranges wait for the running pass to unwind and are drained below.
    //
    // The NEWEST plan replaces an older parked one rather than merging with it. A resume
    // plan is a statement of everything the receiver still lacks, not a delta, so the
    // later one already covers the earlier one; merging two would also have to re-sort and
    // re-coalesce them to satisfy readChunkRanges, which rejects overlapping or unordered
    // ranges on purpose.
    if (out.streaming) {
      if (ranges?.length) out.parked = ranges;
      return;
    }
    out.streaming = true;
    // Deliberately NOT wrapping the whole loop in enqueue(). Doing so made the send
    // queue exclusive to this transfer for its entire duration, so a chat message typed
    // 16.7 MB into a 157 MB send did not arrive until the transfer finished, 20 seconds
    // later. Each FRAME is enqueued individually instead: that still keeps seal-then-send
    // atomic, which matters because the AEAD counter has to increment in the same order
    // the frames go out or the peer's replay guard rejects them, while letting chat
    // interleave between chunks.
    // Anything parked by an earlier pass is superseded by the plan this run was handed:
    // a resume plan already describes everything the receiver lacks, so keeping the old
    // one would re-send chunks nobody asked for a second time.
    out.parked = null;
    (async () => {
      let iterator = null;
      const closeIterator = async () => {
        const it = iterator;
        iterator = null;
        if (it) { try { await it.return?.(); } catch (err) { void err; } }
      };
      try {
        let todo = ranges;
        // One pass per set of ranges. The second and later passes exist only for a resume
        // that landed while this run was still unwinding: see the parking note above.
        for (;;) {
          iterator = readChunkRanges(out.file, out.chunkSize, todo)[Symbol.asyncIterator]();
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
                await this.peer.send(
                  await this.channel.seal(TYPE.FILE_CHUNK, frameChunk(step.value.index, step.value.bytes)),
                );
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
            // Coverage, not a push counter: the slot for this index is SET to the length
            // that was read, and `sent` moves by the difference. Sending the same chunk
            // twice therefore adds nothing the second time, which is what makes an
            // overlapping resume harmless. See newCoverage for the transfer this lost.
            {
              const at = step.value.index;
              const len = step.value.bytes.byteLength;
              if (at < out.coverage.length && out.coverage[at] !== len) {
                out.sent += len - out.coverage[at];
                out.coverage[at] = len;
              }
            }
            out.chunks += 1;
            if (out.chunks % 32 === 0) {
              this.emit('file-progress', { direction: 'out', id: out.id, sent: out.sent, total: out.size, name: out.name });
            }
          }
          await closeIterator();
          // Drain a parked plan BEFORE FILE_END, never after. FILE_END is the receiver's
          // signal to check what it holds and either keep the file or throw it away, so a
          // chunk arriving behind it is a chunk arriving after the verdict.
          if (!out.parked?.length) break;
          todo = out.parked;
          out.parked = null;
        }

        await this.enqueue(async () => {
          await this.peer.send(await this.channel.sealJson(TYPE.FILE_END, {
            // `bytes` is the sender's own coverage total. For every chunk this side
            // actually read it is the length that came off the disk; for a chunk the
            // receiver told us it already holds it is the length the file's size says it
            // must be, which is the only figure available for bytes this run never
            // touched. The receiver checks its own total against the size it was given at
            // FILE_START independently, so a wrong figure here cannot pass a bad file.
            // `chunks` is derived rather than counted: the sender only sends the chunks
            // the receiver was missing, so a counter would be the count of THIS run and
            // not of the file.
            id: out.id, bytes: out.sent, chunks: chunkCount(out.size, out.chunkSize),
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
        await closeIterator();
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
    const served = await this.serveResume(
      out,
      Number(out.resumeOffset ?? 0),
      out.resumeRanges ?? wholeFileRanges(out.size, out.chunkSize),
      Number(out.resumeBytes ?? out.size),
    );
    if (!served) {
      // serveResume has already denied, told the peer and settled this one.
      throw new Error(`that is not the file this transfer began with, so ${out.name} has to be sent again from the start`);
    }
    return finished;
  }

  // ------------------------------------------------------------ receiving files

  /**
   * The peer says the next few FILE_STARTs belong together, so this side can ask once.
   *
   * Accepting has to happen inside a click, because both file pickers require a user gesture
   * and a gesture cannot be manufactured after the fact: that is why a phone sending five
   * photos made the laptop press Accept five times. One announcement means one row, one
   * click, one bounded grant.
   *
   * All of it is peer-controlled and validated before it is shown. `count` bounds how many
   * files one click may consent to, `bytes` how much, and `names` must agree with `count` or
   * a row built from it would misstate what is being agreed to. Failing any of these drops
   * the message with NO reply, as a malformed game message is dropped: answering would tell
   * a peer which of its guesses parsed. Names are sanitised at the DOM boundary in app.js
   * and not here, so the record of what was offered is not rewritten in the middle.
   */
  onBatchOffer(control) {
    const { batch, count, bytes, names } = control;
    if (typeof batch !== 'string' || !BATCH_ID_SHAPE.test(batch)
      || !Number.isInteger(count) || count < 2 || count > MAX_BATCH_FILES
      || !Number.isSafeInteger(bytes) || bytes < 0
      || !Array.isArray(names) || names.length !== count
      || names.some((name) => typeof name !== 'string')) {
      this.emit('warning', 'ignored a malformed offer of several files');
      return;
    }
    // A second announcement replaces the first rather than stacking: two live offers would
    // mean two rows and two clicks, which is the thing being removed. It deliberately does
    // NOT touch an existing grant, so a peer cannot refresh its own allowance by announcing
    // again.
    this.pendingBatch = { batch, count, bytes, names };
    // A NEW announcement clears the old refusal, because that refusal was about a different
    // set of files. Not cleared when the ids match: re-announcing the same id after a Refuse
    // would otherwise be a way to ask again until the answer changes.
    if (this.refusedBatch !== batch) this.refusedBatch = null;
    this.emit('files-offered', { batch, count, bytes, names });
  }

  /**
   * Turn the announced batch into a bounded grant. Called from the user's click, and the
   * directory is chosen by app.js inside that same click and handed down: nothing the PEER
   * sends can open a picker, because a message must not put a dialog in front of the user.
   */
  async acceptBatch({ directory = null } = {}) {
    const pending = this.pendingBatch;
    if (!pending) throw new Error('there is no batch of files to accept');
    // Consumed here, not on the first file. Leaving it set would let a FILE_START arriving
    // after the grant is spent fall back into "still waiting for the user" instead of into
    // the ordinary per-file offer it is supposed to get.
    this.pendingBatch = null;
    this.batchGrant = {
      batch: pending.batch, files: pending.count, bytes: pending.bytes, directory,
    };
    // The first FILE_START of a batch nearly always lands BEFORE the click: the sender
    // announces and immediately offers file one, and onFileStart parked it because the batch
    // row is its row. Without this, the click would grant a batch whose first file was
    // already sitting unanswered and the sender would wait on an accept that never came.
    const inbound = this.incoming;
    if (inbound && !inbound.sink && inbound.meta?.batch === pending.batch) {
      await this.acceptFromGrant(inbound);
    }
    return true;
  }

  /**
   * The other answer to the batch row. Drops the offer and refuses the file already parked
   * against it, so the sender is told rather than left streaming into a bounded buffer.
   */
  async refuseBatch(reason = 'the other device refused these files') {
    const pending = this.pendingBatch;
    if (!pending) return false;
    this.pendingBatch = null;
    // Latched, so the REST of the batch goes too. Without it only the parked file was
    // rejected and every later file under the same id fell through to the ordinary path,
    // where anything under the auto-accept threshold takes itself: "refused these five
    // photos, then took three of them anyway" is not what the button says.
    this.refusedBatch = pending.batch;
    const inbound = this.incoming;
    if (inbound && !inbound.sink && inbound.meta?.batch === pending.batch) {
      this.incoming = null;
      await this.control({ kind: 'file-reject', id: inbound.meta.id, reason });
      this.emit('file-refused', { ...inbound.meta, reason });
    }
    return true;
  }

  /**
   * Take one file under an existing grant, spending the counters BEFORE the file is taken
   * and never after: if the sink fails to open the allowance is still gone, or a peer that
   * can make sink creation fail gets unlimited retries against one click of consent.
   *
   * Does not throw. Both callers want the same thing on failure (tell the peer, tell the
   * user, forget the transfer) and neither has anything to do with an exception.
   */
  async acceptFromGrant(inbound) {
    const grant = this.batchGrant;
    const { meta } = inbound;
    if (!grant) return false;
    const size = Number(meta.size) || 0;
    grant.files -= 1;
    grant.bytes -= size;
    // Read out BEFORE the grant can be dropped on the next line, or the last file of a batch
    // would be the one file that did not go into the chosen folder.
    const { directory } = grant;
    if (grant.files <= 0 || grant.bytes <= 0) this.batchGrant = null;
    try {
      // Both awaits inside the try, exactly as the auto-accept path does it: a failure to
      // fetch the resume machinery is reported and rejected like a sink that would not open.
      const R = await loadResume();
      // With a directory: straight to disk, no dialog, the folder the user picked. Without
      // one: the picker is bypassed and this takes the streaming-download or memory route a
      // browser with no showSaveFilePicker already uses for every file today.
      this.adoptSink(R, inbound, await createSink(meta, directory ? { directory } : { noPicker: true }));
      await this.flushEarly(inbound);
      await this.rememberInboundRecord(inbound);
      await this.control({ kind: 'file-accept', id: meta.id, token: inbound.token });
      this.armInboundQuiet(inbound);
      // Both, for the same reason acceptIncoming emits the first: the user clicked Accept
      // and is owed the note saying where this is going, which for a memory sink is the
      // difference between "saved" and "held in this tab until it finishes". file-incoming
      // is what titles the row.
      this.emit('file-accepted-local', { ...meta, sink: inbound.sink.kind, note: inbound.sink.note ?? null });
      this.emit('file-incoming', meta);
      return true;
    } catch (err) {
      this.emit('warning', `could not start receiving ${meta.name}: ${err.message}`);
      if (this.incoming === inbound) this.incoming = null;
      await this.control({ kind: 'file-reject', id: meta.id, reason: err.message });
      this.emit('file-refused', { ...meta, reason: err.message });
      return false;
    }
  }

  async onFileStart(meta) {
    if (this.incoming) {
      await this.control({ kind: 'file-reject', id: meta.id, reason: 'another transfer is already in progress' });
      return;
    }
    // A batch the user already said no to. Checked before anything else looks at this file,
    // and before this.incoming is set, so the refusal costs no state at all.
    if (this.refusedBatch && meta.batch === this.refusedBatch) {
      const reason = 'the other device refused these files';
      await this.control({ kind: 'file-reject', id: meta.id, reason });
      this.emit('file-refused', { ...meta, reason });
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
      // Minted in adoptSink, which is the only place a sink is ever attached. A transfer
      // that has been offered and not accepted therefore has no token, and that is exactly
      // what makes a resume for it refusable without the refusal saying so.
      token: null,
    };

    // The grant is asked BEFORE the auto-accept threshold below, and that is not a
    // preference: a grant can carry a directory the user chose while auto-accept goes
    // straight to a memory sink, so the other order would land a batch's small files in this
    // tab's heap and its large ones in the chosen folder, from one click that said all of
    // them were going into that folder.
    const batch = typeof meta.batch === 'string' ? meta.batch : null;
    if (batch && this.batchGrant?.batch === batch
      && this.batchGrant.files > 0 && (Number(meta.size) || 0) <= this.batchGrant.bytes) {
      await this.acceptFromGrant(this.incoming);
      return;
    }
    // Announced, drawn, not answered yet: the batch row already carries the Accept covering
    // this file, so file-offered here would draw a SECOND control for the same consent. Park
    // it; acceptBatch takes it on the click and refuseBatch tells the sender.
    if (batch && this.pendingBatch?.batch === batch) return;
    // Falls through on purpose when the id is unknown or the grant is spent, which is the
    // whole bound: a peer that announced three files and sends a fourth under the same id
    // gets the ordinary treatment for the fourth.

    if (meta.size <= AUTO_ACCEPT_BYTES) {
      // No user gesture here, so never try to open a save dialog: straight to memory.
      try {
        // Both awaits are inside the try, so a failure to fetch the resume machinery is
        // reported and rejected exactly like a sink that would not open.
        const R = await loadResume();
        this.adoptSink(R, this.incoming, await createSink(meta, { preferMemory: true }));
        await this.flushEarly(this.incoming);
        await this.rememberInboundRecord(this.incoming);
        await this.control({ kind: 'file-accept', id: meta.id, token: this.incoming.token });
        this.armInboundQuiet(this.incoming);
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

  /**
   * Make a raw sink chunk-addressable and mint the token that names this transfer instance.
   *
   * Every path that creates a sink goes through here, so there is no route that ends up with
   * an un-indexed sink (which would append duplicates) or an untokened transfer (which would
   * accept a resume it never agreed to).
   */
  adoptSink(R, inbound, sink, { written = 0, ledger = null } = {}) {
    const chunkSize = Number(inbound.meta.chunkSize) || CHUNK_BYTES;
    let indexed;
    try {
      indexed = R.createIndexedSink(sink, {
        chunkSize, size: Number(inbound.meta.size), written, ledger,
      });
    } catch (err) {
      // The raw sink is already open by this point, and a FileSystemWritableFileStream left
      // dangling holds a lock on the user's own file until the tab closes. Release it before
      // rethrowing, and keep the original reason: it is the one that says what was wrong.
      sink.abort(err.message).catch(() => {});
      throw err;
    }
    inbound.sink = indexed;
    inbound.received = indexed.position;
    inbound.chunks = indexed.ledger.frontier;
    inbound.token = R.mintResumeToken();
    return indexed;
  }

  /** Called by the UI, from a user gesture, so showSaveFilePicker is allowed. */
  async acceptIncoming() {
    if (!this.incoming) throw new Error('no incoming file to accept');
    const inbound = this.incoming;
    const { meta } = inbound;
    // Fetched HERE, before the save dialog, and deliberately not beside adoptSink below.
    // The check that this is still the transfer in progress is immediately followed by the
    // adopt, and an await between the two would reopen the exact window that check exists
    // to close. Doing it first also overlaps the fetch with the dialog, which is the
    // longest wait on this path by orders of magnitude.
    //
    // primeSink rides along in the SAME await rather than being left to createSink's own
    // first-use fetch below. Two reasons, and the second is the one that matters: sequential
    // awaits would put two round trips between the click and showSaveFilePicker, and a save
    // dialog is only allowed while the transient user activation from that click is still
    // alive. One parallel await spends the same wall clock the single loadResume() already
    // spent. If either fetch fails this rejects with that fetch's own message, which is the
    // behaviour loadResume() alone already had here.
    const [R] = await Promise.all([loadResume(), primeSink()]);
    let sink = null;
    try {
      sink = await createSink(meta);
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
    // The save dialog is modal and can stand open for as long as the user likes. A channel
    // drop during that time discards a transfer that has no sink yet (resetForRenegotiation
    // only keeps the ones already writing somewhere), so by the time a location is chosen
    // this may no longer be the transfer in progress. Adopting the sink anyway left a live
    // writable nobody would ever close, holding a lock on the file the user had just picked,
    // and a row that sat at 0% for the rest of the session.
    if (this.incoming !== inbound) {
      const reason = 'the connection dropped while the save dialog was open';
      try {
        await sink.abort(reason);
      } catch (abortErr) {
        this.emit('warning', `could not close the file that was being saved: ${abortErr.message}`);
      }
      this.emit('file-refused', { ...meta, reason });
      throw new Error(reason);
    }
    this.adoptSink(R, inbound, sink);
    await this.rememberInboundRecord(inbound);
    await this.control({ kind: 'file-accept', id: meta.id, token: inbound.token });
    // From here on this side is waiting on the sender, so the quiet clock starts. Armed
    // after the accept goes out, not before opening the sink: the save dialog is modal and
    // can sit open for as long as the user likes, which is not the sender being quiet.
    this.armInboundQuiet(inbound);
    this.emit('file-accepted-local', {
      ...meta,
      sink: inbound.sink.kind,
      note: inbound.sink.note ?? null,
    });
    // Flush what arrived before the sink existed, now, rather than waiting for the next
    // chunk to push it: the last buffered chunk may be the last chunk of the file, and
    // nothing would ever arrive to flush it. Queued behind the inbound frames so a chunk
    // that lands mid-flush cannot overtake the buffered ones.
    // A chunk held before the sink existed that the sink then refuses is a desynchronised
    // sender (a wrong length for its index, which is also what an old-format chunk looks
    // like). The held bytes are gone either way, so there is nothing to retry onto: fail the
    // transfer with the reason rather than let it reach the UI as a bare rejected promise.
    await this.enqueueInbound(() => (this.incoming === inbound ? this.flushEarly(inbound) : undefined))
      .catch((err) => this.failInbound(inbound, `a chunk held before the transfer was accepted could not be written: ${err.message}`));
  }

  /** Write anything that arrived before there was a sink, in arrival order. */
  async flushEarly(inbound) {
    if (!inbound?.sink || !inbound.early?.length) return;
    const held = inbound.early;
    inbound.early = null;
    inbound.earlyBytes = 0;
    for (const piece of held) {
      await inbound.sink.write(piece.index, piece.bytes);
    }
    // Read back rather than accumulated: the sink is the authority on what it took, and a
    // chunk buffered ahead of a hole advances the ledger without advancing the position.
    inbound.received = inbound.sink.position;
    inbound.chunks = inbound.sink.ledger.frontier;
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
      // Keyed on room AND peer. One key per room meant every Link in a mesh wrote to the
      // same record, so the second peer's transfer erased the first peer's handle and the
      // first peer's completion deleted the second peer's record out from under it.
      await saveResume(this.session.roomId, this.peerId, {
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

  /**
   * Forget THIS pair's record and nobody else's.
   *
   * The peer id is not decoration. Without it this deleted the whole room's key, so one
   * peer finishing its file destroyed another peer's in-flight resume record in the same
   * gate.
   */
  async forgetInboundRecord() {
    if (!this.session.roomId) return;
    try {
      await clearResume(this.session.roomId, this.peerId);
    } catch (err) { this.emit('warning', `could not clear the resume record: ${err.message}`); }
  }

  /**
   * Adopt a transfer recovered from storage into this link.
   *
   * MUST be called from a user gesture: re-granting write permission on a stored handle
   * prompts, and a prompt outside a gesture is refused.
   */
  async adoptInbound(record) {
    if (this.incoming) throw new Error('another transfer is already in progress');
    // Both fetches in one await, for the reason spelled out in acceptIncoming: this path is
    // also inside a user gesture, because re-granting write permission on a stored handle
    // prompts, and a prompt outside a live activation is refused outright.
    const [R] = await Promise.all([loadResume(), primeSink()]);
    // startOffset is a request; the sink clamps it to what the file actually contains,
    // because everything written and not committed before the reload was discarded.
    const chunkSize = Number(record.meta.chunkSize) || CHUNK_BYTES;
    const size = Number(record.meta.size);
    const raw = await createSink(record.meta, { handle: record.handle, startOffset: record.received });
    // Re-granting write permission on a stored handle prompts, and that prompt can stand
    // open while a FILE_START arrives: anything under AUTO_ACCEPT_BYTES accepts itself,
    // builds a sink and arms a quiet timer. Overwriting this.incoming below would strand
    // that sink open and that timer armed, with the sender never told. The recovered
    // transfer is the one that gives way, because it can still be continued later.
    if (this.incoming) {
      const clash = 'another transfer started while this file was being re-opened';
      try {
        await raw.abort(clash);
      } catch (err) {
        this.emit('warning', `could not close the recovered file: ${err.message}`);
      }
      throw new Error(`${clash}, so it was not continued`);
    }
    // FLOOR, not the ceil this used to do. A committed file can end part way through a
    // chunk, and rounding that up claims a chunk this side holds only part of: the sender
    // skips it and the hole is permanent, silent, and invisible to every length check,
    // because the missing tail is never counted by either side. Rewinding to the last whole
    // chunk costs at most one chunk of re-sent data.
    const whole = R.chunksOnDisk(raw.position, chunkSize, size);
    // Clamped, because a complete file reports every chunk including the short last one:
    // whole * chunkSize then overshoots the file by the length of that chunk's padding.
    // Unclamped it was handed to the sink as `written`, and requestResume went on to claim
    // more bytes than the file has, which the sender refuses outright: a transfer that
    // could never be continued, explained by a number that cannot exist.
    const wholeBytes = Math.min(whole * chunkSize, size);
    if (raw.position !== wholeBytes) {
      if (typeof raw.seekTo !== 'function') {
        // Nothing may be appended onto a partial chunk that cannot be rewound: the next
        // chunk would be spliced into the middle of the file and every length check on both
        // sides would still come out right. Only the disk sink can seek, and only the disk
        // sink stores a handle, so this is unreachable today and says so loudly if that
        // stops being true rather than quietly writing at the wrong offset.
        await raw.abort('the recovered file cannot be rewound to a chunk boundary');
        throw new Error(
          `${record.meta.name} was recovered part way through a chunk and this browser cannot rewind it, `
          + 'so the transfer has to start again from the beginning',
        );
      }
      await raw.seekTo(wholeBytes);
    }
    const ledger = new R.ChunkLedger(chunkCount(size, chunkSize));
    for (let i = 0; i < whole; i += 1) ledger.mark(i);
    this.incoming = {
      meta: record.meta,
      received: 0,
      chunks: 0,
      sink: null,
      stalled: true,
      crossedReload: true,
      resumes: 0,
      token: null,
    };
    this.adoptSink(R, this.incoming, raw, { written: wholeBytes, ledger });
    const at = this.incoming.sink.position;
    await this.rememberInboundRecord(this.incoming);
    this.emit('file-incoming', record.meta);
    this.emit('file-progress', {
      direction: 'in', id: record.meta.id, sent: at, total: record.meta.size, name: record.meta.name,
    });
    if (this.state === STATE.CONNECTED) await this.requestResume(this.incoming);
    return at;
  }

  async onFileChunk(plaintext) {
    const inbound = this.incoming;
    if (!inbound) { this.emit('warning', 'received a file chunk with no transfer in progress'); return; }
    let piece;
    try {
      piece = unframeChunk(plaintext);
    } catch (err) {
      this.emit('warning', `ignored a file chunk that could not be read: ${err.message}`);
      return;
    }
    if (inbound.stalled) {
      // The sender must not write at an offset this side has not agreed to. Nothing has
      // been agreed until file-resume-ok has been checked, so this drops rather than
      // guesses; the sender restarts from our reported ranges either way.
      this.emit('warning', 'ignored a file chunk that arrived before the transfer was resumed');
      return;
    }
    if (!inbound.sink) {
      // Chunks arrived before the user accepted. Hold a bounded amount rather than
      // dropping them, so an eager sender does not corrupt the transfer. Held WITH their
      // indices, so the flush can be idempotent for the same reason a live write is.
      inbound.early = inbound.early ?? [];
      inbound.earlyBytes = (inbound.earlyBytes ?? 0) + piece.bytes.byteLength;
      // Both limits, because either one alone can be walked around: bytes alone lets small
      // chunks buy unbounded entries, and entries alone lets big chunks buy unbounded
      // bytes. Same pairing as resume.js's post-accept buffer.
      if (inbound.earlyBytes > EARLY_LIMIT_BYTES || inbound.early.length >= MAX_EARLY_CHUNKS) {
        // Dropping this silently left the other device with a row that never moved and no
        // reason for it, and every later file refused with "another transfer is already in
        // progress" if the sender kept going. Same rule as acceptIncoming: the peer is told
        // it was rejected, and this side says why.
        const reason = `the sender began before the transfer was accepted, and more than ${formatBytes(EARLY_LIMIT_BYTES)} `
          + 'arrived before there was anywhere to write it';
        this.incoming = null;
        await this.control({ kind: 'file-reject', id: inbound.meta.id, reason });
        this.emit('file-failed', { ...inbound.meta, reason });
        return;
      }
      // slice(), because `piece.bytes` is a view over the frame's buffer.
      inbound.early.push({ index: piece.index, bytes: piece.bytes.slice() });
      return;
    }
    try {
      await this.flushEarly(inbound);
    } catch (err) {
      // The held chunks are gone either way, so there is nothing to retry onto. This is
      // also where an OLD-FORMAT chunk lands: one sent by a build that put no index in
      // front of its bytes is the wrong length for its apparent index and the sink refuses
      // it, which is the loud failure that keeps a mis-parse from becoming a corrupt file.
      await this.failInbound(inbound, `a chunk held before the transfer was accepted could not be written: ${err.message}`);
      return;
    }

    let outcome;
    try {
      outcome = await inbound.sink.write(piece.index, piece.bytes);
    } catch (err) {
      // A chunk at an impossible index or the wrong length is a desynchronised sender, not
      // a transient fault: keep the reason and stop rather than write it somewhere.
      await this.failInbound(inbound, `a chunk could not be written: ${err.message}`);
      return;
    }
    inbound.received = inbound.sink.position;
    inbound.chunks = inbound.sink.ledger.frontier;
    // Proof the other device is still there, so the quiet timer starts over. A duplicate
    // counts: it is not progress, but it is not silence either, and silence is the only
    // thing that timer measures.
    this.armInboundQuiet(inbound);
    if (inbound.quietWarned) {
      inbound.quietWarned = false;
      // The warning said it would continue on its own if they came back. They came back,
      // so the row must stop saying it is waiting: a warning that never withdraws is how a
      // working transfer ends up looking broken.
      this.emit('file-resumed', {
        direction: 'in', id: inbound.meta.id, name: inbound.meta.name, offset: inbound.received,
      });
    }
    // A duplicate is ordinary on a resumed transfer and a chunk too far ahead to hold is
    // simply re-requested by the next resume. Neither is progress and neither is an error.
    if (!outcome.written) return;

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
    this.clearInboundQuiet(inbound);
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
    // inbound.chunks is the ledger's contiguous frontier and end.chunks is derived on the
    // sender from the size and chunk size fixed at FILE_START, so both sides now count the
    // FILE's chunks rather than the chunks that happened to move in the last run.
    if (inbound.received !== end.bytes || inbound.chunks !== end.chunks) {
      failures.push(`expected ${end.bytes} bytes in ${end.chunks} chunks, reassembled ${inbound.received} in ${inbound.chunks}`);
    }
    if (!Number.isFinite(declared) || inbound.received !== declared) {
      failures.push(`the file was announced as ${inbound.meta?.size} bytes but ${inbound.received} arrived`);
    }
    // Through failInbound rather than inline, because abort() can itself reject and this
    // is the one path where this.incoming is already null: an unguarded rejection here
    // reached handleFrame's generic catch, which has no transfer left to fail, so the
    // resume record survived and the row never moved again.
    if (failures.length) {
      await this.failInbound(inbound, failures.join('; '));
      return;
    }

    let blob;
    try {
      blob = await inbound.sink.finish();
    } catch (err) {
      // finish() bottoms out in close(), which is exactly where a browser reports a full
      // disk or an exhausted quota: the swap file is only renamed over the real one there.
      // The bytes are not saved, so this is a failed transfer and has to be said out loud.
      await this.failInbound(inbound, `the file could not be finished: ${err.message}`);
      return;
    }
    // The file is whole and closed, so there is nothing left to resume and the record must
    // not outlive it: a stale handle would offer to continue a transfer that is finished.
    await this.forgetInboundRecord();
    // The file is already on disk at this point, so failing to tell the sender is a
    // reporting problem on their end, not a failed transfer on this one.
    try {
      await this.control({ kind: 'file-complete', id: inbound.meta.id, bytes: inbound.received });
    } catch (err) {
      this.emit('warning', `the file was saved but the other device could not be told: ${err.message}`);
    }
    // `handle` is the FileSystemFileHandle the disk sink already holds, null for the memory
    // and stream sinks. Passed along, not newly retained: rememberInboundRecord has stored
    // the same object for resume all along, so no protocol and no storage changes. It is
    // what stops a file written straight to disk being a dead end in the transcript, since
    // app.js can read those bytes back on demand. A reference to a file the user chose, not
    // its contents, and it goes no further than this page.
    this.emit('file-received', {
      ...inbound.meta,
      blob,
      sink: inbound.sink.kind,
      handle: inbound.sink.handle ?? null,
      human: formatBytes(inbound.received),
    });
  }

  async control(message) {
    if (!this.channel || !this.peer?.channel || this.peer.channel.readyState !== 'open') return;
    await this.enqueue(async () => {
      await this.peer.send(await this.channel.sealJson(TYPE.CONTROL, message));
    });
  }

  /**
   * Send one game message to this peer, sealed exactly like every other control message.
   *
   * Returns false rather than throwing when the channel is not open: a move made while
   * the link is reconnecting is a move the game layer has to keep on its own board and
   * re-offer, and a rejected promise on every click is not how that gets said.
   */
  async sendGame(payload) {
    if (this.peer?.channel?.readyState !== 'open') return false;
    await this.control({ kind: 'game', payload });
    return true;
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
    this.clearRevealTimer();
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
    this.peerCommitment = null;
    this.pkSent = false;
    // Before the reference is dropped, or the timer outlives the only object that can tell
    // it to be quiet and fires into a torn-down link.
    this.clearInboundQuiet(this.incoming);
    this.incoming = null;
    // Consent does not survive the gate it was given in. A grant is permission to write onto
    // this user's disk, given once, about a specific set of files; carrying it past a sever
    // would leave a live directory handle and a live allowance on a link that no longer
    // exists, ready for whatever reconnected next. The unanswered offer goes with it, so a
    // batch that was never accepted leaves nothing for a later transfer to inherit.
    this.pendingBatch = null;
    this.batchGrant = null;
    this.refusedBatch = null;
    this.earlyFrames = [];
    this.deriving = null;
    this.peer = null;
    this.state = STATE.SEVERED;
  }
}

/**
 * Read whatever interrupted inbound transfer this room left behind.
 *
 * The NEWEST one. Records are now per peer, so a mesh can leave several behind; the UI
 * offers one at a time and the most recently written is the one the user was watching when
 * the page went away. The others are not lost: they keep their own keys and their own
 * handles, and each is offered in turn as the transfers ahead of it are dealt with.
 */
export async function readInboundRecord(roomId) {
  const records = await listResume(roomId);
  return records[0] ?? null;
}

/** Forget one participant's record. Exported so the session can clear it without a link. */
export async function dropInboundRecord(roomId, peerId) {
  return clearResume(roomId, peerId);
}

/** Forget every record this room left behind. What burning a gate has to do. */
export async function dropRoomInboundRecords(roomId) {
  return clearRoomResume(roomId);
}
