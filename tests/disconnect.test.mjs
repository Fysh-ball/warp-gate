// What a mid-file disconnect ACTUALLY does to a transfer, and what makes it recover.
//
// Written from a user report: "UX of disconnects are bad frankly, if sender disconnects and
// then reconnects it seems the media being sent becomes stalled, these are not that uncommon
// of a scenario this should have been caught". It was not caught because nothing here drove
// a disconnect end to end: tests/outbound.test.mjs drives one Link and checks the sender's
// arithmetic, and the browser suite drives a real gate but cannot cut a connection in the
// middle of a file and put it back. Two failures lived in that gap, and both are reproduced
// below BEFORE the recovery is tested.
//
//   1. THE ICE BLIP THAT DESTROYS A TRANSFER. An ICE restart re-runs connectivity checks
//      over the SAME DTLS and SCTP association: keys, frame counters and the data channel
//      all survive, so the sending loop never falters. The connection state still goes
//      'disconnected' and back to 'connected', holdOpen fired on that, and
//      markTransfersStalled set `incoming.stalled` on a byte stream that had never broken.
//      onFileChunk DROPS every chunk while that flag is set and only onResumeAccepted clears
//      it, so the receiver threw away everything that arrived during the blip while the
//      sender ran happily to FILE_END. Measured on the 21-chunk file below: the sender
//      emitted file-sent, resolved sendFile and declared 328,457 bytes delivered; the
//      receiver failed with "expected 328457 bytes in 21 chunks, reassembled 81920 in 5".
//      The transfer would have completed untouched had nothing been marked at all.
//
//   2. THE ONE-SIDED RECONNECT THAT DEADLOCKS. The sender's half of the connection drops and
//      comes back without the receiver's half ever noticing. The receiver's link therefore
//      never leaves STATE.CONNECTED, setState never fires, afterReconnect never runs, and no
//      resume is ever requested: the sender parks with outbound.stalled true waiting to be
//      told where to continue, and the receiver waits for chunks. Measured: 5 of 21 chunks
//      delivered, sendFile never settling, and not one event on the receiving side. The
//      receiver's quiet timer fired once, said the transfer "continues on its own if they
//      come back", took no action and never fired again.
//
// Two Links are driven directly over stand-in transports for the same reason
// tests/outbound.test.mjs does it: connect() would build an RTCPeerConnection, which Node
// has no business having, and the latches and the arithmetic are the thing under test rather
// than WebRTC. Everything below goes through the real sendFile, driveOutbound, serveResume,
// markTransfersStalled, armInboundQuiet, requestResume, onFileChunk and onFileEnd, over a
// real File and a real indexed sink.

import { check, summary } from './lib/harness.mjs';

// ---------------------------------------------------------------- controllable timers
//
// Installed BEFORE link.js is imported, because armInboundQuiet reads the global at call
// time and the quiet timer is 45 seconds: a suite that waited for it would be a suite nobody
// runs. Only timers armed at exactly INBOUND_QUIET_MS are ever fired, so the reconnect
// backoff and the watchdog stay parked where the test put them rather than firing as a side
// effect of driving something else.
const realSetTimeout = globalThis.setTimeout;
const timers = new Map();
let nextTimerId = 1;
globalThis.setTimeout = (fn, ms, ...args) => {
  const id = nextTimerId;
  nextTimerId += 1;
  timers.set(id, { fn, ms, args });
  return id;
};
globalThis.clearTimeout = (id) => { timers.delete(id); };

/** Every pending timer armed at exactly `ms`, oldest first. */
const timersAt = (ms) => [...timers.entries()].filter(([, t]) => t.ms === ms);

/** Fire the pending timers armed at exactly `ms`. Returns how many ran. */
function fireTimersAt(ms) {
  const due = timersAt(ms);
  for (const [id, t] of due) {
    timers.delete(id);
    t.fn(...t.args);
  }
  return due.length;
}

const { Link, STATE, INBOUND_QUIET_MS } = await import('../public/js/link.js');
const { TYPE } = await import('../public/js/crypto.js');
const { fingerprintFile, formatBytes } = await import('../public/js/transfer.js');
const { chunkCount } = await import('../public/js/chunkwire.js');

const CHUNK = 16 * 1024;
// Not a multiple of the chunk size, for the reason tests/outbound.test.mjs gives: a total
// that is right only because it counted whole chunks cannot pass.
const SIZE = CHUNK * 20 + 777;
const CHUNKS = chunkCount(SIZE, CHUNK);
const file = new File([new Uint8Array(SIZE).map((_, i) => i & 0xff)], 'disconnect.bin', {
  type: 'application/octet-stream',
});
const fingerprint = await fingerprintFile(file);

// ---------------------------------------------------------------- the two-ended harness

/**
 * A session stub with only what one Link touches. `severed` stays false throughout: a burned
 * gate is a different event from a dropped one and mixing them is how a wrong cause gets
 * printed.
 */
function makeSession() {
  const s = {
    roomId: 'disconnect-room',
    severed: false,
    needsRestart: false,
    password: null,
    passwordGate: Promise.resolve(),
    signal: { send: async () => true },
    labelFor: () => 'peer',
    sever: async () => { s.severed = true; },
    teardown: () => { s.torn = true; },
    pendingInbound: null,
    lostInbound: null,
    links: new Map(),
    onLinkTargetGone: () => {},
  };
  return s;
}

/**
 * One end of a gate: a real Link over transports that hand frames straight to the other end.
 *
 * The crypto is bypassed deliberately. seal/sealJson return the plaintext they were given and
 * the receiving end dispatches by frame type, so every byte still goes through the real
 * sendFile, driveOutbound, onFileChunk and onFileEnd; what is skipped is AES-GCM, which
 * tests/crypto.test.mjs owns and which cannot fail differently because a channel dropped.
 */
class End {
  constructor(name, wire, initiator) {
    this.name = name;
    this.wire = wire;
    this.session = makeSession();
    this.link = new Link({ session: this.session, peerId: `${name}-slot`, initiator });
    this.events = [];
    this.chunkFrames = 0;
    this.controlsOut = [];
    // What the transport was HANDED, as opposed to what it carried. `controlsOut` is appended
    // inside peer.send AFTER the closed-channel throw, and link.control() returns before ever
    // reaching peer.send when readyState is not 'open', so a claim of the form "it asked
    // nothing over a dead channel" written against controlsOut cannot fail: nothing can put a
    // frame there while the wire is down. Proved by mutation on 2026-08-10 (link.js's quiet
    // timer guard replaced with `if (false)`: the sibling file-stalled check went BAD and the
    // controlsOut one still printed OK). This records the attempt first, so a frame that was
    // built and refused by the transport is visible as an attempt that was made.
    this.controlAttempts = [];
    this.inbox = Promise.resolve();
    for (const n of ['file-stalled', 'file-failed', 'file-rejected', 'file-resumed',
      'file-sent', 'file-complete', 'file-received', 'file-progress', 'warning']) {
      this.link.addEventListener(n, (e) => this.events.push({ name: n, detail: e.detail }));
    }
    this.attach();
    // Both ends start where a working gate leaves them: confirmed, connected, and having
    // been connected at least once, which is what makes a later drop a pause rather than a
    // pair of devices that never found each other.
    this.link.confirmedByPeer = true;
    this.link.everConnected = true;
    this.link.state = STATE.CONNECTED;
    // connect() would build an RTCPeerConnection. The test drives reconnection by hand
    // instead, which is also the only way to reproduce a ONE-SIDED one.
    this.link.restartConnection = async () => {};
  }

  /** Build (or rebuild, after a renegotiation) the channel and peer stubs. */
  attach() {
    const self = this;
    this.link.channel = {
      seal: async (type, bytes) => ({ type, bytes }),
      sealJson: async (type, body) => ({ type, body }),
    };
    const peer = new EventTarget();
    peer.closed = false;
    // Reads through to the wire, so cutting the wire closes both ends' view of the channel
    // exactly as an SCTP association going away does.
    peer.channel = { get readyState() { return self.wire.open ? 'open' : 'closed'; } };
    peer.maxChunkBytes = () => CHUNK;
    peer.explainStall = () => 'the other device is not reachable at the moment';
    peer.diagnostics = () => null;
    peer.close = () => { peer.closed = true; };
    peer.makeOffer = async () => {};
    peer.send = async (frame) => {
      // Recorded BEFORE the throw, deliberately: see the field's own comment.
      if (frame.type === TYPE.CONTROL) self.controlAttempts.push(frame.body);
      // The same error peer.js's send() throws on a closed channel, and it is load bearing:
      // the sending loop's whole failure path keys off a send that rejects.
      if (!self.wire.open) throw new Error('data channel is not open');
      if (frame.type === TYPE.FILE_CHUNK) self.chunkFrames += 1;
      if (frame.type === TYPE.CONTROL) self.controlsOut.push(frame.body);
      if (self.gate && frame.type === TYPE.FILE_CHUNK) await self.gate(self.chunkFrames);
      self.other.deliver(frame);
    };
    this.link.peer = peer;
    // The REAL listeners, so a drop takes the path a browser would take rather than a path
    // the test invented: channel-close and connection-state both land in holdOpen.
    this.link.wirePeer();
  }

  /**
   * Take a frame from the other end.
   *
   * Queued rather than awaited by the sender: the receiving side answers with control
   * messages of its own, and a synchronous round trip would re-enter the sender's send queue
   * from inside one of its own queued tasks and deadlock on its own acknowledgement.
   */
  deliver(frame) {
    this.inbox = this.inbox.then(async () => {
      const L = this.link;
      if (frame.type === TYPE.CONTROL) return L.onControl(frame.body);
      if (frame.type === TYPE.FILE_START) return L.onFileStart(frame.body);
      if (frame.type === TYPE.FILE_CHUNK) return L.onFileChunk(frame.bytes);
      if (frame.type === TYPE.FILE_END) return L.onFileEnd(frame.body);
      return undefined;
    }).catch((err) => { this.inboxError = err; });
  }

  said(kind) {
    return this.events.filter((e) => e.name === kind);
  }

  lastMessage(kind) {
    const hits = this.said(kind);
    return hits.length ? (hits[hits.length - 1].detail?.message ?? hits[hits.length - 1].detail?.reason ?? '') : '';
  }
}

/** Let every queued frame and every settled promise finish before asserting anything. */
async function settle(ends, rounds = 200) {
  for (let i = 0; i < rounds; i += 1) {
    await Promise.all(ends.map((e) => e.inbox));
    await new Promise((r) => setImmediate(r));
  }
}

/**
 * A gate with a send in flight, held at the Nth chunk so a drop lands in the MIDDLE of the
 * file rather than between transfers.
 */
async function openGate({ holdAt = 6, autoAccept = true } = {}) {
  const wire = { open: true };
  const sender = new End('sender', wire, true);
  const receiver = new End('receiver', wire, false);
  sender.other = receiver;
  receiver.other = sender;

  let release = null;
  let announce = null;
  const reached = new Promise((resolve) => { announce = resolve; });
  if (holdAt) {
    sender.gate = async (n) => {
      if (n !== holdAt) return;
      announce();
      await new Promise((r) => { release = r; });
    };
  }

  const done = sender.link.sendFile(file, 'T-disconnect', fingerprint);
  let outcome = 'pending';
  done.then(() => { outcome = 'resolved'; }, (err) => { outcome = `rejected: ${err.message}`; });
  void autoAccept;

  if (holdAt) await reached;
  await settle([sender, receiver], 40);
  return {
    wire,
    sender,
    receiver,
    release: () => { release?.(); },
    outcome: () => outcome,
    both: [sender, receiver],
  };
}

// ------------------------------------------------- 1. an ICE blip must not destroy a file
{
  // The connection state goes 'disconnected' and back to 'connected' while the data channel
  // stays open the whole time. Nothing about the byte stream broke, so nothing may be marked.
  const g = await openGate({ holdAt: 6 });
  const heldBefore = g.receiver.link.incoming?.received ?? 0;
  check('CONTROL: the blip really does land mid-file, with the receiver holding part of it',
    heldBefore > 0 && heldBefore < SIZE && g.receiver.link.incoming?.sink,
    `held ${heldBefore} of ${SIZE}`);

  for (const end of g.both) {
    end.link.peer.dispatchEvent(new CustomEvent('connection-state', { detail: 'disconnected' }));
  }
  await settle(g.both, 5);
  check('CONTROL: the data channel is still open across the blip, so this is the ICE case '
    + 'and not a dropped channel',
    g.wire.open === true && g.receiver.link.peer.channel.readyState === 'open',
    `wire ${g.wire.open}`);
  check('a blip on a channel that never closed does not stall the receiver, because a stalled '
    + 'receiver DROPS every chunk that arrives',
    g.receiver.link.incoming?.stalled === false,
    `stalled=${g.receiver.link.incoming?.stalled}`);
  check('and does not release the sender\'s streaming latch under its running pass',
    g.sender.link.outbound?.streaming === true,
    `streaming=${g.sender.link.outbound?.streaming}`);

  g.release();
  for (const end of g.both) {
    end.link.peer.dispatchEvent(new CustomEvent('connection-state', { detail: 'connected' }));
  }
  await settle(g.both, 300);

  check('the file survives an ICE blip taken mid-transfer',
    g.receiver.said('file-failed').length === 0,
    g.lastFail ?? g.receiver.lastMessage('file-failed'));
  check('and the receiver reassembles every byte of it',
    g.receiver.said('file-received').length === 1
      && g.receiver.said('file-received')[0].detail.human,
    JSON.stringify(g.receiver.said('file-received').map((e) => e.detail.human)));
  check('and the sender declares it sent, exactly once',
    g.sender.said('file-sent').length === 1 && g.outcome() === 'resolved',
    `sent=${g.sender.said('file-sent').length} outcome=${g.outcome()}`);
  check('and one pass over the file means one chunk per chunk, not two',
    g.sender.chunkFrames === CHUNKS, `frames=${g.sender.chunkFrames} want=${CHUNKS}`);
}

// ------------------------- 2. the pre-fix marking, planted, to prove the check above can fail
{
  // The known-bad state, planted rather than described: `incoming.stalled` set on a channel
  // that never closed is precisely what markTransfersStalled used to do on an ICE blip. If
  // this does NOT fail the transfer, the check above is measuring nothing.
  const g = await openGate({ holdAt: 6 });
  g.receiver.link.incoming.stalled = true;
  g.release();
  await settle(g.both, 300);

  check('CONTROL: stalling the receiver on a live channel really does destroy the transfer, '
    + 'so the check above is not green by accident',
    g.receiver.said('file-failed').length === 1,
    `failed=${g.receiver.said('file-failed').length}`);
  check('CONTROL: and the sender still reports success, which is what made this silent',
    g.sender.said('file-sent').length === 1,
    `sent=${g.sender.said('file-sent').length}`);
}

// --------------------------------- 3. a one-sided reconnect: reproduce the stall, then fix it
{
  // Only the SENDER's peer notices the drop. The receiver's link never leaves CONNECTED, so
  // setState never fires and afterReconnect never runs on the side that owns the offset.
  const g = await openGate({ holdAt: 6 });
  g.wire.open = false;
  g.sender.link.peer.dispatchEvent(new CustomEvent('channel-close'));
  g.release();
  await settle(g.both, 60);

  check('CONTROL: the receiver never learned about the drop, which is what makes this the '
    + 'one-sided case',
    g.receiver.link.state === STATE.CONNECTED && g.receiver.link.incoming?.stalled === false,
    `state=${g.receiver.link.state} stalled=${g.receiver.link.incoming?.stalled}`);

  // The sender's connection comes back on its own. Nothing tells the receiver.
  g.wire.open = true;
  g.sender.link.resetForRenegotiation();
  g.sender.attach();
  g.sender.link.confirmedByPeer = true;
  g.sender.link.setState(STATE.CONNECTED);
  await settle(g.both, 200);

  const held = g.receiver.link.incoming?.received ?? 0;
  check('THE STALL: a reconnect on one side alone leaves the transfer stopped, with the '
    + 'sender parked waiting to be told where to continue',
    g.sender.link.outbound?.active === true && g.sender.link.outbound?.stalled === true
      && held < SIZE && g.outcome() === 'pending',
    JSON.stringify({
      active: g.sender.link.outbound?.active,
      stalled: g.sender.link.outbound?.stalled,
      held,
      of: SIZE,
      outcome: g.outcome(),
    }));
  check('CONTROL: and nothing re-requested the file by itself, so the recovery below is '
    + 'really doing the work',
    g.receiver.controlsOut.filter((c) => c.kind === 'file-resume').length === 0,
    JSON.stringify(g.receiver.controlsOut.map((c) => c.kind)));

  // The receiver's quiet timer is the only thing watching, so it has to be the thing that
  // drives the recovery.
  // This gate's own timer, not "some timer somewhere at 45000ms": see section 4 for the
  // incident. Both gates in this file arm at the same interval, so the global form could not
  // tell the receiver being watched from a stale timer left behind by an earlier section.
  const armed = g.receiver.link.incoming?.quietTimer ?? null;
  check(`the receiver still has a quiet timer armed at ${INBOUND_QUIET_MS}ms after a `
    + 'one-sided drop, so something is watching at all',
    armed !== null && timers.has(armed) && timers.get(armed).ms === INBOUND_QUIET_MS,
    `timer=${armed} ms=${armed === null ? 'none' : timers.get(armed)?.ms}`);

  fireTimersAt(INBOUND_QUIET_MS);
  await settle(g.both, 400);

  check('firing the quiet timer asks the other device to continue, rather than only '
    + 'describing the silence',
    g.receiver.controlsOut.filter((c) => c.kind === 'file-resume').length >= 1,
    JSON.stringify(g.receiver.controlsOut.map((c) => c.kind)));
  check('and the transfer finishes: every byte arrives and the file is kept',
    g.receiver.said('file-received').length === 1 && g.receiver.said('file-failed').length === 0,
    `received=${g.receiver.said('file-received').length} failed=${g.receiver.said('file-failed').length}`);
  check('and the sender\'s own promise settles instead of waiting for ever',
    g.outcome() === 'resolved', g.outcome());

  check('CONTROL: the harness records what the transport was HANDED and not only what it '
    + 'carried, so the "asks nothing" check in section 4 can see an attempt that failed',
    g.receiver.controlAttempts.length >= 1
      && g.receiver.controlAttempts.length >= g.receiver.controlsOut.length,
    `${g.receiver.controlAttempts.length} attempted, ${g.receiver.controlsOut.length} delivered`);

  const retry = g.receiver.said('file-stalled').map((e) => e.detail).filter((d) => d.kind === 'retrying');
  check('and the row says it is retrying, with which attempt, so a live retry does not look '
    + 'like a dead transfer',
    retry.length >= 1 && retry.some((d) => d.attempt === 1 && /attempt 1/.test(d.message)),
    JSON.stringify(retry.map((d) => ({ attempt: d.attempt, message: d.message }))));
}

// ------------------------------------- 4. the quiet timer must not shout over a known drop
{
  // The channel is DOWN and stays down. markTransfersStalled has already explained that and
  // afterReconnect drives the resume when the link returns, so the quiet timer must keep
  // watching and say nothing: two accounts of one event is how a wrong cause gets printed.
  const g = await openGate({ holdAt: 6 });
  g.wire.open = false;
  for (const end of g.both) end.link.peer.dispatchEvent(new CustomEvent('channel-close'));
  g.release();
  await settle(g.both, 60);
  const before = g.receiver.said('file-stalled').length;

  const ran = fireTimersAt(INBOUND_QUIET_MS);
  await settle(g.both, 40);

  check('CONTROL: the quiet timer really did fire while the channel was down',
    ran >= 1, `fired=${ran}`);
  // "No second account" is only a verdict if there was a first: with zero accounts this
  // check would pass over a drop nobody explained at all.
  check('CONTROL: the drop really was explained once before the quiet timer fired',
    before >= 1, `${before} accounts of the drop`);
  check('a quiet timer on a channel that is down adds no second account of the drop',
    g.receiver.said('file-stalled').length === before,
    `${before} -> ${g.receiver.said('file-stalled').length}`);
  // Scoped to THIS gate's own inbound rather than asking `timersAt` globally. The global form
  // was correct only by accident: every gate this file has built shares one timer map, so a
  // timer left armed by section 3 would have satisfied a section-4 assertion about a link that
  // armed nothing. Found in review on 2026-08-10.
  check('and it re-arms itself, so one drop does not leave the transfer unwatched for the '
    + 'rest of its life',
    Boolean(g.receiver.link.incoming?.quietTimer), `timer=${g.receiver.link.incoming?.quietTimer}`);
  // Asserted on what was ATTEMPTED and on whether requestResume was entered at all, not on
  // what arrived. The old form read controlsOut, which nothing can write to while the wire is
  // down, so it printed OK against a tree with the guard removed. The `retrying` count is the
  // half that actually moves: requestResume emits it as its first act, before it builds any
  // frame, so a quiet timer that stopped taking the early return shows up here.
  check('and it asks nothing over a channel that cannot carry the question',
    g.receiver.said('file-stalled').filter((e) => e.detail?.kind === 'retrying').length === 0
      && g.receiver.controlAttempts.filter((c) => c.kind === 'file-resume').length === 0,
    JSON.stringify({
      retrying: g.receiver.said('file-stalled').filter((e) => e.detail?.kind === 'retrying').length,
      attempted: g.receiver.controlAttempts.map((c) => c.kind),
    }));
}

// ---------------- 4b. an ACK is not bytes: the attempt count must not reset on a promise
{
  // `inbound.quietRounds = 0` used to sit in onResumeAccepted, which fires when the sender
  // says it will continue, not when anything arrives. This gate makes the sender do exactly
  // that and no more: it is parked inside driveOutbound at chunk 6, so serveResume finds the
  // streaming latch set, parks the ranges and answers with the ack alone. The receiver is told
  // "continuing" and then gets nothing, for ever, and every message said "attempt 1".
  const g = await openGate({ holdAt: 6 });
  const inbound = g.receiver.link.incoming;
  const heldBefore = inbound.received;
  const retrying = () => g.receiver.said('file-stalled').map((e) => e.detail)
    .filter((d) => d.kind === 'retrying');
  // The ack is fed to the receiver directly rather than being coaxed out of the sender. The
  // sender's send queue is serialised and this gate is holding a chunk inside it, so its own
  // `file-resume-ok` could not go out until the chunk did, which is the opposite of the case
  // under test. Everything the receiver does with it is real: judgeResumeResponse, the
  // fingerprint comparison and the re-arm all run.
  const ack = () => g.receiver.link.onResumeAccepted({
    id: inbound.meta.id,
    token: inbound.token,
    offset: inbound.sink.position,
    fingerprint: inbound.meta.fingerprint ?? null,
  });

  // The receiver's request is built and handed to its transport but goes nowhere. Without
  // this the sender's onResumeRequest would answer over a send queue that this gate is
  // holding a chunk inside, and settle() would wait on a queue that cannot drain: the sender
  // is not the subject here and its real reply is fed in by hand below.
  g.receiver.other = { deliver: () => {} };

  fireTimersAt(INBOUND_QUIET_MS);
  await settle([g.receiver], 40);
  check('CONTROL: the first quiet round asks once and calls itself attempt 1',
    retrying().length === 1 && retrying()[0].attempt === 1,
    JSON.stringify(retrying().map((d) => d.attempt)));

  await ack();
  await settle([g.receiver], 40);
  check('CONTROL: the ack was accepted and carried no bytes, which is what makes the next '
    + 'round a repeat rather than progress',
    inbound.received === heldBefore && g.receiver.said('file-resumed').length === 1,
    JSON.stringify({
      held: inbound.received, was: heldBefore,
      resumed: g.receiver.said('file-resumed').length,
    }));

  fireTimersAt(INBOUND_QUIET_MS);
  await settle([g.receiver], 40);
  check('a second quiet round after an ack that carried no bytes says attempt 2, so a '
    + 'receiver stuck in a request/ack loop can tell it is stuck',
    retrying().length === 2 && retrying()[1].attempt === 2
      && /attempt 2/.test(retrying()[1].message),
    JSON.stringify(retrying().map((d) => d.attempt)));
  g.release();
}

// --------------------------------------- 5. a severed connection has to SAY it was severed
{
  // The link is closed under a running transfer, which is what a participant leaving the
  // gate does: a sender that goes away and comes back is seated in a NEW slot with a new id,
  // so its old link is swept out of the roster and closed. The transfer riding it is dead,
  // because a different participant with a different key schedule cannot continue it.
  const g = await openGate({ holdAt: 6 });
  check('CONTROL: nothing has failed before the link is closed, so the message below is '
    + 'produced by the close and not by the drop',
    g.receiver.said('file-failed').length === 0 && g.sender.said('file-rejected').length === 0,
    JSON.stringify({
      failed: g.receiver.said('file-failed').length,
      rejected: g.sender.said('file-rejected').length,
    }));

  // Captured BEFORE the close, because close() nulls `incoming` on its way out and a figure
  // read afterwards would be read from nothing.
  const held = g.receiver.link.incoming.received;
  g.receiver.link.close('that participant is no longer in the gate');
  g.sender.link.close('that participant is no longer in the gate');
  g.release();
  await settle(g.both, 60);

  const inFail = g.receiver.lastMessage('file-failed');
  const outFail = g.sender.lastMessage('file-rejected');
  check('the receiver is told the transfer stopped rather than left with a bar that stopped '
    + 'moving',
    g.receiver.said('file-failed').length === 1, `count=${g.receiver.said('file-failed').length}`);
  check('and the message names the cause, both possibilities for it, and the next step',
    /severed/.test(inFail) && /accident or on purpose/.test(inFail)
      && /no longer in the gate/.test(inFail) && /establish a new connection/i.test(inFail),
    inFail);
  // Pinned to the receiver's OWN byte count, not to `/of \d/`. That regex cannot fail:
  // formatBytes always yields a leading digit, so "0 B of 0 B arrived" satisfied it, which is
  // the exact wrong figure this check exists to catch. Found in review on 2026-08-10.
  check('and it says how far the file got, because "it failed" without a figure is not an '
    + 'account of anything',
    held > 0 && held < SIZE
      && inFail.includes(`${formatBytes(held)} of ${formatBytes(SIZE)} arrived`),
    `${inFail} (held ${held} of ${SIZE})`);
  check('the sender is told the same thing on its own row',
    g.sender.said('file-rejected').length === 1 && /severed/.test(outFail)
      && /accident or on purpose/.test(outFail) && /establish a new connection/i.test(outFail),
    outFail);
  check('and a given-up row is a different shape from a retrying one: file-failed carries a '
    + 'reason, file-stalled carries kind:retrying',
    g.receiver.said('file-failed')[0]?.detail?.reason
      && g.receiver.said('file-failed')[0]?.detail?.kind === undefined,
    JSON.stringify(Object.keys(g.receiver.said('file-failed')[0]?.detail ?? {})));
}

// ------------------------- 5b. a cause that IS known must be said plainly, and said once
{
  // One sentence was printed for four different causes. Probed with reason = 'Gate burned.'
  // the receiver was told "The connection to the other device was severed, whether by accident
  // or on purpose: Gate burned.. 80 KB of 321 KB arrived": a hedge laid over a fact this
  // device established itself, plus a doubled full stop from appending a period to a reason
  // that already ended in one. Only dropLink's bare clause is genuinely unexplained, and
  // section 5 above is the case that keeps the hedge.
  const cases = [
    // [reason handed to close(), what the row must now say, what it must NOT say]
    ['Gate burned.', 'You burned the gate, so the connection to the other device is gone.'],
    ['The other device burned the gate.', 'The other device burned the gate.'],
    ['The gate expired.', 'The gate expired.'],
  ];
  for (const [reason, plainly] of cases) {
    const g = await openGate({ holdAt: 6 });
    const held = g.receiver.link.incoming.received;
    g.receiver.link.close(reason);
    g.sender.link.close(reason);
    g.release();
    await settle(g.both, 60);

    const inFail = g.receiver.lastMessage('file-failed');
    const outFail = g.sender.lastMessage('file-rejected');
    check(`"${reason}" is said plainly on the receiving row`,
      inFail.startsWith(`${plainly} `), inFail);
    check(`and "${reason}" is not hedged, because this device knows which it was`,
      !/accident or on purpose/.test(inFail), inFail);
    check(`and "${reason}" prints one full stop between the cause and the figure`,
      !/\.\.\s/.test(inFail) && !/\.\.$/.test(inFail), inFail);
    check(`and "${reason}" still carries the figure and the next step`,
      inFail.includes(`${formatBytes(held)} of ${formatBytes(SIZE)} arrived`)
        && /establish a new connection/i.test(inFail), inFail);
    check(`and the sender's row says the same thing for "${reason}"`,
      outFail.startsWith(`${plainly} `) && !/accident or on purpose/.test(outFail)
        && /had been sent/.test(outFail), outFail);
  }
}

// --------------------------------- 6. the sender must see that a file is waiting to be taken
{
  // sendFile awaits pendingAccept and said nothing while it waited. Anything over the
  // auto-accept threshold needs a click on the other device, so this is the ordinary path for
  // every large file: the sender's transcript was empty for as long as the other person took
  // to notice their phone.
  const wire = { open: true };
  const sender = new End('sender', wire, true);
  const receiver = new End('receiver', wire, false);
  sender.other = receiver;
  receiver.other = sender;
  // Hold the offer at the receiver so the waiting state is observable rather than a flicker.
  const held = [];
  receiver.deliver = (frame) => { held.push(frame); };

  const done = sender.link.sendFile(file, 'T-offered', fingerprint);
  done.catch(() => {});
  await settle([sender], 20);

  const offers = sender.said('file-stalled').map((e) => e.detail).filter((d) => d.kind === 'offered');
  check('the sender gets a row the moment the offer goes out, not when it is answered',
    offers.length === 1, JSON.stringify(sender.said('file-stalled').map((e) => e.detail.kind)));
  check('and it says the file is waiting on the other device and that nothing is moving yet',
    /Waiting for it to be accepted/.test(offers[0]?.message ?? '')
      && /nothing is sent/.test(offers[0]?.message ?? ''),
    offers[0]?.message);
  check('and it carries the file\'s own name and size, so the row can title itself',
    offers[0]?.name === file.name && offers[0]?.total === SIZE && offers[0]?.direction === 'out',
    JSON.stringify({ name: offers[0]?.name, total: offers[0]?.total }));
  check('CONTROL: the offer really is still unanswered, so this is the waiting state and not '
    + 'a row drawn after the fact',
    sender.link.pendingAccept !== null && sender.chunkFrames === 0,
    `pending=${Boolean(sender.link.pendingAccept)} chunks=${sender.chunkFrames}`);

  // Answering it turns the row into progress, which is the other half of the requirement:
  // the offer must not be the last thing ever said about the file.
  receiver.deliver = End.prototype.deliver.bind(receiver);
  for (const frame of held) receiver.deliver(frame);
  await settle([sender, receiver], 200);
  check('and answering it moves the same row on, rather than leaving the offer as the last '
    + 'thing said about the file',
    sender.said('file-sent').length === 1
      && sender.said('file-sent')[0].detail.id === 'T-offered',
    JSON.stringify(sender.events.map((e) => e.name)));
}

// ----------- 6b. an offer that is never answered because the connection restarted under it
{
  // THE STRANDED ROW. Section 6 proves the sender gets a row the moment the offer goes out.
  // This proves what happens when that offer is never answered: resetForRenegotiation rejects
  // the pending accept and emits NOTHING, so nothing on the event side can resolve that row.
  // app.js's catch used to skip itself whenever the row existed, on the assumption that
  // file-rejected had already spoken for it, and the row was left saying "Offered to the other
  // device. Waiting for it to be accepted there" for the life of the page.
  const wire = { open: true };
  const sender = new End('sender', wire, true);
  const receiver = new End('receiver', wire, false);
  sender.other = receiver;
  receiver.other = sender;
  receiver.deliver = () => {};

  const done = sender.link.sendFile(file, 'T-renegotiated', fingerprint);
  let outcome = 'pending';
  done.then(() => { outcome = 'resolved'; }, (err) => { outcome = `rejected: ${err.message}`; });
  await settle([sender], 20);
  const drawn = sender.said('file-stalled').filter((e) => e.detail.kind === 'offered').length;
  const before = sender.events.length;

  sender.link.resetForRenegotiation();
  await settle([sender], 20);

  check('CONTROL: the offer really was drawn and really was unanswered, so there IS a row to '
    + 'strand', drawn === 1 && sender.chunkFrames === 0, `offers=${drawn} chunks=${sender.chunkFrames}`);
  check('a renegotiation under an unanswered offer rejects the send',
    /^rejected: the connection restarted before the transfer was accepted$/.test(outcome), outcome);
  check('and emits NOTHING at all, which is why a row cannot be left to an event listener to '
    + 'resolve: this is the silence app.js has to cover from its own catch',
    sender.events.length === before,
    JSON.stringify(sender.events.slice(before).map((e) => e.name)));
}

// --------------- 7. a resume request that throws must still leave a watchdog behind it
{
  // armInboundQuiet was the last statement of requestResume rather than a `finally`, and both
  // awaits above it can reject: loadResume is a network fetch and control() reaches peer.send,
  // which throws on a channel that closed between its own readyState check and the write. The
  // quiet timer's caller re-arms in its catch, but afterReconnect's caller only logs, so a
  // throw there left the transfer with no watchdog at all: the exact unwatched state the arm
  // exists to prevent, reached through the error path of the code that prevents it.
  const g = await openGate({ holdAt: 6 });
  const inbound = g.receiver.link.incoming;
  g.receiver.link.clearInboundQuiet(inbound);
  check('CONTROL: the transfer really is unwatched before the request, so an arm that never '
    + 'happened cannot be mistaken for one that did',
    !inbound.quietTimer, `timer=${inbound.quietTimer}`);

  g.receiver.link.control = async () => { throw new Error('the channel went away mid-write'); };
  let threw = null;
  await g.receiver.link.requestResume(inbound).catch((err) => { threw = err.message; });

  check('CONTROL: the request really did throw, so this is the error path and not the happy '
    + 'one', threw === 'the channel went away mid-write', String(threw));
  check('a resume request that throws still leaves the quiet timer armed, so the transfer is '
    + 'still being watched by something',
    Boolean(inbound.quietTimer) && timers.get(inbound.quietTimer)?.ms === INBOUND_QUIET_MS,
    `timer=${inbound.quietTimer} ms=${timers.get(inbound.quietTimer)?.ms}`);
  g.release();
}

// ------------- 8. a renegotiation that crosses a reveal must not be read as a man in the middle
//
// THE FAILURE THIS PINS, measured on 2026-08-10. The browser suite's "a dropped transfer
// continues" block aborted after 180 seconds waiting for an 8 MB file to finish resuming.
// The page said why, once the log was read as it was written rather than at the end: the
// SENDER had burned its own gate, and the row on screen told both users that somebody was
// sitting between their devices.
//
// Nobody was. Both ends restart when a data channel drops, and a relayed message is not
// instant, so the two ends can be one generation apart for as long as a message is in
// flight. The responder answers commitment C1; while that answer is on the wire the
// initiator renegotiates and commits to C2; the answer lands at an initiator that has just
// dropped its own peer key, so it is taken; the initiator then reveals the key behind C2 to
// a responder still holding C1. The digests cannot match. The verdict for a reveal that does
// not open its commitment is to sever, and severing is what it did: gate burned, transfer
// lost, 1.5 MB of 8.0 MB sent.
//
// The check itself is right and stays exactly as harsh WITHIN a handshake, because there a
// mismatch really is an attack. What was missing is that the reveal never said which
// handshake it was answering, so a message that was not an answer to the question being
// asked was scored against it anyway.
{
  // Enough of an RTCPeerConnection for Peer's constructor and for connect() to reach the key
  // exchange. Nothing here depends on ICE: the question is only which generation of key
  // material each side judges the other by.
  class FakeChannel extends EventTarget {
    constructor(label) { super(); this.label = label; this.readyState = 'connecting'; this.bufferedAmount = 0; }
    send() {}
    close() { this.readyState = 'closed'; }
  }
  class FakePC extends EventTarget {
    constructor() {
      super();
      this.connectionState = 'new';
      this.iceConnectionState = 'new';
      this.iceGatheringState = 'new';
      this.signalingState = 'stable';
      this.localDescription = null;
      this.remoteDescription = null;
    }
    createDataChannel(label) { return new FakeChannel(label); }
    async createOffer() { return { type: 'offer', sdp: 'v=0 fake' }; }
    async createAnswer() { return { type: 'answer', sdp: 'v=0 fake' }; }
    async setLocalDescription(desc) { this.localDescription = desc ?? { type: 'offer', sdp: 'v=0 fake' }; }
    async setRemoteDescription(desc) { this.remoteDescription = desc; }
    async addIceCandidate() {}
    async getStats() { return new Map(); }
    restartIce() {}
    close() { this.connectionState = 'closed'; this.signalingState = 'closed'; }
  }
  const realRTC = globalThis.RTCPeerConnection;
  globalThis.RTCPeerConnection = FakePC;

  const SECRET = new Uint8Array(16).map((_, i) => i + 1);
  const sides = {};
  // Only the key exchange is relayed. ICE and SDP are dropped deliberately: an offer cannot
  // change which generation a key belongs to, and carrying them would put the whole of
  // peer.js between this test and the one thing it is asking about.
  const CARRIED = new Set(['pkc', 'pk', 'restart']);
  let hold = () => false;

  function makeHandshakeSide(name, initiator, peerName) {
    const session = {
      roomId: 'reneg-room',
      secret: SECRET,
      password: null,
      passwordGate: Promise.resolve(),
      iceServers: [],
      needsRestart: false,
      severed: false,
      links: new Map(),
      labelFor: () => peerName,
      onLinkTargetGone: () => {},
      ensurePasswordKey: async () => null,
      sever: async () => { session.severed = true; },
      teardown: () => {},
      signal: {
        send: async (message) => {
          if (!CARRIED.has(message.t)) return true;
          if (hold(name, message)) return true;
          // Delivered on a later turn, like a relayed message. A synchronous hand-off would
          // let one side finish the other's handler inside its own send, which is precisely
          // the ordering that cannot happen over a relay and would hide the bug.
          realSetTimeout(() => {
            sides[peerName].link.onSignalMessage(message)
              .catch((err) => { sides[peerName].error = err.message; });
          }, 0);
          return true;
        },
      },
    };
    const link = new Link({ session, peerId: `${name}-slot`, initiator });
    const side = { name, session, link, authFailed: [] };
    link.addEventListener('auth-failed', (e) => side.authFailed.push(e.detail));
    sides[name] = side;
    return side;
  }

  const settle = (ms = 40) => new Promise((r) => realSetTimeout(r, ms));
  // Waits for a CONDITION, not for a duration. Every handshake below runs real WebCrypto,
  // so how long one takes is a property of the machine and of whatever else is running on
  // it. A fixed sleep that is generous on an idle box is a coin toss on a loaded one, and
  // this section's first CONTROL failed exactly that way on 2026-08-10 while a browser
  // suite ran beside it: `A keys=false B keys=false` after 40ms. The ceiling is not a pass
  // either: it returns whatever the condition says at the end, and the check that follows
  // still has to hold. settle() is kept only where the assertion is that something did NOT
  // happen, which no condition can wait for.
  const waitUntil = async (fn, ms = 5000) => {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      if (fn()) return true;
      await new Promise((r) => realSetTimeout(r, 5));
    }
    return Boolean(fn());
  };
  // B offers, so B is the side that commits; A answers. Only the answering side holds a
  // commitment to judge a reveal against, so only it can reach the mismatch verdict.
  const B = makeHandshakeSide('B', true, 'A');
  const A = makeHandshakeSide('A', false, 'B');

  await B.link.connect();
  await A.link.connect();
  await waitUntil(() => A.link.sessionKeys && B.link.sessionKeys);
  check('CONTROL: the two ends really do complete a key exchange over this harness, so a '
    + 'later failure to complete one means something',
    Boolean(A.link.sessionKeys) && Boolean(B.link.sessionKeys),
    `A keys=${Boolean(A.link.sessionKeys)} B keys=${Boolean(B.link.sessionKeys)}`);

  // The drop: both ends tear down and handshake again, which is restartConnection's tier two
  // with the ICE tier and the backoff removed. A's answer is held on the wire from here.
  let held = null;
  hold = (from, message) => {
    if (from === 'A' && message.t === 'pk' && !held) { held = message; return true; }
    return false;
  };
  B.link.resetForRenegotiation();
  A.link.resetForRenegotiation();
  await B.link.connect();
  await A.link.connect();
  await waitUntil(() => held);
  const heldFor = held?.h;
  check('CONTROL: the answer really is in flight and really is bound to the handshake that '
    + 'is running, so what follows is a crossing message and not a missing one',
    Boolean(held) && heldFor === B.link.handshakeId, `held for ${heldFor}, B is on ${B.link.handshakeId}`);

  // B renegotiates once more and A defers it, which is what onSignalMessage's 'restart'
  // branch does whenever the two ends' last renegotiation straddles RESTART_SETTLE_MS. B does
  // not wait to be agreed with: restartConnection sends 'restart' and tears its half down
  // regardless. Stamped rather than slept, so the settle boundary is the variable under test.
  A.link.lastRenegotiationAt = Date.now();
  B.link.lastRenegotiationAt = 0;
  await B.link.restartConnection();
  await waitUntil(() => B.link.handshakeId && B.link.handshakeId !== heldFor);
  check('CONTROL: the two ends really are one generation apart, so the held answer really is '
    + 'stale by the time it lands',
    Boolean(B.link.handshakeId) && B.link.handshakeId !== heldFor && A.link.handshakeId === heldFor,
    `A is on ${A.link.handshakeId}, B is on ${B.link.handshakeId}`);

  hold = () => false;
  B.link.clearRestartTimer();
  await A.session.signal.send(held);
  await waitUntil(() => B.link.restartTimer);

  // Every verdict below is pass-on-absence: "no key adopted", "no sever", "nobody told".
  // A guard that THREW would satisfy all three equally well, so the handler error the
  // relay captures is read before any of them is allowed to mean anything.
  check('CONTROL: the guard judged the stale answer rather than throwing out of it',
    !B.error, `B handler error: ${B.error}`);
  check('an answer from a handshake that has been restarted is not taken as the answer to '
    + 'the current one', !B.link.peerPublicRaw, `B peer key adopted=${Boolean(B.link.peerPublicRaw)}`);
  check('and neither end burns the gate over it, because a crossing renegotiation is not a '
    + 'man in the middle',
    !A.session.severed && !B.session.severed, `A severed=${A.session.severed} B severed=${B.session.severed}`);
  check('nobody was told that somebody is sitting between the two devices',
    A.authFailed.length === 0 && B.authFailed.length === 0,
    `A said ${JSON.stringify(A.authFailed)}, B said ${JSON.stringify(B.authFailed)}`);

  // Not burning is only half of it. A gate that survives by stalling for ever has failed the
  // user in a quieter way, so the backoff that both ends fall back on has to actually get
  // them to the same generation again. Both settle windows are cleared first: this asks
  // whether the retry works, not whether it is allowed to run yet.
  A.link.lastRenegotiationAt = 0;
  B.link.lastRenegotiationAt = 0;
  const fired = fireTimersAt(2000);
  await waitUntil(() => A.link.sessionKeys && B.link.sessionKeys
    && A.link.handshakeId === B.link.handshakeId);
  check('CONTROL: a reconnect attempt really was armed by the deferral, so the recovery '
    + 'below is the product\'s own retry and not this test doing it by hand',
    fired > 0, `${fired} restart timers fired`);
  check('and the next reconnect gets both ends onto the same handshake again',
    Boolean(A.link.sessionKeys) && Boolean(B.link.sessionKeys)
      && A.link.handshakeId === B.link.handshakeId,
    `A keys=${Boolean(A.link.sessionKeys)} B keys=${Boolean(B.link.sessionKeys)} `
    + `A on ${A.link.handshakeId}, B on ${B.link.handshakeId}`);

  // THE COMMONER HALF OF THE SAME BUG, and the harsher verdict. It needs only ONE end to
  // restart while a reveal is in flight: the reveal lands on a side that has just dropped its
  // commitment, so it is not a reveal that fails to open its commitment, it is a reveal with
  // no commitment in front of it at all. That reads as a peer trying to skip the binding
  // entirely, and severs.
  let heldB = null;
  hold = (from, message) => {
    if (from === 'B' && message.t === 'pk' && !heldB) { heldB = message; return true; }
    return false;
  };
  A.link.lastRenegotiationAt = 0;
  B.link.lastRenegotiationAt = 0;
  A.link.resetForRenegotiation();
  B.link.resetForRenegotiation();
  await B.link.connect();
  await A.link.connect();
  await waitUntil(() => heldB);
  check('CONTROL: the initiator\'s reveal really is in flight and belongs to the handshake '
    + 'that is running, so the tear-down below lands under a live message and not after one',
    Boolean(heldB) && heldB.h === A.link.handshakeId,
    `held for ${heldB?.h}, A is on ${A.link.handshakeId}`);
  A.link.resetForRenegotiation();
  await A.link.connect();
  await settle();
  check('CONTROL: the side the reveal is about to land on really has dropped its commitment, '
    + 'which is what makes the reveal look unbound rather than merely wrong',
    !A.link.peerCommitment, `A commitment=${Boolean(A.link.peerCommitment)}`);

  const authFailedBefore = A.authFailed.length;
  hold = () => false;
  A.link.clearRestartTimer();
  await B.session.signal.send(heldB);
  await waitUntil(() => A.link.restartTimer);
  check('CONTROL: the guard judged the unbound reveal rather than throwing out of it',
    !A.error, `A handler error: ${A.error}`);
  check('a reveal that lands on an end which has just torn its handshake down is not read as '
    + 'a peer skipping the commitment',
    !A.session.severed && A.authFailed.length === authFailedBefore,
    `A severed=${A.session.severed}, A said ${JSON.stringify(A.authFailed.slice(authFailedBefore))}`);

  // ONE RESTART, ONE RESET. restartConnection tells the peer before it drops its own half,
  // and that message is a round trip. Until 2026-08-10 the timestamp the settle guard reads
  // was stamped inside resetForRenegotiation, which ran AFTER that await: a peer 'restart'
  // landing inside the window therefore passed the guard, reset and reconnected, and the
  // local reset that followed threw away the key pair that fresh handshake had just made.
  // The browser dumps show it as two peer connections a tenth of a second apart, and the two
  // ends a generation apart afterwards, which is the state the reveal guard above then has to
  // survive. Counted rather than inferred: a restart may cost exactly one reset.
  //
  // The peer's message is delivered from INSIDE the send, because that is the only place it
  // can land in the real system and the one place a harness that hands messages over on a
  // later turn will never put it by itself.
  A.link.lastRenegotiationAt = 0;
  B.link.lastRenegotiationAt = 0;
  A.link.resetForRenegotiation();
  B.link.resetForRenegotiation();
  hold = () => false;
  heldB = null;
  await B.link.connect();
  await A.link.connect();
  await waitUntil(() => A.link.sessionKeys && B.link.sessionKeys);
  check('CONTROL: the two ends are connected again, so what follows is a restart of a live '
    + 'handshake and not a first connection',
    Boolean(A.link.sessionKeys) && Boolean(B.link.sessionKeys),
    `A keys=${Boolean(A.link.sessionKeys)} B keys=${Boolean(B.link.sessionKeys)}`);

  let bResets = 0;
  const realReset = B.link.resetForRenegotiation.bind(B.link);
  B.link.resetForRenegotiation = () => { bResets += 1; realReset(); };
  hold = (from, message) => {
    if (from !== 'B' || message.t !== 'restart') return false;
    // Not forwarded to A: A is standing in for an end that has already restarted and is
    // announcing it, which is the case where both ends decide to renegotiate at once.
    B.link.onSignalMessage({ t: 'restart' }).catch((err) => { B.error = err.message; });
    return true;
  };
  B.link.lastRenegotiationAt = 0;
  await B.link.restartConnection();
  await waitUntil(() => bResets > 0);
  check('CONTROL: the peer\'s restart really did arrive during the send, so the count below '
    + 'is counting the race and not an ordinary restart',
    bResets > 0, `${bResets} resets`);
  check('one restart tears the handshake down once, even when the peer asks for the same '
    + 'restart while the request is still on the wire',
    bResets === 1, `${bResets} resets for one restart`);
  B.link.resetForRenegotiation = realReset;

  // The relay's catch keeps every handler error; a section that ends with one recorded
  // has been running past a crashed guard, whatever its individual verdicts said.
  check('CONTROL: no relayed handler threw anywhere in this section',
    !A.error && !B.error, `A: ${A.error} B: ${B.error}`);

  A.link.close('test over');
  B.link.close('test over');
  if (realRTC) globalThis.RTCPeerConnection = realRTC;
  else delete globalThis.RTCPeerConnection;
}

globalThis.setTimeout = realSetTimeout;
process.exit(summary('disconnect and recovery') ? 0 : 1);
