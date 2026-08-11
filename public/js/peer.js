// WebRTC peer connection and data channel.
//
// The signalling channel carries only what ICE needs, and everything it carries is
// already sealed by signal.js. This module never touches plaintext application data:
// it hands raw frames up to the caller, which decrypts them.

const CHUNK_PAUSE_BYTES = 8 * 1024 * 1024; // stop feeding the channel above this
const CHUNK_RESUME_BYTES = 2 * 1024 * 1024; // and resume when it drains to here

// Largest application chunk we will ever ask for, whatever SCTP says it could take.
// Bigger frames mean fewer AEAD seals and fewer counter increments per gigabyte, which is
// what a 30 GB transfer actually spends its time on, but they also mean a bigger stall
// when one is retransmitted and more memory pinned per queued frame.
const MAX_CHUNK_BYTES = 256 * 1024;

// The drain wait cannot rely on events alone: pc.close() closes its data channels
// WITHOUT dispatching 'close' (webrtc-pc 4.4.3), and a peer that simply stops reading
// dispatches nothing at all. So the wait also polls, and gives up rather than parking.
const DRAIN_POLL_MS = 250;
const DRAIN_TIMEOUT_MS = 30_000;

// How many ICE candidates may be held while waiting for the description they belong to.
// How long that window lasts is entirely the other side's choice, so it must be bounded.
const MAX_PENDING_CANDIDATES = 64;

/**
 * Can this browser do peer-to-peer at all?
 *
 * Two stages, because one is not enough to tell the difference between a browser that
 * is blocked and a browser that is merely private:
 *
 *   1. Gather with no ICE servers. Contacts nobody. Any candidate means yes.
 *   2. Only if that found nothing, gather again with the configured STUN server.
 *
 * Stage two exists because "Default public interface only" suppresses host candidates
 * on purpose, so a browser set exactly the way the warning recommends would otherwise
 * be reported as blocked. Only a browser that finds nothing in *both* stages truly
 * cannot connect, which is what "Disable non-proxied UDP" and WebRTC-blocking
 * extensions do.
 *
 * Returns { capable, candidateCount, via } or { capable: false, ...advice }.
 */
export async function checkWebRtcCapability(iceServers = [], timeoutMs = 5000) {
  // timeoutMs is the TOTAL budget, not a per-stage one. Bounding each stage separately
  // made a caller that asked for 5 s wait 10 s, on the startup path. Stage two only runs
  // when stage one found nothing, which means stage one ran to its own limit, so the
  // budget is split up front rather than left to whatever happens to remain.
  const deadline = Date.now() + timeoutMs;

  // Stage one asks only for local addresses, so it contacts nobody. It keeps the whole
  // budget when there is no stage two to fund.
  const hasStunServers = Boolean(iceServers && iceServers.length);
  const local = await gatherProbe([], hasStunServers ? Math.max(1, Math.round(timeoutMs * 0.6)) : timeoutMs);
  if (local.error) {
    return { capable: false, candidateCount: 0, headline: `Could not test WebRTC: ${local.error}`, steps: [] };
  }
  if (local.count > 0) return { capable: true, candidateCount: local.count, via: 'host' };

  // Zero local candidates does NOT prove WebRTC is blocked. Chromium's and Brave's
  // "Default public interface only" deliberately suppresses host candidates and
  // exposes only the public address, which can only be found through STUN. Treating
  // that as blocked was a false positive on precisely the setting users are told to
  // choose. So ask again, with STUN, before accusing the browser of anything.
  if (hasStunServers) {
    const reflexive = await gatherProbe(iceServers, Math.max(1, deadline - Date.now()));
    // A stage-two failure is an error, not evidence that the browser blocks WebRTC.
    // Falling through to blockedAdvice() told the user to change privacy settings that
    // were never the cause, which is exactly the false positive this module exists to
    // avoid. Stage one's error is surfaced honestly; stage two's must be too.
    if (reflexive.error) {
      return { capable: false, candidateCount: 0, headline: `Could not test WebRTC: ${reflexive.error}`, steps: [] };
    }
    if (reflexive.count > 0) {
      return { capable: true, candidateCount: reflexive.count, via: 'srflx' };
    }
  }

  return { capable: false, candidateCount: 0, ...blockedAdvice() };
}

/** A single gathering run. Returns { count, types } or { error }. */
async function gatherProbe(iceServers, timeoutMs) {
  let pc;
  try {
    pc = new RTCPeerConnection({ iceServers });
  } catch (err) {
    return { error: err.message, count: 0, types: [] };
  }
  let timer = null;
  try {
    const types = [];
    pc.createDataChannel('probe');

    // The listeners go on BEFORE setLocalDescription. Gathering can complete inside that
    // call, and candidates emitted in that window used to be dropped on the floor: the
    // probe then reported a browser holding a perfectly good host candidate as blocked,
    // and burned the whole timeout doing it, because the end-of-candidates event that
    // would have cleared it had already fired.
    let settle = null;
    const gathered = new Promise((resolve) => { settle = resolve; });
    const done = () => { if (timer) { clearTimeout(timer); timer = null; } settle(); };
    timer = setTimeout(done, timeoutMs);
    pc.addEventListener('icecandidate', (event) => {
      if (!event.candidate) { done(); return; }
      if (event.candidate.type) types.push(event.candidate.type);
    });
    pc.addEventListener('icegatheringstatechange', () => {
      if (pc.iceGatheringState === 'complete') done();
    });

    await pc.setLocalDescription(await pc.createOffer());
    // Gathering may already have finished, in which case no further event is coming.
    if (pc.iceGatheringState === 'complete') done();
    await gathered;
    return { count: types.length, types: [...new Set(types)] };
  } catch (err) {
    return { error: err.message, count: 0, types: [] };
  } finally {
    if (timer) clearTimeout(timer);
    try { pc.close(); } catch (err) { void err; }
  }
}

/**
 * Advice for a browser that gathers nothing, tailored to the browser in use.
 *
 * `settingsPath` is deliberately not rendered as a link: Chromium blocks web pages
 * from navigating to brave:// and chrome:// URLs, and window.open returns null, so a
 * link would simply appear broken. It is offered as one-tap copy instead.
 */
function blockedAdvice() {
  const ua = navigator.userAgent || '';
  const isBrave = typeof navigator.brave !== 'undefined';
  const isFirefox = ua.includes('Firefox');

  if (isBrave) {
    return {
      browser: 'Brave',
      headline: 'Brave is blocking WebRTC on this device, so it cannot connect directly to another device.',
      settingsPath: 'brave://settings/privacy',
      steps: [
        'Copy the settings address below and paste it into a new tab.',
        'Find "WebRTC IP handling policy".',
        'Change it to "Default public and private interfaces".',
        'Come back here and press Re-check.',
      ],
      reassurance: 'You can set this back afterwards. Chromium still hides your real local '
        + 'addresses from web pages behind mDNS names, so this is not the same as exposing them.',
    };
  }
  if (isFirefox) {
    return {
      browser: 'Firefox',
      headline: 'WebRTC is disabled in this Firefox, so it cannot connect directly to another device.',
      settingsPath: 'about:config',
      steps: [
        'Copy the settings address below and paste it into a new tab.',
        'Search for media.peerconnection.enabled.',
        'Set it to true.',
        'Come back here and press Re-check.',
      ],
      reassurance: 'You can set it back to false when you are finished.',
    };
  }
  return {
    browser: null,
    headline: 'This browser produced no network addresses, so it cannot connect directly to another device.',
    settingsPath: null,
    steps: [
      'Check for a privacy extension that blocks WebRTC, and pause it for this site.',
      'Check your browser settings for a WebRTC or IP-handling option.',
      'Then press Re-check.',
    ],
    reassurance: 'You can turn any of it back on once you are finished.',
  };
}

/**
 * Advice for a browser that gathers a public address but no local ones.
 *
 * "Default public interface only" suppresses host candidates. That still connects
 * across networks, but two devices on the *same* network then have to reach each
 * other via their shared public address, which needs NAT hairpinning that many home
 * routers do not perform. Verified: two peers in one browser on one machine fail to
 * connect under this setting.
 */
export function hostSuppressedAdvice() {
  const isBrave = typeof navigator.brave !== 'undefined';
  return {
    browser: isBrave ? 'Brave' : null,
    headline: 'This browser hides local network addresses, so two devices on the same network '
      + 'may not be able to reach each other. Connections between different networks still work.',
    settingsPath: isBrave ? 'brave://settings/privacy' : null,
    steps: isBrave
      ? [
        'Only needed if a same-network connection fails.',
        'Copy the settings address below and paste it into a new tab.',
        'Set "WebRTC IP handling policy" to "Default public and private interfaces".',
        'Come back here and press Re-check.',
      ]
      : [
        'Only needed if a same-network connection fails.',
        'Allow local addresses in your browser\'s WebRTC or IP-handling setting.',
        'Then press Re-check.',
      ],
    reassurance: 'Chromium still hides your real local addresses from web pages behind mDNS '
      + 'names, so allowing them is not the same as exposing them.',
  };
}

export class Peer extends EventTarget {
  constructor({ role, iceServers, signal }) {
    super();
    this.role = role;
    this.isCreator = role === 'a';
    this.signal = signal;
    this.pc = new RTCPeerConnection({
      iceServers,
      // No relay in v1. Left as configuration so adding TURN is a config change.
      iceTransportPolicy: 'all',
      bundlePolicy: 'max-bundle',
    });
    this.channel = null;
    this.channelListeners = null;
    // True once this connection has actually carried data. Everything explainStall says
    // depends on it: a stall before a connection and a stall after one have almost nothing
    // in common, and describing the second as the first is how a peer that simply walked
    // away got reported as a symmetric NAT that needs a relay.
    this.wasConnected = false;
    this.pendingCandidates = [];
    this.candidateOverflowWarned = false;
    this.remoteReady = false;
    this.closed = false;
    this.offerTimer = null;
    // Latched the moment an answer is seen, before setRemoteDescription is awaited.
    this.answered = false;
    this.appliedOfferSdp = null;
    // Pending send() drain waits, so close() can settle them instead of leaving them parked.
    this.drainWaiters = new Set();
    // Kept so a stalled connection can explain itself instead of just spinning.
    this.localCandidateTypes = new Set();
    this.remoteCandidateTypes = new Set();
    this.hadIceServers = (iceServers ?? []).length > 0;

    this.pc.addEventListener('icecandidate', (event) => {
      if (event.candidate) {
        if (event.candidate.type) this.localCandidateTypes.add(event.candidate.type);
        this.emit('candidate', { types: [...this.localCandidateTypes] });
        this.signal.send({ t: 'ice', candidate: event.candidate.toJSON() })
          .catch((err) => this.emit('warning', `could not send an ICE candidate: ${err.message}`));
      } else {
        this.emit('gathering-complete', { types: [...this.localCandidateTypes] });
      }
    });

    this.pc.addEventListener('iceconnectionstatechange', () => {
      this.emit('ice-state', this.pc.iceConnectionState);
    });

    this.pc.addEventListener('connectionstatechange', () => {
      const state = this.pc.connectionState;
      // Latched, never cleared. Once a path has carried traffic, no later stall can
      // honestly be described as "no path could be found": one was, and it worked.
      if (state === 'connected') this.wasConnected = true;
      this.emit('connection-state', state);
      if (state === 'failed') {
        this.emit('failed', this.wasConnected
          ? 'the connection between the two devices dropped'
          : 'ICE could not establish a path between the two devices');
      }
    });

    if (this.isCreator) {
      // The creator owns the channel. Ordered and reliable, so the frame counter can
      // be strictly increasing without a reordering window.
      this.attachChannel(this.pc.createDataChannel('wg', { ordered: true }));
    } else {
      this.pc.addEventListener('datachannel', (event) => this.attachChannel(event.channel));
    }
  }

  emit(name, detail) {
    // Silent after teardown: the peer connection dispatches its own state changes as it
    // closes, and the app has already stopped caring by then.
    if (this.closed) return;
    this.dispatchEvent(new CustomEvent(name, { detail }));
  }

  attachChannel(channel) {
    this.channel = channel;
    channel.binaryType = 'arraybuffer';
    channel.bufferedAmountLowThreshold = CHUNK_RESUME_BYTES;
    // Kept by name so close() can take them off again. Dropping only Peer's reference to
    // the channel left four live listeners behind, each of which emits to the app.
    this.channelListeners = {
      // An open data channel is proof a path exists, and it can be observed before
      // connectionState reaches 'connected', so both places latch it.
      open: () => { this.wasConnected = true; this.emit('channel-open', null); },
      close: () => this.emit('channel-close', null),
      error: (event) => this.emit('warning', `data channel error: ${event.error?.message ?? 'unknown'}`),
      message: (event) => this.emit('frame', event.data),
    };
    for (const [name, fn] of Object.entries(this.channelListeners)) channel.addEventListener(name, fn);
  }

  clearOfferTimer() {
    if (this.offerTimer) { clearTimeout(this.offerTimer); this.offerTimer = null; }
  }

  async start() {
    if (!this.isCreator) return;
    await this.makeOffer(false);
  }

  async makeOffer(iceRestart) {
    // A second chain must not leave the first one's timer running: only one timer is
    // tracked, so the older chain would keep re-sending with its own attempt counter and
    // close() could never reach it.
    this.clearOfferTimer();
    // A fresh offer is by definition unanswered. This is also what makes an ICE restart
    // work at all: a restart always follows an answer, so without reopening the latch its
    // offer would be created, set locally, and never sent.
    this.answered = false;
    try {
      const offer = await this.pc.createOffer({ iceRestart });
      if (this.closed || this.pc.signalingState === 'closed') return;
      await this.pc.setLocalDescription(offer);
      if (this.closed || this.pc.signalingState === 'closed') return;
      await this.deliverOffer();
    } catch (err) {
      this.emit('failed', `could not create an offer: ${err.message}`);
    }
  }

  /**
   * Send the offer, and keep sending it until an answer comes back.
   *
   * The relay reports delivered:false when the other side has no live stream, and a
   * dropped offer used to be lost forever: the joiner would sit with no ICE activity
   * at all, which is exactly what "it never connects" looked like. Retrying also
   * covers a peer whose stream reconnects a moment later.
   */
  async deliverOffer(attempt = 0) {
    if (this.closed || this.pc.signalingState === 'closed') return;
    // `answered` rather than `remoteDescription`: setRemoteDescription is genuinely async
    // and throughout that window remoteDescription is still null, so this guard used to
    // wave a redundant offer through and force the joiner into a pointless renegotiation
    // whose answer was then silently discarded as "stable".
    if (this.answered) return;
    if (!this.pc.localDescription) return;

    let delivered = false;
    try {
      delivered = await this.signal.send({ t: 'offer', sdp: this.pc.localDescription.sdp });
    } catch (err) {
      this.emit('warning', `could not send the offer: ${err.message}`);
    }
    // Re-check after the await: close() may have landed while the send was in flight, and
    // it can only clear a timer that already exists.
    if (this.closed || this.pc.signalingState === 'closed') return;
    this.emit('offer-sent', { attempt, delivered });

    if (attempt >= 6) {
      if (!this.answered) {
        this.emit('warning', 'The other device never answered the connection offer.');
      }
      return;
    }
    // Re-send while unanswered. Cheap: an SDP offer is a few kilobytes.
    this.offerTimer = setTimeout(() => {
      this.offerTimer = null;
      if (!this.answered) this.deliverOffer(attempt + 1);
    }, delivered ? 3000 : 1200);
  }

  /** Handle a decrypted signalling message. */
  async handleMessage(message) {
    try {
      if (message.t === 'offer') {
        // The creator re-sends its offer until it sees an answer, so the same offer
        // arrives more than once as a matter of course. Renegotiating on every copy
        // throws away the answer already in flight. But a repeat exists precisely because
        // the creator has not seen an answer, so re-send the existing one rather than
        // going quiet: that is the case the creator's retry is there to recover.
        if (this.appliedOfferSdp === message.sdp) {
          if (this.pc.localDescription?.type === 'answer') {
            await this.signal.send({ t: 'answer', sdp: this.pc.localDescription.sdp });
          }
          return;
        }
        this.appliedOfferSdp = message.sdp;
        await this.pc.setRemoteDescription({ type: 'offer', sdp: message.sdp });
        await this.drainCandidates();
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        await this.signal.send({ t: 'answer', sdp: this.pc.localDescription.sdp });
        return;
      }
      if (message.t === 'answer') {
        if (this.answered) return; // a duplicate answer is harmless
        // Latch synchronously, BEFORE the await below. setRemoteDescription is genuinely
        // async, and the retry timer firing inside that window is what re-sent an offer
        // that had already been answered.
        this.answered = true;
        this.clearOfferTimer();
        if (this.pc.signalingState === 'stable') return;
        await this.pc.setRemoteDescription({ type: 'answer', sdp: message.sdp });
        await this.drainCandidates();
        return;
      }
      if (message.t === 'ice') {
        // Only the four ICE types the spec defines. `\w+` accepted any token the other
        // side cared to invent, and every distinct one joined a Set that is never cleared
        // and is copied into an array on every diagnostics() call.
        const type = (message.candidate?.candidate ?? '').match(/ typ (host|srflx|prflx|relay)\b/)?.[1];
        if (type) this.remoteCandidateTypes.add(type);
        if (!this.pc.remoteDescription) {
          // Candidates can arrive before the description they belong to. Bounded, because
          // how long that window stays open is the other side's decision, not ours.
          if (this.pendingCandidates.length >= MAX_PENDING_CANDIDATES) {
            if (!this.candidateOverflowWarned) {
              this.candidateOverflowWarned = true;
              this.emit('warning', `more than ${MAX_PENDING_CANDIDATES} network candidates arrived `
                + 'before a connection offer; the rest are being ignored.');
            }
            return;
          }
          this.pendingCandidates.push(message.candidate);
          return;
        }
        await this.pc.addIceCandidate(message.candidate);
      }
    } catch (err) {
      // Let a re-delivered offer be applied again if applying it failed.
      if (message.t === 'offer') this.appliedOfferSdp = null;
      this.emit('warning', `signalling message (${message.t}) failed: ${err.message}`);
    }
  }

  async drainCandidates() {
    const queued = this.pendingCandidates;
    this.pendingCandidates = [];
    let rejected = 0;
    let firstError = null;
    for (const candidate of queued) {
      try {
        await this.pc.addIceCandidate(candidate);
      } catch (err) {
        rejected += 1;
        if (!firstError) firstError = err.message;
      }
    }
    // One summary, not one warning per candidate: the queue is sized by the other side.
    if (rejected > 0) {
      this.emit('warning', `${rejected} of ${queued.length} queued network candidates were rejected (${firstError})`);
    }
  }

  /** Send a frame, honouring backpressure so a large file cannot blow the buffer. */
  async send(frame) {
    const channel = this.channel;
    if (!channel || channel.readyState !== 'open') throw new Error('data channel is not open');
    if (channel.bufferedAmount > CHUNK_PAUSE_BYTES) {
      await new Promise((resolve, reject) => {
        // 'bufferedamountlow' and 'close' are both events that may simply never arrive:
        // pc.close() closes the channel without dispatching 'close', and a peer that
        // stops reading dispatches nothing. Waiting on events alone wedged send() -- and
        // with it session.sendFile's `for await` -- forever, listeners still attached.
        // Running time, not wall-clock time. A backgrounded tab has its timers clamped to
        // about a second and a frozen one runs none at all, while Date.now() keeps moving,
        // so a fixed wall-clock deadline fires the moment the page thaws and reports the
        // peer as dead for something this page did. link.js guards its two auth timers with
        // sleptThrough() for exactly this reason; that helper is not importable from here,
        // and it does not need to be: a poll that was due 250ms ago and ran 40s ago says the
        // same thing more directly. Only the OVERSHOOT is given back, so a hidden page that
        // is genuinely blocked still times out, at roughly four times the interval a clamped
        // poll can measure, rather than never.
        let deadline = Date.now() + DRAIN_TIMEOUT_MS;
        let lastTick = Date.now();
        let poll = null;
        const cleanup = () => {
          if (poll) { clearInterval(poll); poll = null; }
          this.drainWaiters.delete(onClose);
          channel.removeEventListener('bufferedamountlow', onLow);
          channel.removeEventListener('close', onClose);
        };
        const onLow = () => { cleanup(); resolve(); };
        const onClose = () => { cleanup(); reject(new Error('data channel closed while waiting to drain')); };
        poll = setInterval(() => {
          const now = Date.now();
          const late = now - lastTick - DRAIN_POLL_MS;
          lastTick = now;
          if (late > 0) deadline += late;
          if (channel.readyState !== 'open') { onClose(); return; }
          if (channel.bufferedAmount <= CHUNK_RESUME_BYTES) { cleanup(); resolve(); return; }
          if (now >= deadline) {
            cleanup();
            reject(new Error(`the other device stopped accepting data (nothing sent for ${DRAIN_TIMEOUT_MS / 1000}s)`));
          }
        }, DRAIN_POLL_MS);
        channel.addEventListener('bufferedamountlow', onLow);
        channel.addEventListener('close', onClose);
        // close() settles these directly, so teardown does not have to wait for a poll.
        this.drainWaiters.add(onClose);
      });
    }
    channel.send(frame);
  }

  /**
   * The largest application chunk this connection can carry in one datachannel message.
   *
   * SCTP negotiates a maximum message size and a message over it is REJECTED, not split, so
   * this is a hard ceiling rather than a preference. It is only knowable once the SCTP
   * transport exists (pc.sctp is null before that), which is why this is read at send time
   * and not at construction.
   *
   * `floor` is returned whenever the answer is unavailable, implausible, or smaller than
   * the floor: a browser that reports nothing must produce the conservative size that has
   * always worked, never a guess.
   */
  maxChunkBytes(overheadBytes, floor) {
    const reported = Number(this.pc.sctp?.maxMessageSize);
    if (!Number.isFinite(reported) || reported <= 0) return floor;
    // Firefox reports 1073741823 here, so this is clamped by our own ceiling rather than
    // by trusting the peer's number.
    const usable = Math.min(reported - overheadBytes, MAX_CHUNK_BYTES);
    if (!Number.isFinite(usable) || usable < floor) return floor;
    // A whole number of KiB, so the same connection always produces the same size and a
    // resume offset stays chunk-aligned.
    return Math.floor(usable / 1024) * 1024;
  }

  /**
   * Report how the connection is actually routed, so the UI can say DIRECT rather
   * than assume it. Returns 'host' | 'srflx' | 'prflx' | 'relay' | null.
   */
  async routeType() {
    try {
      const stats = await this.pc.getStats();
      let pair = null;
      for (const report of stats.values()) {
        if (report.type === 'candidate-pair' && report.state === 'succeeded' && report.nominated !== false) {
          if (!pair || (report.bytesSent ?? 0) >= (pair.bytesSent ?? 0)) pair = report;
        }
      }
      if (!pair) return null;
      const local = [...stats.values()].find((r) => r.id === pair.localCandidateId);
      const remote = [...stats.values()].find((r) => r.id === pair.remoteCandidateId);
      if (!local || !remote) return null;
      if (local.candidateType === 'relay' || remote.candidateType === 'relay') return 'relay';
      return local.candidateType ?? null;
    } catch (err) {
      this.emit('warning', `could not read connection stats: ${err.message}`);
      return null;
    }
  }

  /**
   * Everything needed to explain a stalled connection in plain language.
   * `srflx` is the one that matters: without a server-reflexive candidate the two
   * devices cannot find each other across different networks.
   */
  diagnostics() {
    const local = [...this.localCandidateTypes];
    const remote = [...this.remoteCandidateTypes];
    return {
      local,
      remote,
      hadIceServers: this.hadIceServers,
      gotReflexive: local.includes('srflx') || local.includes('relay'),
      peerGotReflexive: remote.includes('srflx') || remote.includes('relay'),
      iceGathering: this.pc.iceGatheringState,
      iceConnection: this.pc.iceConnectionState,
      connection: this.pc.connectionState,
      signaling: this.pc.signalingState,
      sentDescription: Boolean(this.pc.localDescription),
      gotDescription: Boolean(this.pc.remoteDescription),
      wasConnected: this.wasConnected,
      role: this.role,
    };
  }

  /**
   * Turn the diagnostics into a specific cause rather than a shrug.
   *
   * `peerLeft` is what the SIGNALLING channel observed: the server reports a peer whose
   * event stream went away. That is a different fact from anything ICE knows, and it is
   * usually the true cause, so it is passed in rather than guessed at.
   */
  explainStall({ peerLeft = false } = {}) {
    const d = this.diagnostics();

    // This branch comes before every other one, and it is not an optimisation.
    //
    // Everything below diagnoses a connection that never formed: no reflexive candidate,
    // no host candidate, a NAT that could not be traversed. None of that can be true of a
    // connection that WAS established, because establishing it is the proof that a usable
    // path existed. Reporting "both devices found public addresses but no direct path
    // succeeded, the signature of a strict or symmetric NAT, a relay would be required" to
    // someone whose transfer had just completed over HOST candidates on their own LAN is
    // not a vague message, it is a false one, and it sends them off to change networks to
    // fix a problem they do not have.
    if (d.wasConnected) {
      if (peerLeft) {
        return 'The other device left the gate: its page was closed, put to sleep, or lost its '
          + 'network. This gate is still open and will reconnect by itself if that device comes back.';
      }
      return 'The two devices were connected and the path between them dropped. This is not a '
        + 'network-compatibility problem: a direct path existed and was carrying data. The usual '
        + 'causes are one side changing network, losing signal, or backgrounding the page. This '
        + 'gate is still open and is trying to reconnect.';
    }

    // Check this first. If no descriptions were exchanged, ICE never ran at all, and
    // blaming STUN would be wrong: nothing had yet asked STUN anything.
    if (!d.gotDescription) {
      return d.role === 'a'
        ? 'The other device never answered the connection offer. It may have closed the page, lost '
          + 'its connection, or never finished loading. Ask it to open the link again.'
        : 'No connection offer arrived from the other device, so this one never started connecting. '
          + 'The other side may have closed the page or lost its connection.';
    }
    if (!d.hadIceServers) {
      return 'No STUN server is configured, so this browser could only find local network addresses. '
        + 'Connections work on the same network and nowhere else.';
    }
    if (d.local.length === 0) {
      // Gathering that finishes having produced nothing is browser policy, not the
      // network: even an offline machine yields a host candidate. Reuse the same
      // advice the capability banner gives, so the two never contradict each other.
      const advice = blockedAdvice();
      return `${advice.headline} This is a browser setting rather than a network problem`
        + `${advice.settingsPath ? `, in ${advice.settingsPath}` : ''}. ${advice.reassurance ?? ''}`;
    }
    if (!d.gotReflexive) {
      return 'This device could not discover its public address: the network appears to be blocking '
        + 'the STUN server. A firewall, a captive portal or a restrictive corporate network usually causes this.';
    }
    if (!d.peerGotReflexive && d.remote.length > 0) {
      return 'The other device could not discover its public address, so no usable path exists between you. '
        + 'Its network is likely blocking STUN.';
    }
    if (d.remote.length === 0) {
      return 'No network candidates arrived from the other device. It may have closed the page, lost '
        + 'connectivity, or be on a network that blocks peer-to-peer traffic entirely.';
    }
    const noHostEither = !d.local.includes('host') && !d.remote.includes('host');
    if (noHostEither) {
      // Both sides advertised only their public address. On the same network that
      // requires the router to hairpin, which many do not do.
      return 'Both devices advertised only their public address and no local one, so if they are on '
        + 'the same network there is no usable path between them: that needs NAT hairpinning, which '
        + 'many home routers do not perform. Allow local addresses in your browser\'s WebRTC setting, '
        + 'or put the two devices on different networks.';
    }
    return 'Both devices found public addresses but no direct path between them succeeded. This is the '
      + 'signature of a strict or symmetric NAT, common on mobile carrier networks. A relay would be '
      + 'required to connect these two networks.';
  }

  close() {
    this.closed = true;
    this.clearOfferTimer();
    const channel = this.channel;
    if (channel && this.channelListeners) {
      for (const [name, fn] of Object.entries(this.channelListeners)) channel.removeEventListener(name, fn);
    }
    this.channelListeners = null;
    try { channel?.close(); } catch (err) { void err; }
    try { this.pc.close(); } catch (err) { void err; }
    // pc.close() closes the channel without a 'close' event, so anything parked in send()
    // has to be told here or it never settles.
    const waiters = [...this.drainWaiters];
    this.drainWaiters.clear();
    for (const fail of waiters) fail();
    this.channel = null;
    this.pendingCandidates = [];
  }
}
