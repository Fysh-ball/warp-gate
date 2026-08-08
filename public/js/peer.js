// WebRTC peer connection and data channel.
//
// The signalling channel carries only what ICE needs, and everything it carries is
// already sealed by signal.js. This module never touches plaintext application data:
// it hands raw frames up to the caller, which decrypts them.

const CHUNK_PAUSE_BYTES = 1024 * 1024; // stop feeding the channel above this
const CHUNK_RESUME_BYTES = 256 * 1024; // and resume when it drains to here

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
  // Stage one asks only for local addresses, so it contacts nobody.
  const local = await gatherProbe([], timeoutMs);
  if (local.error) {
    return { capable: false, candidateCount: 0, headline: `Could not test WebRTC: ${local.error}`, steps: [] };
  }
  if (local.count > 0) return { capable: true, candidateCount: local.count, via: 'host' };

  // Zero local candidates does NOT prove WebRTC is blocked. Chromium's and Brave's
  // "Default public interface only" deliberately suppresses host candidates and
  // exposes only the public address, which can only be found through STUN. Treating
  // that as blocked was a false positive on precisely the setting users are told to
  // choose. So ask again, with STUN, before accusing the browser of anything.
  if (iceServers && iceServers.length) {
    const reflexive = await gatherProbe(iceServers, timeoutMs);
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
  try {
    const types = [];
    pc.createDataChannel('probe');
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((resolve) => {
      const done = setTimeout(resolve, timeoutMs);
      pc.addEventListener('icecandidate', (event) => {
        if (!event.candidate) { clearTimeout(done); resolve(); return; }
        if (event.candidate.type) types.push(event.candidate.type);
      });
    });
    return { count: types.length, types: [...new Set(types)] };
  } catch (err) {
    return { error: err.message, count: 0, types: [] };
  } finally {
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
        'Change it to "Default public interface only".',
        'Come back here and press Re-check.',
      ],
      reassurance: 'You can set this back to "Disable non-proxied UDP" once you are finished. '
        + '"Default public interface only" still hides your local network addresses.',
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
    this.pendingCandidates = [];
    this.remoteReady = false;
    this.makingOffer = false;
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
      this.emit('connection-state', state);
      if (state === 'failed') {
        this.emit('failed', 'ICE could not establish a path between the two devices');
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
    this.dispatchEvent(new CustomEvent(name, { detail }));
  }

  attachChannel(channel) {
    this.channel = channel;
    channel.binaryType = 'arraybuffer';
    channel.bufferedAmountLowThreshold = CHUNK_RESUME_BYTES;
    channel.addEventListener('open', () => this.emit('channel-open', null));
    channel.addEventListener('close', () => this.emit('channel-close', null));
    channel.addEventListener('error', (event) => {
      this.emit('warning', `data channel error: ${event.error?.message ?? 'unknown'}`);
    });
    channel.addEventListener('message', (event) => this.emit('frame', event.data));
  }

  async start() {
    if (!this.isCreator) return;
    await this.makeOffer(false);
  }

  async makeOffer(iceRestart) {
    try {
      this.makingOffer = true;
      const offer = await this.pc.createOffer({ iceRestart });
      await this.pc.setLocalDescription(offer);
      await this.deliverOffer();
    } catch (err) {
      this.emit('failed', `could not create an offer: ${err.message}`);
    } finally {
      this.makingOffer = false;
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
    if (this.pc.remoteDescription) return; // answered already
    if (!this.pc.localDescription) return;

    let delivered = false;
    try {
      delivered = await this.signal.send({ t: 'offer', sdp: this.pc.localDescription.sdp });
    } catch (err) {
      this.emit('warning', `could not send the offer: ${err.message}`);
    }
    this.emit('offer-sent', { attempt, delivered });

    if (attempt >= 6) {
      if (!this.pc.remoteDescription) {
        this.emit('warning', 'The other device never answered the connection offer.');
      }
      return;
    }
    // Re-send while unanswered. Cheap: an SDP offer is a few kilobytes.
    this.offerTimer = setTimeout(() => {
      this.offerTimer = null;
      if (!this.pc.remoteDescription) this.deliverOffer(attempt + 1);
    }, delivered ? 3000 : 1200);
  }

  /** Handle a decrypted signalling message. */
  async handleMessage(message) {
    try {
      if (message.t === 'offer') {
        await this.pc.setRemoteDescription({ type: 'offer', sdp: message.sdp });
        await this.drainCandidates();
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        await this.signal.send({ t: 'answer', sdp: this.pc.localDescription.sdp });
        return;
      }
      if (message.t === 'answer') {
        if (this.pc.signalingState === 'stable') return; // a duplicate answer is harmless
        await this.pc.setRemoteDescription({ type: 'answer', sdp: message.sdp });
        await this.drainCandidates();
        return;
      }
      if (message.t === 'ice') {
        const type = (message.candidate?.candidate ?? '').match(/ typ (\w+)/)?.[1];
        if (type) this.remoteCandidateTypes.add(type);
        if (!this.pc.remoteDescription) {
          // Candidates can arrive before the description they belong to.
          this.pendingCandidates.push(message.candidate);
          return;
        }
        await this.pc.addIceCandidate(message.candidate);
      }
    } catch (err) {
      this.emit('warning', `signalling message (${message.t}) failed: ${err.message}`);
    }
  }

  async drainCandidates() {
    const queued = this.pendingCandidates;
    this.pendingCandidates = [];
    for (const candidate of queued) {
      try {
        await this.pc.addIceCandidate(candidate);
      } catch (err) {
        this.emit('warning', `queued ICE candidate rejected: ${err.message}`);
      }
    }
  }

  /** Send a frame, honouring backpressure so a large file cannot blow the buffer. */
  async send(frame) {
    const channel = this.channel;
    if (!channel || channel.readyState !== 'open') throw new Error('data channel is not open');
    if (channel.bufferedAmount > CHUNK_PAUSE_BYTES) {
      await new Promise((resolve, reject) => {
        const onLow = () => { cleanup(); resolve(); };
        const onClose = () => { cleanup(); reject(new Error('data channel closed while waiting to drain')); };
        const cleanup = () => {
          channel.removeEventListener('bufferedamountlow', onLow);
          channel.removeEventListener('close', onClose);
        };
        channel.addEventListener('bufferedamountlow', onLow);
        channel.addEventListener('close', onClose);
      });
    }
    channel.send(frame);
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
      role: this.role,
    };
  }

  /** Turn the diagnostics into a specific cause rather than a shrug. */
  explainStall() {
    const d = this.diagnostics();

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
    return 'Both devices found public addresses but no direct path between them succeeded. This is the '
      + 'signature of a strict or symmetric NAT, common on mobile carrier networks. A relay would be '
      + 'required to connect these two networks.';
  }

  close() {
    this.closed = true;
    if (this.offerTimer) { clearTimeout(this.offerTimer); this.offerTimer = null; }
    try { this.channel?.close(); } catch (err) { void err; }
    try { this.pc.close(); } catch (err) { void err; }
    this.channel = null;
    this.pendingCandidates = [];
  }
}
