// WebRTC peer connection and data channel.
//
// The signalling channel carries only what ICE needs, and everything it carries is
// already sealed by signal.js. This module never touches plaintext application data:
// it hands raw frames up to the caller, which decrypts them.

const CHUNK_PAUSE_BYTES = 1024 * 1024; // stop feeding the channel above this
const CHUNK_RESUME_BYTES = 256 * 1024; // and resume when it drains to here

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
      return 'This browser produced no network addresses at all, which usually means peer-to-peer '
        + 'traffic is blocked outright, or an extension or policy is disabling WebRTC.';
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
