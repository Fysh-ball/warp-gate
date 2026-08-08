// Session orchestration: the protocol state machine that ties the room secret, the
// signalling channel, the peer connection and the frame layer together.
//
// The UI in app.js subscribes to events from here and never touches crypto directly.

import {
  deriveRoomId, deriveSignalKey, generateKeyPair, deriveSession, Channel,
  b64u, TYPE, equalCt, decodeJson, decodeText, encodeText, typeName,
} from './crypto.js';
import { Signal, createRoom, joinRoom } from './signal.js';
import { Peer } from './peer.js';
import { CHUNK_BYTES, readChunks, createSink, canAccept, formatBytes } from './transfer.js';

export const STATE = {
  IDLE: 'idle',
  CREATING: 'creating',
  WAITING: 'waiting-for-peer',
  EXCHANGING: 'exchanging-keys',
  NEGOTIATING: 'negotiating',
  CONNECTING: 'connecting',
  CONFIRMING: 'confirming',
  CONNECTED: 'connected',
  AUTH_FAILED: 'auth-failed',
  SEVERED: 'severed',
};

const CONFIRM_TIMEOUT_MS = 8000;
const MAX_AUTH_FAILURES = 3;

export class Session extends EventTarget {
  constructor({ secret, iceServers }) {
    super();
    this.secret = secret;
    this.iceServers = iceServers;
    this.state = STATE.IDLE;
    this.role = null;
    this.roomId = null;
    this.channel = null;
    this.peer = null;
    this.signal = null;
    this.keyPair = null;
    this.peerPublicRaw = null;
    this.sessionKeys = null;
    this.confirmedByPeer = false;
    this.confirmSent = false;
    this.incoming = null;
    this.sendQueue = Promise.resolve();
    this.severed = false;
    this.confirmTimer = null;
  }

  emit(name, detail) { this.dispatchEvent(new CustomEvent(name, { detail })); }

  setState(state, detail) {
    if (this.state === state) return;
    this.state = state;
    this.emit('state', { state, detail });
  }

  // ------------------------------------------------------------ lifecycle

  async create(sessionMinutes) {
    this.role = 'a';
    this.setState(STATE.CREATING);
    this.roomId = await deriveRoomId(this.secret);
    const room = await createRoom(this.roomId, sessionMinutes);
    this.expiresAt = room.expiresAt;
    await this.openSignal(room.token);
    this.setState(STATE.WAITING);
    return room;
  }

  async join() {
    this.role = 'b';
    this.setState(STATE.CREATING);
    this.roomId = await deriveRoomId(this.secret);
    const room = await joinRoom(this.roomId);
    this.expiresAt = room.expiresAt;
    await this.openSignal(room.token);
    return room;
  }

  async openSignal(token) {
    const signalKey = await deriveSignalKey(this.secret);
    this.signal = new Signal({ roomId: this.roomId, token, signalKey });

    this.signal.addEventListener('hello', (event) => {
      if (event.detail?.peerPresent) this.beginHandshake();
    });
    this.signal.addEventListener('peer-joined', () => this.beginHandshake());
    this.signal.addEventListener('peer-left', () => {
      if (this.state !== STATE.SEVERED) this.emit('peer-left', 'The other device disconnected.');
    });
    this.signal.addEventListener('closed', (event) => {
      const reason = event.detail?.reason ?? 'closed';
      this.teardown(reason === 'ttl' ? 'The gate expired.' : 'The other device severed the gate.');
    });
    this.signal.addEventListener('undecryptable', (event) => {
      // Someone is in the room without the room secret. Not fatal, but the user
      // should know a device failed verification rather than see silence.
      this.emit('intruder', event.detail);
    });
    this.signal.addEventListener('message', (event) => this.onSignalMessage(event.detail));
    this.signal.addEventListener('reconnecting', () => this.emit('warning', 'Signalling connection interrupted, retrying.'));
    this.signal.connect();
  }

  async beginHandshake() {
    if (this.keyPair) return; // already under way
    this.setState(STATE.EXCHANGING);
    this.keyPair = await generateKeyPair();
    if (this.keyPair.privateExtractable) {
      this.emit('warning', 'This browser would not create a non-extractable key; key hygiene is degraded.');
    }
    this.peer = new Peer({ role: this.role, iceServers: this.iceServers, signal: this.signal });
    this.wirePeer();
    await this.signal.send({ t: 'pk', pk: b64u.encode(this.keyPair.publicRaw) });

    // The peer's public key can arrive before generateKeyPair() above resolves. In that
    // case onSignalMessage stored it and returned without deriving, because we had no
    // key of our own yet. Deriving here covers that ordering; deriveKeys is idempotent.
    await this.deriveKeys();

    if (this.role === 'a') {
      this.setState(STATE.NEGOTIATING);
      await this.peer.start();
    }
  }

  wirePeer() {
    this.peer.addEventListener('channel-open', () => {
      this.setState(STATE.CONFIRMING);
      this.maybeConfirm();
    });
    this.peer.addEventListener('channel-close', () => {
      if (!this.severed && this.state === STATE.CONNECTED) this.emit('warning', 'The data channel closed.');
    });
    this.peer.addEventListener('frame', (event) => this.onFrame(event.detail));
    this.peer.addEventListener('connection-state', (event) => {
      this.emit('connection-state', event.detail);
      if (event.detail === 'connecting' && this.state === STATE.NEGOTIATING) this.setState(STATE.CONNECTING);
    });
    this.peer.addEventListener('failed', (event) => {
      this.emit('unreachable', event.detail);
      this.setState(STATE.AUTH_FAILED, event.detail);
    });
    this.peer.addEventListener('warning', (event) => this.emit('warning', event.detail));
  }

  async onSignalMessage(message) {
    if (!message || typeof message.t !== 'string') return;
    if (message.t === 'pk') {
      if (this.peerPublicRaw) return;
      this.peerPublicRaw = b64u.decode(message.pk);
      await this.deriveKeys();
      return;
    }
    if (message.t === 'sever') {
      this.teardown('The other device severed the gate.');
      return;
    }
    if (!this.peer) await this.beginHandshake();
    await this.peer.handleMessage(message);
  }

  async deriveKeys() {
    if (!this.keyPair || !this.peerPublicRaw || this.sessionKeys) return;
    try {
      this.sessionKeys = await deriveSession({
        secret: this.secret,
        privateKey: this.keyPair.privateKey,
        publicRaw: this.keyPair.publicRaw,
        peerPublicRaw: this.peerPublicRaw,
        role: this.role,
        roomId: this.roomId,
      });
    } catch (err) {
      this.setState(STATE.AUTH_FAILED, `key agreement failed: ${err.message}`);
      return;
    }
    this.channel = new Channel(this.sessionKeys);
    this.emit('sas', this.sessionKeys.sas);
    this.maybeConfirm();
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

  // ------------------------------------------------------------ frames

  async onFrame(raw) {
    if (!this.channel) return;
    let opened;
    try {
      opened = await this.channel.open(raw);
    } catch (err) {
      this.emit('frame-rejected', err.message);
      if (this.channel.authFailures >= MAX_AUTH_FAILURES) {
        this.emit('auth-failed', `${this.channel.authFailures} frames failed authentication. Severing.`);
        await this.sever();
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
      if (!expected || !equalCt(b64u.decode(control.value), expected)) {
        this.setState(STATE.AUTH_FAILED, 'key confirmation mismatch');
        this.emit('auth-failed', 'The other device proved it does not hold the same room secret.');
        await this.sever();
        return;
      }
      this.confirmedByPeer = true;
      if (this.confirmTimer) { clearTimeout(this.confirmTimer); this.confirmTimer = null; }
      this.setState(STATE.CONNECTED);
      const route = await this.peer.routeType();
      this.emit('route', route);
      return;
    }
    if (control.kind === 'sever') { this.teardown('The other device severed the gate.'); return; }
    if (control.kind === 'file-accept') { this.emit('file-accepted', control); return; }
    if (control.kind === 'file-reject') { this.emit('file-rejected', control); return; }
    if (control.kind === 'file-progress') { this.emit('file-progress', { direction: 'out', ...control }); return; }
    if (control.kind === 'file-complete') { this.emit('file-complete', { direction: 'out', ...control }); return; }
    this.emit('warning', `ignored unknown control message "${control.kind}"`);
  }

  // ------------------------------------------------------------ sending

  /** Serialise sends so a file transfer cannot interleave its own frames. */
  enqueue(task) {
    this.sendQueue = this.sendQueue.then(task, task);
    return this.sendQueue;
  }

  requireConnected() {
    if (this.state !== STATE.CONNECTED) throw new Error('the gate is not connected');
  }

  async sendChat(text) {
    this.requireConnected();
    return this.enqueue(async () => {
      await this.peer.send(await this.channel.seal(TYPE.CHAT, encodeText(text)));
      this.emit('chat', { from: 'me', text });
    });
  }

  async sendSecret(text) {
    this.requireConnected();
    return this.enqueue(async () => {
      await this.peer.send(await this.channel.seal(TYPE.SECRET, encodeText(text)));
      this.emit('secret', { from: 'me', text });
    });
  }

  async sendFile(file) {
    this.requireConnected();
    const id = b64u.encode(globalThis.crypto.getRandomValues(new Uint8Array(8)));
    return this.enqueue(async () => {
      // Name, MIME type and size travel inside the ciphertext. The server never sees
      // any of them (DESIGN.md 1.4, section 8).
      await this.peer.send(await this.channel.sealJson(TYPE.FILE_START, {
        id, name: file.name, mime: file.type || 'application/octet-stream', size: file.size, chunkSize: CHUNK_BYTES,
      }));

      let sent = 0;
      let chunks = 0;
      for await (const chunk of readChunks(file, CHUNK_BYTES)) {
        if (this.severed) throw new Error('gate severed during transfer');
        await this.peer.send(await this.channel.seal(TYPE.FILE_CHUNK, chunk));
        sent += chunk.byteLength;
        chunks += 1;
        if (chunks % 32 === 0) this.emit('file-progress', { direction: 'out', id, sent, total: file.size, name: file.name });
      }

      await this.peer.send(await this.channel.sealJson(TYPE.FILE_END, { id, bytes: sent, chunks }));
      this.emit('file-progress', { direction: 'out', id, sent, total: file.size, name: file.name });
      this.emit('file-sent', { id, name: file.name, size: file.size });
    });
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
    this.incoming = { meta, received: 0, chunks: 0, sink: null };
    this.emit('file-offered', meta);
  }

  /** Called by the UI, from a user gesture, so showSaveFilePicker is allowed. */
  async acceptIncoming() {
    if (!this.incoming) throw new Error('no incoming file to accept');
    this.incoming.sink = await createSink(this.incoming.meta);
    await this.control({ kind: 'file-accept', id: this.incoming.meta.id });
    this.emit('file-accepted-local', {
      ...this.incoming.meta,
      sink: this.incoming.sink.kind,
      note: this.incoming.sink.note ?? null,
    });
  }

  async onFileChunk(bytes) {
    const inbound = this.incoming;
    if (!inbound) { this.emit('warning', 'received a file chunk with no transfer in progress'); return; }
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
    if (inbound.early?.length) {
      for (const held of inbound.early) {
        await inbound.sink.write(held);
        inbound.received += held.byteLength;
        inbound.chunks += 1;
      }
      inbound.early = null;
    }
    await inbound.sink.write(bytes);
    inbound.received += bytes.byteLength;
    inbound.chunks += 1;
    if (inbound.chunks % 32 === 0) {
      this.emit('file-progress', { direction: 'in', id: inbound.meta.id, sent: inbound.received, total: inbound.meta.size, name: inbound.meta.name });
    }
  }

  async onFileEnd(end) {
    const inbound = this.incoming;
    if (!inbound) return;
    this.incoming = null;
    if (!inbound.sink) { this.emit('warning', 'transfer ended before it was accepted'); return; }

    // Every chunk was individually authenticated and sequence-bound by the AEAD, so
    // there is no whole-file hash to check (DESIGN.md 1.14). What is worth checking
    // is that we reassembled exactly what was sent.
    if (inbound.received !== end.bytes || inbound.chunks !== end.chunks) {
      await inbound.sink.abort('length mismatch');
      this.emit('file-failed', {
        ...inbound.meta,
        reason: `expected ${end.bytes} bytes in ${end.chunks} chunks, reassembled ${inbound.received} in ${inbound.chunks}`,
      });
      return;
    }

    const blob = await inbound.sink.finish();
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

  async sever() {
    if (this.severed) return;
    this.severed = true;
    // Tell the peer first, while the channel still exists.
    try {
      if (this.channel && this.peer?.channel?.readyState === 'open') {
        await this.peer.send(await this.channel.sealJson(TYPE.CONTROL, { kind: 'sever' }));
      }
    } catch (err) {
      this.emit('warning', `could not notify the peer: ${err.message}`);
    }
    try { await this.signal?.bye(); } catch (err) { this.emit('warning', `could not delete the room: ${err.message}`); }
    this.teardown('Warp Gate severed.');
  }

  /**
   * Drop every reference to key material. The AES keys are non-extractable CryptoKey
   * objects, so their bytes were never in the JS heap; releasing the reference is the
   * strongest erasure a browser offers (DESIGN.md 1.11).
   */
  teardown(reason) {
    this.severed = true;
    if (this.confirmTimer) { clearTimeout(this.confirmTimer); this.confirmTimer = null; }
    try { this.peer?.close(); } catch (err) { void err; }
    try { this.signal?.close(); } catch (err) { void err; }
    if (this.incoming?.sink) {
      this.incoming.sink.abort('gate severed').catch(() => {});
    }
    if (this.secret) this.secret.fill(0);
    this.secret = null;
    this.sessionKeys = null;
    this.channel = null;
    this.keyPair = null;
    this.peerPublicRaw = null;
    this.incoming = null;
    this.peer = null;
    this.signal = null;
    this.setState(STATE.SEVERED, reason);
    this.emit('severed', reason);
  }
}
