// Signalling transport.
//
// Everything sent through here is sealed under k_sig before it leaves the page, so
// the server and any proxy in front of it see only {n, c}. That matters most for the
// SDP and ICE candidates, which are IP addresses (DESIGN.md 1.4).

import { sealEnvelope, openEnvelope } from './crypto.js';

export class Signal extends EventTarget {
  constructor({ roomId, token, signalKey }) {
    super();
    this.roomId = roomId;
    this.token = token;
    this.signalKey = signalKey;
    this.source = null;
    this.closed = false;
  }

  connect() {
    if (this.closed) throw new Error('signal channel already closed');
    const url = `/api/events?room=${encodeURIComponent(this.roomId)}&token=${encodeURIComponent(this.token)}`;
    const source = new EventSource(url);
    this.source = source;

    const forward = (name) => {
      source.addEventListener(name, (event) => {
        let data = null;
        try {
          data = event.data ? JSON.parse(event.data) : null;
        } catch (err) {
          this.dispatchEvent(new CustomEvent('protocol-error', { detail: `malformed ${name} event: ${err.message}` }));
          return;
        }
        this.dispatchEvent(new CustomEvent(name, { detail: data }));
      });
    };
    for (const name of ['hello', 'peer-joined', 'peer-left', 'closed']) forward(name);

    source.addEventListener('relay', async (event) => {
      let envelope;
      try {
        envelope = JSON.parse(event.data);
      } catch (err) {
        this.dispatchEvent(new CustomEvent('protocol-error', { detail: `malformed relay event: ${err.message}` }));
        return;
      }
      try {
        const message = await openEnvelope(this.signalKey, envelope);
        this.dispatchEvent(new CustomEvent('message', { detail: message }));
      } catch (err) {
        // Someone in the room does not hold the room secret, or a proxy mangled the
        // payload. Either way this is not something to act on silently.
        this.dispatchEvent(new CustomEvent('undecryptable', { detail: err.message }));
      }
    });

    source.addEventListener('error', () => {
      // EventSource reconnects on its own; only a closed readyState is terminal.
      if (source.readyState === EventSource.CLOSED) {
        this.dispatchEvent(new CustomEvent('disconnected', { detail: 'event stream closed' }));
      } else {
        this.dispatchEvent(new CustomEvent('reconnecting', { detail: 'event stream interrupted' }));
      }
    });

    return this;
  }

  /** Seal a signalling message and hand it to the server for relay. */
  async send(message) {
    if (this.closed) return false;
    const envelope = await sealEnvelope(this.signalKey, message);
    const res = await fetch('/api/relay', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ roomId: this.roomId, token: this.token, envelope }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: `http ${res.status}` }));
      throw new Error(`relay failed: ${body.error ?? res.status}`);
    }
    const { delivered } = await res.json();
    return delivered;
  }

  /** Tell the server to delete the room. Best effort: teardown must not depend on it. */
  async bye() {
    if (this.closed) return;
    try {
      await fetch('/api/bye', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ roomId: this.roomId, token: this.token }),
        signal: AbortSignal.timeout(4000),
        keepalive: true,
      });
    } catch (err) {
      this.dispatchEvent(new CustomEvent('protocol-error', { detail: `bye failed: ${err.message}` }));
    }
  }

  close() {
    this.closed = true;
    try { this.source?.close(); } catch (err) { void err; }
    this.source = null;
  }
}

export async function createRoom(roomId, sessionMinutes, requiresPassword = false) {
  const res = await fetch('/api/create', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ roomId, sessionMinutes, requiresPassword }),
    signal: AbortSignal.timeout(8000),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `create failed: http ${res.status}`);
  return body;
}

export async function joinRoom(roomId) {
  const res = await fetch('/api/join', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ roomId }),
    signal: AbortSignal.timeout(8000),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `join failed: http ${res.status}`);
  return body;
}

/** Check whether a stored slot is still valid, so a reload can resume rather than fail. */
export async function checkRoom(roomId, token) {
  const res = await fetch(`/api/room?room=${encodeURIComponent(roomId)}&token=${encodeURIComponent(token)}`, {
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) return null;
  return res.json();
}

export async function fetchConfig() {
  const res = await fetch('/api/config', { signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`config failed: http ${res.status}`);
  return res.json();
}
