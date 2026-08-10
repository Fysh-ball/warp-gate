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
    // This device's own slot id, learned from the server's `hello`. It rides INSIDE the
    // sealed envelope on every message we send, because the receiver has to know which of
    // its links a relayed offer belongs to and the server must not be the one to say: the
    // envelope is handed on unmodified, and adding a field to it would make the server a
    // participant in a conversation it is supposed to be unable to read.
    //
    // Be clear about what `from` is and is not. It is sealed under k_sig, which EVERY
    // participant in the room holds, so it is unforgeable by the server and by anyone
    // outside the room, and forgeable by anyone inside it, which is why every message is
    // now cross-checked against `sfrom` on the way in: see checkSender below.
    this.selfId = null;

    // Replay control for signalling.
    //
    // k_sig is HKDF(S, "wg/v1/signal"), so it depends on the room secret alone and the
    // AAD is a constant. A captured envelope therefore opens as many times as anyone
    // cares to relay it. That is denial of service rather than compromise (a replayed
    // offer carries a stale public key, so key confirmation fails closed), but it lets
    // anyone who can observe signalling wedge a gate repeatedly, so it is worth closing.
    //
    // A strictly increasing per-sender counter is enough, and cheaper than putting a
    // sequence into the AAD: `seq` rides inside the sealed envelope, so it cannot be
    // altered by the server or by anyone outside the room, and the receiver simply
    // refuses anything it has already passed.
    //
    // Deliberately NOT reset when the event stream reconnects. EventSource reconnects on
    // its own, and a counter that restarted would make the receiver reject every message
    // after a blip.
    //
    // The counter alone is not enough, and the first version of this shipped broken: it
    // was monotonic for the life of the PAGE, but a slot survives a reload. After a
    // refresh the resuming device restarts at 0 while its peer still remembers the
    // highest sequence from the previous page, so every message was refused as a replay,
    // the resume failed, and the fallback cleared the slot AND the room secret. A guard
    // against a denial of service that itself denies service is not a trade worth making.
    //
    // So each page load stamps an epoch, and a message is accepted when it is newer by
    // (epoch, seq) than anything already seen from that sender. A reloaded peer presents
    // a HIGHER epoch, so it is accepted from sequence 1. A replayed envelope always
    // carries an epoch and sequence that have already been seen, so it is still refused.
    this.epoch = Date.now();
    this.sendSeq = 0;
    /** @type {Map<string, {epoch: number, seq: number}>} sender slot id -> newest accepted */
    this.seenSeq = new Map();
  }

  /**
   * Refuse a replayed signalling message.
   *
   * Cross-SESSION replay is already impossible and deliberately not handled here: slot
   * ids are freshly random per gate, and routing is gated on the current roster, so an
   * envelope captured from an earlier gate names a participant this one does not seat and
   * is dropped before it reaches a link.
   *
   * What this closes is replay WITHIN a live session.
   */
  acceptSeq(message) {
    const from = message?.from;
    const seq = message?.seq;
    const epoch = message?.epoch;
    // A message with no sender, counter or epoch cannot be placed. Older senders do not
    // exist: both sides ship together, so this is a malformed or forged frame.
    if (typeof from !== 'string' || !from
      || !Number.isSafeInteger(seq) || seq < 1
      || !Number.isSafeInteger(epoch) || epoch < 1) {
      this.dispatchEvent(new CustomEvent('undecryptable', {
        detail: 'a signalling message arrived without a usable sender, epoch or sequence number',
      }));
      return false;
    }
    const last = this.seenSeq.get(from);
    // Newer by (epoch, seq). A reloaded peer brings a higher epoch and is accepted from
    // sequence 1; a replay carries a pair that has already been seen and is not.
    const newer = !last || epoch > last.epoch || (epoch === last.epoch && seq > last.seq);
    if (!newer) {
      this.dispatchEvent(new CustomEvent('replay-refused', {
        detail: `refused a repeated signalling message from ${from} `
          + `(epoch ${epoch} seq ${seq}, already at epoch ${last.epoch} seq ${last.seq})`,
      }));
      return false;
    }
    this.seenSeq.set(from, { epoch, seq });
    return true;
  }

  /**
   * Refuse a message whose sealed `from` is not who the server says sent it.
   *
   * WHAT THIS CLOSES. `from` rides inside the envelope under k_sig, and k_sig comes from
   * the room secret alone, so every seated participant can seal one. Before this check,
   * any one seat could therefore write any other seat's name on a signalling message, and
   * session.js routes on that name and will open a link for it. From a single seat that
   * bought three attacks on a pair the attacker was not part of: seal a `pk` as another
   * peer and the victim pins the wrong key and never revisits it, permanently partitioning
   * the pair; seal a `restart` and drive the victim's renegotiation; seal a `sever` and end
   * the victim's gate.
   *
   * It is NOT a confidentiality break and must not be described as one. Every send is
   * addressed at exactly one peer (LinkSignal), so a victim's real public key only ever
   * reaches the genuine peer; what a forger got was disruption, not a session.
   *
   * THE CONTRACT. The server attaches the token-authenticated sender's slot id as a
   * SIBLING field `sfrom`, next to the sealed envelope and never inside it, and passes the
   * envelope itself through byte-identical. It has to be outside: putting it inside would
   * mean the server writing into a payload it is not supposed to be able to read.
   *
   * ABSENT `sfrom` IS A DROP, deliberately. Treating "the server did not say" as "trusted"
   * would reinstate the entire bug, because the field an attacker controls is the one
   * inside the envelope and the one it does not control is the one it would rather were
   * missing. The same reasoning already governs `acceptSeq` above, which refuses a message
   * with no epoch or sequence rather than assuming an older sender: both halves of this
   * app ship together, so there is no such thing as a peer or a server that predates a
   * field. What a stale server DOES get is a named diagnosis rather than silence: the
   * `undecryptable` event below says the server did not attest the sender, which is the
   * one sentence that turns "the gate mysteriously never connects" into "that server is
   * running an older build".
   */
  checkSender(message, envelope) {
    const sealed = typeof message?.from === 'string' ? message.from : null;
    const attested = typeof envelope?.sfrom === 'string' && envelope.sfrom ? envelope.sfrom : null;
    if (!attested) {
      this.dispatchEvent(new CustomEvent('undecryptable', {
        detail: 'the server did not say which seat sent a signalling message, so it was dropped: '
          + 'this server is running a build older than this page',
      }));
      return false;
    }
    if (sealed !== attested) {
      this.dispatchEvent(new CustomEvent('impersonation-refused', {
        detail: `refused a signalling message that claims to come from ${sealed ?? 'nobody'} `
          + `but was sent by ${attested}`,
      }));
      return false;
    }
    return true;
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
        // Before acceptSeq, on purpose. acceptSeq REMEMBERS (epoch, seq) per sender, so
        // letting a forged message reach it first would let one seat burn another seat's
        // sequence space and have every genuine later message refused as a replay.
        if (!this.checkSender(message, envelope)) return;
        if (!this.acceptSeq(message)) return;
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

  /**
   * Seal a signalling message and hand it to the server for relay to ONE participant.
   *
   * `to` is a slot id and it is mandatory. The server refuses a relay with no target
   * rather than falling back to a broadcast, and this refuses to send one: a pair's ECDH
   * is only private to that pair because nobody else ever receives it, so an unaddressed
   * relay is a key exchange handed to the whole room.
   */
  async send(message, to) {
    if (this.closed) return false;
    if (typeof to !== 'string' || !to) {
      throw new Error('a signalling message must be addressed at one participant');
    }
    this.sendSeq += 1;
    const envelope = await sealEnvelope(this.signalKey, {
      ...message, from: this.selfId, seq: this.sendSeq, epoch: this.epoch,
    });
    const res = await fetch('/api/relay', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ roomId: this.roomId, token: this.token, to, envelope }),
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

// createRoom() and joinRoom() used to live here and were never called: session.js builds
// both requests itself because they carry a join proof derived from the room secret, which
// these helpers never knew about. They are gone rather than left as two exported functions
// that would be refused by the server the moment anything used them.

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
