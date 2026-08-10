// The match layer: two peers, one game, over the gate's control channel.
//
// Engines in js/games/ know rules and nothing else. link.js carries `{ kind: 'game' }`
// payloads and understands none of them. This is the piece in between: it decides who
// sits on which seat, turns a click into a wire message, validates what comes back
// against the engine before anything changes, and gives the UI a single object to draw.
//
// ---------------------------------------------------------------- the two shapes
//
// Most games are SHARED: both devices hold the same board, apply the same move, and
// stay identical because the engines are pure. A move message is the whole story.
//
// Battleships is MIRRORED: neither device may hold the other's fleet, so each side runs
// its own state and a shot needs two messages. We fire, they apply it as `incoming` and
// answer with the result, and only then does our board learn what happened. The mapping
// lives in `receiveMirrored` and is the only place that asymmetry exists.
//
// ---------------------------------------------------------------- hostile peer
//
// Everything here arrives from another device. The engines already refuse a malformed
// or illegal move without throwing, so this layer's job is the part they cannot see:
// that a move claims the seat its sender actually holds, that it is for the match we
// think we are in, and that it lands in the right order. A peer that fails any of those
// is not corrected, it ends the match: two boards that have silently diverged are worse
// than no game, and there is no referee to say which one is right.

import { getGame, GAME_IDS } from './games/index.js';

/**
 * Seat ids per game, in turn order: the first plays first.
 *
 * The engines own the ids but do not export them, so this table restates them. It is
 * checked against the registry by `playableGames()` rather than by throwing at import:
 * a game added without a seat entry should be missing from the menu, not take the whole
 * gate down. tests/games.test.mjs asserts the table covers every registered id and that
 * each first seat really is the side to move on a fresh board.
 */
export const SEATS = Object.freeze({
  tictactoe: Object.freeze(['x', 'o']),
  connect4: Object.freeze(['r', 'y']),
  battleships: Object.freeze(['a', 'b']),
  chess: Object.freeze(['w', 'b']),
});

/** Games where each side holds its own half of the truth. See the header. */
export const MIRRORED = Object.freeze(new Set(['battleships']));

/** Registry entries this layer can actually seat, in registry order. */
export function playableGames() {
  return GAME_IDS.map((id) => getGame(id)).filter((entry) => entry && SEATS[entry.id]);
}

const otherSeat = (gameId, seat) => SEATS[gameId].find((s) => s !== seat);

function randomHex(bytes) {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * A fleet seed, generated locally and never sent.
 *
 * Battleships lays ships out from a seeded PRNG, so a seed on the wire IS the fleet.
 * Each side therefore rolls its own and keeps it: the invite carries no randomness at
 * all, which is also why nothing here has to agree on a seed in the first place.
 */
function fleetSeed() {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return buf[0] >>> 0;
}

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

export class GameSession extends EventTarget {
  /**
   * @param {object} options
   * @param {(peerId: string, payload: object) => Promise<boolean>} options.send
   *   Hands a payload to one peer. Returns false if that peer is not connected, which
   *   this layer treats as "the invitation did not leave", never as a game state change.
   */
  constructor({ send }) {
    super();
    if (typeof send !== 'function') throw new TypeError('GameSession needs a send function');
    this.transport = send;
    /** The current match, running or finished, or null. */
    this.match = null;
    /** An invitation we sent that has not been answered. */
    this.outgoing = null;
    /** An invitation they sent that we have not answered. */
    this.incoming = null;
    /** One line for the UI about the last thing that happened outside a board. */
    this.notice = null;
  }

  changed() { this.dispatchEvent(new CustomEvent('update')); }

  /** True while a match is on the board and still playable. */
  get busy() { return Boolean(this.match && !this.match.ended); }

  // ---------------------------------------------------------------- invitations

  async invite(peer, gameId, seat = null) {
    if (this.busy || this.outgoing) return false;
    const entry = getGame(gameId);
    if (!entry || !SEATS[gameId]) return false;
    const mine = SEATS[gameId].includes(seat) ? seat : SEATS[gameId][0];
    const mid = randomHex(8);
    this.match = null;
    this.incoming = null;
    this.notice = null;
    this.outgoing = { mid, peer, gameId, name: entry.name, seat: mine };
    this.changed();
    const ok = await this.transport(peer, { t: 'invite', mid, game: gameId, seat: mine });
    if (!ok) {
      this.outgoing = null;
      this.notice = 'that device is not connected any more';
      this.changed();
    }
    return ok;
  }

  async cancelInvite() {
    const out = this.outgoing;
    if (!out) return;
    this.outgoing = null;
    this.changed();
    await this.transport(out.peer, { t: 'cancel', mid: out.mid });
  }

  async accept() {
    const inv = this.incoming;
    if (!inv || this.busy) return false;
    this.incoming = null;
    this.start(inv.mid, inv.peer, inv.gameId, otherSeat(inv.gameId, inv.seat));
    const ok = await this.transport(inv.peer, { t: 'accept', mid: inv.mid });
    if (!ok) {
      this.match = null;
      this.notice = 'that device is not connected any more';
      this.changed();
    }
    return ok;
  }

  async decline() {
    const inv = this.incoming;
    if (!inv) return;
    this.incoming = null;
    this.changed();
    await this.transport(inv.peer, { t: 'decline', mid: inv.mid });
  }

  // ---------------------------------------------------------------- the match

  start(mid, peer, gameId, seat) {
    const entry = getGame(gameId);
    const mirrored = MIRRORED.has(gameId);
    const options = mirrored ? { side: seat, seed: fleetSeed() } : {};
    const match = {
      mid,
      peer,
      gameId,
      name: entry.name,
      engine: entry.engine,
      board: entry.board,
      mirrored,
      seat,
      theirSeat: otherSeat(gameId, seat),
      state: entry.engine.create(options),
      // Moves applied to a SHARED board, by either side. It rides on every move message
      // so a duplicate or a reordered one is caught rather than played twice. Mirrored
      // games cannot use it: the two sides apply different numbers of moves.
      n: 0,
      readySent: false,
      lastEffect: null,
      ended: null,
    };
    if (mirrored) {
      // Auto-placement up front, so the first thing on screen is a fleet rather than an
      // empty grid and a manual. Shuffle re-rolls it until Ready is pressed.
      const placed = match.engine.applyMove(match.state, { type: 'autoplace', seed: fleetSeed() });
      if (placed.ok) match.state = placed.state;
    }
    this.match = match;
    this.notice = null;
    this.changed();
    return match;
  }

  /** Snapshot for the renderer: never mutate what comes back. */
  view() {
    const m = this.match;
    if (!m) return null;
    const status = m.engine.status(m.state);
    return {
      mid: m.mid,
      peer: m.peer,
      gameId: m.gameId,
      name: m.name,
      board: m.board,
      seat: m.seat,
      theirSeat: m.theirSeat,
      mirrored: m.mirrored,
      state: m.state,
      status,
      readySent: m.readySent,
      ended: m.ended,
      lastEffect: m.lastEffect,
      yourTurn: !status.over && !m.ended && status.turn === m.seat,
      legal: m.engine.legalMoves(m.state),
    };
  }

  // ---------------------------------------------------------------- local moves

  async play(move) {
    const m = this.match;
    if (!m || m.ended) return { ok: false, error: 'there is no game running' };
    if (m.mirrored) return this.playMirrored(m, move);

    const before = m.engine.status(m.state);
    if (before.over) return { ok: false, error: 'the game is over' };
    if (before.turn !== m.seat) return { ok: false, error: 'it is not your turn' };
    const res = m.engine.applyMove(m.state, move);
    if (!res.ok) return res;
    m.state = res.state;
    m.lastEffect = res.effect ?? null;
    const n = m.n;
    m.n += 1;
    this.settle(m);
    this.changed();
    await this.transport(m.peer, { t: 'move', mid: m.mid, n, move });
    return { ok: true };
  }

  async playMirrored(m, move) {
    if (!isObject(move)) return { ok: false, error: 'move must be an object' };

    if (move.type === 'shuffle') {
      if (m.readySent) return { ok: false, error: 'your fleet is already locked in' };
      // The engine refuses to place twice, on purpose, so a re-roll is a fresh state.
      // Nothing has been sent yet at this point, so no peer can be out of step with it.
      const fresh = m.engine.create({ side: m.seat, seed: fleetSeed() });
      const placed = m.engine.applyMove(fresh, { type: 'autoplace', seed: fleetSeed() });
      if (!placed.ok) return placed;
      m.state = placed.ok ? placed.state : fresh;
      // Their readiness is theirs, not ours: keep it across a re-roll of our own fleet.
      if (this.opponentWasReady) {
        const again = m.engine.applyMove(m.state, { type: 'opponentReady' });
        if (again.ok) m.state = again.state;
      }
      this.changed();
      return { ok: true };
    }

    if (move.type === 'ready') {
      if (m.readySent) return { ok: false, error: 'you are already ready' };
      m.readySent = true;
      this.changed();
      await this.transport(m.peer, { t: 'move', mid: m.mid, move: { type: 'ready' } });
      return { ok: true };
    }

    if (move.type === 'fire') {
      if (!m.readySent) return { ok: false, error: 'lock your fleet in first' };
      const res = m.engine.applyMove(m.state, { type: 'fire', x: move.x, y: move.y });
      if (!res.ok) return res;
      m.state = res.state;
      this.changed();
      await this.transport(m.peer, { t: 'move', mid: m.mid, move: { type: 'fire', x: move.x, y: move.y } });
      return { ok: true };
    }

    return { ok: false, error: `you cannot play ${JSON.stringify(move.type)}` };
  }

  async resign() {
    const m = this.match;
    if (!m || m.ended) return;
    m.ended = { winner: m.theirSeat, reason: 'resigned', by: 'you' };
    this.changed();
    await this.transport(m.peer, { t: 'resign', mid: m.mid });
  }

  /** Clear the board without conceding: only offered once a game has ended. */
  close() {
    if (this.busy) return;
    this.match = null;
    this.notice = null;
    this.changed();
  }

  // ---------------------------------------------------------------- the wire

  /**
   * A payload from a peer. Never throws: a bad message ends the match, it does not
   * crash the gate.
   */
  async receive(peer, payload) {
    if (!isObject(payload) || typeof payload.t !== 'string') return;
    if (typeof payload.mid !== 'string' || payload.mid.length === 0 || payload.mid.length > 64) return;
    const t = payload.t;

    if (t === 'invite') return this.receiveInvite(peer, payload);

    if (t === 'cancel') {
      if (this.incoming && this.incoming.mid === payload.mid && this.incoming.peer === peer) {
        this.incoming = null;
        this.notice = 'they took the invitation back';
        this.changed();
      }
      return undefined;
    }

    if (t === 'decline') {
      if (this.outgoing && this.outgoing.mid === payload.mid && this.outgoing.peer === peer) {
        this.outgoing = null;
        this.notice = payload.reason === 'busy'
          ? 'they are already in a game'
          : 'they said no thanks';
        this.changed();
      }
      return undefined;
    }

    if (t === 'accept') {
      const out = this.outgoing;
      if (!out || out.mid !== payload.mid || out.peer !== peer) return undefined;
      this.outgoing = null;
      this.start(out.mid, peer, out.gameId, out.seat);
      return undefined;
    }

    const m = this.match;
    if (!m || m.mid !== payload.mid || m.peer !== peer) return undefined;

    if (t === 'resign') {
      if (m.ended) return undefined;
      m.ended = { winner: m.seat, reason: 'resigned', by: 'them' };
      this.changed();
      return undefined;
    }

    if (t === 'end') {
      if (m.ended) return undefined;
      m.ended = { winner: null, reason: 'abandoned', by: 'them', detail: typeof payload.reason === 'string' ? payload.reason.slice(0, 200) : null };
      this.changed();
      return undefined;
    }

    if (t === 'move') {
      if (m.ended) return undefined;
      return m.mirrored ? this.receiveMirrored(m, payload) : this.receiveShared(m, payload);
    }

    return undefined;
  }

  receiveInvite(peer, payload) {
    const entry = getGame(payload.game);
    if (!entry || !SEATS[entry.id]) {
      return this.transport(peer, { t: 'decline', mid: payload.mid, reason: 'unknown' });
    }
    if (!SEATS[entry.id].includes(payload.seat)) {
      return this.transport(peer, { t: 'decline', mid: payload.mid, reason: 'unknown' });
    }
    if (this.busy) {
      return this.transport(peer, { t: 'decline', mid: payload.mid, reason: 'busy' });
    }
    const invite = { mid: payload.mid, peer, gameId: entry.id, name: entry.name, seat: payload.seat };

    // Both sides pressing invite at the same moment would otherwise leave two people
    // each waiting for the other to answer. The smaller match id wins, which both
    // devices can work out without another round trip, and the loser's invitation is
    // dropped in favour of the winner's.
    if (this.outgoing && this.outgoing.peer === peer) {
      if (this.outgoing.mid < payload.mid) {
        return this.transport(peer, { t: 'decline', mid: payload.mid, reason: 'busy' });
      }
      this.outgoing = null;
    }

    this.incoming = invite;
    this.notice = null;
    this.changed();
    return undefined;
  }

  receiveShared(m, payload) {
    if (!Number.isInteger(payload.n) || payload.n !== m.n) {
      return this.fail(m, 'the two boards fell out of step');
    }
    const before = m.engine.status(m.state);
    if (before.over) return this.fail(m, 'they played after the game had ended');
    // The engine plays a move as whoever is to move, so without this a peer could send
    // a move on OUR turn and it would apply as if we had played it.
    if (before.turn !== m.theirSeat) return this.fail(m, 'they played out of turn');
    const res = m.engine.applyMove(m.state, payload.move);
    if (!res.ok) return this.fail(m, `they sent a move the rules refuse: ${res.error}`);
    m.state = res.state;
    m.lastEffect = res.effect ?? null;
    m.n += 1;
    this.settle(m);
    this.changed();
    return undefined;
  }

  async receiveMirrored(m, payload) {
    const move = payload.move;
    if (!isObject(move)) return this.fail(m, 'they sent a move that is not a move');

    if (move.type === 'ready') {
      const res = m.engine.applyMove(m.state, { type: 'opponentReady' });
      if (!res.ok) return this.fail(m, `they said ready twice: ${res.error}`);
      m.state = res.state;
      this.opponentWasReady = true;
      this.changed();
      return undefined;
    }

    if (move.type === 'fire') {
      // Their shot lands on our fleet. The engine works out what it hit, and that answer
      // is the only thing they learn: it goes straight back as a result.
      const res = m.engine.applyMove(m.state, { type: 'incoming', x: move.x, y: move.y });
      if (!res.ok) return this.fail(m, `they fired when they could not: ${res.error}`);
      m.state = res.state;
      m.lastEffect = res.effect ?? null;
      this.settle(m);
      this.changed();
      await this.transport(m.peer, {
        t: 'move',
        mid: m.mid,
        move: { type: 'result', x: move.x, y: move.y, outcome: res.effect.outcome },
      });
      return undefined;
    }

    if (move.type === 'result') {
      const res = m.engine.applyMove(m.state, {
        type: 'result', x: move.x, y: move.y, outcome: move.outcome,
      });
      if (!res.ok) return this.fail(m, `they answered a shot we did not fire: ${res.error}`);
      m.state = res.state;
      m.lastEffect = { outcome: move.outcome, mine: true };
      this.settle(m);
      this.changed();
      return undefined;
    }

    return this.fail(m, `they sent ${JSON.stringify(move.type)}, which is not theirs to send`);
  }

  settle(m) {
    if (m.ended) return;
    const status = m.engine.status(m.state);
    if (status.over) m.ended = { winner: status.winner, reason: status.reason, by: null };
  }

  /**
   * End a match because the protocol broke. Ending is the whole point: from here on the
   * two boards may disagree, and a game that carries on is one that will silently show
   * two different truths.
   */
  fail(m, reason) {
    if (m.ended) return undefined;
    m.ended = { winner: null, reason: 'protocol', by: null, detail: reason };
    this.notice = reason;
    this.changed();
    return this.transport(m.peer, { t: 'end', mid: m.mid, reason });
  }

  /**
   * Drop anything involving a peer who is no longer in the gate.
   *
   * Driven by the roster rather than by a departure event, because the roster is the
   * membership itself: a peer can also vanish because their link failed, or because the
   * gate re-formed, and only one of those raises a "left" event. Reading the list that
   * decides who can be played with is the check that cannot miss a case.
   */
  reconcile(livePeers) {
    const live = new Set(livePeers);
    for (const peer of [this.outgoing?.peer, this.incoming?.peer, this.match?.peer]) {
      if (peer && !live.has(peer)) this.peerLeft(peer);
    }
  }

  /** A peer went away: nothing involving them can carry on. */
  peerLeft(peer) {
    let touched = false;
    if (this.outgoing && this.outgoing.peer === peer) { this.outgoing = null; touched = true; }
    if (this.incoming && this.incoming.peer === peer) { this.incoming = null; touched = true; }
    const m = this.match;
    if (m && m.peer === peer && !m.ended) {
      m.ended = { winner: null, reason: 'left', by: 'them' };
      touched = true;
    }
    if (touched) {
      this.notice = 'the other device left the gate';
      this.changed();
    }
  }

  /** The gate itself is gone. */
  reset() {
    this.match = null;
    this.outgoing = null;
    this.incoming = null;
    this.notice = null;
    this.opponentWasReady = false;
    this.changed();
  }
}
