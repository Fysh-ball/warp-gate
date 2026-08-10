// Time killer games: the registry, and the one place the engine contract is written down.
//
// Two people who are already connected in a gate can play while a transfer runs. The UI
// and the peer link are written ONCE against the contract below, so every engine here
// has to obey it exactly. A game that needs a shape this does not cover needs the
// contract widened for everybody, not a special case in the UI.
//
// ---------------------------------------------------------------- the contract
//
//   create(options?)          -> state
//   legalMoves(state)         -> Move[]
//   applyMove(state, move)    -> { ok: true, state, effect? } | { ok: false, error }
//   status(state)             -> { over, winner, reason, turn, ... }
//   serialize(state)          -> JSON-safe value
//   deserialize(value)        -> state
//
// `options` is always an object and every field is optional. `seed` is the only field
// every engine understands; engines with nothing random ignore it. Battleships also
// takes `side`, chess takes `fen`.
//
// `status` always returns at least these four:
//   over    boolean
//   winner  a player id, or null for a draw AND for a game still running
//   reason  a short machine-readable string. 'in-progress' while the game is running,
//           otherwise the terminal condition: 'draw', 'checkmate', 'stalemate',
//           'fifty-move', 'threefold', 'insufficient-material', 'three-in-a-row',
//           'four-in-a-row', 'fleet-sunk'.
//   turn    the player id to move. Still reported once the game is over, because the
//           UI keeps drawing the board.
// Engines may add fields on top (`line` for the winning run, `phase` and `pending` for
// battleships). Callers must not require them.
//
// Player ids are per game and are plain lowercase strings: 'x'/'o', 'r'/'y', 'a'/'b',
// 'w'/'b'. The network layer maps its own two peers onto them once, at the start.
//
// ---------------------------------------------------------------- rules for engines
//
// 1. PURE. No Date.now, no Math.random, no DOM, no fetch, no imports from outside this
//    directory. Given the same state and move, every device must reach the same result,
//    or the two boards silently diverge and nobody can tell which one is right.
// 2. Randomness comes from a seed and a PRNG defined in the module. Battleships is the
//    only engine that needs any, for auto-placement.
// 3. applyMove NEVER mutates its input, and NEVER throws on a bad move. A move is a
//    value that arrived from another device: it can be null, an array, a string, an
//    object with fractional or out-of-range indices, a legal move played out of turn, or
//    a legal move played after the game ended. All of those return { ok: false, error }.
//    An engine that trusts its input is a hole, not a bug.
// 4. deserialize DOES throw, because a corrupt state is not a recoverable move: it is a
//    protocol failure, and the caller must not carry on with half a board. It validates
//    invariants rather than trusting the wire, so a forged state is rejected up front.
// 5. deserialize(serialize(state)) must equal state.
//
// `effect` on a successful applyMove is optional, and carries the part of the outcome
// that is not recoverable from the new state alone: the landing square of a connect 4
// disc, or what a battleships shot did to our fleet. The network layer sends it on.

import * as tictactoe from './tictactoe.js';
import * as connect4 from './connect4.js';
import * as battleships from './battleships.js';
import * as chess from './chess.js';

/**
 * `board` is metadata for layout, not rules: it is what the UI needs to reserve space
 * before an engine is even loaded. min and max are the smallest and largest sensible
 * rendered size in CSS pixels for the square grid the game draws.
 */
export const GAMES = Object.freeze([
  Object.freeze({
    id: 'tictactoe',
    name: 'Tic Tac Toe',
    players: Object.freeze({ min: 2, max: 2 }),
    board: Object.freeze({ cols: 3, rows: 3, min: 180, max: 420 }),
    engine: tictactoe,
    create: tictactoe.create,
  }),
  Object.freeze({
    id: 'connect4',
    name: 'Connect 4',
    players: Object.freeze({ min: 2, max: 2 }),
    board: Object.freeze({ cols: 7, rows: 6, min: 280, max: 640 }),
    engine: connect4,
    create: connect4.create,
  }),
  Object.freeze({
    id: 'battleships',
    name: 'Battleships',
    players: Object.freeze({ min: 2, max: 2 }),
    board: Object.freeze({ cols: 10, rows: 10, min: 260, max: 560 }),
    engine: battleships,
    create: battleships.create,
  }),
  Object.freeze({
    id: 'chess',
    name: 'Chess',
    players: Object.freeze({ min: 2, max: 2 }),
    board: Object.freeze({ cols: 8, rows: 8, min: 280, max: 640 }),
    engine: chess,
    create: chess.create,
  }),
]);

const BY_ID = new Map(GAMES.map((entry) => [entry.id, entry]));

/** The registry entry for an id, or null. Ids arrive over the wire, so no throwing. */
export function getGame(id) {
  return BY_ID.get(id) || null;
}

/**
 * Start a game by id. Returns null for an unknown id rather than throwing, so a peer
 * proposing a game this build does not have is a declined invitation, not a crash.
 */
export function createGame(id, options = {}) {
  const entry = BY_ID.get(id);
  if (!entry) return null;
  return { id, state: entry.engine.create(options) };
}

export const GAME_IDS = Object.freeze(GAMES.map((entry) => entry.id));
