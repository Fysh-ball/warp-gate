// Battleships: 10x10, standard fleet of 5, 4, 3, 3, 2.
//
// ---------------------------------------------------------------- why this is one-sided
//
// There is no referee. Two browsers hold two halves of the game and the whole point is
// that neither can see the other's ships, so an omniscient state object holding both
// fleets could not exist on either device without leaking the answer. This engine
// therefore models exactly what ONE player legitimately knows:
//
//   - `ships`      our own fleet, and which of its cells have been hit
//   - `incoming`   every square the opponent has fired at us, and what it did
//   - `shots`      every square we have fired at, and what the opponent SAID it did
//
// The consequence is that hit/miss/sunk for our shots is reported by the opponent, and
// a lying peer can report a miss on a hit. That is unfixable without a referee and is
// out of scope: the same peer could equally refuse to play. What this engine does
// enforce is that a report is well formed, is for the shot we actually fired, and
// arrives when it is that peer's turn to speak. See THREAT-MODEL.md for the general
// stance on a hostile peer.
//
// Turn order is strict alternation: a hit does NOT grant another shot. That is the
// variant with the shorter, more predictable game, which is what a wait-for-transfer
// filler wants.
//
// ---------------------------------------------------------------- move origins
//
// `legalMoves` lists only the moves the LOCAL player may choose. Three move types are
// opponent-originated and never appear there, because the local player does not get to
// decide them: `opponentReady`, `result` (their answer to our shot) and `incoming`
// (their shot at us). `applyMove` accepts and validates all six.

export const SIZE = 10;
export const CELLS = SIZE * SIZE;

/** Largest first: auto-placement gets the awkward ship down while the board is empty. */
export const FLEET = Object.freeze([
  Object.freeze({ name: 'carrier', size: 5 }),
  Object.freeze({ name: 'battleship', size: 4 }),
  Object.freeze({ name: 'cruiser', size: 3 }),
  Object.freeze({ name: 'submarine', size: 3 }),
  Object.freeze({ name: 'destroyer', size: 2 }),
]);

const SIDES = Object.freeze(['a', 'b']);
const OUTCOMES = Object.freeze(['miss', 'hit', 'sunk']);
const INCOMING_STATES = Object.freeze(['none', 'miss', 'hit']);
const SHOT_STATES = Object.freeze(['none', 'miss', 'hit', 'sunk']);

const other = (side) => (side === 'a' ? 'b' : 'a');
const idx = (x, y) => y * SIZE + x;
const inBounds = (x, y) => Number.isInteger(x) && Number.isInteger(y) && x >= 0 && x < SIZE && y >= 0 && y < SIZE;

function isMoveObject(move) {
  return typeof move === 'object' && move !== null && !Array.isArray(move);
}

// ---------------------------------------------------------------- deterministic PRNG
//
// mulberry32: 32 bits of state, no dependencies, and identical output everywhere. It is
// not cryptographic and must never be used for anything but ship layout. The seed comes
// from outside the engine so that a test can reproduce a board exactly and so that two
// devices never accidentally share a layout.

export function prng(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The board indices a ship occupies. */
export function cellsOf(ship) {
  const cells = [];
  for (let i = 0; i < ship.size; i += 1) {
    cells.push(ship.dir === 'h' ? idx(ship.x + i, ship.y) : idx(ship.x, ship.y + i));
  }
  return cells;
}

function fits(ship) {
  if (!inBounds(ship.x, ship.y)) return false;
  if (ship.dir === 'h') return ship.x + ship.size <= SIZE;
  if (ship.dir === 'v') return ship.y + ship.size <= SIZE;
  return false;
}

/** Placement validity: on the board and not overlapping. Touching is allowed. */
function layoutError(ships) {
  const used = new Set();
  for (const ship of ships) {
    if (!fits(ship)) return `${ship.name} does not fit at ${ship.x},${ship.y} ${ship.dir}`;
    for (const cell of cellsOf(ship)) {
      if (used.has(cell)) return `${ship.name} overlaps another ship`;
      used.add(cell);
    }
  }
  return null;
}

/**
 * A fleet laid out deterministically from a seed. Exported because the UI offers a
 * "shuffle" button and the network layer never sees the result.
 */
export function autoLayout(seed) {
  const rand = prng(seed);
  const placed = [];
  for (const { name, size } of FLEET) {
    let ship = null;
    for (let attempt = 0; attempt < 200 && !ship; attempt += 1) {
      const dir = rand() < 0.5 ? 'h' : 'v';
      const span = SIZE - size + 1;
      const x = Math.floor(rand() * (dir === 'h' ? span : SIZE));
      const y = Math.floor(rand() * (dir === 'h' ? SIZE : span));
      const candidate = { name, size, x, y, dir, hits: new Array(size).fill(false) };
      if (!layoutError([...placed, candidate])) ship = candidate;
    }
    if (!ship) {
      // 200 rejections on a 10x10 board with five ships is close to impossible, but
      // "close to impossible" is not "cannot", and a placement loop that can spin
      // forever is a hang on someone's phone. Fall back to a deterministic scan.
      for (const dir of ['h', 'v']) {
        for (let y = 0; y < SIZE && !ship; y += 1) {
          for (let x = 0; x < SIZE && !ship; x += 1) {
            const candidate = { name, size, x, y, dir, hits: new Array(size).fill(false) };
            if (!layoutError([...placed, candidate])) ship = candidate;
          }
        }
      }
    }
    if (!ship) throw new Error(`battleships: could not place ${name}`);
    placed.push(ship);
  }
  return placed;
}

/**
 * Normalise a caller-supplied layout onto the canonical fleet. Names in the input are
 * ignored: the fleet is defined by its sizes, and letting a peer name a 5-long ship
 * "destroyer" would make the sunk reports meaningless.
 */
function normaliseLayout(input) {
  if (!Array.isArray(input) || input.length !== FLEET.length) {
    return { error: `fleet must have ${FLEET.length} ships` };
  }
  const pool = FLEET.map((entry) => ({ ...entry, taken: false }));
  const ships = [];
  for (const raw of input) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return { error: 'each ship must be an object' };
    }
    const { x, y, dir } = raw;
    const size = raw.size;
    if (!Number.isInteger(size)) return { error: 'ship size must be an integer' };
    const slot = pool.find((entry) => entry.size === size && !entry.taken);
    if (!slot) return { error: `fleet has no unplaced ship of size ${size}` };
    if (dir !== 'h' && dir !== 'v') return { error: "ship dir must be 'h' or 'v'" };
    if (!inBounds(x, y)) return { error: `ship origin ${x},${y} is off the board` };
    slot.taken = true;
    ships.push({ name: slot.name, size, x, y, dir, hits: new Array(size).fill(false) });
  }
  const bad = layoutError(ships);
  if (bad) return { error: bad };
  // Keep the canonical order so two states with the same layout serialize identically.
  ships.sort((p, q) => FLEET.findIndex((f) => f.name === p.name) - FLEET.findIndex((f) => f.name === q.name));
  return { ships };
}

// ---------------------------------------------------------------- state

export function create(options = {}) {
  const side = SIDES.includes(options.side) ? options.side : 'a';
  const seed = Number.isInteger(options.seed) ? options.seed >>> 0 : 1;
  return {
    game: 'battleships',
    side,
    seed,
    ships: [],
    incoming: new Array(CELLS).fill('none'),
    shots: new Array(CELLS).fill('none'),
    pending: null,
    opponentReady: false,
    turn: 'a', // side 'a' fires first, once both fleets are down
  };
}

const shipSunk = (ship) => ship.hits.every(Boolean);
const fleetSunk = (ships) => ships.length > 0 && ships.every(shipSunk);
const sunkReported = (shots) => shots.filter((s) => s === 'sunk').length;

export function phaseOf(state) {
  if (state.ships.length === 0 || !state.opponentReady) return 'placing';
  return 'battle';
}

export function status(state) {
  const phase = phaseOf(state);
  const base = { turn: state.turn, phase, pending: state.pending ? { ...state.pending } : null };
  if (sunkReported(state.shots) === FLEET.length) {
    return { over: true, winner: state.side, reason: 'fleet-sunk', ...base };
  }
  if (fleetSunk(state.ships)) {
    return { over: true, winner: other(state.side), reason: 'fleet-sunk', ...base };
  }
  return { over: false, winner: null, reason: 'in-progress', ...base };
}

export function legalMoves(state) {
  if (status(state).over) return [];
  if (state.ships.length === 0) {
    // Manual layouts are validated, not enumerated: there are millions of them, and the
    // UI drags ships around rather than picking from a list.
    return [{ type: 'autoplace' }];
  }
  if (phaseOf(state) !== 'battle') return [];
  if (state.turn !== state.side || state.pending) return [];
  const moves = [];
  for (let y = 0; y < SIZE; y += 1) {
    for (let x = 0; x < SIZE; x += 1) {
      if (state.shots[idx(x, y)] === 'none') moves.push({ type: 'fire', x, y });
    }
  }
  return moves;
}

function clone(state) {
  return {
    game: 'battleships',
    side: state.side,
    seed: state.seed,
    ships: state.ships.map((ship) => ({ ...ship, hits: ship.hits.slice() })),
    incoming: state.incoming.slice(),
    shots: state.shots.slice(),
    pending: state.pending ? { ...state.pending } : null,
    opponentReady: state.opponentReady,
    turn: state.turn,
  };
}

export function applyMove(state, move) {
  if (status(state).over) return { ok: false, error: 'game is over' };
  if (!isMoveObject(move)) return { ok: false, error: 'move must be an object' };
  const type = move.type;

  if (type === 'autoplace' || type === 'place') {
    if (state.ships.length > 0) return { ok: false, error: 'fleet is already placed' };
    let ships;
    if (type === 'autoplace') {
      ships = autoLayout(Number.isInteger(move.seed) ? move.seed >>> 0 : state.seed);
    } else {
      const result = normaliseLayout(move.ships);
      if (result.error) return { ok: false, error: result.error };
      ships = result.ships;
    }
    const next = clone(state);
    next.ships = ships;
    return { ok: true, state: next };
  }

  if (type === 'opponentReady') {
    if (state.opponentReady) return { ok: false, error: 'opponent is already ready' };
    const next = clone(state);
    next.opponentReady = true;
    return { ok: true, state: next };
  }

  if (type === 'fire') {
    if (phaseOf(state) !== 'battle') return { ok: false, error: 'both fleets must be placed first' };
    if (state.turn !== state.side) return { ok: false, error: 'not your turn' };
    if (state.pending) return { ok: false, error: 'waiting for the result of the last shot' };
    const { x, y } = move;
    if (!inBounds(x, y)) return { ok: false, error: `${x},${y} is off the board` };
    if (state.shots[idx(x, y)] !== 'none') return { ok: false, error: `already fired at ${x},${y}` };
    const next = clone(state);
    next.pending = { x, y };
    return { ok: true, state: next };
  }

  if (type === 'result') {
    if (!state.pending) return { ok: false, error: 'no shot is awaiting a result' };
    const { x, y, outcome } = move;
    if (state.pending.x !== x || state.pending.y !== y) {
      return { ok: false, error: `result is for ${x},${y} but the pending shot is ${state.pending.x},${state.pending.y}` };
    }
    if (!OUTCOMES.includes(outcome)) return { ok: false, error: `bad outcome ${JSON.stringify(outcome)}` };
    if (outcome === 'sunk' && sunkReported(state.shots) >= FLEET.length) {
      return { ok: false, error: 'the whole fleet is already reported sunk' };
    }
    const next = clone(state);
    next.shots[idx(x, y)] = outcome;
    next.pending = null;
    next.turn = other(state.side);
    return { ok: true, state: next };
  }

  if (type === 'incoming') {
    if (phaseOf(state) !== 'battle') return { ok: false, error: 'both fleets must be placed first' };
    if (state.turn !== other(state.side)) return { ok: false, error: 'not their turn' };
    const { x, y } = move;
    if (!inBounds(x, y)) return { ok: false, error: `${x},${y} is off the board` };
    if (state.incoming[idx(x, y)] !== 'none') return { ok: false, error: `they already fired at ${x},${y}` };
    const next = clone(state);
    const cell = idx(x, y);
    const ship = next.ships.find((s) => cellsOf(s).includes(cell));
    let outcome = 'miss';
    let name = null;
    if (ship) {
      ship.hits[cellsOf(ship).indexOf(cell)] = true;
      outcome = shipSunk(ship) ? 'sunk' : 'hit';
      name = ship.name;
    }
    next.incoming[cell] = ship ? 'hit' : 'miss';
    next.turn = state.side;
    // The caller has to send this back: it is the only thing the opponent learns.
    return { ok: true, state: next, effect: { outcome, ship: outcome === 'sunk' ? name : null } };
  }

  return { ok: false, error: `unknown move type ${JSON.stringify(type)}` };
}

export function serialize(state) {
  return {
    game: 'battleships',
    side: state.side,
    seed: state.seed,
    ships: state.ships.map((ship) => ({
      name: ship.name, size: ship.size, x: ship.x, y: ship.y, dir: ship.dir, hits: ship.hits.slice(),
    })),
    incoming: state.incoming.slice(),
    shots: state.shots.slice(),
    pending: state.pending ? { x: state.pending.x, y: state.pending.y } : null,
    opponentReady: state.opponentReady,
    turn: state.turn,
  };
}

export function deserialize(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('battleships: state must be an object');
  }
  if (value.game !== 'battleships') throw new Error('battleships: wrong game tag');
  if (!SIDES.includes(value.side)) throw new Error('battleships: side must be a or b');
  if (!SIDES.includes(value.turn)) throw new Error('battleships: turn must be a or b');
  if (!Number.isInteger(value.seed)) throw new Error('battleships: seed must be an integer');
  if (typeof value.opponentReady !== 'boolean') throw new Error('battleships: opponentReady must be a boolean');

  const readGrid = (grid, allowed, label) => {
    if (!Array.isArray(grid) || grid.length !== CELLS) throw new Error(`battleships: ${label} must have ${CELLS} cells`);
    return grid.map((cell) => {
      if (!allowed.includes(cell)) throw new Error(`battleships: bad ${label} cell ${JSON.stringify(cell)}`);
      return cell;
    });
  };
  const incoming = readGrid(value.incoming, INCOMING_STATES, 'incoming');
  const shots = readGrid(value.shots, SHOT_STATES, 'shots');

  if (!Array.isArray(value.ships)) throw new Error('battleships: ships must be an array');
  let ships = [];
  if (value.ships.length > 0) {
    const result = normaliseLayout(value.ships);
    if (result.error) throw new Error(`battleships: ${result.error}`);
    ships = result.ships;
    // normaliseLayout drops damage, because a fresh placement has none. Put it back and
    // check it: a hits array of the wrong length is a forged state.
    for (const ship of ships) {
      const source = value.ships.find((s) => s.x === ship.x && s.y === ship.y && s.dir === ship.dir && s.size === ship.size);
      const hits = source && source.hits;
      if (!Array.isArray(hits) || hits.length !== ship.size || hits.some((h) => typeof h !== 'boolean')) {
        throw new Error(`battleships: bad hits for ${ship.name}`);
      }
      ship.hits = hits.slice();
    }
  }

  // The incoming grid and our own damage are two views of the same events, so they must
  // agree. If they do not, one of them was edited.
  const hitCells = new Set();
  for (const ship of ships) {
    cellsOf(ship).forEach((cell, i) => { if (ship.hits[i]) hitCells.add(cell); });
  }
  const occupied = new Set(ships.flatMap(cellsOf));
  for (let cell = 0; cell < CELLS; cell += 1) {
    if (incoming[cell] === 'hit' && !hitCells.has(cell)) throw new Error(`battleships: incoming hit at ${cell} with no damaged ship`);
    if (incoming[cell] === 'miss' && occupied.has(cell)) throw new Error(`battleships: incoming miss at ${cell} lands on a ship`);
    if (incoming[cell] === 'none' && hitCells.has(cell)) throw new Error(`battleships: damage at ${cell} with no incoming shot`);
  }

  let pending = null;
  if (value.pending !== null && value.pending !== undefined) {
    const { x, y } = value.pending;
    if (!inBounds(x, y)) throw new Error('battleships: pending shot is off the board');
    if (shots[idx(x, y)] !== 'none') throw new Error('battleships: pending shot has already been resolved');
    pending = { x, y };
  }

  return {
    game: 'battleships',
    side: value.side,
    seed: value.seed >>> 0,
    ships,
    incoming,
    shots,
    pending,
    opponentReady: value.opponentReady,
    turn: value.turn,
  };
}
