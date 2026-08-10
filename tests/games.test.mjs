// Time killer game engines: rules, hostile input, serialization, and chess perft.
//
// The engines are pure functions over plain data, so unlike the other suites this one
// imports the modules directly instead of driving a server. There is nothing on the wire
// to observe: the thing under test IS the function.
//
// Two things earn most of the space here. The first is hostile input: moves arrive from
// the other device, so every engine is fed nulls, arrays, strings, fractional indices,
// out-of-range indices, moves out of turn and moves after the game ended, and must
// answer { ok: false } every time without throwing and without touching the old state.
// The second is chess perft: a move generator that has not been counted against
// published node counts is untested, because almost every generator bug is invisible in
// casual play and obvious at depth 3.

import { check, summary } from './lib/harness.mjs';
import * as tictactoe from '../public/js/games/tictactoe.js';
import * as connect4 from '../public/js/games/connect4.js';
import * as battleships from '../public/js/games/battleships.js';
import * as chess from '../public/js/games/chess.js';
import { GAMES, GAME_IDS, getGame, createGame } from '../public/js/games/index.js';

// ---------------------------------------------------------------- helpers

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i]) && ka.every((k) => deepEqual(a[k], b[k]));
}

/** Snapshot through serialize, which is the engine's own definition of "all of it". */
const snap = (engine, state) => JSON.stringify(engine.serialize(state));

/** Values that are not moves. Every one of these must be refused, not thrown on. */
const GARBAGE = [null, undefined, 0, 1, -1, NaN, '', 'e2e4', true, false, [], [0], {}, { index: '0' }];

function rejectsGarbage(engine, state) {
  const bad = [];
  for (const value of GARBAGE) {
    let result;
    try {
      result = engine.applyMove(state, value);
    } catch (err) {
      bad.push(`threw on ${JSON.stringify(value) ?? String(value)}: ${err.message}`);
      continue;
    }
    if (!result || result.ok !== false || typeof result.error !== 'string') {
      bad.push(`accepted ${JSON.stringify(value) ?? String(value)}`);
    }
  }
  return bad;
}

// ---------------------------------------------------------------- registry
{
  check('the registry lists all four games with unique ids',
    GAME_IDS.length === 4 && new Set(GAME_IDS).size === 4
      && ['tictactoe', 'connect4', 'battleships', 'chess'].every((id) => GAME_IDS.includes(id)),
    GAME_IDS.join(','));

  // Written out rather than read back from the entry, so a registry that claims connect 4
  // is 3x3 fails here instead of agreeing with itself.
  const DIMENSIONS = { tictactoe: [3, 3], connect4: [7, 6], battleships: [10, 10], chess: [8, 8] };
  const missing = [];
  for (const entry of GAMES) {
    const dims = DIMENSIONS[entry.id];
    if (!dims || entry.board.cols !== dims[0] || entry.board.rows !== dims[1]) {
      missing.push(`${entry.id}.board is ${entry.board.cols}x${entry.board.rows}`);
    }
    if (!(entry.board.min > 0) || !(entry.board.max > entry.board.min)) missing.push(`${entry.id}.board size range`);
    for (const fn of ['create', 'legalMoves', 'applyMove', 'status', 'serialize', 'deserialize']) {
      if (typeof entry.engine[fn] !== 'function') missing.push(`${entry.id}.${fn}`);
    }
    if (typeof entry.name !== 'string' || !entry.name) missing.push(`${entry.id}.name`);
    if (!entry.board || !Number.isInteger(entry.board.cols) || !Number.isInteger(entry.board.rows)) missing.push(`${entry.id}.board`);
    if (!entry.players || entry.players.min !== 2 || entry.players.max !== 2) missing.push(`${entry.id}.players`);
  }
  check('every registry entry exposes the whole contract plus its metadata', missing.length === 0, missing.join(', '));

  check('an unknown game id is declined rather than thrown on, because ids arrive over the wire',
    getGame('chess-960') === null && createGame('__proto__') === null && createGame('') === null,
    `${getGame('chess-960')} / ${createGame('__proto__')}`);

  const unstarted = GAMES.filter((entry) => {
    const started = createGame(entry.id, { seed: 5, side: 'b' });
    return !started || started.id !== entry.id || entry.engine.status(started.state).reason !== 'in-progress';
  }).map((entry) => entry.id);
  check('createGame starts every registered game and hands back a state its own engine recognises',
    unstarted.length === 0, unstarted.join(', '));
}

// ---------------------------------------------------------------- shared contract
{
  const engines = [
    ['tictactoe', tictactoe, tictactoe.create()],
    ['connect4', connect4, connect4.create()],
    ['battleships', battleships, battleships.create({ side: 'a', seed: 7 })],
    ['chess', chess, chess.create()],
  ];

  for (const [name, engine, state] of engines) {
    const bad = rejectsGarbage(engine, state);
    check(`${name} refuses every malformed move without throwing`, bad.length === 0, bad.join(' | '));

    const before = snap(engine, state);
    engine.applyMove(state, GARBAGE[0]);
    engine.applyMove(state, engine.legalMoves(state)[0]);
    check(`${name} leaves the input state untouched on both a rejected and an accepted move`,
      snap(engine, state) === before, 'state was mutated in place');

    const value = engine.serialize(state);
    check(`${name} serializes to something JSON can carry unchanged`,
      deepEqual(JSON.parse(JSON.stringify(value)), value), JSON.stringify(value).slice(0, 80));

    check(`${name} round-trips a fresh state exactly`,
      deepEqual(engine.deserialize(engine.serialize(state)), state), 'deserialize(serialize(s)) differs from s');

    const st = engine.status(state);
    check(`${name} reports a fresh game as in progress with a side to move`,
      st.over === false && st.winner === null && st.reason === 'in-progress' && typeof st.turn === 'string' && st.turn.length > 0,
      JSON.stringify(st));

    let threw = false;
    try { engine.deserialize({ game: 'not-this-game', board: [] }); } catch { threw = true; }
    check(`${name} rejects a state that is not its own rather than half-loading it`, threw, 'deserialize accepted a foreign state');
  }
}

// ---------------------------------------------------------------- tic tac toe
{
  const play = (indices) => {
    let state = tictactoe.create();
    for (const index of indices) {
      const result = tictactoe.applyMove(state, { index });
      if (!result.ok) return { error: `${index}: ${result.error}` };
      state = result.state;
    }
    return { state };
  };

  const otherCells = (line) => [0, 1, 2, 3, 4, 5, 6, 7, 8].filter((i) => !line.includes(i));

  // Written out here rather than read from the module. Looping over tictactoe.LINES
  // would silently test seven lines if someone deleted one, which is the definition of
  // a check that cannot fail.
  const ALL_LINES = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8],
    [0, 3, 6], [1, 4, 7], [2, 5, 8],
    [0, 4, 8], [2, 4, 6],
  ];
  check('the module agrees with this suite about what the eight winning lines are',
    tictactoe.LINES.length === 8
    && ALL_LINES.every((line) => tictactoe.LINES.some((l) => deepEqual([...l], line))),
    JSON.stringify(tictactoe.LINES));

  // Every line, for the side that moves first. Five plies: x x x interleaved with two o.
  {
    const bad = [];
    for (const line of ALL_LINES) {
      const fill = otherCells(line);
      const { state, error } = play([line[0], fill[0], line[1], fill[1], line[2]]);
      if (error) { bad.push(`${line}: ${error}`); continue; }
      const st = tictactoe.status(state);
      if (!st.over || st.winner !== 'x' || st.reason !== 'three-in-a-row' || !deepEqual([...st.line].sort(), [...line].sort())) {
        bad.push(`${line}: ${JSON.stringify(st)}`);
      }
    }
    check('x wins on all eight lines and the winning line is reported', bad.length === 0, bad.join(' | '));
  }

  // And for the second player, which needs three x moves that are NOT themselves a line.
  {
    const bad = [];
    for (const line of ALL_LINES) {
      const fill = otherCells(line);
      // Pick three of the six free cells that do not win: otherwise x ends it first.
      let xs = null;
      for (let a = 0; a < fill.length && !xs; a += 1) {
        for (let b = a + 1; b < fill.length && !xs; b += 1) {
          for (let c = b + 1; c < fill.length && !xs; c += 1) {
            const trio = [fill[a], fill[b], fill[c]];
            if (!tictactoe.LINES.some((l) => l.every((cell) => trio.includes(cell)))) xs = trio;
          }
        }
      }
      const { state, error } = play([xs[0], line[0], xs[1], line[1], xs[2], line[2]]);
      if (error) { bad.push(`${line}: ${error}`); continue; }
      const st = tictactoe.status(state);
      if (!st.over || st.winner !== 'o' || st.reason !== 'three-in-a-row') bad.push(`${line}: ${JSON.stringify(st)}`);
    }
    check('o wins on all eight lines', bad.length === 0, bad.join(' | '));
  }

  {
    const { state } = play([0, 1, 2, 4, 3, 5, 7, 6, 8]);
    const st = tictactoe.status(state);
    check('a full board with no line is a draw, not a win',
      st.over && st.winner === null && st.reason === 'draw' && st.line === null, JSON.stringify(st));
    check('a finished game offers no legal moves and refuses the ones that look free',
      tictactoe.legalMoves(state).length === 0, `${tictactoe.legalMoves(state).length} offered`);
  }

  {
    const { state } = play([0, 3, 1, 4, 2]); // x wins on the top row
    const result = tictactoe.applyMove(state, { index: 5 });
    check('a move after the game is over is refused', result.ok === false && /over/i.test(result.error), JSON.stringify(result.error));
  }

  {
    const { state } = play([4]);
    const cases = [
      ['an occupied cell', { index: 4 }],
      ['index 9', { index: 9 }],
      ['index -1', { index: -1 }],
      ['a fractional index', { index: 1.5 }],
      ['a string index', { index: '1' }],
      ['no index at all', { mark: 'x' }],
    ];
    const bad = cases.filter(([, move]) => tictactoe.applyMove(state, move).ok !== false).map(([label]) => label);
    check('tictactoe refuses occupied, out-of-range and non-integer cells', bad.length === 0, bad.join(', '));

    // A peer that names its own mark must not get to play out of turn: the engine takes
    // the mark from whose turn it is and ignores anything the move claims.
    const forged = tictactoe.applyMove(state, { index: 0, mark: 'x', turn: 'x' });
    check('a move claiming its own mark still places the side to move',
      forged.ok && forged.state.board[0] === 'o' && forged.state.turn === 'x',
      forged.ok ? `placed ${forged.state.board[0]}` : forged.error);
  }

  {
    const { state } = play([0, 3, 1, 4]);
    check('a played-out tictactoe state round-trips exactly',
      deepEqual(tictactoe.deserialize(tictactoe.serialize(state)), state), snap(tictactoe, state));

    const forged = tictactoe.serialize(state);
    forged.board[8] = 'x'; // an extra mark that no legal sequence could have produced
    let threw = false;
    try { tictactoe.deserialize(forged); } catch { threw = true; }
    check('a forged tictactoe board with impossible mark counts is rejected', threw, 'deserialize accepted it');
  }
}

// ---------------------------------------------------------------- connect 4
{
  const play = (columns, state = connect4.create()) => {
    for (const column of columns) {
      const result = connect4.applyMove(state, { column });
      if (!result.ok) return { error: `${column}: ${result.error}` };
      state = result.state;
    }
    return { state };
  };

  {
    const first = connect4.applyMove(connect4.create(), { column: 3 });
    const second = connect4.applyMove(first.state, { column: 3 });
    check('a disc falls to the bottom of its column and the next one stacks on it',
      first.effect.row === 5 && second.effect.row === 4
      && first.state.board[5 * 7 + 3] === 'r' && second.state.board[4 * 7 + 3] === 'y',
      `${first.effect.row} then ${second.effect.row}`);
  }

  const wins = [
    ['vertical', [3, 4, 3, 4, 3, 4, 3], 'r'],
    ['horizontal', [0, 0, 1, 1, 2, 2, 3], 'r'],
    ['diagonal up to the right', [0, 1, 1, 2, 2, 3, 2, 3, 3, 6, 3], 'r'],
    ['diagonal down to the right', [2, 2, 1, 3, 1, 1, 0, 6, 0, 6, 0, 0], 'y'],
  ];
  for (const [label, columns, winner] of wins) {
    const { state, error } = play(columns);
    const st = state ? connect4.status(state) : null;
    check(`connect 4 detects a ${label} win`,
      !error && st.over && st.winner === winner && st.reason === 'four-in-a-row' && st.line.length === 4,
      error || JSON.stringify(st));
  }

  {
    // A win must be the LAST event, not something the sequence stumbled through earlier.
    const bad = [];
    for (const [label, columns] of wins) {
      let state = connect4.create();
      for (let i = 0; i < columns.length; i += 1) {
        state = connect4.applyMove(state, { column: columns[i] }).state;
        const over = connect4.status(state).over;
        if (over !== (i === columns.length - 1)) bad.push(`${label} over=${over} at move ${i}`);
      }
    }
    check('none of the win sequences ended early, so each check tested the run it names', bad.length === 0, bad.join(' | '));
  }

  {
    // Columns 0 and 1 filled alternately, so neither stacks four of a colour.
    const { state } = play([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]);
    const cases = [
      ['a full column', { column: 0 }],
      ['column 7', { column: 7 }],
      ['column -1', { column: -1 }],
      ['a fractional column', { column: 2.5 }],
      ['a string column', { column: '2' }],
      ['no column', { row: 0 }],
    ];
    const bad = cases.filter(([, move]) => connect4.applyMove(state, move).ok !== false).map(([label]) => label);
    check('connect 4 refuses full, out-of-range and non-integer columns', bad.length === 0, bad.join(', '));
    check('the twelve discs alternated colour, so turn order is enforced by the engine',
      state.board.filter((c) => c === 'r').length === 6 && state.board.filter((c) => c === 'y').length === 6,
      snap(connect4, state));
  }

  {
    // A drop order that fills all 42 squares with no run of four. Found by search over a
    // colour pattern of two-high blocks, phase-shifted per column: every vertical,
    // horizontal and diagonal run in that pattern is at most two long.
    const order = [0, 0, 2, 0, 0, 1, 0, 0, 1, 2, 1, 1, 4, 1, 1, 2, 2, 3, 2, 2, 3, 4, 3, 3,
      6, 3, 3, 4, 4, 5, 4, 4, 5, 6, 5, 6, 6, 5, 6, 5, 5, 6];
    let state = connect4.create();
    let earlyOver = -1;
    for (let i = 0; i < order.length; i += 1) {
      const result = connect4.applyMove(state, { column: order[i] });
      if (!result.ok) { earlyOver = -2; break; }
      state = result.state;
      if (connect4.status(state).over && i < order.length - 1 && earlyOver < 0) earlyOver = i;
    }
    const st = connect4.status(state);
    check('a full connect 4 board with no run of four is a draw',
      earlyOver === -1 && state.ply === 42 && st.over && st.winner === null && st.reason === 'draw',
      `earlyOver=${earlyOver} ply=${state.ply} ${JSON.stringify(st)}`);
    check('the drawn board really is full and no further move is offered',
      state.board.every((cell) => cell !== null) && connect4.legalMoves(state).length === 0
      && connect4.applyMove(state, { column: 3 }).ok === false,
      `${state.board.filter(Boolean).length} discs`);
    check('the drawn connect 4 state round-trips exactly',
      deepEqual(connect4.deserialize(connect4.serialize(state)), state), 'round trip differs');
  }

  {
    const forged = connect4.serialize(connect4.create());
    forged.board[0] = 'r'; // top-left, with nothing under it
    forged.ply = 1;
    let threw = false;
    try { connect4.deserialize(forged); } catch (err) { threw = /floating/.test(err.message); }
    check('a connect 4 state with a disc floating in mid-air is rejected', threw, 'deserialize accepted a floating disc');
  }
}

// ---------------------------------------------------------------- battleships
{
  const totalCells = 17; // 5 + 4 + 3 + 3 + 2, stated rather than summed from FLEET
  check('the module ships the standard fleet',
    deepEqual(battleships.FLEET.map((s) => s.size), [5, 4, 3, 3, 2])
    && new Set(battleships.FLEET.map((s) => s.name)).size === 5,
    JSON.stringify(battleships.FLEET.map((s) => `${s.name}:${s.size}`)));

  {
    const a = battleships.autoLayout(4242);
    const b = battleships.autoLayout(4242);
    check('the same seed lays out the same fleet, square for square',
      deepEqual(a, b), JSON.stringify(a.map((s) => [s.name, s.x, s.y, s.dir])));

    const differing = [1, 2, 3, 4, 5, 6, 7, 8].filter((seed) => !deepEqual(battleships.autoLayout(seed), a));
    check('different seeds lay out different fleets, so the PRNG is actually consuming the seed',
      differing.length === 8, `${differing.length} of 8 differed`);

    const sizes = a.map((s) => s.size).sort((p, q) => q - p);
    const cells = new Set(a.flatMap(battleships.cellsOf));
    const inBounds = a.every((s) => (s.dir === 'h' ? s.x + s.size <= 10 : s.y + s.size <= 10) && s.x >= 0 && s.y >= 0);
    check('an auto-placed fleet is the standard 5,4,3,3,2, on the board and not overlapping',
      deepEqual(sizes, [5, 4, 3, 3, 2]) && inBounds && cells.size === totalCells,
      `${sizes.join(',')} covering ${cells.size} of ${totalCells} cells`);

    // A hundred seeds, because a placement bug that only bites on a rare retry path is
    // exactly the kind that ships.
    const broken = [];
    for (let seed = 0; seed < 100; seed += 1) {
      const fleet = battleships.autoLayout(seed);
      const occupied = new Set(fleet.flatMap(battleships.cellsOf));
      const fits = fleet.every((s) => battleships.cellsOf(s).every((c) => c >= 0 && c < 100)
        && (s.dir === 'h' ? s.x + s.size <= 10 : s.y + s.size <= 10));
      if (occupied.size !== totalCells || !fits) broken.push(seed);
    }
    check('a hundred seeds all produce a legal fleet', broken.length === 0, `bad seeds: ${broken.join(',')}`);

    const viaMove = battleships.applyMove(battleships.create({ side: 'a', seed: 4242 }), { type: 'autoplace' });
    check('autoplace through applyMove uses the state seed and matches autoLayout',
      viaMove.ok && deepEqual(viaMove.state.ships, a), viaMove.ok ? 'layout differed' : viaMove.error);
  }

  {
    const fresh = () => battleships.create({ side: 'a', seed: 1 });
    const good = [
      { size: 5, x: 0, y: 0, dir: 'h' }, { size: 4, x: 0, y: 1, dir: 'h' },
      { size: 3, x: 0, y: 2, dir: 'h' }, { size: 3, x: 0, y: 3, dir: 'h' },
      { size: 2, x: 0, y: 4, dir: 'h' },
    ];
    const placed = battleships.applyMove(fresh(), { type: 'place', ships: good });
    check('a valid manual layout is accepted and named from the canonical fleet',
      placed.ok && placed.state.ships.length === 5 && placed.state.ships[0].name === 'carrier'
      && placed.state.ships.every((s) => s.hits.length === s.size && s.hits.every((h) => h === false)),
      placed.ok ? placed.state.ships.map((s) => s.name).join(',') : placed.error);

    const bad = [
      ['overlapping ships', good.map((s, i) => (i === 1 ? { ...s, y: 0, x: 4 } : s))],
      ['a ship hanging off the edge', good.map((s, i) => (i === 0 ? { ...s, x: 7 } : s))],
      ['a negative origin', good.map((s, i) => (i === 0 ? { ...s, x: -1 } : s))],
      ['a fractional origin', good.map((s, i) => (i === 0 ? { ...s, y: 1.5 } : s))],
      ['a bad direction', good.map((s, i) => (i === 0 ? { ...s, dir: 'diagonal' } : s))],
      ['the wrong ship sizes', good.map((s, i) => (i === 0 ? { ...s, size: 6 } : s))],
      ['too few ships', good.slice(1)],
      ['too many ships', [...good, { size: 2, x: 0, y: 6, dir: 'h' }]],
      ['a ship that is not an object', [null, ...good.slice(1)]],
      ['ships that are not an array', 'a fleet'],
    ];
    const accepted = bad.filter(([, ships]) => battleships.applyMove(fresh(), { type: 'place', ships }).ok !== false)
      .map(([label]) => label);
    check('every invalid manual layout is refused', accepted.length === 0, accepted.join(', '));

    const twice = battleships.applyMove(placed.state, { type: 'place', ships: good });
    check('a second fleet placement is refused, so a peer cannot move its ships mid-game',
      twice.ok === false, JSON.stringify(twice.error));
  }

  {
    // Turn and phase enforcement, one hostile message at a time.
    let a = battleships.create({ side: 'a', seed: 11 });
    let b = battleships.create({ side: 'b', seed: 22 });
    check('nobody may fire before both fleets are down',
      battleships.applyMove(a, { type: 'fire', x: 0, y: 0 }).ok === false, 'fire was accepted during placement');

    a = battleships.applyMove(a, { type: 'autoplace' }).state;
    b = battleships.applyMove(b, { type: 'autoplace' }).state;
    check('placing our own fleet is not enough: the opponent has to be ready too',
      battleships.applyMove(a, { type: 'fire', x: 0, y: 0 }).ok === false
      && battleships.status(a).phase === 'placing', battleships.status(a).phase);

    a = battleships.applyMove(a, { type: 'opponentReady' }).state;
    b = battleships.applyMove(b, { type: 'opponentReady' }).state;
    check('a duplicate ready message is refused',
      battleships.applyMove(a, { type: 'opponentReady' }).ok === false, 'duplicate ready accepted');

    check('side b cannot fire first', battleships.applyMove(b, { type: 'fire', x: 0, y: 0 }).ok === false,
      JSON.stringify(battleships.status(b)));
    // The mirror of that: on a's own turn the opponent has no business shooting, so an
    // incoming message then is a peer trying to take two shots in a row.
    check('an incoming shot arriving on our own turn is refused',
      battleships.applyMove(a, { type: 'incoming', x: 0, y: 0 }).ok === false
      && battleships.applyMove(b, { type: 'incoming', x: 0, y: 0 }).ok === true,
      'turn direction for incoming shots is wrong');

    const offBoard = [{ x: 10, y: 0 }, { x: 0, y: 10 }, { x: -1, y: 0 }, { x: 1.5, y: 0 }, { x: '0', y: 0 }]
      .filter((c) => battleships.applyMove(a, { type: 'fire', ...c }).ok !== false);
    check('shots off the board or at non-integer squares are refused', offBoard.length === 0, JSON.stringify(offBoard));

    const fired = battleships.applyMove(a, { type: 'fire', x: 4, y: 4 });
    check('a legal shot is accepted and leaves the turn with the shooter until it is answered',
      fired.ok && deepEqual(fired.state.pending, { x: 4, y: 4 }) && fired.state.turn === 'a',
      fired.ok ? JSON.stringify(fired.state.pending) : fired.error);
    check('firing twice without a result is refused',
      battleships.applyMove(fired.state, { type: 'fire', x: 5, y: 5 }).ok === false, 'double shot accepted');

    const wrongSquare = battleships.applyMove(fired.state, { type: 'result', x: 5, y: 5, outcome: 'hit' });
    check('a result for a square we never fired at is refused', wrongSquare.ok === false, JSON.stringify(wrongSquare.error));
    const wrongOutcome = battleships.applyMove(fired.state, { type: 'result', x: 4, y: 4, outcome: 'obliterated' });
    check('a result with an outcome outside miss/hit/sunk is refused', wrongOutcome.ok === false, JSON.stringify(wrongOutcome.error));
    check('an unknown move type is refused rather than ignored',
      battleships.applyMove(fired.state, { type: 'surrender' }).ok === false, 'unknown type accepted');

    const answered = battleships.applyMove(fired.state, { type: 'result', x: 4, y: 4, outcome: 'miss' }).state;
    check('once answered the turn passes to the opponent and the square cannot be fired at again',
      answered.turn === 'b' && answered.pending === null
      && battleships.applyMove(answered, { type: 'fire', x: 4, y: 4 }).ok === false,
      `turn ${answered.turn}`);
    check('we cannot fire on the opponent turn', battleships.applyMove(answered, { type: 'fire', x: 1, y: 1 }).ok === false,
      'fired out of turn');

    const incoming = battleships.applyMove(answered, { type: 'incoming', x: 9, y: 9 });
    check('an incoming shot is resolved against our own board and reports what to send back',
      incoming.ok && ['miss', 'hit', 'sunk'].includes(incoming.effect.outcome) && incoming.state.turn === 'a',
      incoming.ok ? JSON.stringify(incoming.effect) : incoming.error);
    // Take the turn back round to the opponent so the replay is refused for being a
    // replay, not merely for arriving out of turn.
    const roundTrip = battleships.applyMove(
      battleships.applyMove(incoming.state, { type: 'fire', x: 0, y: 1 }).state,
      { type: 'result', x: 0, y: 1, outcome: 'miss' },
    );
    const replay = battleships.applyMove(roundTrip.state, { type: 'incoming', x: 9, y: 9 });
    check('the same incoming square cannot be replayed to grind our fleet down',
      roundTrip.ok && roundTrip.state.turn === 'b' && replay.ok === false && /already fired/.test(replay.error),
      roundTrip.ok ? JSON.stringify(replay.error) : roundTrip.error);
  }

  {
    // A whole game, played by two independent one-sided engines that never see each
    // other's ships. The only channel between them is the fire/result/incoming triple,
    // which is exactly what the peer link carries.
    let a = battleships.create({ side: 'a', seed: 2024 });
    let b = battleships.create({ side: 'b', seed: 1337 });
    for (const move of [{ type: 'autoplace' }, { type: 'opponentReady' }]) {
      a = battleships.applyMove(a, move).state;
      b = battleships.applyMove(b, move).state;
    }
    let shots = 0;
    let error = null;
    while (!battleships.status(a).over && !battleships.status(b).over) {
      if (shots > 400) { error = 'the game did not end'; break; }
      shots += 1;
      const shooterIsA = battleships.status(a).turn === 'a';
      let shooter = shooterIsA ? a : b;
      let target = shooterIsA ? b : a;
      const move = battleships.legalMoves(shooter)[0];
      if (!move) { error = `no legal move for ${shooterIsA ? 'a' : 'b'}`; break; }
      const fire = battleships.applyMove(shooter, move);
      const resolved = battleships.applyMove(target, { type: 'incoming', x: move.x, y: move.y });
      if (!fire.ok || !resolved.ok) { error = fire.error || resolved.error; break; }
      const answered = battleships.applyMove(fire.state, { type: 'result', x: move.x, y: move.y, outcome: resolved.effect.outcome });
      if (!answered.ok) { error = answered.error; break; }
      shooter = answered.state;
      target = resolved.state;
      if (shooterIsA) { a = shooter; b = target; } else { b = shooter; a = target; }
    }
    const sa = battleships.status(a);
    const sb = battleships.status(b);
    check('a full two-sided game ends with a winner', !error && sa.over && sb.over && sa.winner !== null,
      error || `${JSON.stringify(sa)} / ${JSON.stringify(sb)}`);
    check('both sides independently reach the SAME verdict, which is the only thing that keeps two boards honest',
      sa.winner === sb.winner && sa.reason === 'fleet-sunk' && sb.reason === 'fleet-sunk',
      `${sa.winner} vs ${sb.winner}`);

    const loser = sa.winner === 'a' ? b : a;
    const victor = sa.winner === 'a' ? a : b;
    check('the loser has every ship cell hit, and the winner counted five sunk reports',
      loser.ships.every((s) => s.hits.every(Boolean))
      && victor.shots.filter((s) => s === 'sunk').length === 5,
      `${loser.ships.filter((s) => s.hits.every(Boolean)).length} sunk / ${victor.shots.filter((s) => s === 'sunk').length} reported`);
    check('the finished game offers no further moves and refuses one anyway',
      battleships.legalMoves(a).length === 0 && battleships.applyMove(a, { type: 'fire', x: 0, y: 0 }).ok === false,
      `${battleships.legalMoves(a).length} moves offered`);
    check('a played-out battleships state round-trips exactly',
      deepEqual(battleships.deserialize(battleships.serialize(a)), a), 'round trip differs');
  }

  {
    // The incoming grid and our own damage are two records of the same events. A state
    // where they disagree was forged, and loading it would hand a peer free misses.
    let a = battleships.create({ side: 'a', seed: 3 });
    a = battleships.applyMove(a, { type: 'autoplace' }).state;
    const shipCell = battleships.cellsOf(a.ships[0])[0];
    const forged = battleships.serialize(a);
    forged.incoming[shipCell] = 'miss';
    let threw = false;
    try { battleships.deserialize(forged); } catch { threw = true; }
    check('a battleships state claiming a miss on one of our own ship squares is rejected', threw, 'deserialize accepted it');

    const forged2 = battleships.serialize(a);
    forged2.ships[0].hits[0] = true; // damage with no shot to explain it
    let threw2 = false;
    try { battleships.deserialize(forged2); } catch { threw2 = true; }
    check('a battleships state with damage nobody fired at is rejected', threw2, 'deserialize accepted it');

    const forged3 = battleships.serialize(a);
    forged3.ships[1] = { ...forged3.ships[1], x: forged3.ships[0].x, y: forged3.ships[0].y, dir: forged3.ships[0].dir };
    let threw3 = false;
    try { battleships.deserialize(forged3); } catch { threw3 = true; }
    check('a battleships state with overlapping ships is rejected', threw3, 'deserialize accepted it');
  }
}

// ---------------------------------------------------------------- chess: perft
//
// Perft counts leaf nodes of the legal move tree. It is the only practical way to test a
// move generator, because it is sensitive to every rule at once: miss one en passant
// case, one castling restriction or one pinned-piece exclusion and the count is wrong at
// depth 3. The reference numbers below are the published ones for the standard test
// positions, so a match is agreement with every other engine in the world.

const START_FEN = 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1';

/** Perft over an injected generator, so the same harness can be pointed at a broken one. */
function perftWith(generate, state, depth) {
  if (depth === 0) return 1;
  const moves = generate(state);
  if (depth === 1) return moves.length;
  let nodes = 0;
  for (const move of moves) {
    const result = chess.applyMove(state, move);
    if (!result.ok) throw new Error(`perft: applyMove refused a generated move ${JSON.stringify(move)}: ${result.error}`);
    nodes += perftWith(generate, result.state, depth - 1);
  }
  return nodes;
}

const perft = (state, depth) => perftWith(chess.legalMoves, state, depth);

const POSITIONS = [
  ['startpos', START_FEN, [20, 400, 8902, 197281]],
  ['kiwipete', 'r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq - 0 1', [48, 2039, 97862]],
  ['position 3 (rook and pawn endgame)', '8/2p5/3p4/KP5r/1R3p1k/8/4P1P1/8 w - - 0 1', [14, 191, 2812, 43238]],
  ['position 4 (promotions and pins)', 'r3k2r/Pppp1ppp/1b3nbN/nP6/BBP1P3/q4N2/Pp1P2PP/R2Q1RK1 w kq - 0 1', [6, 264, 9467]],
  ['position 5', 'rnbq1k1r/pp1Pbppp/2p5/8/2B5/8/PPP1NnPP/RNBQK2R w KQ - 1 8', [44, 1486, 62379]],
];

for (const [label, fen, expected] of POSITIONS) {
  const state = chess.fromFen(fen);
  const got = expected.map((_, i) => perft(state, i + 1));
  check(`perft(${label}) matches the published counts at depth 1 to ${expected.length}`,
    deepEqual(got, expected), `got ${got.join(', ')} wanted ${expected.join(', ')}`);
}

// ---------------------------------------------------------------- chess: perft negative control
{
  // A perft harness that cannot fail proves nothing, and "the numbers matched" is only
  // evidence if a wrong generator would have produced different numbers. So run the SAME
  // harness against a deliberately crippled generator: one that never offers a knight
  // move. If that still counts 20 and 8902, the harness is measuring nothing.
  const pieceAt = (fen, square) => {
    const rows = fen.split(' ')[0].split('/');
    const file = square.charCodeAt(0) - 97;
    const rank = Number(square[1]);
    let x = 0;
    for (const ch of rows[8 - rank]) {
      if (ch >= '1' && ch <= '8') x += Number(ch);
      else { if (x === file) return ch; x += 1; }
    }
    return null;
  };
  const noKnights = (state) => {
    const fen = chess.toFen(state);
    return chess.legalMoves(state).filter((move) => !'nN'.includes(pieceAt(fen, move.from)));
  };

  const start = chess.fromFen(START_FEN);
  check('the piece reader the control depends on actually reads the board',
    pieceAt(START_FEN, 'b1') === 'N' && pieceAt(START_FEN, 'e2') === 'P' && pieceAt(START_FEN, 'e4') === null
    && pieceAt(START_FEN, 'e8') === 'k',
    `${pieceAt(START_FEN, 'b1')} ${pieceAt(START_FEN, 'e2')} ${pieceAt(START_FEN, 'e4')} ${pieceAt(START_FEN, 'e8')}`);

  const brokenD1 = perftWith(noKnights, start, 1);
  const brokenD3 = perftWith(noKnights, start, 3);
  check('the same perft harness reports WRONG counts for a generator missing knight moves, so it can fail',
    brokenD1 !== 20 && brokenD3 !== 8902 && brokenD1 === 16 && brokenD3 > 0,
    `crippled generator gave ${brokenD1} at depth 1 and ${brokenD3} at depth 3, against 20 and 8902`);
  check('and the real generator passes that identical harness, so the difference is the generator',
    perftWith(chess.legalMoves, start, 1) === 20 && perftWith(chess.legalMoves, start, 3) === 8902,
    'the real generator failed the control harness');
}

// ---------------------------------------------------------------- chess: rules
{
  const has = (state, from, to, promotion) => chess.legalMoves(state)
    .some((m) => m.from === from && m.to === to && (promotion === undefined || m.promotion === promotion));
  const playMoves = (state, moves) => {
    for (const move of moves) {
      const result = chess.applyMove(state, move);
      if (!result.ok) return { error: `${move.from}${move.to}: ${result.error}` };
      state = result.state;
    }
    return { state };
  };
  const uci = (text) => text.split(' ').map((token) => (token.length === 5
    ? { from: token.slice(0, 2), to: token.slice(2, 4), promotion: token[4] }
    : { from: token.slice(0, 2), to: token.slice(2, 4) }));

  // ---- castling
  {
    const state = chess.fromFen('r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1');
    check('both castles are offered when nothing is in the way', has(state, 'e1', 'g1') && has(state, 'e1', 'c1'),
      chess.legalMoves(state).filter((m) => m.from === 'e1').map((m) => m.to).join(','));

    const short = chess.applyMove(state, { from: 'e1', to: 'g1' });
    const long = chess.applyMove(state, { from: 'e1', to: 'c1' });
    check('castling moves the rook as well as the king',
      short.ok && /^r3k2r\/8\/8\/8\/8\/8\/8\/R4RK1 b kq/.test(chess.toFen(short.state))
      && long.ok && /^r3k2r\/8\/8\/8\/8\/8\/8\/2KR3R b kq/.test(chess.toFen(long.state)),
      short.ok ? chess.toFen(short.state) : short.error);

    const blocked = chess.fromFen('r3k2r/8/8/8/8/8/8/R2QK1NR w KQkq - 0 1');
    check('castling is refused when a piece stands between king and rook',
      !has(blocked, 'e1', 'g1') && !has(blocked, 'e1', 'c1')
      && chess.applyMove(blocked, { from: 'e1', to: 'g1' }).ok === false, 'a blocked castle was allowed');

    const through = chess.fromFen('5rk1/8/8/8/8/8/8/R3K2R w KQ - 0 1');
    check('castling through an attacked square is refused, but the other side is still legal',
      !has(through, 'e1', 'g1') && has(through, 'e1', 'c1'), 'f1 is attacked by the rook on f8');

    const inCheck = chess.fromFen('4r1k1/8/8/8/8/8/8/R3K2R w KQ - 0 1');
    check('castling out of check is refused on both sides',
      !has(inCheck, 'e1', 'g1') && !has(inCheck, 'e1', 'c1') && chess.inCheck(inCheck), 'castled while in check');

    const into = chess.fromFen('6r1/8/8/3k4/8/8/8/R3K2R w KQ - 0 1');
    check('castling into an attacked square is refused', !has(into, 'e1', 'g1'), 'g1 is attacked by the rook on g8');

    const moved = playMoves(chess.fromFen('r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1'), uci('a1b1 a8b8 b1a1 b8a8'));
    check('moving a rook out and back permanently loses that castling right',
      !moved.error && !has(moved.state, 'e1', 'c1') && has(moved.state, 'e1', 'g1'),
      moved.error || chess.toFen(moved.state));
    check('and the FEN records the loss of exactly those two rights',
      !moved.error && chess.toFen(moved.state).split(' ')[2] === 'Kk',
      moved.error || chess.toFen(moved.state).split(' ')[2]);

    const kingMoved = playMoves(chess.fromFen('r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1'), uci('e1f1 a8b8 f1e1 b8a8'));
    check('moving the king loses both of its castling rights for good',
      !kingMoved.error && !has(kingMoved.state, 'e1', 'g1') && !has(kingMoved.state, 'e1', 'c1'),
      kingMoved.error || chess.toFen(kingMoved.state));
  }

  // ---- en passant
  {
    const before = chess.fromFen('4k3/8/8/8/4p3/8/3P4/4K3 w - - 0 1');
    const pushed = chess.applyMove(before, { from: 'd2', to: 'd4' });
    check('a double pawn push makes the en passant capture available to the pawn beside it',
      pushed.ok && has(pushed.state, 'e4', 'd3'), pushed.ok ? chess.toFen(pushed.state) : pushed.error);
    const captured = chess.applyMove(pushed.state, { from: 'e4', to: 'd3' });
    check('en passant removes the pawn that jumped past, not the square it landed on',
      captured.ok && chess.toFen(captured.state).startsWith('4k3/8/8/8/8/3p4/8/4K3 w'),
      captured.ok ? chess.toFen(captured.state) : captured.error);

    // Two single pushes reach the same square as one double push, so if the engine set
    // the en passant square on arrival rather than on the jump, exd3 would be offered
    // here with nothing on d3 to capture.
    const crawled = playMoves(before, uci('d2d3 e8d8 d3d4'));
    check('a pawn that walked to the fourth rank in two steps grants no en passant',
      !crawled.error && !has(crawled.state, 'e4', 'd3')
      && chess.applyMove(crawled.state, { from: 'e4', to: 'd3' }).ok === false
      && chess.toFen(crawled.state).split(' ')[3] === '-',
      crawled.error || chess.toFen(crawled.state));

    const stale = playMoves(before, uci('d2d4 e8d8 e1e2 d8e8'));
    check('an en passant chance not taken immediately is gone',
      !stale.error && !has(stale.state, 'e4', 'd3'), stale.error || chess.toFen(stale.state));

    // The classic: both pawns leave the fourth rank at once, so a rook behind them ends
    // up staring at the king. Generators that test legality by moving only the capturing
    // pawn miss this every time.
    const pinned = chess.fromFen('8/8/8/8/k2Pp2R/8/8/4K3 b - d3 0 1');
    const unpinned = chess.fromFen('8/8/8/8/k2Pp3/8/8/4K3 b - d3 0 1');
    check('en passant is refused when the capture would expose our own king along the rank',
      !has(pinned, 'e4', 'd3') && chess.applyMove(pinned, { from: 'e4', to: 'd3' }).ok === false,
      chess.legalMoves(pinned).filter((m) => m.from === 'e4').map((m) => m.to).join(','));
    check('and the same position without the rook does allow it, so that check is not vacuous',
      has(unpinned, 'e4', 'd3'), 'the engine never generates this en passant at all');
  }

  // ---- promotion
  {
    const state = chess.fromFen('4k3/P7/8/8/8/8/8/4K3 w - - 0 1');
    const promos = chess.legalMoves(state).filter((m) => m.from === 'a7' && m.to === 'a8');
    check('a pawn reaching the last rank offers exactly four promotions',
      promos.length === 4 && deepEqual(promos.map((m) => m.promotion).sort(), ['b', 'n', 'q', 'r']),
      promos.map((m) => m.promotion).join(','));
    const knight = chess.applyMove(state, { from: 'a7', to: 'a8', promotion: 'n' });
    check('promoting to a knight puts a knight on the board, not a queen',
      knight.ok && chess.toFen(knight.state).startsWith('N3k3/8/'), knight.ok ? chess.toFen(knight.state) : knight.error);
    check('a promotion with no piece named is refused rather than assumed to be a queen',
      chess.applyMove(state, { from: 'a7', to: 'a8' }).ok === false,
      JSON.stringify(chess.applyMove(state, { from: 'a7', to: 'a8' }).error));
    const bogus = ['k', 'p', 'Q', 'x', 1, null, 'qq'].filter((p) => chess.applyMove(state, { from: 'a7', to: 'a8', promotion: p }).ok !== false);
    check('a promotion to a king, a pawn or nonsense is refused', bogus.length === 0, JSON.stringify(bogus));

    const capture = chess.fromFen('1n2k3/P7/8/8/8/8/8/4K3 w - - 0 1');
    check('a pawn may also promote by capturing onto the last rank',
      chess.legalMoves(capture).filter((m) => m.from === 'a7' && m.to === 'b8').length === 4,
      chess.legalMoves(capture).filter((m) => m.from === 'a7').map((m) => `${m.to}${m.promotion}`).join(','));
  }

  // ---- terminal conditions
  {
    const fools = playMoves(chess.create(), uci('f2f3 e7e5 g2g4 d8h4'));
    const st = fools.error ? null : chess.status(fools.state);
    check('checkmate is detected and the winner is the side that gave it',
      !fools.error && st.over && st.winner === 'b' && st.reason === 'checkmate' && st.turn === 'w'
      && chess.legalMoves(fools.state).length === 0,
      fools.error || JSON.stringify(st));
    check('a move after checkmate is refused',
      !fools.error && chess.applyMove(fools.state, { from: 'g1', to: 'h3' }).ok === false, 'played on after mate');

    const stale = chess.fromFen('7k/5Q2/6K1/8/8/8/8/8 b - - 0 1');
    const ss = chess.status(stale);
    check('stalemate is a draw with no winner, and is not confused with checkmate',
      ss.over && ss.winner === null && ss.reason === 'stalemate' && !chess.inCheck(stale)
      && chess.legalMoves(stale).length === 0, JSON.stringify(ss));

    const nearly = chess.fromFen('4k3/8/8/8/8/8/8/R3K2R w - - 99 60');
    check('the game is still live at 99 halfmoves', chess.status(nearly).over === false, JSON.stringify(chess.status(nearly)));
    const fifty = chess.applyMove(nearly, { from: 'a1', to: 'a2' });
    const fs = fifty.ok ? chess.status(fifty.state) : null;
    check('the hundredth quiet halfmove ends the game as a draw',
      fifty.ok && fs.over && fs.winner === null && fs.reason === 'fifty-move',
      fifty.ok ? JSON.stringify(fs) : fifty.error);

    const reset = chess.fromFen('4k3/8/8/8/8/8/P7/4K3 w - - 99 60');
    const pushed = chess.applyMove(reset, { from: 'a2', to: 'a3' });
    check('a pawn move resets the halfmove clock instead of ending the game',
      pushed.ok && chess.status(pushed.state).over === false && chess.toFen(pushed.state).split(' ')[4] === '0',
      pushed.ok ? chess.toFen(pushed.state) : pushed.error);

    const twice = playMoves(chess.create(), uci('g1f3 g8f6 f3g1 f6g8'));
    check('the position repeated twice is not yet a draw',
      !twice.error && chess.status(twice.state).over === false, twice.error || JSON.stringify(chess.status(twice.state)));
    const thrice = playMoves(twice.state, uci('g1f3 g8f6 f3g1 f6g8'));
    const ts = thrice.error ? null : chess.status(thrice.state);
    check('the third occurrence of the same position is a draw by repetition',
      !thrice.error && ts.over && ts.winner === null && ts.reason === 'threefold',
      thrice.error || JSON.stringify(ts));
  }

  // ---- hostile moves
  {
    const state = chess.create();
    const cases = [
      ['a black piece while white is to move', { from: 'e7', to: 'e5' }],
      ['a piece from an empty square', { from: 'e4', to: 'e5' }],
      ['a rook move through its own pawn', { from: 'a1', to: 'a4' }],
      ['a pawn three squares', { from: 'e2', to: 'e5' }],
      ['a square that does not exist', { from: 'e2', to: 'e9' }],
      ['a file that does not exist', { from: 'e2', to: 'i4' }],
      ['an uppercase square', { from: 'E2', to: 'E4' }],
      ['a move to its own square', { from: 'e2', to: 'e2' }],
      ['numeric coordinates', { from: 12, to: 28 }],
      ['a from field that is an object', { from: { file: 4, rank: 1 }, to: 'e4' }],
      ['a castle that is not available', { from: 'e1', to: 'g1' }],
    ];
    const accepted = cases.filter(([, move]) => chess.applyMove(state, move).ok !== false).map(([label]) => label);
    check('chess refuses every hostile or malformed move at the start position', accepted.length === 0, accepted.join(', '));

    const exposed = chess.fromFen('4k3/8/8/8/8/8/4R3/4K3 b - - 0 1');
    check('a king may not walk into check', !has(exposed, 'e8', 'e7') && chess.applyMove(exposed, { from: 'e8', to: 'e7' }).ok === false,
      chess.legalMoves(exposed).map((m) => m.to).join(','));

    // Same knight on the same square in both positions: the only difference is whether
    // the black rook stands on the e file behind it.
    const pinned = chess.fromFen('4r2k/8/8/8/8/8/4N3/4K3 w - - 0 1');
    const free = chess.fromFen('5r1k/8/8/8/8/8/4N3/4K3 w - - 0 1');
    check('a pinned piece may not move off the pin line, while the same piece unpinned may',
      has(free, 'e2', 'd4') && !has(pinned, 'e2', 'd4')
      && chess.legalMoves(pinned).every((m) => m.from !== 'e2')
      && chess.applyMove(pinned, { from: 'e2', to: 'd4' }).ok === false,
      chess.legalMoves(pinned).filter((m) => m.from === 'e2').map((m) => m.to).join(','));

    // A rook on e2 checks the black king down the e file. The only replies are the four
    // king steps off that file: Ke7 stays on it and Kd8/Kf8/Kd7/Kf7 do not. Naming the
    // exact set is the point, because "some moves exist" would pass on a broken engine.
    const inCheckPos = chess.fromFen('4k3/8/8/8/8/8/4R3/4K3 b - - 0 1');
    const replies = chess.legalMoves(inCheckPos).map((m) => `${m.from}${m.to}`).sort();
    check('in check, the legal replies are exactly the moves that escape the check',
      chess.inCheck(inCheckPos) && deepEqual(replies, ['e8d7', 'e8d8', 'e8f7', 'e8f8']),
      replies.join(','));
    check('and the same position with the rook one file over is not check at all, so that is not vacuous',
      !chess.inCheck(chess.fromFen('4k3/8/8/8/8/8/5R2/4K3 b - - 0 1')), 'a rook on f2 was read as check on e8');
  }

  // ---- serialization
  {
    // A game with castling, a capture, an en passant window and a promotion in it, so the
    // round trip has to carry rights, the clock and the repetition history, not just the
    // pieces.
    const played = playMoves(chess.create(),
      uci('e2e4 e7e5 g1f3 b8c6 f1c4 g8f6 e1g1 f8c5 d2d3 e8g8 c1g5 d7d6 b1c3 c8g4'));
    check('a fifteen-move opening with both castles played out cleanly', !played.error, played.error || '');
    // Fall back to the start position if that failed, so the rest of this block reports
    // its own verdicts instead of dying on an undefined state and hiding them.
    const state = played.state || chess.create();
    const restored = chess.deserialize(chess.serialize(state));
    check('a mid-game chess state round-trips exactly',
      deepEqual(restored, state) && chess.toFen(restored) === chess.toFen(state), chess.toFen(state));
    check('and the restored state generates the identical move list, so nothing invisible was lost',
      deepEqual(chess.legalMoves(restored), chess.legalMoves(state)),
      `${chess.legalMoves(restored).length} vs ${chess.legalMoves(state).length}`);

    const value = chess.serialize(state);
    check('the serialized chess state survives JSON unchanged',
      deepEqual(JSON.parse(JSON.stringify(value)), value), JSON.stringify(value).slice(0, 100));

    // Repetition history has to survive the wire: a state restored without it would let a
    // peer avoid a draw simply by reconnecting.
    const twice = playMoves(chess.create(), uci('g1f3 g8f6 f3g1 f6g8'));
    const carried = twice.state ? chess.deserialize(chess.serialize(twice.state)) : null;
    const afterRestore = carried ? playMoves(carried, uci('g1f3 g8f6 f3g1 f6g8')) : { error: twice.error };
    check('repetition history survives serialization, so a reconnect cannot dodge a threefold draw',
      !afterRestore.error && chess.status(afterRestore.state).reason === 'threefold',
      afterRestore.error || JSON.stringify(chess.status(afterRestore.state)));

    let threw = false;
    try { chess.deserialize({ game: 'chess', fen: 'not a fen' }); } catch { threw = true; }
    check('a corrupt chess state is rejected rather than half-loaded', threw, 'deserialize accepted garbage');

    const before = snap(chess, state);
    chess.applyMove(state, chess.legalMoves(state)[0]);
    chess.applyMove(state, { from: 'zz', to: 'zz' });
    check('applyMove never writes through to the state it was handed',
      snap(chess, state) === before, 'the mid-game state was mutated');
  }
}

process.exit(summary('games') ? 0 : 1);
