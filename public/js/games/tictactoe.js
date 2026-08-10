// Tic tac toe: 3x3, X moves first.
//
// The smallest engine in the set, so it doubles as the reference implementation of the
// shared contract documented in index.js. Anything the other three do differently is a
// deliberate difference, not an accident.
//
// Moves arrive from the other device over the peer link, so nothing here trusts its
// input. A move is a value that came off a wire: it may be null, an array, a string, or
// an object with a fractional index. Every one of those is a rejection, not a throw.

export const SIZE = 3;
export const CELLS = SIZE * SIZE;

/** Index triples that win. Precomputed because a 3x3 board has only eight of them. */
export const LINES = Object.freeze([
  [0, 1, 2], [3, 4, 5], [6, 7, 8], // rows
  [0, 3, 6], [1, 4, 7], [2, 5, 8], // columns
  [0, 4, 8], [2, 4, 6], // diagonals
].map(Object.freeze));

const MARKS = Object.freeze(['x', 'o']);

function isMoveObject(move) {
  return typeof move === 'object' && move !== null && !Array.isArray(move);
}

/**
 * A fresh game. There is nothing random about tic tac toe, so the seed argument that
 * the other engines take is accepted and ignored: the registry calls every factory the
 * same way.
 */
export function create() {
  return {
    game: 'tictactoe',
    board: new Array(CELLS).fill(null),
    turn: 'x',
    ply: 0,
  };
}

/** The winning mark and its line, or null. Read-only. */
function findWin(board) {
  for (const line of LINES) {
    const [a, b, c] = line;
    if (board[a] && board[a] === board[b] && board[a] === board[c]) {
      return { mark: board[a], line };
    }
  }
  return null;
}

export function status(state) {
  const win = findWin(state.board);
  if (win) return { over: true, winner: win.mark, reason: 'three-in-a-row', turn: state.turn, line: win.line };
  if (state.board.every((cell) => cell !== null)) {
    return { over: true, winner: null, reason: 'draw', turn: state.turn, line: null };
  }
  return { over: false, winner: null, reason: 'in-progress', turn: state.turn, line: null };
}

export function legalMoves(state) {
  if (status(state).over) return [];
  const moves = [];
  for (let i = 0; i < CELLS; i += 1) {
    if (state.board[i] === null) moves.push({ index: i });
  }
  return moves;
}

export function applyMove(state, move) {
  if (status(state).over) return { ok: false, error: 'game is over' };
  if (!isMoveObject(move)) return { ok: false, error: 'move must be an object' };
  const { index } = move;
  if (!Number.isInteger(index)) return { ok: false, error: 'index must be an integer' };
  if (index < 0 || index >= CELLS) return { ok: false, error: `index ${index} is off the board` };
  if (state.board[index] !== null) return { ok: false, error: `cell ${index} is taken` };
  // The mover is always the side to move. A move carrying its own "mark" field would let
  // a hostile peer play twice, so any such field is ignored.
  const board = state.board.slice();
  board[index] = state.turn;
  return {
    ok: true,
    state: {
      game: 'tictactoe',
      board,
      turn: state.turn === 'x' ? 'o' : 'x',
      ply: state.ply + 1,
    },
  };
}

export function serialize(state) {
  return {
    game: 'tictactoe',
    board: state.board.slice(),
    turn: state.turn,
    ply: state.ply,
  };
}

export function deserialize(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('tictactoe: state must be an object');
  }
  if (value.game !== 'tictactoe') throw new Error('tictactoe: wrong game tag');
  if (!Array.isArray(value.board) || value.board.length !== CELLS) {
    throw new Error('tictactoe: board must have nine cells');
  }
  const board = value.board.map((cell) => {
    if (cell === null) return null;
    if (MARKS.includes(cell)) return cell;
    throw new Error(`tictactoe: bad cell ${JSON.stringify(cell)}`);
  });
  if (!MARKS.includes(value.turn)) throw new Error('tictactoe: turn must be x or o');
  if (!Number.isInteger(value.ply) || value.ply < 0 || value.ply > CELLS) {
    throw new Error('tictactoe: bad ply count');
  }
  // The ply count is redundant with the board, so a mismatch means the value was edited
  // by hand or in transit. Rebuilding it from the board would hide that.
  const placed = board.filter((cell) => cell !== null).length;
  if (placed !== value.ply) throw new Error('tictactoe: ply does not match the board');
  const xs = board.filter((cell) => cell === 'x').length;
  if (xs !== Math.ceil(value.ply / 2)) throw new Error('tictactoe: mark counts are impossible');
  if (value.turn !== (value.ply % 2 === 0 ? 'x' : 'o')) throw new Error('tictactoe: turn does not match the ply');
  return { game: 'tictactoe', board, turn: value.turn, ply: value.ply };
}
