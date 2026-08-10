// Connect 4: seven columns, six rows, red moves first.
//
// The board is a flat array indexed `row * COLS + col` with row 0 at the TOP, so a disc
// dropped into an empty column lands at row ROWS-1. Rendering code reads the array in
// order and gets the board the right way up.
//
// Same hostile-input stance as the rest of the set: a move is a column number that came
// off the wire, and anything else about it is ignored. See index.js for the contract.

export const COLS = 7;
export const ROWS = 6;
export const CELLS = COLS * ROWS;
export const CONNECT = 4;

const DISCS = Object.freeze(['r', 'y']);

// Right, down, down-right, down-left. Only four directions are needed: a run in the
// opposite direction is the same run found from its other end.
const DIRECTIONS = Object.freeze([[0, 1], [1, 0], [1, 1], [1, -1]]);

function isMoveObject(move) {
  return typeof move === 'object' && move !== null && !Array.isArray(move);
}

const at = (board, row, col) => board[row * COLS + col];

export function create() {
  return {
    game: 'connect4',
    board: new Array(CELLS).fill(null),
    turn: 'r',
    ply: 0,
  };
}

/** The lowest empty row in a column, or -1 if the column is full. */
export function dropRow(state, col) {
  for (let row = ROWS - 1; row >= 0; row -= 1) {
    if (at(state.board, row, col) === null) return row;
  }
  return -1;
}

function findWin(board) {
  for (let row = 0; row < ROWS; row += 1) {
    for (let col = 0; col < COLS; col += 1) {
      const disc = at(board, row, col);
      if (!disc) continue;
      for (const [dr, dc] of DIRECTIONS) {
        const endRow = row + dr * (CONNECT - 1);
        const endCol = col + dc * (CONNECT - 1);
        if (endRow < 0 || endRow >= ROWS || endCol < 0 || endCol >= COLS) continue;
        const line = [];
        let run = true;
        for (let step = 0; step < CONNECT; step += 1) {
          const r = row + dr * step;
          const c = col + dc * step;
          if (at(board, r, c) !== disc) { run = false; break; }
          line.push(r * COLS + c);
        }
        if (run) return { disc, line };
      }
    }
  }
  return null;
}

export function status(state) {
  const win = findWin(state.board);
  if (win) return { over: true, winner: win.disc, reason: 'four-in-a-row', turn: state.turn, line: win.line };
  if (state.ply >= CELLS) return { over: true, winner: null, reason: 'draw', turn: state.turn, line: null };
  return { over: false, winner: null, reason: 'in-progress', turn: state.turn, line: null };
}

export function legalMoves(state) {
  if (status(state).over) return [];
  const moves = [];
  for (let col = 0; col < COLS; col += 1) {
    if (dropRow(state, col) >= 0) moves.push({ column: col });
  }
  return moves;
}

export function applyMove(state, move) {
  if (status(state).over) return { ok: false, error: 'game is over' };
  if (!isMoveObject(move)) return { ok: false, error: 'move must be an object' };
  const { column } = move;
  if (!Number.isInteger(column)) return { ok: false, error: 'column must be an integer' };
  if (column < 0 || column >= COLS) return { ok: false, error: `column ${column} is off the board` };
  const row = dropRow(state, column);
  if (row < 0) return { ok: false, error: `column ${column} is full` };
  const board = state.board.slice();
  board[row * COLS + column] = state.turn;
  return {
    ok: true,
    state: {
      game: 'connect4',
      board,
      turn: state.turn === 'r' ? 'y' : 'r',
      ply: state.ply + 1,
    },
    // The landing square is not derivable from the move alone once the state has moved
    // on, and the animation needs it.
    effect: { row, column, disc: state.turn },
  };
}

export function serialize(state) {
  return {
    game: 'connect4',
    board: state.board.slice(),
    turn: state.turn,
    ply: state.ply,
  };
}

export function deserialize(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('connect4: state must be an object');
  }
  if (value.game !== 'connect4') throw new Error('connect4: wrong game tag');
  if (!Array.isArray(value.board) || value.board.length !== CELLS) {
    throw new Error('connect4: board must have 42 cells');
  }
  const board = value.board.map((cell) => {
    if (cell === null) return null;
    if (DISCS.includes(cell)) return cell;
    throw new Error(`connect4: bad cell ${JSON.stringify(cell)}`);
  });
  // Gravity is an invariant, not a rendering detail: a disc with a hole under it means
  // the state was forged, and accepting it would let a peer place anywhere it liked.
  for (let col = 0; col < COLS; col += 1) {
    let seenEmpty = false;
    for (let row = ROWS - 1; row >= 0; row -= 1) {
      if (at(board, row, col) === null) seenEmpty = true;
      else if (seenEmpty) throw new Error(`connect4: floating disc in column ${col}`);
    }
  }
  if (!DISCS.includes(value.turn)) throw new Error('connect4: turn must be r or y');
  if (!Number.isInteger(value.ply) || value.ply < 0 || value.ply > CELLS) {
    throw new Error('connect4: bad ply count');
  }
  const placed = board.filter((cell) => cell !== null).length;
  if (placed !== value.ply) throw new Error('connect4: ply does not match the board');
  const reds = board.filter((cell) => cell === 'r').length;
  if (reds !== Math.ceil(value.ply / 2)) throw new Error('connect4: disc counts are impossible');
  if (value.turn !== (value.ply % 2 === 0 ? 'r' : 'y')) throw new Error('connect4: turn does not match the ply');
  return { game: 'connect4', board, turn: value.turn, ply: value.ply };
}
