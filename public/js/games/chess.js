// Chess rules engine: pure, deterministic, no AI.
//
// Two humans play over a peer link, so every move this module sees arrived from
// another device and is assumed hostile until proved legal. applyMove takes an
// arbitrary JavaScript value and answers ok/error; it never throws and never
// trusts a shape. The only path that changes a position is a move that appears,
// exactly, in legalMoves(state). There is no "close enough": a promotion without
// its piece is rejected rather than defaulted to a queen, because the remote side
// silently getting a different piece than it thought it played is the kind of
// desync that ends a game in an argument.
//
// ---------------------------------------------------------------- representation
//
// The public state is a plain JSON object and nothing else, so serialize is a
// deep copy and deserialize is a validator. It carries exactly what the rules
// need:
//
//   board     64 characters, rank 8 first, a-file first: "rnbqkbnr/..." without
//             the slashes and with '.' for an empty square. FEN letters, so it
//             reads correctly in a debugger and converts to FEN by run-length.
//   turn      'w' | 'b'
//   castling  subset of "KQkq" in that order, '' for none
//   ep        en passant TARGET square ('e3') or null, set after every double
//             push exactly as FEN does, whether or not a capture is available
//   halfmove  plies since the last pawn move or capture (the fifty-move counter)
//   fullmove  standard, increments after black moves
//   history   repetition keys, one per position reached, current one last
//
// Internally, move generation runs on a 0x88 Int8Array: one board, one array
// index per square, and an off-board test that is a single bitwise AND. Legality
// is decided by making the move on a scratch copy and asking whether our king is
// attacked, then unmaking. That is slower than pin-aware generation and it is
// also the only version that gets en passant right without special cases: the
// captured pawn is genuinely off the board while the test runs, so the classic
// "capture exposes my own king along the rank" position rejects itself.
//
// The scratch board is private and never escapes. applyMove copies before it
// writes, so the state a caller holds is never touched.
//
// ---------------------------------------------------------------- draws are automatic
//
// The fifty-move rule and threefold repetition are reported as over: true the
// moment the condition holds, rather than as a claim one side may make. A
// claimable draw needs a claim message, a rule for who may send it, and a way to
// resolve both sides claiming at once - three things a two-browser link with no
// server arbiter cannot settle. Automatic means both devices compute the same
// answer from the same state with no extra traffic, which is the only property
// that matters here. Over-the-board tournament rules would differ.
//
// ---------------------------------------------------------------- caching
//
// legalMoves memoises on the state OBJECT in a WeakMap, and applyMove reuses that
// list to validate. State is immutable by contract, so this is invisible; mutate
// a state you already passed in and you get stale answers, which is your bug, not
// this module's. It exists because perft through the public API otherwise
// regenerates the parent's move list once per child.

const WHITE = 8;
const BLACK = 16;
const COLOR = WHITE | BLACK;

const PAWN = 1;
const KNIGHT = 2;
const BISHOP = 3;
const ROOK = 4;
const QUEEN = 5;
const KING = 6;

const PIECE_CHARS = '.pnbrqk';
const FILE_CHARS = 'abcdefgh';

const KNIGHT_DIRS = [33, 31, 18, 14, -33, -31, -18, -14];
const KING_DIRS = [16, -16, 1, -1, 17, 15, -17, -15];
const BISHOP_DIRS = [17, 15, -17, -15];
const ROOK_DIRS = [16, -16, 1, -1];

// Internal move: from | to<<8 | promotionType<<16 | flags.
const F_EP = 1 << 20;
const F_CASTLE = 1 << 21;
const F_DOUBLE = 1 << 22;

const START_FEN = 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1';

// Corners, in 0x88 coordinates. Any move that starts or ends on one of these
// kills the matching castling right, which covers "rook moved" and "rook was
// captured where it stood" with one rule.
const A1 = 0, H1 = 7, E1 = 4, A8 = 112, H8 = 119, E8 = 116;

// ------------------------------------------------------------------ squares

function sqToAlg(sq) {
  return FILE_CHARS[sq & 7] + (1 + (sq >> 4));
}

// -1 for anything that is not a real square name, so callers can branch on it
// instead of catching.
function algToSq(s) {
  if (typeof s !== 'string' || s.length !== 2) return -1;
  const f = s.charCodeAt(0) - 97;
  const r = s.charCodeAt(1) - 49;
  if (f < 0 || f > 7 || r < 0 || r > 7) return -1;
  return r * 16 + f;
}

// board string index (0 = a8, 63 = h1) <-> 0x88 square
function idxToSq(i) {
  return (7 - (i >> 3)) * 16 + (i & 7);
}
function sqToIdx(sq) {
  return (7 - (sq >> 4)) * 8 + (sq & 7);
}

function pieceFromChar(ch) {
  const lower = ch.toLowerCase();
  const type = PIECE_CHARS.indexOf(lower);
  if (type < 1) return -1;
  return type | (ch === lower ? BLACK : WHITE);
}

function charFromPiece(p) {
  if (!p) return '.';
  const ch = PIECE_CHARS[p & 7];
  return (p & WHITE) ? ch.toUpperCase() : ch;
}

// ------------------------------------------------------------------ board array

function boardToArray(boardStr) {
  const b = new Int8Array(128);
  for (let i = 0; i < 64; i++) {
    const ch = boardStr[i];
    if (ch === '.') continue;
    b[idxToSq(i)] = pieceFromChar(ch);
  }
  return b;
}

function arrayToBoard(b) {
  let out = '';
  for (let i = 0; i < 64; i++) out += charFromPiece(b[idxToSq(i)]);
  return out;
}

function findKing(b, color) {
  for (let sq = 0; sq < 128; sq++) {
    if (sq & 0x88) continue;
    const p = b[sq];
    if (p && (p & COLOR) === color && (p & 7) === KING) return sq;
  }
  return -1;
}

// ------------------------------------------------------------------ attacks

// Is `sq` attacked by any piece of `by`? Used for check, for castling transit
// squares, and for the post-move legality filter.
function isAttacked(b, sq, by) {
  // Pawns: walk backwards from the target along the capture diagonals.
  const back = by === WHITE ? -16 : 16;
  for (const side of [-1, 1]) {
    const from = sq + back + side;
    if (from & 0x88) continue;
    const p = b[from];
    if (p && (p & COLOR) === by && (p & 7) === PAWN) return true;
  }

  for (let i = 0; i < 8; i++) {
    const from = sq + KNIGHT_DIRS[i];
    if (from & 0x88) continue;
    const p = b[from];
    if (p && (p & COLOR) === by && (p & 7) === KNIGHT) return true;
  }

  for (let i = 0; i < 8; i++) {
    const from = sq + KING_DIRS[i];
    if (from & 0x88) continue;
    const p = b[from];
    if (p && (p & COLOR) === by && (p & 7) === KING) return true;
  }

  for (let i = 0; i < 4; i++) {
    const d = BISHOP_DIRS[i];
    for (let from = sq + d; !(from & 0x88); from += d) {
      const p = b[from];
      if (!p) continue;
      if ((p & COLOR) === by) {
        const t = p & 7;
        if (t === BISHOP || t === QUEEN) return true;
      }
      break;
    }
  }

  for (let i = 0; i < 4; i++) {
    const d = ROOK_DIRS[i];
    for (let from = sq + d; !(from & 0x88); from += d) {
      const p = b[from];
      if (!p) continue;
      if ((p & COLOR) === by) {
        const t = p & 7;
        if (t === ROOK || t === QUEEN) return true;
      }
      break;
    }
  }

  return false;
}

// ------------------------------------------------------------------ move generation

function pushMove(out, from, to, promo, flags) {
  out.push(from | (to << 8) | (promo << 16) | flags);
}

function genPawn(b, out, sq, us, them, epSq) {
  const dir = us === WHITE ? 16 : -16;
  const startRank = us === WHITE ? 1 : 6;
  const lastRank = us === WHITE ? 6 : 1; // rank the pawn stands on before promoting
  const promoting = (sq >> 4) === lastRank;

  const one = sq + dir;
  if (!(one & 0x88) && b[one] === 0) {
    if (promoting) {
      pushMove(out, sq, one, QUEEN, 0);
      pushMove(out, sq, one, ROOK, 0);
      pushMove(out, sq, one, BISHOP, 0);
      pushMove(out, sq, one, KNIGHT, 0);
    } else {
      pushMove(out, sq, one, 0, 0);
      const two = sq + dir + dir;
      if ((sq >> 4) === startRank && b[two] === 0) pushMove(out, sq, two, 0, F_DOUBLE);
    }
  }

  for (const side of [-1, 1]) {
    const to = sq + dir + side;
    if (to & 0x88) continue;
    const target = b[to];
    if (target && (target & COLOR) === them) {
      if (promoting) {
        pushMove(out, sq, to, QUEEN, 0);
        pushMove(out, sq, to, ROOK, 0);
        pushMove(out, sq, to, BISHOP, 0);
        pushMove(out, sq, to, KNIGHT, 0);
      } else {
        pushMove(out, sq, to, 0, 0);
      }
    } else if (target === 0 && to === epSq) {
      pushMove(out, sq, to, 0, F_EP);
    }
  }
}

function genStep(b, out, sq, us, dirs) {
  for (let i = 0; i < dirs.length; i++) {
    const to = sq + dirs[i];
    if (to & 0x88) continue;
    const target = b[to];
    if (target && (target & COLOR) === us) continue;
    pushMove(out, sq, to, 0, 0);
  }
}

function genSlide(b, out, sq, us, dirs) {
  for (let i = 0; i < dirs.length; i++) {
    const d = dirs[i];
    for (let to = sq + d; !(to & 0x88); to += d) {
      const target = b[to];
      if (target) {
        if ((target & COLOR) !== us) pushMove(out, sq, to, 0, 0);
        break;
      }
      pushMove(out, sq, to, 0, 0);
    }
  }
}

// Castling is generated fully checked: rights present, king and the named rook
// actually standing where the rights claim, path empty, and none of the king's
// three squares attacked. The rook presence test matters because a FEN can carry
// rights that its position does not support, and we would rather generate no
// move than an impossible one.
function genCastle(b, out, us, castling, kingSq) {
  const them = us === WHITE ? BLACK : WHITE;
  const home = us === WHITE ? E1 : E8;
  if (kingSq !== home) return;
  const rook = ROOK | us;
  const kingSide = us === WHITE ? 'K' : 'k';
  const queenSide = us === WHITE ? 'Q' : 'q';

  if (castling.indexOf(kingSide) >= 0 && b[home + 3] === rook) {
    if (b[home + 1] === 0 && b[home + 2] === 0 &&
        !isAttacked(b, home, them) && !isAttacked(b, home + 1, them) &&
        !isAttacked(b, home + 2, them)) {
      pushMove(out, home, home + 2, 0, F_CASTLE);
    }
  }
  if (castling.indexOf(queenSide) >= 0 && b[home - 4] === rook) {
    if (b[home - 1] === 0 && b[home - 2] === 0 && b[home - 3] === 0 &&
        !isAttacked(b, home, them) && !isAttacked(b, home - 1, them) &&
        !isAttacked(b, home - 2, them)) {
      pushMove(out, home, home - 2, 0, F_CASTLE);
    }
  }
}

function genPseudo(b, us, castling, epSq, kingSq) {
  const them = us === WHITE ? BLACK : WHITE;
  const out = [];
  for (let sq = 0; sq < 128; sq++) {
    if (sq & 0x88) continue;
    const p = b[sq];
    if (!p || (p & COLOR) !== us) continue;
    switch (p & 7) {
      case PAWN: genPawn(b, out, sq, us, them, epSq); break;
      case KNIGHT: genStep(b, out, sq, us, KNIGHT_DIRS); break;
      case BISHOP: genSlide(b, out, sq, us, BISHOP_DIRS); break;
      case ROOK: genSlide(b, out, sq, us, ROOK_DIRS); break;
      case QUEEN: genSlide(b, out, sq, us, KING_DIRS); break;
      case KING: genStep(b, out, sq, us, KING_DIRS); break;
      default: break;
    }
  }
  if (kingSq >= 0) genCastle(b, out, us, castling, kingSq);
  return out;
}

// Make the move on the shared scratch board, ask the question, put everything
// back. The board is left byte-identical, which is why one array serves the whole
// generation pass.
function selfCheck(b, mv, us, kingSq) {
  const from = mv & 127;
  const to = (mv >> 8) & 127;
  const piece = b[from];
  const captured = b[to];
  let epSq = -1;
  let epPiece = 0;

  b[to] = piece;
  b[from] = 0;
  if (mv & F_EP) {
    epSq = us === WHITE ? to - 16 : to + 16;
    epPiece = b[epSq];
    b[epSq] = 0;
  }

  const k = (piece & 7) === KING ? to : kingSq;
  const bad = k < 0 ? false : isAttacked(b, k, us === WHITE ? BLACK : WHITE);

  b[from] = piece;
  b[to] = captured;
  if (epSq >= 0) b[epSq] = epPiece;
  return bad;
}

function genLegal(b, us, castling, epSq) {
  const kingSq = findKing(b, us);
  const pseudo = genPseudo(b, us, castling, epSq, kingSq);
  const legal = [];
  for (let i = 0; i < pseudo.length; i++) {
    if (!selfCheck(b, pseudo[i], us, kingSq)) legal.push(pseudo[i]);
  }
  return legal;
}

// Mutates b. Callers pass a copy they own.
function applyToBoard(b, mv, us) {
  const from = mv & 127;
  const to = (mv >> 8) & 127;
  const promo = (mv >> 16) & 7;
  const piece = b[from];

  b[from] = 0;
  if (mv & F_EP) b[us === WHITE ? to - 16 : to + 16] = 0;
  b[to] = promo ? (promo | us) : piece;

  if (mv & F_CASTLE) {
    if ((to & 7) === 6) { // king side: rook h -> f
      b[to - 1] = b[to + 1];
      b[to + 1] = 0;
    } else { // queen side: rook a -> d
      b[to + 1] = b[to - 2];
      b[to - 2] = 0;
    }
  }
}

function nextCastling(castling, from, to, piece, us) {
  let c = castling;
  if ((piece & 7) === KING) {
    c = us === WHITE ? c.replace('K', '').replace('Q', '')
                     : c.replace('k', '').replace('q', '');
  }
  for (const sq of [from, to]) {
    if (sq === H1) c = c.replace('K', '');
    else if (sq === A1) c = c.replace('Q', '');
    else if (sq === H8) c = c.replace('k', '');
    else if (sq === A8) c = c.replace('q', '');
  }
  return c;
}

// ------------------------------------------------------------------ repetition

// Two positions repeat when the pieces, the side to move, the castling rights and
// the en passant OPPORTUNITY match. Opportunity, not the FEN field: a recorded ep
// square that no pawn can actually capture on does not make the position
// different, and treating it as different would silently lose repetitions after
// any double push. The test is pseudo-legal adjacency, which is what every engine
// that bothers uses; a pinned capturer is a rounding error and costs a movegen to
// detect.
function epIsLive(b, epSq, turn) {
  if (epSq < 0) return false;
  const us = turn === 'w' ? WHITE : BLACK;
  const back = us === WHITE ? -16 : 16;
  for (const side of [-1, 1]) {
    const from = epSq + back + side;
    if (from & 0x88) continue;
    const p = b[from];
    if (p && (p & COLOR) === us && (p & 7) === PAWN) return true;
  }
  return false;
}

function repKey(boardStr, turn, castling, b, epSq) {
  const ep = epIsLive(b, epSq, turn) ? sqToAlg(epSq) : '-';
  return boardStr + ' ' + turn + ' ' + (castling || '-') + ' ' + ep;
}

// ------------------------------------------------------------------ state plumbing

// Per-state scratch: the parsed board, and the generated move list plus its
// lookup map. Keyed on the state object, dropped when the caller drops the state.
const cache = new WeakMap();

function entryFor(state) {
  let e = cache.get(state);
  if (!e) {
    e = { b: null, moves: null, internal: null, byKey: null };
    cache.set(state, e);
  }
  return e;
}

function boardOf(state) {
  const e = entryFor(state);
  if (!e.b) e.b = boardToArray(state.board);
  return e.b;
}

function generationOf(state) {
  const e = entryFor(state);
  if (!e.moves) {
    const b = boardOf(state);
    const us = state.turn === 'w' ? WHITE : BLACK;
    const internal = genLegal(b, us, state.castling, algToSq(state.ep || ''));
    const moves = new Array(internal.length);
    for (let i = 0; i < internal.length; i++) {
      const mv = internal[i];
      const promo = (mv >> 16) & 7;
      const m = { from: sqToAlg(mv & 127), to: sqToAlg((mv >> 8) & 127) };
      if (promo) m.promotion = PIECE_CHARS[promo];
      moves[i] = m;
    }
    e.internal = internal;
    e.moves = moves;
  }
  return e;
}

function moveKey(from, to, promotion) {
  return from + to + (promotion || '');
}

function lookupOf(state) {
  const e = generationOf(state);
  if (!e.byKey) {
    const map = new Map();
    for (let i = 0; i < e.moves.length; i++) {
      const m = e.moves[i];
      map.set(moveKey(m.from, m.to, m.promotion), i);
    }
    e.byKey = map;
  }
  return e;
}

const BOARD_RE = /^[.pnbrqkPNBRQK]{64}$/;
const CASTLING_RE = /^K?Q?k?q?$/;

function assertState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new TypeError('chess: state must be an object');
  }
  if (typeof state.board !== 'string' || !BOARD_RE.test(state.board)) {
    throw new TypeError('chess: bad board');
  }
  if (state.turn !== 'w' && state.turn !== 'b') throw new TypeError('chess: bad turn');
  if (typeof state.castling !== 'string' || !CASTLING_RE.test(state.castling)) {
    throw new TypeError('chess: bad castling rights');
  }
  if (state.ep !== null && algToSq(state.ep) < 0) throw new TypeError('chess: bad ep square');
  if (state.ep !== null) {
    const rank = state.ep.charCodeAt(1) - 48;
    const want = state.turn === 'w' ? 6 : 3;
    if (rank !== want) throw new TypeError('chess: ep square contradicts side to move');
  }
  if (!Number.isInteger(state.halfmove) || state.halfmove < 0) {
    throw new TypeError('chess: bad halfmove clock');
  }
  if (!Number.isInteger(state.fullmove) || state.fullmove < 1) {
    throw new TypeError('chess: bad fullmove number');
  }
  if (!Array.isArray(state.history) || state.history.some((h) => typeof h !== 'string')) {
    throw new TypeError('chess: bad history');
  }
  return state;
}

function makeState(boardStr, turn, castling, ep, halfmove, fullmove, history) {
  return { v: 1, board: boardStr, turn, castling, ep, halfmove, fullmove, history };
}

// ------------------------------------------------------------------ FEN

export function fromFen(fen) {
  if (typeof fen !== 'string') throw new TypeError('chess: FEN must be a string');
  const parts = fen.trim().split(/\s+/);
  if (parts.length < 4) throw new TypeError('chess: FEN needs at least 4 fields');

  const ranks = parts[0].split('/');
  if (ranks.length !== 8) throw new TypeError('chess: FEN needs 8 ranks');
  let boardStr = '';
  for (const rank of ranks) {
    let row = '';
    for (const ch of rank) {
      if (ch >= '1' && ch <= '8') row += '.'.repeat(Number(ch));
      else if (pieceFromChar(ch) > 0) row += ch;
      else throw new TypeError('chess: bad FEN piece "' + ch + '"');
    }
    if (row.length !== 8) throw new TypeError('chess: FEN rank is not 8 squares');
    boardStr += row;
  }

  const turn = parts[1];
  if (turn !== 'w' && turn !== 'b') throw new TypeError('chess: bad FEN side to move');

  let castling = '';
  if (parts[2] !== '-') {
    if (!/^K?Q?k?q?$/.test(parts[2])) throw new TypeError('chess: bad FEN castling field');
    castling = parts[2];
  }

  let ep = null;
  if (parts[3] !== '-') {
    if (algToSq(parts[3]) < 0) throw new TypeError('chess: bad FEN ep square');
    const rank = parts[3].charCodeAt(1) - 48;
    if (rank !== (turn === 'w' ? 6 : 3)) {
      throw new TypeError('chess: FEN ep square contradicts side to move');
    }
    ep = parts[3];
  }

  const halfmove = parts.length > 4 ? Number(parts[4]) : 0;
  const fullmove = parts.length > 5 ? Number(parts[5]) : 1;
  if (!Number.isInteger(halfmove) || halfmove < 0) throw new TypeError('chess: bad FEN halfmove clock');
  if (!Number.isInteger(fullmove) || fullmove < 1) throw new TypeError('chess: bad FEN fullmove number');

  const b = boardToArray(boardStr);
  // A position with two kings missing, a pawn on a back rank, or the side that
  // just moved still in check cannot arise from play, and letting one in means
  // every later answer is fiction.
  if (findKing(b, WHITE) < 0 || findKing(b, BLACK) < 0) {
    throw new TypeError('chess: FEN needs one king of each colour');
  }
  let whiteKings = 0;
  let blackKings = 0;
  for (let i = 0; i < 64; i++) {
    const ch = boardStr[i];
    if (ch === 'K') whiteKings++;
    else if (ch === 'k') blackKings++;
    else if ((ch === 'P' || ch === 'p') && (i < 8 || i >= 56)) {
      throw new TypeError('chess: FEN has a pawn on a back rank');
    }
  }
  if (whiteKings !== 1 || blackKings !== 1) throw new TypeError('chess: FEN needs exactly one king of each colour');

  const them = turn === 'w' ? BLACK : WHITE;
  if (isAttacked(b, findKing(b, them), turn === 'w' ? WHITE : BLACK)) {
    throw new TypeError('chess: FEN has the side not to move in check');
  }

  const state = makeState(boardStr, turn, castling, ep, halfmove, fullmove, []);
  state.history = [repKey(boardStr, turn, castling, b, algToSq(ep || ''))];
  return state;
}

export function toFen(state) {
  assertState(state);
  let placement = '';
  for (let r = 0; r < 8; r++) {
    if (r) placement += '/';
    let run = 0;
    for (let f = 0; f < 8; f++) {
      const ch = state.board[r * 8 + f];
      if (ch === '.') {
        run++;
        continue;
      }
      if (run) {
        placement += run;
        run = 0;
      }
      placement += ch;
    }
    if (run) placement += run;
  }
  return placement + ' ' + state.turn + ' ' + (state.castling || '-') + ' ' +
    (state.ep || '-') + ' ' + state.halfmove + ' ' + state.fullmove;
}

// ------------------------------------------------------------------ public API

export function create(options) {
  if (options === undefined || options === null) return fromFen(START_FEN);
  if (typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('chess: options must be an object');
  }
  if (options.fen === undefined || options.fen === null) return fromFen(START_FEN);
  return fromFen(options.fen);
}

// Rules-legal moves only. This ignores the fifty-move and repetition draws on
// purpose: those end the GAME, they do not change which moves are legal, and a
// perft walk must be able to keep counting through them. It returns [] only when
// there genuinely is no legal move, which is checkmate or stalemate.
export function legalMoves(state) {
  assertState(state);
  return generationOf(state).moves.map((m) =>
    m.promotion ? { from: m.from, to: m.to, promotion: m.promotion } : { from: m.from, to: m.to });
}

export function inCheck(state) {
  assertState(state);
  const b = boardOf(state);
  const us = state.turn === 'w' ? WHITE : BLACK;
  const k = findKing(b, us);
  return k >= 0 && isAttacked(b, k, us === WHITE ? BLACK : WHITE);
}

// K vs K, K+B vs K, K+N vs K. Deliberately not the wider "K+B vs K+B on the same
// colour" case: it needs square colours and is not what the brief asked for.
function insufficientMaterial(state) {
  let minors = 0;
  for (let i = 0; i < 64; i++) {
    const ch = state.board[i];
    if (ch === '.' || ch === 'K' || ch === 'k') continue;
    const lower = ch.toLowerCase();
    if (lower === 'n' || lower === 'b') {
      minors++;
      if (minors > 1) return false;
    } else {
      return false; // pawn, rook or queen: mate is still constructible
    }
  }
  return true;
}

function countRepetitions(state) {
  const key = state.history.length ? state.history[state.history.length - 1] : null;
  if (!key) return 0;
  let n = 0;
  for (let i = 0; i < state.history.length; i++) {
    if (state.history[i] === key) n++;
  }
  return n;
}

export function status(state) {
  assertState(state);
  const turn = state.turn;
  const moves = generationOf(state).moves;

  if (moves.length === 0) {
    if (inCheck(state)) {
      return { over: true, winner: turn === 'w' ? 'b' : 'w', reason: 'checkmate', turn };
    }
    return { over: true, winner: null, reason: 'stalemate', turn };
  }

  // Mate beats every draw rule, which is why it is tested first: a checkmate
  // delivered on the hundredth halfmove is a win, not a draw.
  if (insufficientMaterial(state)) {
    return { over: true, winner: null, reason: 'insufficient-material', turn };
  }
  if (state.halfmove >= 100) {
    return { over: true, winner: null, reason: 'fifty-move', turn };
  }
  if (countRepetitions(state) >= 3) {
    return { over: true, winner: null, reason: 'threefold', turn };
  }
  return { over: false, winner: null, reason: 'in-progress', turn };
}

function nextState(state, mv) {
  const us = state.turn === 'w' ? WHITE : BLACK;
  const from = mv & 127;
  const to = (mv >> 8) & 127;
  const b = boardOf(state).slice();
  const piece = b[from];
  const captured = (mv & F_EP) ? (PAWN | (us === WHITE ? BLACK : WHITE)) : b[to];

  applyToBoard(b, mv, us);

  const boardStr = arrayToBoard(b);
  const turn = state.turn === 'w' ? 'b' : 'w';
  const castling = nextCastling(state.castling, from, to, piece, us);
  const ep = (mv & F_DOUBLE) ? sqToAlg(us === WHITE ? from + 16 : from - 16) : null;
  const irreversible = (piece & 7) === PAWN || captured !== 0;
  const halfmove = irreversible ? 0 : state.halfmove + 1;
  const fullmove = state.turn === 'b' ? state.fullmove + 1 : state.fullmove;

  const key = repKey(boardStr, turn, castling, b, algToSq(ep || ''));
  // An irreversible move makes every earlier position unreachable, so the
  // repetition window restarts. This also keeps history from growing without
  // bound over a long game.
  const history = irreversible ? [key] : state.history.concat(key);

  const next = makeState(boardStr, turn, castling, ep, halfmove, fullmove, history);
  // The board array is already built and correct: hand it to the child so its
  // first legalMoves does not re-parse the string.
  entryFor(next).b = b;
  return next;
}

const PROMOTION_PIECES = ['q', 'r', 'b', 'n'];

// Never throws. Every rejection is { ok: false, error }, with these reasons:
//   invalid-state, malformed-move, bad-square, bad-promotion,
//   unexpected-promotion, missing-promotion, illegal-move, game-over
export function applyMove(state, move) {
  try {
    assertState(state);
  } catch (err) {
    return { ok: false, error: 'invalid-state: ' + err.message };
  }

  try {
    if (!move || typeof move !== 'object' || Array.isArray(move)) {
      return { ok: false, error: 'malformed-move' };
    }
    const from = move.from;
    const to = move.to;
    if (algToSq(from) < 0 || algToSq(to) < 0) return { ok: false, error: 'bad-square' };

    let promotion;
    if (move.promotion !== undefined && move.promotion !== null) {
      if (typeof move.promotion !== 'string' || PROMOTION_PIECES.indexOf(move.promotion) < 0) {
        return { ok: false, error: 'bad-promotion' };
      }
      promotion = move.promotion;
    }

    const st = status(state);
    if (st.over) return { ok: false, error: 'game-over' };

    const e = lookupOf(state);
    const idx = e.byKey.get(moveKey(from, to, promotion));
    if (idx === undefined) {
      // Separate the two ways a from/to pair can be right and the move still
      // wrong, because the UI wants to ask for a piece rather than say "no".
      let promotable = false;
      let plain = false;
      for (const m of e.moves) {
        if (m.from !== from || m.to !== to) continue;
        if (m.promotion) promotable = true;
        else plain = true;
      }
      if (promotable && promotion === undefined) return { ok: false, error: 'missing-promotion' };
      if (plain && promotion !== undefined) return { ok: false, error: 'unexpected-promotion' };
      return { ok: false, error: 'illegal-move' };
    }

    return { ok: true, state: nextState(state, e.internal[idx]) };
  } catch (err) {
    // A bug here must not take the peer connection down with it.
    return { ok: false, error: 'internal-error: ' + (err && err.message ? err.message : String(err)) };
  }
}

// serialize is a deep copy in the state's own shape, so a serialized value is
// itself a valid state and deserialize(serialize(s)) deep-equals s.
export function serialize(state) {
  assertState(state);
  return {
    v: 1,
    board: state.board,
    turn: state.turn,
    castling: state.castling,
    ep: state.ep,
    halfmove: state.halfmove,
    fullmove: state.fullmove,
    history: state.history.slice(),
  };
}

// deserialize validates SHAPE, not provenance. A state is a claim about a whole
// game, halfmove clock and repetition history included, so a peer that could hand
// you one could hand you a drawn game or a position it never earned. Send moves
// over the link and keep the state local; deserialize is for your own storage and
// for resuming your own session.
export function deserialize(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('chess: serialized state must be an object');
  }
  if (value.v !== 1) throw new TypeError('chess: unknown state version');
  const state = makeState(
    value.board,
    value.turn,
    value.castling,
    value.ep === undefined ? null : value.ep,
    value.halfmove,
    value.fullmove,
    Array.isArray(value.history) ? value.history.slice() : value.history,
  );
  assertState(state);
  // Cheap structural sanity beyond the field types: a state whose board cannot
  // hold a game is garbage however well-formed its JSON was.
  const b = boardToArray(state.board);
  if (findKing(b, WHITE) < 0 || findKing(b, BLACK) < 0) {
    throw new TypeError('chess: serialized state has no king');
  }
  return state;
}
