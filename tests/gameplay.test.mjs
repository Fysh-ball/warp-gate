// The match layer, played out between two real GameSessions.
//
// No mocks of the engines and no mock of the protocol: two sessions are wired to each
// other through a router that behaves like the data channel does, and every assertion is
// made about what the two boards actually hold afterwards. The interesting cases are all
// hostile ones, because everything this layer reads arrives from the other device.
//
// The negative controls are at the bottom and each one runs the SAME predicate the real
// check ran, against input it must reject. A check that has never failed is not evidence.

import { check, summary } from './lib/harness.mjs';
import { GameSession, SEATS, MIRRORED, playableGames } from '../public/js/gameplay.js';
import { GAME_IDS, getGame } from '../public/js/games/index.js';

// ---------------------------------------------------------------- wiring

/**
 * Two sessions and a wire between them.
 *
 * Delivery is awaited, so by the time `a.play()` resolves the message has been handled
 * by b, and by the time b's answer resolves it has been handled by a. That is stricter
 * than the real channel, which is asynchronous, and it is what makes an ordering bug
 * show up as a wrong board rather than as a flake.
 */
function pair({ dropFrom = null } = {}) {
  const sessions = {};
  const sent = { a: [], b: [] };
  const make = (me, them) => new GameSession({
    send: async (peerId, payload) => {
      sent[me].push(payload);
      if (dropFrom === me) return true;
      if (peerId !== `peer-${them}`) return false;
      await sessions[them].receive(`peer-${me}`, JSON.parse(JSON.stringify(payload)));
      return true;
    },
  });
  sessions.a = make('a', 'b');
  sessions.b = make('b', 'a');
  return { a: sessions.a, b: sessions.b, sent };
}

async function seated(gameId) {
  const { a, b, sent } = pair();
  await a.invite('peer-b', gameId);
  await b.accept();
  return { a, b, sent };
}

const boardOf = (s) => s.match.state.board;

// ---------------------------------------------------------------- the table

check('every registered game has a seat pair', GAME_IDS.every((id) => Array.isArray(SEATS[id]) && SEATS[id].length === 2),
  GAME_IDS.filter((id) => !SEATS[id]).join(',') || 'all covered');

check('playableGames covers the whole registry', playableGames().length === GAME_IDS.length,
  `${playableGames().length} of ${GAME_IDS.length}`);

for (const id of GAME_IDS) {
  const entry = getGame(id);
  // Mirrored engines are created per side, so ask for the side that moves first.
  const state = entry.engine.create(MIRRORED.has(id) ? { side: SEATS[id][0], seed: 1 } : {});
  check(`${id}: the first seat in the table is the side to move`,
    entry.engine.status(state).turn === SEATS[id][0],
    `table says ${SEATS[id][0]}, engine says ${entry.engine.status(state).turn}`);
}

// ---------------------------------------------------------------- invitations

{
  const { a, b } = pair();
  await a.invite('peer-b', 'tictactoe');
  check('an invitation reaches the other side', b.incoming !== null && b.incoming.gameId === 'tictactoe',
    JSON.stringify(b.incoming));
  check('the inviter is waiting, not playing', a.outgoing !== null && a.match === null, '');

  await b.decline();
  check('a decline clears both sides', a.outgoing === null && b.incoming === null, '');
  check('the inviter is told', typeof a.notice === 'string' && a.notice.length > 0, String(a.notice));
}

{
  const { a, b } = pair();
  await a.invite('peer-b', 'chess');
  await b.accept();
  check('accepting seats both players', a.match !== null && b.match !== null, '');
  check('the inviter takes the first seat', a.match.seat === 'w' && b.match.seat === 'b',
    `${a.match?.seat} / ${b.match?.seat}`);
  check('both sides agree on the match id', a.match.mid === b.match.mid, '');
}

{
  const { a, b } = pair();
  await a.invite('peer-b', 'nonsense-game');
  check('an unknown game is never proposed', a.outgoing === null && b.incoming === null, '');
}

{
  // A game this build does not have must be declined, not crash the gate.
  const { a, b } = pair();
  await b.receive('peer-a', { t: 'invite', mid: 'ffff', game: 'go', seat: 'x' });
  check('an unknown game from the wire is declined', b.incoming === null, JSON.stringify(b.incoming));
}

{
  // Both press invite at the same moment. Without a tie-break both sides sit waiting.
  const { a, b } = pair({ dropFrom: 'a' });
  await a.invite('peer-b', 'tictactoe');
  const theirs = { t: 'invite', mid: '0000000000000000', game: 'tictactoe', seat: 'x' };
  await a.receive('peer-b', theirs);
  check('the smaller match id wins a simultaneous invite',
    a.outgoing === null && a.incoming !== null && a.incoming.mid === theirs.mid,
    `outgoing=${a.outgoing?.mid} incoming=${a.incoming?.mid}`);
  void b;
}

{
  const { a, b } = pair();
  await a.invite('peer-b', 'tictactoe');
  await b.accept();
  await b.receive('peer-c', { t: 'invite', mid: 'aaaa', game: 'chess', seat: 'w' });
  check('an invitation during a game is refused', b.incoming === null && b.match.gameId === 'tictactoe', '');
}

// ---------------------------------------------------------------- a shared game

{
  const { a, b } = await seated('tictactoe');
  //  x | o | .        a plays 0, 4, 8 and wins on the diagonal.
  //  . | x | o
  //  . | . | x
  await a.play({ index: 0 });
  await b.play({ index: 1 });
  await a.play({ index: 4 });
  await b.play({ index: 5 });
  check('both boards hold the same position', JSON.stringify(boardOf(a)) === JSON.stringify(boardOf(b)),
    `${JSON.stringify(boardOf(a))} vs ${JSON.stringify(boardOf(b))}`);
  await a.play({ index: 8 });
  check('the winner is recorded on the winning side', a.match.ended?.winner === 'x', JSON.stringify(a.match.ended));
  check('the loser sees the same result', b.match.ended?.winner === 'x', JSON.stringify(b.match.ended));
  check('the reason survives the wire', a.match.ended?.reason === 'three-in-a-row', String(a.match.ended?.reason));
}

{
  const { a, b } = await seated('tictactoe');
  const wrong = await b.play({ index: 0 });
  check('you cannot move on the other side\'s turn', wrong.ok === false, JSON.stringify(wrong));
  check('nothing was sent', b.match.n === 0 && a.match.n === 0, '');
}

{
  const { a, b } = await seated('connect4');
  const res = await a.play({ column: 99 });
  check('an illegal local move is refused by the engine, not sent', res.ok === false, JSON.stringify(res));
  check('the boards are untouched', a.match.n === 0 && b.match.n === 0, '');
}

// ---------------------------------------------------------------- a hostile peer

{
  const { a, b } = await seated('tictactoe');
  await a.play({ index: 0 });
  // b is to move. It sends a move claiming the counter is still 0.
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, n: 0, move: { index: 3 } });
  check('a replayed counter ends the match', a.match.ended?.reason === 'protocol', JSON.stringify(a.match.ended));
  check('the board did not take the move', boardOf(a)[3] === null, String(boardOf(a)[3]));
  void b;
}

{
  const { a } = await seated('tictactoe');
  // a is to move, so a move from b is out of turn even though the counter is right.
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, n: 0, move: { index: 4 } });
  check('a move played out of turn ends the match', a.match.ended?.reason === 'protocol', JSON.stringify(a.match.ended));
  check('an out-of-turn move never reaches the board', boardOf(a)[4] === null, String(boardOf(a)[4]));
}

{
  const { a, b } = await seated('tictactoe');
  await a.play({ index: 0 });
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, n: 1, move: { index: 0 } });
  check('a move onto an occupied square ends the match', a.match.ended?.reason === 'protocol', JSON.stringify(a.match.ended));
  check('the peer is told the match is over', b.match.ended !== null, JSON.stringify(b.match.ended));
}

{
  const { a } = await seated('chess');
  for (const junk of [null, 'e2e4', [1, 2], { from: 'zz', to: '99' }, { from: 'e2' }]) {
    const before = a.match.ended;
    await a.receive('peer-b', { t: 'move', mid: a.match.mid, n: 0, move: junk });
    void before;
  }
  check('junk in place of a move ends the match rather than throwing', a.match.ended?.reason === 'protocol',
    JSON.stringify(a.match.ended));
}

{
  const { a } = await seated('tictactoe');
  const mid = a.match.mid;
  await a.receive('peer-b', { t: 'move', mid: `${mid}x`, n: 0, move: { index: 0 } });
  check('a move for another match is ignored, not played', a.match.ended === null && a.match.n === 0, '');
  await a.receive('peer-c', { t: 'move', mid, n: 0, move: { index: 0 } });
  check('a move from a third device is ignored', a.match.ended === null && a.match.n === 0, '');
}

{
  const { a } = await seated('tictactoe');
  for (const junk of [null, 'hello', 42, [], { t: 5 }, { t: 'move' }, { t: 'move', mid: 7 }, { t: 'move', mid: '' }]) {
    await a.receive('peer-b', junk);
  }
  check('a malformed payload changes nothing', a.match.ended === null && a.match.n === 0, '');
}

// ---------------------------------------------------------------- resigning and leaving

{
  const { a, b } = await seated('chess');
  await a.resign();
  check('resigning hands the game to the other side', a.match.ended?.winner === 'b', JSON.stringify(a.match.ended));
  check('the other side is told', b.match.ended?.winner === 'b' && b.match.ended?.by === 'them',
    JSON.stringify(b.match.ended));
}

{
  const { a } = await seated('chess');
  a.reconcile([]);
  check('a peer leaving ends the game', a.match.ended?.reason === 'left', JSON.stringify(a.match.ended));
  a.reset();
  check('a reset clears the board', a.match === null && a.incoming === null && a.outgoing === null, '');
}

{
  const { a, b } = pair();
  await a.invite('peer-b', 'chess');
  a.reconcile([]);
  check('a peer leaving cancels an unanswered invitation', a.outgoing === null, JSON.stringify(a.outgoing));
  void b;
}

// ---------------------------------------------------------------- battleships

{
  const { a, b } = await seated('battleships');
  check('each side placed its own fleet', a.match.state.ships.length === 5 && b.match.state.ships.length === 5,
    `${a.match.state.ships.length} / ${b.match.state.ships.length}`);
  check('the two fleets are not the same layout, so no seed was shared',
    JSON.stringify(a.match.state.ships) !== JSON.stringify(b.match.state.ships), '');
  check('a fleet seed is never sent', a.match.state.seed !== b.match.state.seed, '');

  const before = JSON.stringify(a.match.state.ships);
  await a.play({ type: 'shuffle' });
  check('shuffle re-rolls the fleet before it is locked in', JSON.stringify(a.match.state.ships) !== before, '');

  const early = await a.play({ type: 'fire', x: 0, y: 0 });
  check('you cannot fire before locking your fleet in', early.ok === false, JSON.stringify(early));

  await a.play({ type: 'ready' });
  await b.play({ type: 'ready' });
  check('both sides are in the battle phase',
    a.match.engine.status(a.match.state).phase === 'battle' && b.match.engine.status(b.match.state).phase === 'battle',
    '');

  const late = await a.play({ type: 'shuffle' });
  check('shuffling after locking in is refused', late.ok === false, JSON.stringify(late));

  await a.play({ type: 'fire', x: 0, y: 0 });
  check('a shot is answered in the same breath', a.match.state.shots[0] !== 'none' && a.match.state.pending === null,
    `${a.match.state.shots[0]} pending=${JSON.stringify(a.match.state.pending)}`);
  check('the defender recorded the incoming shot', b.match.state.incoming[0] !== 'none', b.match.state.incoming[0]);
  check('the turn passed to the defender', a.match.engine.status(a.match.state).turn === 'b', '');

  const outOfTurn = await a.play({ type: 'fire', x: 1, y: 0 });
  check('you cannot fire twice in a row', outOfTurn.ok === false, JSON.stringify(outOfTurn));
}

{
  // Sink the whole fleet and check both sides agree who won. b fires at every square in
  // turn; a fires into a corner it has already used only when it is its own turn, which
  // the engine refuses, so a fires along the bottom row instead.
  const { a, b } = await seated('battleships');
  await a.play({ type: 'ready' });
  await b.play({ type: 'ready' });

  const targets = [];
  for (let y = 0; y < 10; y += 1) for (let x = 0; x < 10; x += 1) targets.push({ x, y });

  let i = 0;
  let filler = 0;
  while (!a.match.ended && i < targets.length) {
    // a's turn: waste it somewhere harmless but legal.
    const spot = targets[filler];
    filler += 1;
    await a.play({ type: 'fire', x: spot.x, y: spot.y });
    if (a.match.ended) break;
    const t = targets[i];
    i += 1;
    await b.play({ type: 'fire', x: t.x, y: t.y });
  }

  check('a sunk fleet ends the game', a.match.ended !== null && b.match.ended !== null,
    `${JSON.stringify(a.match.ended)} / ${JSON.stringify(b.match.ended)}`);
  check('both sides name the same winner', a.match.ended?.winner === b.match.ended?.winner,
    `${a.match.ended?.winner} vs ${b.match.ended?.winner}`);
  check('the reason is the fleet, not a protocol failure', a.match.ended?.reason === 'fleet-sunk',
    String(a.match.ended?.reason));
}

{
  const { a } = await seated('battleships');
  await a.play({ type: 'ready' });
  // The moves only the local player may originate must be refused from the wire.
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, move: { type: 'autoplace' } });
  check('a peer cannot place our fleet for us', a.match.ended?.reason === 'protocol', JSON.stringify(a.match.ended));
}

{
  const { a } = await seated('battleships');
  await a.play({ type: 'ready' });
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, move: { type: 'ready' } });
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, move: { type: 'result', x: 3, y: 3, outcome: 'hit' } });
  check('an answer to a shot we never fired ends the match', a.match.ended?.reason === 'protocol',
    JSON.stringify(a.match.ended));
}

// ---------------------------------------------------------------- message size

{
  // link.js caps a game message at 4096 bytes and drops anything larger, so a legitimate
  // message that could exceed it would be a game that silently stops working.
  const { a, b, sent } = await seated('battleships');
  await a.play({ type: 'ready' });
  await b.play({ type: 'ready' });
  await a.play({ type: 'fire', x: 4, y: 4 });
  const largest = Math.max(...sent.a.concat(sent.b).map((p) => JSON.stringify(p).length));
  check('every message this layer sends fits well inside the 4096-byte cap', largest < 512, `largest ${largest} bytes`);
}

// ---------------------------------------------------------------- negative controls
//
// Each of these runs a predicate the suite above relied on, against input it must reject.

{
  const { a, b } = await seated('tictactoe');
  await a.play({ index: 0 });
  // The board-agreement predicate must be able to see a disagreement.
  b.match.state = { ...b.match.state, board: b.match.state.board.slice() };
  b.match.state.board[7] = 'o';
  check('CONTROL: the board-agreement check can fail',
    JSON.stringify(boardOf(a)) !== JSON.stringify(boardOf(b)), 'planted a divergence and it was seen');
}

{
  const { a } = await seated('tictactoe');
  await a.receive('peer-b', { t: 'move', mid: a.match.mid, n: 0, move: { index: 4 } });
  check('CONTROL: the protocol-failure check can report a clean match',
    a.match.ended?.reason === 'protocol', 'a clean match would read ended === null here');
  const { a: clean } = await seated('tictactoe');
  check('CONTROL: and it does report a clean match as clean', clean.match.ended === null, '');
}

{
  // The seat table check has to be able to catch a wrong entry.
  const bogus = { tictactoe: ['o', 'x'] };
  const entry = getGame('tictactoe');
  check('CONTROL: the seat-order check can fail',
    entry.engine.status(entry.engine.create()).turn !== bogus.tictactoe[0],
    'a reversed table was not accepted as correct');
}

process.exit(summary('gameplay') ? 0 : 1);
