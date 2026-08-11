// The match layer, played out between two real GameSessions.
//
// No mocks of the engines and no mock of the protocol: two sessions are wired to each
// other through a router that behaves like the data channel does, and every assertion is
// made about what the two boards actually hold afterwards. The interesting cases are all
// hostile ones, because everything this layer reads arrives from the other device.
//
// The negative controls are at the bottom and each one runs the SAME predicate the real
// check ran, against input it must reject. A check that has never failed is not evidence.

import { check, summary, startServer, freePort } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';
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
  // One fresh match per payload. The first protocol failure ends a match, so feeding all
  // five to one match validated only the first: the other four landed on a corpse whose
  // guards never ran.
  for (const junk of [null, 'e2e4', [1, 2], { from: 'zz', to: '99' }, { from: 'e2' }]) {
    const { a } = await seated('chess');
    await a.receive('peer-b', { t: 'move', mid: a.match.mid, n: 0, move: junk });
    check(`junk ${JSON.stringify(junk)} in place of a move ends the match rather than throwing`,
      a.match.ended?.reason === 'protocol', JSON.stringify(a.match.ended));
  }
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
  const payloads = sent.a.concat(sent.b);
  // Math.max of an empty set is -Infinity, which is under any cap: with no messages
  // captured this check used to pass while measuring nothing.
  const largest = Math.max(...payloads.map((p) => JSON.stringify(p).length));
  check('every message this layer sends fits well inside the 4096-byte cap',
    payloads.length >= 3 && largest < 512, `${payloads.length} messages, largest ${largest} bytes`);
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

// ================================================================ the drawer it is drawn in
//
// Everything above this line is the protocol, and every check in it passed while the
// feature was broken in a real gate between two devices. That is the point of this block.
//
// The failure was not in the match layer, in an engine or on the wire. An invitation
// arrives, gameplay.js accepts it, gameui.js renders the Play button, and all of that
// happens inside `<details id="games-disc">`, which is SHUT, because its summary reads
// "something to do while you wait" and nobody opens that while they are waiting for
// something else. Measured in a real browser before the fix: the button existed,
// checkVisibility() returned false, and document.elementFromPoint at its own coordinates
// returned `screen-connected`, the page behind it. The inviter waited on "Waiting for them
// to accept" forever, and the person who was asked was never told.
//
// So this runs in a real browser against the real /app document, because it is the only
// place the defect exists: a node assertion about GameSession cannot see a disclosure
// widget, which is exactly how it shipped. One tab, no gate and no WebRTC: the transport
// is already covered above and by tests/browser.test.mjs, and what is under test here is
// whether the answer this screen demands is on screen at all.

if (!findBrowser()) {
  // Not skipped. A check that quietly does not run reports the same 0 failed as a check
  // that passed, and this is the only block in the file that can see the bug it guards.
  check('a browser is available to test the games drawer in', false,
    'no Chromium-based browser found, so the drawer regression was NOT measured');
} else {
  const PORT = await freePort(3843);
  const STUN = 3844;
  const CDP_PORT = await freePort(9843);
  const server = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_PORT: String(STUN),
    WG_STUN_URL: `stun:127.0.0.1:${STUN}`,
  });
  const browser = await launchBrowser({ port: CDP_PORT });
  try {
    const tab = await browser.newTab(`http://127.0.0.1:${PORT}/app`);

    // WAIT FOR app.js TO HAVE PICKED A SCREEN BEFORE FORCING ONE.
    //
    // boot() in app.js is async and ends in `show('onboarding')` on a first visit. Until
    // that lands, every `section.screen` still carries the `hidden` attribute it ships
    // with, and `[hidden]` is `display: none !important` in style.css. Forcing
    // #screen-connected visible before boot finishes therefore holds only until boot
    // catches up, and boot then hides it again from underneath the measurement.
    //
    // Measured: boot() completed 773ms after this eval started. Runs where it landed
    // mid-eval reported found:true, visible:false, hitIsButton:false, hitWas:"bar" for
    // the drawer checks below, because the button's rect had collapsed to 0x0 at the
    // origin and elementFromPoint(0, 0) returns the masthead. That reads exactly like an
    // element covered by the sticky bar and is nothing of the kind. Three consecutive
    // runs gave 0, 1 and 2 failures, and the run with 2 failed the OPEN-drawer CONTROL
    // with the identical payload, which is what proves the cause is the screen going
    // away rather than anything about the drawer.
    //
    // This is the idiom the rest of the browser suite already uses (tests/browser.test.mjs
    // gates on the same expression in a dozen places); this block was the one that did not.
    await tab.waitFor("!document.getElementById('screen-onboarding').hidden",
      { timeout: 20000, label: "app.js boot to have shown a screen, so forcing #screen-connected sticks" });

    // The drawer lives on the connected screen, so that screen has to be the one showing
    // or every visibility answer below would be about the screen rather than the drawer.
    // Nothing else is touched: the disclosure is left in the state a person leaves it in.
    const raw = await tab.eval(`
      for (const s of document.querySelectorAll('section.screen')) s.hidden = s.id !== 'screen-connected';
      const [play, ui] = await Promise.all([import('/js/gameplay.js'), import('/js/gameui.js')]);

      const drawer = document.getElementById('games-disc');
      const area = document.getElementById('game-area');
      // Two frames, THEN the drawer's own opening animation, THEN one more frame.
      //
      // app.js listens for the <details> toggle and adds .is-opening, and style.css runs
      // wg-rise-sm at var(--motion-small), 150ms, with fill: both on the .disc-body,
      // whose first keyframe is opacity: 0. checkVisibility({ opacityProperty: true })
      // answers false for an opacity of exactly 0, which is what the fill holds until the
      // animation has ticked. Two rAF is ~32ms into a 150ms fade, so measuring there is
      // measuring the fade rather than the layout: it reported visible:false with
      // hitIsButton:true, an element that is demonstrably present and hit-testable.
      //
      // Waiting for the real animation rather than sleeping a fixed 200ms, because the
      // duration is a CSS token and a test that hardcodes it goes quietly wrong when it
      // changes. Infinite animations are excluded or the wait would never resolve, and a
      // cancelled animation rejects finished, which is "it is not running any more" and
      // is exactly what this is waiting for.
      const settle = async () => {
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
        const running = (document.getAnimations ? document.getAnimations() : [])
          .filter((a) => a.effect && a.effect.getComputedTiming().iterations !== Infinity);
        await Promise.all(running.map((a) => a.finished.catch((err) => {
          // Cancelled, which resolves the question this wait is asking. Named rather
          // than swallowed so a future failure here is not invisible.
          void err;
        })));
        await new Promise((r) => requestAnimationFrame(r));
      };

      // Where the Play button really is: visible to the browser's own test, and the thing
      // that answers a hit test at its own centre. Two different questions, because
      // checkVisibility alone would still pass for a button under an overlay.
      const reachable = () => {
        const b = [...area.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Play');
        if (!b) return { found: false };
        b.scrollIntoView({ block: 'center' });
        const r = b.getBoundingClientRect();
        const x = Math.round(r.left + r.width / 2);
        const y = Math.round(r.top + r.height / 2);
        const hit = document.elementFromPoint(x, y);
        return {
          found: true,
          visible: b.checkVisibility({ checkVisibilityCSS: true, contentVisibilityAuto: true, opacityProperty: true }),
          hitIsButton: hit === b,
          hitWas: hit ? (hit.id || hit.className || hit.tagName) : 'nothing',
        };
      };

      const build = (peerLabel) => {
        const notices = [];
        const games = new play.GameSession({ send: async () => true });
        const gameUi = new ui.GameUI({
          root: area,
          games,
          partners: () => [{ peer: 'peer-them', label: peerLabel }],
          onNotice: (t) => notices.push(t),
        });
        return { games, gameUi, notices };
      };

      const out = {};

      // 1. The measurement itself has to be able to say "visible". Drawer open by hand.
      {
        const { games, gameUi, notices } = build('Open Drawer');
        area.replaceChildren();
        drawer.open = true;
        gameUi.render();
        await games.receive('peer-them', { t: 'invite', mid: 'aaaa000000000001', game: 'tictactoe', seat: 'x' });
        await settle();
        out.whenOpen = { ...reachable(), drawerOpen: drawer.open, notices: notices.slice() };
      }

      // 2. The real case. The drawer is SHUT, which is how it is delivered and how a
      //    person who has not gone looking for games leaves it.
      {
        const { games, gameUi, notices } = build('Their Device');
        area.replaceChildren();
        drawer.open = false;
        gameUi.render();
        out.shutBefore = drawer.open;
        await games.receive('peer-them', { t: 'invite', mid: 'aaaa000000000002', game: 'chess', seat: 'w' });
        await settle();
        out.whenShut = { ...reachable(), drawerOpen: drawer.open, notices: notices.slice() };

        // 3. Somebody who shuts it again has answered by shutting it. A later render
        //    must not fight them for it.
        drawer.open = false;
        gameUi.render();
        await settle();
        out.reshutStaysShut = drawer.open === false;
      }

      // 4. A peer that REUSES a match id. An honest client rolls a fresh one per
      //    invitation, so this needs a peer that does not, which is exactly the party
      //    whose input must not be able to switch the announcement off. Decline the first
      //    invitation, shut the drawer, then send the same mid again.
      {
        const { games, gameUi, notices } = build('Repeat Offender');
        area.replaceChildren();
        drawer.open = false;
        gameUi.render();
        await games.receive('peer-them', { t: 'invite', mid: 'bbbb000000000001', game: 'chess', seat: 'w' });
        await settle();
        await games.decline();
        drawer.open = false;
        gameUi.render();
        await settle();
        const before = notices.length;
        await games.receive('peer-them', { t: 'invite', mid: 'bbbb000000000001', game: 'chess', seat: 'w' });
        await settle();
        out.repeatedMid = {
          drawerOpen: drawer.open,
          announced: notices.length > before,
          notices: notices.slice(),
        };
      }

      // 5. Control: with nothing to answer, a shut drawer stays shut.
      {
        const { gameUi } = build('Nobody');
        area.replaceChildren();
        drawer.open = false;
        gameUi.render();
        await settle();
        out.noInviteStaysShut = drawer.open === false;
      }

      // The precondition, re-read at the END rather than assumed from the top. Every
      // "not visible" answer above is only about the drawer if the screen holding it was
      // still displayed when it was measured, and app.js re-hiding it is precisely the
      // race that used to make this block report a covered button. Read as a computed
      // style, not as the hidden attribute: [hidden] is display:none !important here, so
      // the style is the thing that actually decides, and either route to display:none
      // invalidates the block the same way.
      out.screenHeld = !document.getElementById('screen-connected').hidden
        && getComputedStyle(document.getElementById('screen-connected')).display !== 'none';

      return JSON.stringify(out);
    `);
    const seen = JSON.parse(raw);

    // Runs before everything, including the CONTROL. If the screen went away mid-block,
    // every answer below is about a display:none subtree and none of them is about the
    // drawer, so this check exists to name that cause instead of letting it masquerade
    // as an element hidden behind the masthead.
    check('the connected screen was still displayed when the drawer was measured',
      seen.screenHeld === true,
      'app.js re-hid #screen-connected mid-block, so every visibility answer below is '
      + 'about a display:none subtree rather than about the drawer');

    // Runs first on purpose. If this fails, every "not reachable" answer below is about a
    // broken measurement rather than about the drawer, and the block reports nothing.
    check('CONTROL: an invitation in an OPEN drawer is visible and answers a hit test',
      seen.whenOpen.found === true && seen.whenOpen.visible === true && seen.whenOpen.hitIsButton === true,
      JSON.stringify(seen.whenOpen));

    check('an invitation arriving at a SHUT drawer opens it, so the answer it wants is on screen',
      seen.shutBefore === false && seen.whenShut.drawerOpen === true
      && seen.whenShut.found === true && seen.whenShut.visible === true
      && seen.whenShut.hitIsButton === true,
      JSON.stringify(seen.whenShut));

    check('and the invitation is also written to the activity log, which outlives the drawer',
      seen.whenShut.notices.some((n) => /wants to play Chess/.test(n)),
      JSON.stringify(seen.whenShut.notices));

    check('a drawer the person shuts again is not reopened by the next render',
      seen.reshutStaysShut === true, `drawer.open after a re-render: ${!seen.reshutStaysShut}`);

    check('a second invitation reusing the same match id is still announced, so the latch '
      + 'cannot be switched off by the sender',
      seen.repeatedMid.drawerOpen === true && seen.repeatedMid.announced === true,
      JSON.stringify(seen.repeatedMid));
    check('CONTROL: with nothing to answer, a shut drawer stays shut',
      seen.noInviteStaysShut === true, 'an unconditional open would pass the check above for free');

    // ---------------------------------------------------------------- on a phone
    //
    // Everything above calls scrollIntoView() itself before measuring, so it answers
    // "could this be reached" and not "was it put in front of the person". Those came
    // apart when the layout pass moved the Games panel from an unset `order` (which put
    // it at the very top of the connected column) to `order: 5`, below the transcript,
    // the composer and Connection details. The drawer now opens a long way down a
    // scrolling column.
    //
    // Measured at 360x640 with the drawer opened by an invitation and nothing scrolled:
    // masthead bottom y=45, drawer top y=625, the Play row at y 694..730 in a 640px
    // viewport, page still at scrollTop 0 with 842px of scroll available, and
    // elementFromPoint at the button's centre returning nothing at all. The check above
    // passed the whole time, because it scrolled first.
    //
    // 360x640 rather than 390x844 on purpose: at 390x844 the same row lands at y=678 and
    // fits by 130px, so a check at that size would have passed with the bug present and
    // proved nothing. This is the smallest widely used phone viewport, and it is the one
    // the requirement is actually about.
    const phone = await browser.newTab(`http://127.0.0.1:${PORT}/app`);
    try {
      await phone.send('Emulation.setDeviceMetricsOverride',
        { width: 360, height: 640, deviceScaleFactor: 1, mobile: true });
      await phone.waitFor("!document.getElementById('screen-onboarding').hidden",
        { timeout: 20000, label: 'app.js boot on the phone tab' });
      const phoneRaw = await phone.eval(`
        for (const s of document.querySelectorAll('section.screen')) s.hidden = s.id !== 'screen-connected';
        const [play, ui] = await Promise.all([import('/js/gameplay.js'), import('/js/gameui.js')]);
        const drawer = document.getElementById('games-disc');
        const area = document.getElementById('game-area');
        // Same settle as the block above, and for the same reason: the drawer's 150ms
        // opening fade holds .disc-body at opacity 0 until it ticks.
        const settle = async () => {
          await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
          const running = (document.getAnimations ? document.getAnimations() : [])
            .filter((a) => a.effect && a.effect.getComputedTiming().iterations !== Infinity);
          await Promise.all(running.map((a) => a.finished.catch((err) => { void err; })));
          await new Promise((r) => requestAnimationFrame(r));
        };

        const games = new play.GameSession({ send: async () => true });
        const gameUi = new ui.GameUI({
          root: area,
          games,
          partners: () => [{ peer: 'peer-them', label: 'Their Device' }],
          onNotice: () => {},
        });
        area.replaceChildren();
        drawer.open = false;
        gameUi.render();
        await settle();

        await games.receive('peer-them', { t: 'invite', mid: 'cccc000000000001', game: 'chess', seat: 'w' });
        // Three settles, not one: the scroll is deferred by a frame because the row it
        // aims at does not exist until render() has finished appending it.
        await settle(); await settle(); await settle();

        // Deliberately NO scrollIntoView here. That is the entire difference between this
        // measurement and the ones above, and its absence is what makes this ask the
        // question in the check's own name rather than mere reachability.
        const answerBox = () => {
          const b = [...area.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Play');
          if (!b) return { found: false };
          const r = b.getBoundingClientRect();
          const bar = document.querySelector('header.bar').getBoundingClientRect();
          const hit = document.elementFromPoint(Math.round(r.left + r.width / 2), Math.round(r.top + r.height / 2));
          return {
            found: true,
            drawerOpen: drawer.open,
            visible: b.checkVisibility({ checkVisibilityCSS: true, contentVisibilityAuto: true, opacityProperty: true }),
            hitIsButton: hit === b,
            hitWas: hit ? (hit.id || hit.className || hit.tagName) : 'nothing',
            // Below the masthead, which is sticky at top: 0, and above the fold. Either
            // failure leaves the person hunting for the control the screen is waiting on.
            belowMasthead: r.top >= bar.bottom,
            aboveTheFold: r.bottom <= innerHeight,
            top: Math.round(r.top), bottom: Math.round(r.bottom),
            barBottom: Math.round(bar.bottom), viewportH: innerHeight,
          };
        };
        const out = { down: answerBox() };

        // THE OTHER DIRECTION, and the one the sticky masthead actually decides.
        //
        // Scrolling DOWN to something below the fold parks it against the bottom edge,
        // where a masthead pinned to the TOP cannot reach it. Scrolling UP is where the
        // offset earns its place: the drawer sits at order 5 with the burn control below
        // it, so a person reading the foot of the column has the drawer above the
        // viewport, and block: nearest aligns the row's top to the top of the
        // scrollport, which is where .bar is pinned. Without the scroll-margin-top in
        // style.css the answer lands UNDER the masthead and is exactly as unreachable as
        // it was below the fold, so this is measured rather than reasoned about.
        await games.decline();
        await settle();
        const scroller = [document.querySelector('.page'), document.scrollingElement]
          .find((n) => n && n.scrollHeight > n.clientHeight + 1) || document.scrollingElement;
        scroller.scrollTop = scroller.scrollHeight;
        await settle();
        out.scrolledToFoot = Math.round(scroller.scrollTop) > 0;
        await games.receive('peer-them', { t: 'invite', mid: 'cccc000000000002', game: 'chess', seat: 'w' });
        await settle(); await settle(); await settle();
        out.up = answerBox();
        return JSON.stringify(out);
      `);
      const phoneSeen = JSON.parse(phoneRaw);
      const ph = phoneSeen.down;
      check('on a 360x640 phone the answer is on screen WITHOUT the test scrolling to it, '
        + 'below the masthead and above the fold',
        ph.found === true && ph.drawerOpen === true && ph.visible === true
        && ph.belowMasthead === true && ph.aboveTheFold === true && ph.hitIsButton === true,
        phoneRaw);

      check('CONTROL: the page really was scrolled to its foot before the second invitation',
        phoneSeen.scrolledToFoot === true,
        'nothing scrolled, so the check below never faced the masthead and measured nothing');

      const up = phoneSeen.up;
      check('an invitation arriving while the drawer is ABOVE the scroll position clears '
        + 'the sticky masthead rather than landing under it',
        up.found === true && up.visible === true && up.belowMasthead === true
        && up.aboveTheFold === true && up.hitIsButton === true,
        JSON.stringify(up));
    } finally {
      await phone.close();
    }
  } catch (err) {
    check('the games drawer block ran to completion', false, err.message);
  } finally {
    await browser.close();
    await server.stop();
  }
}

process.exit(summary('gameplay') ? 0 : 1);
