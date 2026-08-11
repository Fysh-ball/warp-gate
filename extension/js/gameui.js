// The board on screen.
//
// One renderer for every game, because the engines all answer the same five questions
// (js/games/index.js) and gameplay.js already turned "who are we and whose turn is it"
// into one object. What is left here is geometry and glyphs.
//
// Everything is built as DOM nodes, never as an HTML string. Two of the things drawn
// here come from the other device: their display name and, on a protocol failure, the
// reason. A template string would make those two an injection route into a page whose
// whole job is holding somebody's keys, and the CSP is the last line of that defence,
// not the first.
//
// The whole view is re-rendered on every change rather than patched. A board is at most
// 100 cells, it changes only when a move lands, and a diffing renderer here would be a
// second source of truth about what is on screen.

import { playableGames } from './gameplay.js';

// ---------------------------------------------------------------- the board stylesheet
//
// css/games.css is pastel board and shelf styling that only matters once the drawer is
// open, so it is fetched here rather than linked from app.html. Same reasoning as the
// engines: a gate whose two people never open a board should not pay for one. It was ~7 KB
// when this comment was written and is 25.3 KB raw / 9.2 KB gzipped since the games shelf
// landed on 2026-08-10, which changes nothing about the argument: none of it is on the
// eager graph, and tests/size.test.mjs asserts exactly that about this module.
//
// A <link> element, not a <style> element and not a style attribute: the gate's CSP sets
// `style-src 'self'`, which permits a same-origin stylesheet and forbids both of the
// others. Nothing here is inline.
//
// There is no flash of unstyled board, because the board does not exist until the module
// that draws it has loaded, and that is strictly after this runs.
const BOARD_CSS = '/css/games.css';
let cssRequested = false;

function ensureBoardCss() {
  if (cssRequested) return;
  cssRequested = true;
  // Guarded by the document as well as by the flag: two GameUIs in one page (a second
  // gate in the same tab) would otherwise stack duplicate links.
  if (document.querySelector(`link[href="${BOARD_CSS}"]`)) return;
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = BOARD_CSS;
  // A missing stylesheet must not be silent: the board still works, but it looks broken,
  // and "looks broken" with nothing in the log is the hardest kind of bug to be told
  // about. Reset the flag so a later render tries again.
  link.addEventListener('error', () => {
    cssRequested = false;
    console.warn('[warp gate] the board stylesheet did not load; boards will be unstyled');
  }, { once: true });
  document.head.appendChild(link);
}

const CHESS_GLYPHS = Object.freeze({
  k: '♚', q: '♛', r: '♜', b: '♝', n: '♞', p: '♟',
});

/**
 * Solid glyphs for both colours, not the hollow set for white.
 *
 * The outline pieces (♔ and friends) are drawn as thin strokes, and on the pastel
 * squares below they lose to the fill at small sizes on a phone. The same solid shape in
 * two inks reads at any size, and it is the convention every board on a screen uses.
 */
function chessGlyph(piece) {
  const lower = piece.toLowerCase();
  return CHESS_GLYPHS[lower] || '';
}

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
};

function button(label, className, onClick) {
  const b = el('button', className, label);
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}

// ---------------------------------------------------------------- the shelf's art
//
// One tile per game, drawn here as SVG nodes rather than fetched, because a fetched image
// is a request and this product's whole claim is that nothing leaves the two browsers. It
// is also why there is no sprite sheet, no data: URI and no icon font: the CSP the gate is
// served with would refuse an external one, and the three alternatives that would survive
// it are all worse than 40 lines of geometry.
//
// Every tile is a MINIATURE OF THE GAME'S OWN BOARD. That was the design decision worth
// writing down, because the obvious alternative (a symbolic icon per game: an anchor for
// battleships, a crown for chess) was tried first and thrown away. A symbol has to be
// learned; a board does not, and the tiles then come free of the palette that is already
// in games.css, so the connect four tile is made of the same rose and butter as the discs
// the player is about to drop. The card and the board it opens are visibly one object.
//
// The colours live in games.css, not here. An SVG presentation attribute cannot read a
// custom property, so `fill="var(--g-rose)"` does not work, and hardcoding #f2b8c6 in this
// file would put a second copy of the palette somewhere nobody editing the stylesheet
// would ever look for it. Each shape therefore carries a class and games.css fills it.

const SVG_NS = 'http://www.w3.org/2000/svg';

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const name of Object.keys(attrs)) node.setAttribute(name, String(attrs[name]));
  return node;
}

/**
 * The shared 80x50 canvas. That ratio is the 8:5 the card's art slot is given in
 * games.css, so nothing is ever letterboxed and no tile needs its own preserveAspectRatio.
 *
 * aria-hidden because the tile is a picture of the name and the description sitting
 * directly under it inside the same button. Left announced, every card would read its own
 * decoration out before its label.
 */
function artCanvas(children) {
  const root = svg('svg', { viewBox: '0 0 80 50', 'aria-hidden': 'true', focusable: 'false' });
  root.append(...children);
  return root;
}

function artTicTacToe() {
  const rule = (x1, y1, x2, y2) => svg('line', { class: 'a-rule', x1, y1, x2, y2 });
  const cross = (cx, cy, r) => [
    svg('line', { class: 'a-x', x1: cx - r, y1: cy - r, x2: cx + r, y2: cy + r }),
    svg('line', { class: 'a-x', x1: cx + r, y1: cy - r, x2: cx - r, y2: cy + r }),
  ];
  // A 36px board on a 36px cell pitch, centred: x 22..58, y 7..43, so the four rules are
  // the two inner gridlines on each axis and the marks land on cell centres.
  return artCanvas([
    rule(34, 7, 34, 43), rule(46, 7, 46, 43),
    rule(22, 19, 58, 19), rule(22, 31, 58, 31),
    ...cross(28, 13, 4),
    svg('circle', { class: 'a-o', cx: 40, cy: 25, r: 4.2 }),
    ...cross(52, 37, 4),
  ]);
}

function artConnect4() {
  const parts = [svg('rect', { class: 'a-frame', x: 14, y: 6, width: 52, height: 38, rx: 5 })];
  const cols = [23, 34.3, 45.7, 57];
  const rows = [16, 25, 34];
  // A position, not a random scatter: three discs resting on the floor and one stacked on
  // top of the leftmost, which is what a real board two moves in looks like. A tile
  // showing discs floating in mid air would be the one thing about this game a first-time
  // player could get wrong from the picture.
  const played = { '0,2': 'a-rose', '1,2': 'a-butter', '2,2': 'a-rose', '0,1': 'a-butter' };
  for (let c = 0; c < cols.length; c += 1) {
    for (let r = 0; r < rows.length; r += 1) {
      parts.push(svg('circle', {
        class: played[`${c},${r}`] || 'a-hole', cx: cols[c], cy: rows[r], r: 4.2,
      }));
    }
  }
  return artCanvas(parts);
}

function artBattleships() {
  const parts = [svg('rect', { class: 'a-sea', x: 13, y: 6, width: 54, height: 38, rx: 3 })];
  for (let i = 1; i < 6; i += 1) {
    parts.push(svg('line', { class: 'a-rule-faint', x1: 13 + i * 9, y1: 6, x2: 13 + i * 9, y2: 44 }));
  }
  for (let i = 1; i < 5; i += 1) {
    parts.push(svg('line', { class: 'a-rule-faint', x1: 13, y1: 6 + i * 7.6, x2: 67, y2: 6 + i * 7.6 }));
  }
  parts.push(svg('rect', { class: 'a-ship', x: 17, y: 11, width: 26, height: 6, rx: 3 }));
  parts.push(svg('rect', { class: 'a-ship', x: 50, y: 21, width: 6, height: 19, rx: 3 }));
  // One hit and two misses, in the same three colours the board uses for them, so the tile
  // teaches the only piece of notation the game has before the game starts.
  parts.push(svg('circle', { class: 'a-hit', cx: 22, cy: 32, r: 4 }));
  parts.push(svg('circle', { class: 'a-dot', cx: 35, cy: 27, r: 1.6 }));
  parts.push(svg('circle', { class: 'a-dot', cx: 62, cy: 14, r: 1.6 }));
  return artCanvas(parts);
}

function artChess() {
  const parts = [];
  const size = 9;
  // Four squares by four rather than eight by eight. At the 159px card width a phone gets,
  // an 8x8 grid puts each square under 3 device pixels and the checker turns into a flat
  // grey wash: the pattern reads at every size only if the cells are big.
  for (let r = 0; r < 4; r += 1) {
    for (let c = 0; c < 4; c += 1) {
      parts.push(svg('rect', {
        class: (r + c) % 2 === 1 ? 'a-sq-d' : 'a-sq-l',
        x: 22 + c * size, y: 7 + r * size, width: size, height: size,
      }));
    }
  }
  const glyph = svg('text', { class: 'a-piece', x: 40, y: 34, 'text-anchor': 'middle' });
  // The knight, and the same solid glyph the board draws, for the reason chessGlyph()
  // above already gives: the hollow set loses to the fill at small sizes.
  glyph.textContent = CHESS_GLYPHS.n;
  parts.push(glyph);
  return artCanvas(parts);
}

const GAME_ART = Object.freeze({
  tictactoe: artTicTacToe,
  connect4: artConnect4,
  battleships: artBattleships,
  chess: artChess,
});

// One line each, in the second person and about what PLAYING it is like, not about the
// rules. These are keyed by id and looked up with a fallback for the same reason
// playableGames() filters rather than throws: a game added to the registry without an
// entry here should get a plain card, not take the shelf down.
//
// They are also SHORT, and that is a measurement rather than a preference. The first draft
// ran to about seventy characters each ("Drop a disc down a column and line up four.
// Gravity does half the work.") and on a 390px phone, where a card is 159px wide, that
// wrapped to four lines and took the card to 247px tall: two of them filled more than half
// the screen. At roughly thirty characters every blurb is two lines at 159px and two lines
// at 220px, so the shelf is the same shape on a phone and on a desktop.
const GAME_BLURBS = Object.freeze({
  tictactoe: 'Three in a row, over in a minute.',
  connect4: 'Drop a disc, line up four.',
  battleships: 'Hide a fleet, then hunt for theirs.',
  chess: 'The full rules, en passant included.',
});
const DEFAULT_BLURB = 'Two players, one board.';

const SEAT_NAMES = Object.freeze({
  x: 'X', o: 'O', r: 'Red', y: 'Yellow', w: 'White', b: 'Black', a: 'Blue',
});

/** Battleships uses 'b' for one side and chess uses it for Black: disambiguate by game. */
function seatName(gameId, seat) {
  if (gameId === 'battleships') return seat === 'a' ? 'first' : 'second';
  return SEAT_NAMES[seat] || seat;
}

export class GameUI {
  /**
   * @param {object} options
   * @param {HTMLElement} options.root       where the whole thing is drawn
   * @param {import('./gameplay.js').GameSession} options.games
   * @param {() => Array<{peer: string, label: string}>} options.partners
   * @param {(text: string) => void} [options.onNotice]  one line for the activity log
   */
  constructor({ root, games, partners, onNotice = null }) {
    this.root = root;
    this.games = games;
    this.partners = partners;
    this.onNotice = onNotice;
    // Chess is the one game where a move is two clicks, so the half-finished move lives
    // here rather than in the match: it is a fact about this screen, not about the game,
    // and it must not survive a move arriving from the other side.
    this.selected = null;
    this.chosenPeer = null;
    // The match id of the last invitation this screen announced. See announceInvite().
    this.announcedInvite = null;
    // Set by announceInvite, consumed by renderInvite. Declared here so the field exists
    // before the first render rather than appearing on the instance halfway through a match.
    this.inviteArriving = false;
    this.games.addEventListener('update', () => this.render());
  }

  /**
   * Make an incoming invitation impossible to miss.
   *
   * Everything this class draws lives inside a collapsed disclosure whose summary reads
   * "something to do while you wait", and nobody opens that while they are waiting for
   * something else. An invitation drawn into a shut drawer is in the DOM and is not on
   * screen: the browser reports checkVisibility() false for the Play button and hit
   * testing at its coordinates returns the page behind it. So the person who pressed a
   * card sits on "Waiting for them to accept" forever, the person who was asked is never
   * told they were asked, and both of them correctly report that games do not work.
   *
   * This is the one thing rendered here that REQUIRES an answer from the person looking
   * at the screen, so it is also the one thing allowed to open the drawer itself. Two
   * signals, because they fail differently: the drawer opens, and the invitation goes to
   * the activity log, which survives the drawer being shut again.
   *
   * Once per invitation, keyed on the match id, and never on a plain re-render. Somebody
   * who shuts the drawer again has answered the question by shutting it, and a panel that
   * springs back open on the next move is worse than one that never opened.
   */
  announceInvite(inv) {
    // Identity, not the match id. Keying on `mid` looked equivalent because an honest
    // client rolls a fresh one per invitation, but a peer that REUSES a mid it already
    // used, after that invitation was declined, would find the second invitation silently
    // swallowed: this.incoming is set, the Play button is drawn, and it is drawn into a
    // shut drawer with nothing said about it. That is precisely the failure this method
    // exists to prevent, so the latch must not be forgeable by the sender.
    if (this.announcedInvite === inv) return;
    this.announcedInvite = inv;
    // Consumed by renderInvite, once. The row is about to be built by the same render()
    // call, and a later re-render for an unrelated notice must not replay the arrival:
    // motion that repeats without a new event stops meaning "something happened".
    this.inviteArriving = true;
    if (this.onNotice) this.onNotice(`${this.labelFor(inv.peer)} wants to play ${inv.name}.`);
    // closest() rather than a known id: this class is handed a root and does not own the
    // markup around it, and a copy of the app that does not wrap it in a disclosure at all
    // should get the log line and no error.
    const drawer = this.root && this.root.closest ? this.root.closest('details') : null;
    if (drawer && !drawer.open) drawer.open = true;

    // Opening the drawer is not the same thing as putting the answer on screen, and on a
    // small phone it is not even close. Measured on the connected screen at 360x640 with
    // the drawer opened by an invitation and nothing else touched:
    //
    //     masthead bottom      y =  45
    //     drawer top           y = 625
    //     Play button          y = 694..730     viewport height 640
    //     scrollTop after      0                scrollable range 842
    //
    // So the control that answers the invitation sat 54px BELOW the fold, the page did
    // not move, and elementFromPoint at its centre returned nothing at all: off screen.
    // The drawer had opened onto something the person was never shown. At 390x844 the
    // same measurement puts it at y=678 and it happens to fit, which is exactly why this
    // cannot be left to the layout: it is one block of transcript away from not fitting,
    // and the Games panel moved from second to sixth on the phone layout, so the drawer
    // now opens further down the column than it used to.
    //
    // Deferred by one frame because the invitation itself is not in the DOM yet:
    // announceInvite() runs from render() BEFORE renderInvite() appends the row, so a
    // scroll issued here would be aimed at the previous contents. One rAF is enough,
    // since render() finishes synchronously.
    //
    // `block: 'nearest'` rather than 'center' or 'start': it is a no-op when the row is
    // already fully on screen, so somebody who had the drawer open and was reading it
    // does not get yanked around by a scroll they did not ask for. The masthead is
    // `position: sticky; top: 0`, so a scroll that ignored it would park the row
    // underneath it; the offset lives in CSS as `scroll-margin-top` on .game-status,
    // beside the token that carries the masthead's height.
    //
    // Instant, never smooth: this is a jump to something that needs an answer, and a
    // 300ms animated scroll on a screen that may be running a live transfer is motion
    // spent on a decoration.
    if (drawer && typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => {
        const answer = this.root && this.root.querySelector ? this.root.querySelector('.game-status') : null;
        if (answer && typeof answer.scrollIntoView === 'function') {
          answer.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'auto' });
        }
      });
    }
  }

  render() {
    const root = this.root;
    if (!root) return;
    ensureBoardCss();
    root.replaceChildren();

    const gs = this.games;
    if (gs.notice) root.append(el('p', 'game-note', gs.notice));

    if (gs.incoming) {
      this.announceInvite(gs.incoming);
      return this.renderInvite(root, gs.incoming);
    }
    if (gs.outgoing) return this.renderWaiting(root, gs.outgoing);
    const view = gs.view();
    if (!view) return this.renderMenu(root);
    return this.renderMatch(root, view);
  }

  // ---------------------------------------------------------------- lobby

  renderMenu(root) {
    const partners = this.partners();
    if (partners.length === 0) {
      root.append(el('p', 'game-idle', 'Once the other device is connected you can play something here while a transfer runs.'));
      return;
    }

    if (partners.length > 1) {
      const row = el('div', 'game-row');
      row.append(el('span', 'game-label', 'Play with'));
      const select = el('select', 'game-select');
      for (const p of partners) {
        const option = el('option', null, p.label);
        option.value = p.peer;
        select.append(option);
      }
      select.value = this.chosenPeer && partners.some((p) => p.peer === this.chosenPeer)
        ? this.chosenPeer
        : partners[0].peer;
      this.chosenPeer = select.value;
      select.addEventListener('change', () => { this.chosenPeer = select.value; });
      row.append(select);
      root.append(row);
    } else {
      this.chosenPeer = partners[0].peer;
    }

    root.append(this.shelf({
      onPick: (entry) => {
        this.selected = null;
        this.games.invite(this.chosenPeer || partners[0].peer, entry.id);
      },
    }));
  }

  /**
   * The shelf: one card per playable game, and the same shelf under all three lobby states.
   *
   * What was here before 2026-08-10 was `.game-menu`, a flex row of four small bordered
   * buttons carrying nothing but the game's name, and the three states each replaced it
   * with a sentence. Two things were wrong with that and only one of them was cosmetic.
   * The cosmetic one is in the games.css comment: the global `button { width: 100% }` made
   * the row four stacked full-width bars. The other is that "waiting for them to accept
   * Chess" wiped the shelf off the screen, so the one moment a person most wants to see
   * WHICH game is in play showed them the least. Now the shelf stays, every card goes to
   * the disabled 0.5 opacity the global button rule already gives, and the game in
   * question is the single lit card. One renderer, three states, one thing lit.
   *
   * The card IS the button. A Play button nested inside a clickable card would be a button
   * inside a button, which no browser renders as written, so `.game-card-cta` is a span.
   * It is deliberately not aria-hidden and there is deliberately no aria-label: an
   * aria-label would replace the card's contents for a screen reader, and the contents are
   * the useful part. The accessible name reads "Chess. The full rules... Play", which is
   * the name, the description and the verb, in that order.
   *
   * @param {object} options
   * @param {string|null} options.activeId    the game to light up, if any
   * @param {boolean}     options.locked      disable every card (an invitation is in the air)
   * @param {string}      options.activeCta   what the lit card's pill says instead of Play
   * @param {((entry: object) => void)|null} options.onPick
   */
  shelf({ activeId = null, locked = false, activeCta = 'Play', onPick = null } = {}) {
    const shelf = el('div', 'game-shelf');
    for (const entry of playableGames()) {
      const active = entry.id === activeId;
      const card = el('button', `game-card${active ? ' is-active' : ''}`);
      card.type = 'button';
      // A data attribute rather than a class per game: games.css keys each card's pastel
      // off [data-game], and this is the same string the click handler needs anyway.
      card.dataset.game = entry.id;
      card.disabled = locked;

      const art = el('span', 'game-card-art');
      const draw = GAME_ART[entry.id];
      // A registered game with no tile still gets a card. The art slot keeps its pastel
      // wash from games.css, so the failure mode is a plain coloured rectangle rather than
      // a hole, and the name and blurb underneath still say what it is.
      if (draw) art.append(draw());

      const body = el('span', 'game-card-body');
      body.append(el('span', 'game-card-name', entry.name));
      body.append(el('span', 'game-card-desc', GAME_BLURBS[entry.id] || DEFAULT_BLURB));
      body.append(el('span', 'game-card-cta', active ? activeCta : 'Play'));

      card.append(art, body);
      if (onPick) card.addEventListener('click', () => onPick(entry));
      shelf.append(card);
    }
    return shelf;
  }

  renderWaiting(root, out) {
    const row = el('div', 'game-row game-status');
    row.append(el('p', 'game-idle', `Waiting for them to accept ${out.name}.`));
    row.append(button('Cancel', 'btn ghost small', () => this.games.cancelInvite()));
    root.append(row);
    root.append(this.shelf({ activeId: out.gameId, locked: true, activeCta: 'Waiting' }));
  }

  renderInvite(root, inv) {
    const who = this.labelFor(inv.peer);
    const row = el('div', 'game-row game-status');
    // Only for an invitation that has just been announced. The class drives a 4px rise in
    // style.css, the same one a message landing in the transcript gets, because it is the
    // same kind of event: something the other device sent, into a panel that may have just
    // opened itself to show it.
    if (this.inviteArriving) {
      row.classList.add('is-arriving');
      this.inviteArriving = false;
    }
    row.append(el('p', 'game-idle', `${who} wants to play ${inv.name}.`));
    row.append(button('Play', 'btn small', () => { this.selected = null; this.games.accept(); }));
    row.append(button('No thanks', 'btn ghost small', () => this.games.decline()));
    root.append(row);
    root.append(this.shelf({ activeId: inv.gameId, locked: true, activeCta: 'Their pick' }));
  }

  labelFor(peer) {
    const found = this.partners().find((p) => p.peer === peer);
    return found ? found.label : 'The other device';
  }

  // ---------------------------------------------------------------- a match

  renderMatch(root, view) {
    const head = el('div', 'game-head');
    head.append(el('span', 'game-name', view.name));
    head.append(el('span', 'game-turn', this.statusLine(view)));
    root.append(head);

    if (view.gameId === 'battleships') this.renderBattleships(root, view);
    else if (view.gameId === 'chess') this.renderChess(root, view);
    else if (view.gameId === 'connect4') this.renderConnect4(root, view);
    else this.renderTicTacToe(root, view);

    const controls = el('div', 'game-row game-controls');
    if (view.ended) {
      controls.append(button('Play again', 'btn small', () => {
        // The loser of the last game moves first in the next one, which is the ordinary
        // courtesy and needs no negotiation: seats are named in the invitation.
        this.selected = null;
        this.games.close();
        this.games.invite(view.peer, view.gameId, view.theirSeat);
      }));
      controls.append(button('Close', 'btn ghost small', () => { this.selected = null; this.games.close(); }));
    } else {
      controls.append(button('Resign', 'btn ghost small', () => this.games.resign()));
    }
    root.append(controls);
  }

  statusLine(view) {
    if (view.ended) {
      const e = view.ended;
      if (e.reason === 'protocol') return 'The game was abandoned: the two boards disagreed.';
      if (e.reason === 'left') return 'They left the gate.';
      if (e.reason === 'resigned') return e.by === 'you' ? 'You resigned.' : 'They resigned.';
      if (e.winner === null) return 'A draw.';
      return e.winner === view.seat ? 'You won.' : 'They won.';
    }
    if (view.gameId === 'battleships') {
      if (!view.readySent) return 'Place your fleet, then lock it in.';
      if (view.status.phase === 'placing') return 'Waiting for them to be ready.';
      if (view.state.pending) return 'Waiting to hear what that shot hit.';
      return view.yourTurn ? 'Take a shot.' : 'They are taking a shot.';
    }
    const you = seatName(view.gameId, view.seat);
    return view.yourTurn ? `Your move, you are ${you}.` : `Their move, you are ${you}.`;
  }

  /** A square grid that fills the column without overflowing it. */
  gridFor(cols, rows, extra = '') {
    const grid = el('div', `game-grid ${extra}`.trim());
    // CSSOM, not a style attribute: the CSP forbids the latter, not this.
    grid.style.setProperty('--game-cols', String(cols));
    grid.style.setProperty('--game-rows', String(rows));
    return grid;
  }

  // ---------------------------------------------------------------- tic tac toe

  renderTicTacToe(root, view) {
    const grid = this.gridFor(3, 3, 'game-ttt');
    for (let i = 0; i < 9; i += 1) {
      const mark = view.state.board[i];
      const cell = el('button', `game-cell${mark ? ` mark-${mark}` : ''}`, mark ? mark.toUpperCase() : '');
      cell.type = 'button';
      cell.disabled = Boolean(mark) || !view.yourTurn;
      cell.setAttribute('aria-label', `row ${Math.floor(i / 3) + 1} column ${(i % 3) + 1}${mark ? `, ${mark.toUpperCase()}` : ', empty'}`);
      if (view.status.line && view.status.line.includes(i)) cell.classList.add('game-win');
      cell.addEventListener('click', () => this.play({ index: i }));
      grid.append(cell);
    }
    root.append(grid);
  }

  // ---------------------------------------------------------------- connect 4

  renderConnect4(root, view) {
    const grid = this.gridFor(7, 6, 'game-c4');
    const legal = new Set(view.legal.map((m) => m.column));
    for (let i = 0; i < 42; i += 1) {
      const col = i % 7;
      const disc = view.state.board[i];
      const cell = el('button', `game-cell disc${disc ? ` disc-${disc}` : ''}`, '');
      cell.type = 'button';
      cell.disabled = !view.yourTurn || !legal.has(col);
      cell.setAttribute('aria-label', `column ${col + 1}${disc ? `, ${disc === 'r' ? 'red' : 'yellow'}` : ''}`);
      if (view.status.line && view.status.line.includes(i)) cell.classList.add('game-win');
      cell.addEventListener('click', () => this.play({ column: col }));
      grid.append(cell);
    }
    root.append(grid);
  }

  // ---------------------------------------------------------------- chess

  renderChess(root, view) {
    const flipped = view.seat === 'b';
    const legal = view.yourTurn ? view.legal : [];
    const fromSquares = new Set(legal.map((m) => m.from));
    const targets = this.selected
      ? new Set(legal.filter((m) => m.from === this.selected).map((m) => m.to))
      : new Set();

    const grid = this.gridFor(8, 8, 'game-chess');
    for (let rank = 0; rank < 8; rank += 1) {
      for (let file = 0; file < 8; file += 1) {
        const r = flipped ? 7 - rank : rank;
        const f = flipped ? 7 - file : file;
        const index = r * 8 + f;
        const square = `${'abcdefgh'[f]}${8 - r}`;
        const piece = view.state.board[index];
        const dark = (r + f) % 2 === 1;
        const cell = el('button', `game-cell sq ${dark ? 'sq-dark' : 'sq-light'}`, piece === '.' ? '' : chessGlyph(piece));
        cell.type = 'button';
        if (piece !== '.') cell.classList.add(piece === piece.toUpperCase() ? 'piece-w' : 'piece-b');
        if (this.selected === square) cell.classList.add('sq-picked');
        if (targets.has(square)) cell.classList.add('sq-target');
        cell.setAttribute('aria-label', square + (piece === '.' ? ', empty' : `, ${piece}`));
        cell.disabled = !view.yourTurn || (!fromSquares.has(square) && !targets.has(square) && this.selected === null);
        cell.addEventListener('click', () => this.clickSquare(view, square, legal));
        grid.append(cell);
      }
    }
    root.append(grid);

    if (view.status.reason === 'check' || (view.status.check && !view.ended)) {
      root.append(el('p', 'game-note', 'Check.'));
    }
  }

  clickSquare(view, square, legal) {
    if (!view.yourTurn) return;
    if (this.selected === square) { this.selected = null; this.render(); return; }
    const moves = legal.filter((m) => m.from === this.selected && m.to === square);
    if (this.selected && moves.length > 0) {
      // Promotions arrive as four separate moves to the same square. Offering the choice
      // is a dialog for a case that is nearly always a queen, so a queen it is, and the
      // rest of the list is still there if the engine ever needs it.
      const move = moves.find((m) => m.promotion === 'q') || moves[0];
      this.selected = null;
      this.play(move);
      return;
    }
    this.selected = legal.some((m) => m.from === square) ? square : null;
    this.render();
  }

  // ---------------------------------------------------------------- battleships

  renderBattleships(root, view) {
    const placing = !view.readySent;

    const theirs = el('div', 'game-side');
    theirs.append(el('p', 'game-side-title', 'Their waters'));
    const fire = this.gridFor(10, 10, 'game-sea');
    const canFire = view.yourTurn && !placing && view.status.phase === 'battle' && !view.state.pending;
    for (let y = 0; y < 10; y += 1) {
      for (let x = 0; x < 10; x += 1) {
        const shot = view.state.shots[y * 10 + x];
        const cell = el('button', `game-cell sea shot-${shot}`, '');
        cell.type = 'button';
        cell.disabled = !canFire || shot !== 'none';
        cell.setAttribute('aria-label', `${'ABCDEFGHIJ'[x]}${y + 1}, ${shot === 'none' ? 'not fired at' : shot}`);
        cell.addEventListener('click', () => this.play({ type: 'fire', x, y }));
        fire.append(cell);
      }
    }
    theirs.append(fire);

    const ours = el('div', 'game-side');
    ours.append(el('p', 'game-side-title', 'Your fleet'));
    const own = this.gridFor(10, 10, 'game-sea');
    const shipCells = new Set();
    for (const ship of view.state.ships) {
      for (let i = 0; i < ship.size; i += 1) {
        shipCells.add(ship.dir === 'h' ? (ship.y * 10 + ship.x + i) : ((ship.y + i) * 10 + ship.x));
      }
    }
    for (let i = 0; i < 100; i += 1) {
      const hit = view.state.incoming[i];
      const cell = el('div', `game-cell sea${shipCells.has(i) ? ' ship' : ''} shot-${hit}`, '');
      own.append(cell);
    }
    ours.append(own);

    const boards = el('div', 'game-seas');
    boards.append(theirs, ours);
    root.append(boards);

    if (placing) {
      const row = el('div', 'game-row');
      row.append(button('Shuffle', 'btn ghost small', () => this.play({ type: 'shuffle' })));
      row.append(button('Ready', 'btn small', () => this.play({ type: 'ready' })));
      root.append(row);
    }
  }

  // ---------------------------------------------------------------- moves

  async play(move) {
    const res = await this.games.play(move);
    if (res && res.ok === false && this.onNotice) this.onNotice(res.error);
  }
}
