// The backpressure deadline, and what a backgrounded tab does to it.
//
// Peer.send stops feeding the data channel above CHUNK_PAUSE_BYTES and waits for it to
// drain. That wait needs a deadline, because 'bufferedamountlow' and 'close' are both
// events that may simply never arrive. The deadline used to be wall clock:
//
//     const deadline = Date.now() + DRAIN_TIMEOUT_MS;
//
// A phone that locks its screen, or a tab the user switches away from, has its timers
// clamped to about a second and can be frozen outright, while Date.now() keeps moving.
// Thirty seconds of that and the first poll after the thaw is already past the deadline,
// so the send rejects with "the other device stopped accepting data" about a peer that did
// nothing wrong, and session.sendFile's loop stops. That is the user report this exists
// for: "no send unless the screen is on".
//
// The deadline now measures time this page was actually RUNNING: a poll that arrives later
// than its interval hands the overshoot back. A page that is merely hidden still times out,
// because a clamped poll overshoots by a bounded amount each round; a page that was not
// executing at all is not charged for the time it was gone.
//
// Driven with a stand-in channel and a stand-in clock rather than a real connection: the
// arithmetic is the thing under test, and a real freeze is not something a test can ask a
// browser for. Every line of the real send() runs, including the real setInterval body.

import { check, summary } from './lib/harness.mjs';

const CHUNK_PAUSE_BYTES = 8 * 1024 * 1024;
const DRAIN_POLL_MS = 250;
const DRAIN_TIMEOUT_MS = 30_000;

const realSetInterval = globalThis.setInterval;
const realClearInterval = globalThis.clearInterval;
const realNow = Date.now;
const realSetTimeout = globalThis.setTimeout;

/** Let the microtask queue and any real timer settle, on the real clock. */
const settle = () => new Promise((resolve) => realSetTimeout(resolve, 0));

/**
 * A channel that is permanently over the pause threshold and dispatches nothing.
 *
 * That is the case the deadline exists for: no 'bufferedamountlow', no 'close', nothing to
 * wait on but time. Whether time is being counted correctly is the whole question.
 */
function stuckChannel() {
  return {
    readyState: 'open',
    bufferedAmount: CHUNK_PAUSE_BYTES + 1024 * 1024,
    addEventListener() {},
    removeEventListener() {},
    send() { throw new Error('send() must not be reached while the channel is over its pause threshold'); },
  };
}

/**
 * Run Peer.prototype.send against a stand-in clock and a stand-in interval.
 *
 * `setInterval` is swapped for a manual scheduler so the poll body can be stepped one tick
 * at a time with the clock under the test's control. peer.js calls the bare globals, so
 * this reaches the real code without the real code knowing.
 */
async function driveSend() {
  let clock = 1_000_000_000_000;
  let tick = null;
  globalThis.setInterval = (fn) => { tick = fn; return 'poll'; };
  globalThis.clearInterval = () => { tick = null; };
  Date.now = () => clock;

  // Imported INSIDE the swap so nothing in peer.js can have captured the real globals at
  // module scope. It does not today, and a test that would still pass if it did is not
  // measuring what it claims to.
  const { Peer } = await import('../public/js/peer.js');
  const peer = Object.create(Peer.prototype);
  peer.channel = stuckChannel();
  peer.drainWaiters = new Set();

  let outcome = null;
  const sending = peer.send(new Uint8Array(8));
  sending.then(() => { outcome = { ok: true }; }, (err) => { outcome = { ok: false, message: err.message }; });
  await settle();

  return {
    /** Advance the clock by `ms` and run one poll, which is what a live page looks like. */
    async run(ms) {
      clock += ms;
      if (tick) tick();
      await settle();
    },
    /** Time passes, no poll runs. A frozen tab, or a clamped one that skipped its slot. */
    async sleep(ms) {
      clock += ms;
      await settle();
    },
    get outcome() { return outcome; },
    get polling() { return tick !== null; },
    restore() {
      globalThis.setInterval = realSetInterval;
      globalThis.clearInterval = realClearInterval;
      Date.now = realNow;
    },
  };
}

// -------------------------------------------------------------------- a page that runs

{
  const d = await driveSend();
  try {
    check('a send over the pause threshold waits rather than throwing',
      d.outcome === null && d.polling === true, JSON.stringify(d.outcome));

    // Just under the deadline, entirely in the foreground.
    for (let ms = 0; ms < DRAIN_TIMEOUT_MS - DRAIN_POLL_MS; ms += DRAIN_POLL_MS) await d.run(DRAIN_POLL_MS);
    check('it is still waiting one poll short of the deadline',
      d.outcome === null, JSON.stringify(d.outcome));

    await d.run(DRAIN_POLL_MS);
    await d.run(DRAIN_POLL_MS);
    check('a channel that never drains does time out, so the deadline has not been removed',
      d.outcome?.ok === false && d.outcome.message.includes('stopped accepting data'),
      JSON.stringify(d.outcome));
  } finally {
    d.restore();
  }
}

// -------------------------------------------------------------------- a page that slept

{
  const d = await driveSend();
  try {
    // Ten seconds of ordinary foreground waiting, then the screen locks for a minute.
    for (let ms = 0; ms < 10_000; ms += DRAIN_POLL_MS) await d.run(DRAIN_POLL_MS);
    check('CONTROL: ten seconds in, well inside the deadline, still waiting',
      d.outcome === null, JSON.stringify(d.outcome));

    await d.sleep(60_000);
    await d.run(0);
    check('the first poll after a 60s freeze does not fail the transfer',
      d.outcome === null, JSON.stringify(d.outcome));

    // The remaining budget is what was left when the page stopped, not zero.
    for (let ms = 0; ms < 19_000; ms += DRAIN_POLL_MS) await d.run(DRAIN_POLL_MS);
    check('and the rest of the budget survived the freeze intact',
      d.outcome === null, JSON.stringify(d.outcome));

    // Spent now, on running time alone.
    for (let ms = 0; ms < 2_000; ms += DRAIN_POLL_MS) await d.run(DRAIN_POLL_MS);
    check('a freeze delays the deadline, it does not abolish it',
      d.outcome?.ok === false && d.outcome.message.includes('stopped accepting data'),
      JSON.stringify(d.outcome));
  } finally {
    d.restore();
  }
}

// -------------------------------------------------------------------- a page merely hidden

{
  const d = await driveSend();
  try {
    // A hidden tab still polls, at the ~1s clamp rather than 250ms. Each round overshoots
    // by 750ms and hands that back, so the deadline stretches by roughly four times. It
    // must still be reached: a bounded stretch is a grace period, an unbounded one is a
    // wait that no peer failure can ever end.
    let ran = 0;
    for (; ran < 600 && d.outcome === null; ran += 1) await d.run(1000);
    check('a tab that is only throttled still reaches the deadline',
      d.outcome?.ok === false, JSON.stringify(d.outcome));
    check('and reaches it in a bounded number of clamped polls, not eventually',
      ran <= 4 * (DRAIN_TIMEOUT_MS / 1000) + 2, `${ran} clamped polls`);
  } finally {
    d.restore();
  }
}

process.exit(summary('drain deadline') ? 0 : 1);
