// What the SENDER declares it sent, when a resume overlaps a send that is still running.
//
// This exists for one measured data loss. A 434 MB file arrived complete and correct and
// was thrown away, because FILE_END declared 832,087,527 bytes for a 455,030,247 byte
// file: exactly the 377,057,280 the receiver already held, plus the whole file again. The
// receiver had every chunk, in the right order, at the right length, and failed the
// transfer on the sender's arithmetic alone.
//
// The mechanism: `out.sent` was a running total of bytes PUSHED. serveResume rebased it to
// what the receiver already had, and that rebase sits BEFORE driveOutbound consults its
// `streaming` latch. So a resume landing while the previous run was still unwinding
// rebased the figure and then let the old loop go on adding to it.
//
// Link is driven directly with stand-in transports because the arithmetic is the thing
// under test, not WebRTC: connect() would build an RTCPeerConnection, which Node has no
// business having. Every byte below goes through the real sendFile, the real driveOutbound
// and the real serveResume, over a real File.

import { check, summary } from './lib/harness.mjs';
import { Link, STATE as LINK_STATE } from '../public/js/link.js';
import { TYPE } from '../public/js/crypto.js';
import { fingerprintFile } from '../public/js/transfer.js';
import { chunkCount } from '../public/js/chunkwire.js';

const CHUNK = 16 * 1024;
// Deliberately NOT a multiple of the chunk size. The final chunk is 777 bytes, so a total
// that is right only because it counted whole chunks cannot pass.
const SIZE = CHUNK * 20 + 777;
const CHUNKS = chunkCount(SIZE, CHUNK);

function makeFile() {
  const bytes = new Uint8Array(SIZE);
  for (let i = 0; i < SIZE; i += 1) bytes[i] = i & 0xff;
  return new File([bytes], 'accounting.bin', { type: 'application/octet-stream' });
}

/**
 * A Link wired to transports that record instead of transmitting.
 *
 * `gateAt` suspends the Nth chunk send, which is how a resume is made to land WHILE the
 * previous run is mid-flight. That overlap is the whole bug: without it the latch alone
 * would have been enough and the coverage map would be unnecessary.
 */
function harness({ gateAt = null } = {}) {
  const sealed = [];
  const controls = [];
  // Every frame in the order it went out, so an ordering claim ("the parked chunks went
  // before FILE_END") is checked against the wire rather than inferred from a total.
  const order = [];
  let releaseGate = null;
  let announceGate = null;
  const reachedGate = new Promise((resolve) => { announceGate = resolve; });
  let chunkSends = 0;

  const session = {
    roomId: 'test-room',
    severed: false,
    needsRestart: false,
    passwordGate: Promise.resolve(),
    signal: { send: async () => true },
    labelFor: () => 'peer',
    sever: async () => { session.severed = true; },
  };
  const link = new Link({ session, peerId: 'zzz', initiator: true });
  link.state = LINK_STATE.CONNECTED;
  link.channel = {
    seal: async (type, bytes) => ({ type, bytes }),
    sealJson: async (type, body) => { sealed.push({ type, body }); return { type, body }; },
  };
  link.peer = {
    maxChunkBytes: () => CHUNK,
    send: async (frame) => {
      if (frame.type !== TYPE.FILE_CHUNK) {
        if (frame.type === TYPE.FILE_END) order.push({ end: true });
        return;
      }
      // The index is the first four bytes of the sealed plaintext, big endian, which is
      // the same place the receiver reads it from.
      const view = new DataView(frame.bytes.buffer, frame.bytes.byteOffset, frame.bytes.byteLength);
      order.push({ chunk: view.getUint32(0, false) });
      chunkSends += 1;
      if (gateAt !== null && chunkSends === gateAt) {
        announceGate();
        await new Promise((resolve) => { releaseGate = resolve; });
      }
    },
  };
  // Stubbed to bypass the send queue, and that is load bearing rather than convenience:
  // the real control() enqueues, and the gated chunk send is itself holding the queue, so
  // a resume arriving mid-send would deadlock on its own acknowledgement instead of
  // reproducing the overlap. Nothing about control's own behaviour is under test here.
  link.control = async (message) => { controls.push(message); };

  return {
    link,
    sealed,
    controls,
    order,
    reachedGate,
    release: () => { releaseGate?.(); },
    get chunkSends() { return chunkSends; },
    fileEnd: () => sealed.filter((s) => s.type === TYPE.FILE_END).map((s) => s.body),
  };
}

/** Start a send and accept it the way an auto-accepting receiver does. */
function startSend(h, file, fingerprint) {
  const done = h.link.sendFile(file, 'T-accounting', fingerprint);
  done.catch(() => {});
  h.link.pendingAccept.resolve(true);
  return done;
}

const file = makeFile();
const fingerprint = await fingerprintFile(file);

// ------------------------------------------------------------------ the undisturbed send
{
  const h = harness();
  await startSend(h, file, fingerprint);
  const [end] = h.fileEnd();

  check('a send with nothing in its way declares exactly the file it sent',
    end?.bytes === SIZE, JSON.stringify({ declared: end?.bytes, size: SIZE }));
  check('and declares the chunk count the file is actually cut into',
    end?.chunks === CHUNKS, JSON.stringify({ declared: end?.chunks, want: CHUNKS }));
  // Not `end.bytes % CHUNK !== 0`: that is implied by the equality above and by SIZE being
  // a compile-time constant, so it could never fail on its own. What is worth asserting is
  // that the file really does end in a SHORT chunk and that the short chunk's own slot was
  // counted at its real length, which is checked by summing the wire.
  const lastLen = SIZE - (CHUNKS - 1) * CHUNK;
  check('CONTROL: the file really does end in a short chunk, so the total is not right '
    + 'merely by counting whole ones',
    lastLen > 0 && lastLen < CHUNK, `last chunk ${lastLen} of ${CHUNK}`);
  check('and every chunk index went out exactly once, in order',
    h.order.filter((o) => o.chunk !== undefined).map((o) => o.chunk).join(',')
      === Array.from({ length: CHUNKS }, (_, i) => i).join(','),
    JSON.stringify(h.order.slice(0, 4)));
}

// -------------------------------------------- a zero-byte file: no chunks, no shortfall
{
  const h = harness();
  const empty = new File([new Uint8Array(0)], 'nothing.bin', { type: 'application/octet-stream' });
  await startSend(h, empty, await fingerprintFile(empty));
  const [end] = h.fileEnd();

  check('an empty file is a legal transfer and declares nothing rather than failing',
    end?.bytes === 0 && end?.chunks === 0, JSON.stringify(end));
  check('CONTROL: and no chunk frame went out at all', h.chunkSends === 0, `sends=${h.chunkSends}`);
}

// ------------------------------------------------- a resume landing mid-send: THE BUG
{
  // Held at the 5th chunk, so 16 of the file's 21 chunks are still to come when the resume
  // arrives. The receiver claims the first 12 and asks for 12..21.
  const h = harness({ gateAt: 5 });
  const done = startSend(h, file, fingerprint);
  await h.reachedGate;

  const out = h.link.outbound;
  const ranges = [[12, CHUNKS]];
  const offset = 12 * CHUNK;
  const served = await h.link.serveResume(out, offset, ranges, SIZE - offset);
  check('the resume is served while the first run is still in flight',
    served === true && out.streaming === true,
    JSON.stringify({ served, streaming: out.streaming, sends: h.chunkSends }));

  h.release();
  await done;
  const [end] = h.fileEnd();

  check('a resume that lands mid-send does not make the sender declare more than the file',
    end?.bytes === SIZE,
    JSON.stringify({ declared: end?.bytes, size: SIZE, over: (end?.bytes ?? 0) - SIZE }));
  check('and the declared chunk count is still the file\'s, not this run\'s',
    end?.chunks === CHUNKS, JSON.stringify({ declared: end?.chunks, want: CHUNKS }));
  check('and exactly one FILE_END went out, so the total is not right only by averaging two',
    h.fileEnd().length === 1, `count=${h.fileEnd().length}`);
}

// --------------------------------------------- a resume asking for chunks already sent
{
  // The degenerate overlap: the receiver asks for the WHOLE file again while the whole
  // file is already going out, so the requested ranges cover chunks the running loop has
  // already passed and will never revisit. Seeding must not erase those: coverage records
  // what was read and sent, and only a read may write it.
  const h = harness({ gateAt: 3 });
  const done = startSend(h, file, fingerprint);
  await h.reachedGate;

  const out = h.link.outbound;
  const before = h.chunkSends;
  await h.link.serveResume(out, 0, [[0, CHUNKS]], SIZE);
  const overlapped = out.streaming === true;
  h.release();
  await done;
  const [end] = h.fileEnd();

  check('CONTROL: the resume asks for chunks the running send has already pushed, so the '
    + 'case is really the overlapping one',
    before >= 2 && overlapped, `sentBefore=${before} streaming=${overlapped}`);
  check('re-requesting the whole file mid-send still declares the whole file, not a shortfall',
    end?.bytes === SIZE,
    JSON.stringify({ declared: end?.bytes, size: SIZE, off: (end?.bytes ?? 0) - SIZE }));
}

// ------------------------------- a resume for chunks the running pass has already passed
{
  // The failure the parking exists for. The receiver lost frames out of the MIDDLE of the
  // window and asks for chunks 0 and 1, which the running loop went past several chunks
  // ago and will never revisit. serveResume answers `file-resume-ok`, so the receiver has
  // been told those chunks are coming. Before parking, driveOutbound took the ranges,
  // hit the streaming latch and dropped them on the floor: the promise was made and never
  // kept, and the transfer died on the receiver's quiet timer with the arithmetic looking
  // perfectly healthy.
  const h = harness({ gateAt: 6 });
  const done = startSend(h, file, fingerprint);
  await h.reachedGate;

  const out = h.link.outbound;
  await h.link.serveResume(out, 0, [[0, 2]], 2 * CHUNK);
  h.release();
  await done;

  const chunks = h.order.filter((o) => o.chunk !== undefined).map((o) => o.chunk);
  const endAt = h.order.findIndex((o) => o.end);
  check('a resume asking for chunks the running pass is already past is honoured, not dropped',
    chunks.length === CHUNKS + 2, `sends=${chunks.length} want=${CHUNKS + 2}`);
  check('and the re-sent chunks are the two that were asked for',
    chunks.slice(-2).join(',') === '0,1', chunks.slice(-4).join(','));
  check('and they go out BEFORE FILE_END, not behind the receiver\'s verdict',
    endAt === h.order.length - 1 && h.order.slice(0, endAt).every((o) => o.chunk !== undefined),
    `end at ${endAt} of ${h.order.length}`);
  const [end] = h.fileEnd();
  check('and re-sending them does not inflate the declared total',
    end?.bytes === SIZE, JSON.stringify({ declared: end?.bytes, size: SIZE }));
}

// -------------------------------------------------- a plain resume, nothing in flight
{
  // The ordinary case the coverage map must not regress: a transfer that stopped, and a
  // receiver that holds the first 12 chunks and asks for the rest.
  const h = harness();
  const out = {
    id: 'T-plain',
    name: file.name,
    size: SIZE,
    mime: 'application/octet-stream',
    chunkSize: CHUNK,
    file,
    fingerprint,
    peerFingerprint: fingerprint,
    sent: 0,
    chunks: 0,
    active: true,
    stalled: true,
    streaming: false,
    settle: null,
  };
  h.link.outbound = out;
  const finished = new Promise((resolve, reject) => { out.settle = { resolve, reject }; });
  finished.catch(() => {});
  await h.link.serveResume(out, 12 * CHUNK, [[12, CHUNKS]], SIZE - 12 * CHUNK);
  await finished;
  const [end] = h.fileEnd();

  check('a resume with nothing in flight declares the whole file, not just the part it sent',
    end?.bytes === SIZE, JSON.stringify({ declared: end?.bytes, size: SIZE }));
  check('CONTROL: and it moved only the missing chunks, not the file',
    h.chunkSends === CHUNKS - 12, `sends=${h.chunkSends} want=${CHUNKS - 12}`);
}

process.exit(summary('outbound accounting') ? 0 : 1);
