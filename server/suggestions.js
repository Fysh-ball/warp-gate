// The suggestion box.
//
// This is the one place in Warp Gate that keeps something on disk, so it is written to
// keep as little as it possibly can and to be readable by a person with `cat`.
//
// What is stored: the text, and the hour it arrived in. That is the whole record.
//
// What is deliberately NOT stored, and must never be added:
//
//   - the IP, or the rate-limit key derived from it. The limiter needs the key for the
//     length of the request and then forgets it; writing it down would turn a feature
//     request into a record of who was using the site and when.
//   - the user agent, the referrer, or any header.
//   - the minute or second. Rounded to the hour on purpose: a full timestamp correlates
//     a suggestion with the gate its author had open, and this process can see both.
//   - a room id, a token, or anything from the signalling side. There is no code path
//     between the two and there should not be one.
//
// The format is JSON Lines: one object per line, append-only, never rewritten. A partial
// write from a crash costs the last line and nothing else, which is why this is not a
// single JSON array.

import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

export const ERR = {
  OFF: 'suggestions_disabled',
  EMPTY: 'empty',
  TOO_LONG: 'too_long',
  FULL: 'store_full',
  UNWRITABLE: 'store_unwritable',
};

/** Whether an operator has turned the box on at all. */
export function enabled() {
  return Boolean(config.suggestions.path);
}

/**
 * Can this process actually write where the operator pointed it?
 *
 * Called once at startup, because the alternative is what happened on 2026-08-10: the box
 * was enabled, the landing rendered it, the endpoint answered every submission with 400
 * `store_unwritable`, and the only trace was one line per attempt in a container log
 * nobody was reading. From the outside a store that refuses every write is
 * indistinguishable from one nobody has written to. An operator would have checked an
 * empty file for weeks and concluded, reasonably, that nobody had anything to say.
 *
 * The cause there is worth stating because it is not obvious and it will recur: the
 * container drops ALL capabilities, so uid 0 inside it has no CAP_DAC_OVERRIDE and is
 * subject to ordinary permission checks like anybody else. Root that cannot override
 * permissions is just a uid, and it did not own the bind.
 *
 * Returns null when the store is usable, or a human-readable reason when it is not.
 * Deliberately does NOT create the file: a typo that silently created a second store
 * elsewhere is the failure this is meant to surface, not cause.
 */
export function storeProblem() {
  if (!enabled()) return null;
  const file = path.resolve(config.suggestions.path);
  const dir = path.dirname(file);
  try {
    // The directory must exist and be writable: appending to a file creates it, so the
    // directory is the permission that actually matters, and it is the one that was wrong.
    fs.accessSync(dir, fs.constants.W_OK | fs.constants.X_OK);
  } catch (err) {
    return `cannot write into ${dir} (${err.code || err.message})`;
  }
  try {
    // If the file already exists it must be writable too. An existing root-owned file in
    // a writable directory is a real configuration, and appending to it would fail.
    fs.accessSync(file, fs.constants.W_OK);
  } catch (err) {
    if (err.code !== 'ENOENT') return `cannot write ${file} (${err.code || err.message})`;
  }
  return null;
}

/**
 * Strip a submission down to text a person can read.
 *
 * Control characters are removed rather than escaped, because the file is meant to be
 * read with `cat` and a raw escape sequence in it is a terminal-injection primitive: an
 * ANSI CSI in a suggestion could repaint or clear the screen of whoever reads the box.
 * Newline survives, because a suggestion with a list in it is a normal suggestion.
 *
 * Returns the cleaned string, which may be empty.
 */
export function clean(input) {
  if (typeof input !== 'string') return '';
  return input
    // C0 except \n and \t, DEL, and the C1 block. \r is folded into \n first so a
    // Windows submission does not lose its line breaks entirely.
    .replace(/\r\n?/g, '\n')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, '')
    // Zero-width and bidi-override characters: invisible in a terminal, and the bidi ones
    // can make stored text render in an order other than the one it is stored in.
    .replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '')
    // Three or more blank lines is padding, not structure.
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * The hour a suggestion arrived, as an ISO string with minutes and seconds zeroed.
 *
 * Exported so the test can assert the rounding rather than infer it, and so the reader
 * and the writer cannot disagree about the format.
 */
export function hourStamp(now = Date.now()) {
  const d = new Date(now);
  d.setUTCMinutes(0, 0, 0);
  return d.toISOString();
}

// A full store is invisible to the person who submitted (they get the same 204 an
// accepted suggestion gets, so the fill level is not externally readable), so it has to
// be visible to the operator instead. Rate limited hard: a script hitting a full store
// thousands of times a minute must not be able to turn this into the request log this
// server deliberately does not keep. The path is named because it is the operator's own
// stderr and the whole message is useless without it.
const FULL_LOG_INTERVAL_MS = 60 * 60 * 1000;
let lastFullLogAt = 0;

function noteFull(file, size, now) {
  if (now - lastFullLogAt < FULL_LOG_INTERVAL_MS) return;
  lastFullLogAt = now;
  console.error(`[suggest] store full at ${size} of ${config.suggestions.maxBytes} bytes: ${file}`);
  console.error('[suggest] submissions are being accepted at the wire and DISCARDED. Rotate or move it.');
  console.error(`[suggest] reported at most once per ${FULL_LOG_INTERVAL_MS / 60000} minutes.`);
}

/**
 * Append one suggestion.
 *
 * Resolves to `{ ok: true }`, or `{ ok: false, error }` with one of ERR. Never rejects: a
 * suggestion box that can 500 is a suggestion box that tells an attacker which inputs
 * reach the filesystem.
 *
 * Asynchronous, and it has to be: statSync and appendFileSync block the event loop, and
 * this process is holding every live SSE stream on that loop. The stat ran even when the
 * store was full, so a full store cost a blocking syscall per request forever.
 */
// Writes are serialised through this one chain. Going asynchronous bought the event loop
// back, but it also split what used to be one indivisible statSync/appendFileSync pair
// into two awaits with a gap in the middle: two submissions in flight together would both
// stat under the cap and both append past it, and the size cap would be exceeded by as
// much as the concurrency allows. The chain restores exactly the property the synchronous
// version had for free. It never rejects, so one failed write cannot wedge the queue.
let writeChain = Promise.resolve();

function serialise(work) {
  const next = writeChain.then(work, work);
  writeChain = next.then(() => {}, () => {});
  return next;
}

export async function append(text, now = Date.now()) {
  if (!enabled()) return { ok: false, error: ERR.OFF };

  const body = clean(text);
  if (!body) return { ok: false, error: ERR.EMPTY };
  // Measured in code points, not UTF-16 units, so an emoji counts as one character to the
  // person who typed it and to this check alike.
  if ([...body].length > config.suggestions.maxChars) {
    return { ok: false, error: ERR.TOO_LONG };
  }
  // ...and in bytes as well, because the FILE cap is in bytes and the two have to agree.
  // 600 code points of ASCII is 644 bytes on the line; 600 emoji was 2,444, so the store
  // filled after 429 submissions rather than the ~1,700 the file cap was reasoned about
  // with. Same error code as the character cap on purpose: "too long" is the whole of
  // what the submitter needs to know, and which of the two caps they hit is not.
  if (Buffer.byteLength(body) > config.suggestions.maxTextBytes) {
    return { ok: false, error: ERR.TOO_LONG };
  }

  const line = `${JSON.stringify({ at: hourStamp(now), text: body })}\n`;
  const file = path.resolve(config.suggestions.path);

  return serialise(async () => {
    try {
      // Checked before the write rather than after, so the cap is a cap and not a
      // high-water mark that every submission exceeds by its own length.
      let size = 0;
      try {
        size = (await fs.promises.stat(file)).size;
      } catch (err) {
        // ENOENT is the empty store, which is fine. Anything else is a real problem and
        // must not be read as "the file is empty, write away".
        if (err.code !== 'ENOENT') return { ok: false, error: ERR.UNWRITABLE, detail: err.message };
      }
      if (size + Buffer.byteLength(line) > config.suggestions.maxBytes) {
        noteFull(file, size, now);
        return { ok: false, error: ERR.FULL };
      }

      // 0o600: this file holds what strangers chose to say to the operator, and nothing
      // else on the host has any business reading it. The mode only applies on creation, so
      // an existing file keeps whatever the operator set.
      await fs.promises.appendFile(file, line, { mode: 0o600 });
      return { ok: true };
    } catch (err) {
      // The message goes to the caller's log, never to the client: "EACCES /srv/wg/data"
      // hands a stranger the deployment layout.
      return { ok: false, error: ERR.UNWRITABLE, detail: err.message };
    }
  });
}

/**
 * How much larger than the writer's own cap a file may be before this refuses to read it.
 *
 * The path comes from process.argv, so this is not reachable from HTTP, and the operator
 * is allowed to point it at whatever they like. What is not acceptable is reading an
 * arbitrarily large file into one string with no ceiling at all: a mistyped path at a
 * multi-gigabyte file is an OOM rather than an error message. The writer refuses past
 * maxBytes, so anything past several times that was not written by this server.
 */
const READ_SIZE_FACTOR = 4;

export class SuggestionsTooLarge extends Error {}

/**
 * Read the store back.
 *
 * A malformed line is reported, not skipped. Silently dropping it would mean a truncated
 * file reads as a shorter one, and the whole point of an append-only store is that you
 * can tell the difference.
 *
 * Synchronous on purpose, and the one place in this file that is allowed to be: this runs
 * in the operator's CLI, in a process that holds no streams and answers no requests.
 */
export function read(file = config.suggestions.path) {
  if (!file) return { entries: [], malformed: 0 };
  const resolved = path.resolve(file);
  const cap = config.suggestions.maxBytes * READ_SIZE_FACTOR;
  let raw;
  try {
    // stat first. Refusing AFTER the read would be a refusal that has already paid the
    // cost it exists to avoid.
    const { size } = fs.statSync(resolved);
    if (size > cap) {
      throw new SuggestionsTooLarge(
        `${resolved} is ${size} bytes, past the ${cap} byte read cap `
        + `(${READ_SIZE_FACTOR}x WG_SUGGESTIONS_MAX_BYTES). Refusing to read it into memory.`,
      );
    }
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return { entries: [], malformed: 0 };
    throw err;
  }
  const entries = [];
  let malformed = 0;
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      if (typeof row?.text === 'string' && typeof row?.at === 'string') entries.push(row);
      else malformed += 1;
    } catch (err) {
      void err;
      malformed += 1;
    }
  }
  return { entries, malformed };
}
