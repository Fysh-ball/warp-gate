#!/usr/bin/env node
// Read the suggestion box.
//
//   node deploy/read-suggestions.mjs [path]
//
// Path defaults to $WG_SUGGESTIONS_PATH. There is no web view of this on purpose: a page
// that lists what strangers wrote is a page that has to moderate what strangers wrote,
// and the operator reading a file over SSH needs neither an auth system nor a moderation
// queue.
//
// Text is printed with control characters already stripped at write time, so this cannot
// repaint your terminal. It re-checks anyway, because a file edited by hand is a file
// nobody sanitised.

import { read, clean, SuggestionsTooLarge } from '../server/suggestions.js';

const file = process.argv[2] || process.env.WG_SUGGESTIONS_PATH || '';
if (!file) {
  console.error('no path: pass one, or set WG_SUGGESTIONS_PATH');
  process.exit(2);
}

let entries;
let malformed;
try {
  ({ entries, malformed } = read(file));
} catch (err) {
  // read() refuses a file far past the writer's own cap rather than pulling it into one
  // string. Reported with its own message and its own exit code, never swallowed.
  if (err instanceof SuggestionsTooLarge) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(`cannot read ${file}: ${err.message}`);
  process.exit(2);
}

// Deliberately not truncated and not paged. This is an enumeration question ("what has
// come in"), and piping it through head would make a long list read as a short one.
for (const row of entries) {
  // The WRITER's clean(), imported rather than reimplemented. This was a local copy of a
  // regex that stripped C0 and C1 only, so RLO, ZWSP, LRI and BOM all survived a reader
  // whose entire stated purpose is re-checking a file somebody may have edited by hand.
  // Two sanitisers with the same job drift apart; one cannot.
  //
  // `at` gets it too. It was printed through no filter at all, so a hand-edited line could
  // put a raw ANSI CSI in the timestamp and repaint the terminal of the one person this
  // whole script exists to protect.
  console.log(`--- ${clean(row.at)}`);
  console.log(clean(row.text));
  console.log('');
}

console.log(`${entries.length} suggestion(s) in ${file}`);
if (malformed) {
  // Reported, never silently skipped: an unreadable line means either a crash mid-append
  // or something writing to this file that is not this server.
  console.log(`WARNING: ${malformed} unreadable line(s). The file has been edited or a write was cut short.`);
  process.exit(1);
}
