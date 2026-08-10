// Naming a file inside a directory the user granted, without ever overwriting one.
//
// Split out of transfer.js and reached through import() from createSink's directory branch,
// which is unreachable until a batch has been accepted into a folder: a decision nobody has
// made while a gate is opening. See the head of tests/size.test.mjs for why anything of that
// shape is kept off the eager graph. transfer.js has finished evaluating by the time it
// imports this, so the import back the other way below is already satisfied.
import { sanitizeFilename } from './transfer.js';

// Bounded because the loop below asks the file system a question per attempt: a directory
// that answers "taken" forever has to end somewhere rather than spin.
const MAX_NAME_ATTEMPTS = 50;

/**
 * Derive the file to write inside a directory the user chose, WITHOUT ever overwriting.
 *
 * The one genuinely dangerous thing about a directory grant. A save dialog puts the
 * overwrite decision in front of the user every time; a directory handle does not, and
 * `getFileHandle(name, {create:true})` on an existing name opens THAT file and truncates it
 * on the first write, so a peer sending "taxes.pdf" would destroy the taxes.pdf already
 * there. Losing data the user had is worse than failing to receive data they did not, so
 * the name moves aside rather than the bytes landing on top.
 *
 * The probe is `getFileHandle` WITHOUT create, and NotFoundError is the ONLY answer read as
 * "free": every other error is a directory that could not be read, and mistaking that for an
 * empty one is how the overwrite comes back. Between probe and create is a window in which
 * something else could take the name; nothing here races it (a batch is written one file at
 * a time) and the API offers no atomic create-exclusive, so it is stated not pretended away.
 */
export async function childHandle(directory, rawName) {
  const name = sanitizeFilename(rawName);
  // The LAST dot, so " (2)" lands before the extension. A leading dot cannot reach here:
  // sanitizeFilename strips them.
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  for (let attempt = 1; attempt <= MAX_NAME_ATTEMPTS; attempt += 1) {
    const candidate = attempt === 1 ? name : `${stem} (${attempt})${ext}`;
    let taken = true;
    try {
      await directory.getFileHandle(candidate);
    } catch (err) {
      if (err.name === 'NotFoundError') taken = false;
      else {
        throw new Error(
          `could not check whether "${candidate}" is already in the folder you chose `
          + `(${err.name}: ${err.message}), and overwriting a file you have is not something `
          + 'this will do on a guess',
        );
      }
    }
    if (taken) continue;
    try {
      return await directory.getFileHandle(candidate, { create: true });
    } catch (err) {
      throw new Error(`could not create "${candidate}" in the folder you chose: ${err.name}: ${err.message}`);
    }
  }
  throw new Error(
    `"${name}" is in the folder you chose, and so are the next ${MAX_NAME_ATTEMPTS - 1} numbered `
    + 'versions of it, so there is nowhere to put this one without destroying a file you have',
  );
}
