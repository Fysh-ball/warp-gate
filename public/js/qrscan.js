// Read a gate code off another device's screen with this device's camera.
//
// The other direction has always worked: the phone shows a QR, the laptop reads it with
// its eyes and a click. This is the one that needed hardware, because a phone joining a
// gate created on a laptop has no way to get 60 characters across except by typing them.
//
// Everything here is local. The frames go from the camera to a canvas to qrdecode.js and
// are then overwritten by the next frame; nothing is uploaded, stored, or kept after the
// scanner closes. That is not a policy, it is the absence of any code that could do it:
// there is no fetch in this file.
//
// Loaded on demand from app.js. qrdecode.js is 45 KB and the camera path is a decision
// most people never make, so neither belongs on the eager graph.

import { decodeQr, lastDecodeError } from './qrdecode.js';

// How often to look at a frame. The decoder costs 80-350 ms on a real phone, so running
// it every frame would just queue work behind itself and heat the device; a person aiming
// a camera at a screen holds still for far longer than this.
const SCAN_INTERVAL_MS = 260;

// The frame handed to the decoder. Bigger is not better: the decoder downsamples anything
// over ~1 MP itself, and a 4K frame costs 344 ms before it has looked at a single module.
const MAX_FRAME_EDGE = 960;

// Give up rather than hold a camera open forever. Long enough to find the code, short
// enough that a scanner left running in a pocket turns itself off.
const SCAN_TIMEOUT_MS = 60_000;

// Why the last decode attempt inside a live scan failed, or null.
//
// The scan loop CANNOT throw: it runs per video frame, and one hostile or malformed frame
// must not take the scanner down, because the next frame is a fresh attempt and is very
// often the one that works. The reason was previously discarded outright (`void err`),
// which left the camera path with no error channel whatsoever: a decoder throwing on every
// single frame was indistinguishable from a camera pointed at a blank wall, and it is the
// only diagnostic this path can produce. Kept here instead, exactly as qrdecode.js keeps
// lastDecodeError, and for the same reason.
let lastError = null;
export const lastScanError = () => lastError;

export const SCAN_ERR = {
  UNSUPPORTED: 'unsupported',
  DENIED: 'denied',
  NO_CAMERA: 'no_camera',
  IN_USE: 'in_use',
  TIMEOUT: 'timeout',
  CANCELLED: 'cancelled',
};

/**
 * Whether this browser can scan at all, asked before the button is offered.
 *
 * mediaDevices is undefined outside a secure context, so this is also the check that
 * hides the button on a plain-HTTP self-hosted instance rather than offering one that
 * throws the moment it is pressed.
 */
export function scanSupported() {
  return typeof globalThis.navigator?.mediaDevices?.getUserMedia === 'function';
}

/**
 * Turn a getUserMedia rejection into something a person can act on.
 *
 * The names are the spec's, and they matter: "you said no" and "there is no camera" want
 * completely different sentences, and a single "could not open the camera" for both is a
 * diagnostic that names neither cause.
 */
function classify(err) {
  switch (err?.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return SCAN_ERR.DENIED;
    case 'NotFoundError':
    case 'OverconstrainedError':
      return SCAN_ERR.NO_CAMERA;
    case 'NotReadableError':
    case 'AbortError':
      return SCAN_ERR.IN_USE;
    default:
      return SCAN_ERR.NO_CAMERA;
  }
}

/**
 * Open the camera and resolve with the first QR payload it reads.
 *
 * @param {HTMLVideoElement} video where to show what the camera sees. Showing it is not
 *   decoration: a scanner with no preview is a camera the user cannot aim, and it is also
 *   the only honest signal that the camera is on.
 * @param {{ signal?: AbortSignal }} options
 * @returns {Promise<string>} the decoded text
 *
 * Rejects with an Error whose `.code` is one of SCAN_ERR. The camera is released on every
 * exit path, including the ones nobody plans for.
 */
export async function scanOnce(video, { signal } = {}) {
  // Cleared per scan, so a message left over from a previous session cannot be read as an
  // account of this one. An error field that outlives its cause is worse than an empty one.
  lastError = null;
  if (!globalThis.navigator?.mediaDevices?.getUserMedia) {
    throw Object.assign(new Error('this browser cannot open a camera'),
      { code: SCAN_ERR.UNSUPPORTED });
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      // The back camera on a phone, which is the one pointed at the other screen. `ideal`
      // rather than `exact`: a laptop has only a front camera and must still work.
      video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
  } catch (err) {
    throw Object.assign(new Error(err.message || 'camera unavailable'), { code: classify(err) });
  }

  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  let timer = null;
  let deadline = null;

  // ONE stop path, called from success, failure, timeout and abort alike. A camera left
  // running because one branch forgot to close it is the worst bug this file could have:
  // the indicator light stays on and the user is right to conclude they are being
  // recorded. Written to be safe to call twice.
  const stop = () => {
    if (timer) { clearInterval(timer); timer = null; }
    if (deadline) { clearTimeout(deadline); deadline = null; }
    for (const track of stream.getTracks()) track.stop();
    if (video.srcObject === stream) video.srcObject = null;
  };

  try {
    video.srcObject = stream;
    video.setAttribute('playsinline', '');   // iOS otherwise takes the video fullscreen
    video.muted = true;
    await video.play();

    return await new Promise((resolve, reject) => {
      const fail = (code, message) => { stop(); reject(Object.assign(new Error(message), { code })); };

      if (signal) {
        if (signal.aborted) return fail(SCAN_ERR.CANCELLED, 'scan cancelled');
        signal.addEventListener('abort', () => fail(SCAN_ERR.CANCELLED, 'scan cancelled'), { once: true });
      }
      deadline = setTimeout(() => fail(SCAN_ERR.TIMEOUT, 'no code found'), SCAN_TIMEOUT_MS);

      timer = setInterval(() => {
        // videoWidth is 0 until the first frame decodes. Reading it before then gives a
        // 0x0 canvas and a decoder that is handed nothing and reports "no code", which
        // would look exactly like a camera pointed at a wall.
        const w = video.videoWidth;
        const h = video.videoHeight;
        if (!w || !h) return;

        const scale = Math.min(1, MAX_FRAME_EDGE / Math.max(w, h));
        canvas.width = Math.round(w * scale);
        canvas.height = Math.round(h * scale);
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

        let found = null;
        try {
          found = decodeQr(ctx.getImageData(0, 0, canvas.width, canvas.height));
        } catch (err) {
          // A decoder that throws must not take the scanner down: the next frame is a
          // fresh attempt and is very often the one that works. The message is KEPT rather
          // than discarded, which is what the comment here used to claim while `void err`
          // did the opposite: see lastScanError at the top of this file.
          lastError = err instanceof Error ? err.message : String(err);
          return;
        }
        if (!found?.text) return;   // lastDecodeError() says why, for the caller's log

        stop();
        resolve(found.text);
      }, SCAN_INTERVAL_MS);
    });
  } catch (err) {
    stop();
    throw err;
  }
}

export { lastDecodeError };
