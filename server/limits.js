// Abuse limiting that does not retain IP addresses (DESIGN.md 1.12).
//
// Buckets are keyed by HMAC-SHA256(boot_salt, ip). The salt is generated at boot and
// never persisted, so the keys are unlinkable to an IP without it and meaningless
// after a restart. Nothing here is written to disk or logged.

import crypto from 'node:crypto';
import { config } from './config.js';

const bootSalt = crypto.randomBytes(32);

/** Opaque, unlinkable, per-boot identifier for a client address. */
export function keyFor(ip) {
  return crypto.createHmac('sha256', bootSalt).update(String(ip)).digest('base64url').slice(0, 16);
}

// name -> Map<key, {count, resetAt}>
const buckets = new Map();

/**
 * Fixed-window counter. Returns true if the call is allowed.
 * Fixed windows can permit a 2x burst at a boundary; that is acceptable here because
 * the limits exist to stop abuse, not to meter a paid resource.
 */
export function allow(name, key, limit, windowMs, now = Date.now()) {
  let bucket = buckets.get(name);
  if (!bucket) {
    bucket = new Map();
    buckets.set(name, bucket);
  }
  const entry = bucket.get(key);
  if (entry && entry.resetAt > now) {
    if (entry.count >= limit) return false;
    entry.count += 1;
    return true;
  }
  // The sweeper is not a bound: an entry is pinned for its whole window (five minutes
  // for create/join), so a caller can hold hundreds of thousands of them at once and
  // exhaust the container before any of them expire. Hence a hard cap, and eviction
  // rather than failing closed, which would let one flood lock out every later client.
  // Evicted in batches, not one per admission: a fresh Map iterator has to walk past
  // the tombstones of everything already deleted, so evicting singly costs more the
  // longer the flood runs (measured: 44 us per admission, against 3 us batched).
  if (bucket.size >= config.limits.maxBucketEntries) {
    let room = Math.max(1, config.limits.maxBucketEntries >> 4);
    for (const oldest of bucket.keys()) {
      bucket.delete(oldest);
      if ((room -= 1) === 0) break;
    }
  }
  // Delete before set so Map insertion order stays age order, which is what makes
  // "evict from the front" mean "evict the entry closest to expiry".
  if (entry) bucket.delete(key);
  bucket.set(key, { count: 1, resetAt: now + windowMs });
  return true;
}

/** Non-consuming read, so a check can precede the work it is protecting. */
export function exhausted(name, key, limit, now = Date.now()) {
  const entry = buckets.get(name)?.get(key);
  return Boolean(entry && entry.resetAt > now && entry.count >= limit);
}

// Resume state for the sweep: buckets still to walk in this pass, and a live iterator
// into the one being walked. Map iterators tolerate deletion of entries behind them.
let pending = [];
let walking = null;

/**
 * Drop expired entries, a bounded slice at a time. A single full pass over the maps
 * blocks the event loop for hundreds of milliseconds once they are large, which is a
 * self-inflicted stall on every SSE stream, so a pass is spread across several calls.
 * Empty buckets are left in place: there are a handful of fixed names, and deleting
 * them would invalidate the resume point.
 */
export function sweep(now = Date.now(), slice = config.limits.sweepSlice) {
  let dropped = 0;
  let budget = slice;
  let refilled = false;
  while (budget > 0) {
    if (!walking) {
      if (!pending.length) {
        if (refilled) break; // at most one fresh pass per call, so this cannot spin
        pending = [...buckets.values()];
        refilled = true;
        if (!pending.length) break;
      }
      walking = { bucket: pending.shift(), iter: null };
      walking.iter = walking.bucket.keys();
    }
    const next = walking.iter.next();
    if (next.done) {
      walking = null;
      continue;
    }
    budget -= 1;
    const entry = walking.bucket.get(next.value);
    if (entry && entry.resetAt <= now) {
      walking.bucket.delete(next.value);
      dropped += 1;
    }
  }
  return dropped;
}

// Counters of concurrent long-lived streams per key. Separate from the rate windows
// because these are gauges, not counters: they go down as well as up.
const streams = new Map();

export function streamOpen(key, max) {
  const n = streams.get(key) ?? 0;
  if (n >= max) return false;
  streams.set(key, n + 1);
  return true;
}

export function streamClose(key) {
  const n = streams.get(key) ?? 0;
  if (n <= 1) streams.delete(key);
  else streams.set(key, n - 1);
}
