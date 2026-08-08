// Abuse limiting that does not retain IP addresses (DESIGN.md 1.12).
//
// Buckets are keyed by HMAC-SHA256(boot_salt, ip). The salt is generated at boot and
// never persisted, so the keys are unlinkable to an IP without it and meaningless
// after a restart. Nothing here is written to disk or logged.

import crypto from 'node:crypto';

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
  if (!entry || entry.resetAt <= now) {
    bucket.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count += 1;
  return true;
}

/** Drop expired entries so an attacker cannot grow the maps without bound. */
export function sweep(now = Date.now()) {
  let dropped = 0;
  for (const [name, bucket] of buckets) {
    for (const [key, entry] of bucket) {
      if (entry.resetAt <= now) {
        bucket.delete(key);
        dropped += 1;
      }
    }
    if (bucket.size === 0) buckets.delete(name);
  }
  return dropped;
}

/** Total tracked entries, for the health endpoint. Never exposes keys. */
export function size() {
  let n = 0;
  for (const bucket of buckets.values()) n += bucket.size;
  return n;
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
