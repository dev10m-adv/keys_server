/**
 * JTI (request-ID) replay cache — two-layer: in-memory (fast) + PostgreSQL (cross-restart).
 *
 * Every signed request carries a unique jti valid for 30 seconds.
 * Storing seen JTIs prevents any captured request from being replayed within that window.
 *
 * In-memory layer: O(1) lookup, evicted every 30 s.
 * DB layer: survives server restarts; the jti_cache table is purged by backgroundJobs
 *           every 60 seconds (deletes rows older than 30 s).
 *
 * For multi-instance deployments, the DB layer is sufficient for cross-node protection
 * (both nodes write and read from the same PostgreSQL jti_cache table).
 */
import db from '../db/database.js';
import { logger } from '../utils/logger.js';

const cache = new Map(); // jti → expiresAt (ms)
const TTL_MS = 30_000;

/** Evict expired entries from the in-memory cache. */
function evict() {
  const now = Date.now();
  for (const [k, exp] of cache) {
    if (exp < now) cache.delete(k);
  }
}

setInterval(evict, TTL_MS).unref();

/**
 * Check if a JTI has already been used.
 * Checks memory first (fast path), then falls back to the DB (cross-restart path).
 */
export async function hasJti(jti) {
  evict();
  if (cache.has(jti)) return true;

  try {
    const row = await db.prepare(
      `SELECT 1 FROM jti_cache WHERE jti = ? LIMIT 1`
    ).get(jti);
    return row !== undefined;
  } catch (err) {
    // DB unavailable — fail open (log and allow) to avoid locking out all requests
    logger.error('jti DB check failed', { err: err.message });
    return false;
  }
}

/**
 * Mark a JTI as used. Writes to memory immediately and persists to DB (fire-and-forget).
 * Must be called ONLY after all validation passes to avoid poisoning the cache.
 */
export function addJti(jti) {
  cache.set(jti, Date.now() + TTL_MS);

  db.prepare(
    `INSERT INTO jti_cache (jti) VALUES (?) ON CONFLICT (jti) DO NOTHING`
  ).run(jti).catch((err) => {
    logger.error('jti DB write failed', { jti, err: err.message });
  });
}
