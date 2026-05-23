/**
 * In-memory JTI (JWT ID) replay cache.
 *
 * Each signed request carries a unique jti with a 30-second validity window
 * that matches the client-side timestamp window. Storing seen JTIs here
 * prevents any captured request from being replayed within that window.
 *
 * For a multi-instance deployment, replace this with a Redis-backed store.
 */

const cache = new Map(); // jti -> expiresAt (ms timestamp)
const TTL_MS = 30_000;

export function hasJti(jti) {
  evict();
  return cache.has(jti);
}

export function addJti(jti) {
  cache.set(jti, Date.now() + TTL_MS);
}

function evict() {
  const now = Date.now();
  for (const [k, exp] of cache) {
    if (exp < now) cache.delete(k);
  }
}

// Periodic cleanup so the Map never grows without bound
setInterval(evict, TTL_MS).unref();
