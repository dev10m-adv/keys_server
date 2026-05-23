import db from '../db/database.js';

/** Hard-delete deleted_keys rows whose 180-day recovery window has passed. */
async function purgeExpiredDeletedKeys() {
  const { changes } = await db.prepare(
    `DELETE FROM deleted_keys WHERE recoverable_until < now()`
  ).run();
  if (changes > 0) console.log(`[jobs] purged ${changes} expired deleted_key(s)`);
}

/**
 * Finalize revocations: after 24 hours move revocation_pending → revoked
 * and remove the key from public discovery.
 */
async function finalizeRevocations() {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const pending = await db.prepare(`
    SELECT key_id, email, algorithm FROM keys
    WHERE status = 'revocation_pending' AND revoked_at <= ?
  `).all(cutoff);

  for (const key of pending) {
    await db.prepare(`
      UPDATE keys SET status = 'revoked', is_preferred = 0, discoverable = 0
      WHERE key_id = ?
    `).run(key.key_id);
    console.log(`[jobs] key ${key.key_id} (${key.email}) finalized to revoked`);
  }
}

/** Evict expired JTI rows from the DB (in-memory cache is the primary guard). */
async function purgeJtiCache() {
  await db.prepare(
    `DELETE FROM jti_cache WHERE seen_at < now() - interval '30 seconds'`
  ).run();
}

/** Remove expired OTP records so the table stays small. */
async function purgeExpiredOtps() {
  await db.prepare(`DELETE FROM otp_store WHERE expires_at < now()`).run();
}

export async function startBackgroundJobs() {
  // Run once at startup to catch anything missed while the server was down
  await purgeExpiredDeletedKeys();
  await finalizeRevocations();
  await purgeJtiCache();
  await purgeExpiredOtps();

  setInterval(() => void purgeExpiredDeletedKeys(), 24 * 60 * 60 * 1000).unref(); // daily
  setInterval(() => void finalizeRevocations(), 60 * 60 * 1000).unref();    // hourly
  setInterval(() => void purgeJtiCache(), 60 * 1000).unref();          // every minute
  setInterval(() => void purgeExpiredOtps(), 10 * 60 * 1000).unref();        // every 10 min
}
