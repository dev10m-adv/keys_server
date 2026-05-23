import bcrypt from 'bcrypt';
import { randomInt } from 'crypto';
import db from '../db/database.js';

const BCRYPT_ROUNDS = 10;
const OTP_TTL_MS = 10 * 60 * 1000;    // 10 minutes
const MAX_VERIFY_ATTEMPTS = 5;

/**
 * Generate and store a 6-digit OTP for email.
 * Returns the plaintext OTP (caller sends it via SMTP).
 *
 * Rate limiting (max 3 sends per 10 min) is enforced by the express-rate-limit
 * middleware applied to the /auth/bootstrap route.
 */
export async function generateAndStoreOtp(email) {
  const otp = String(randomInt(100000, 999999)).padStart(6, '0');
  const otpHash = await bcrypt.hash(otp, BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();

  await db.prepare(`
    INSERT INTO otp_store (email, otp_hash, attempts, expires_at, created_at)
    VALUES (?, ?, 0, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(email) DO UPDATE SET
      otp_hash   = excluded.otp_hash,
      attempts   = 0,
      expires_at = excluded.expires_at,
      created_at = excluded.created_at
  `).run(email, otpHash, expiresAt);

  return otp;
}

/**
 * Verify the OTP for email. Consumes it on success (single-use).
 * Throws a coded error on failure.
 */
export async function verifyOtp(email, otp) {
  const record = await db.prepare(
    `SELECT otp_hash, attempts, expires_at FROM otp_store WHERE email = ?`
  ).get(email);

  if (!record) {
    throw Object.assign(new Error('No pending OTP for this email'), { code: 'otp_not_found' });
  }

  if (new Date(record.expires_at) <= new Date()) {
    await db.prepare(`DELETE FROM otp_store WHERE email = ?`).run(email);
    throw Object.assign(new Error('OTP has expired'), { code: 'otp_expired' });
  }

  if (record.attempts >= MAX_VERIFY_ATTEMPTS) {
    await db.prepare(`DELETE FROM otp_store WHERE email = ?`).run(email);
    throw Object.assign(new Error('Too many failed OTP attempts'), { code: 'otp_attempts_exceeded' });
  }

  const valid = await bcrypt.compare(String(otp), record.otp_hash);
  if (!valid) {
    await db.prepare(`UPDATE otp_store SET attempts = attempts + 1 WHERE email = ?`).run(email);
    throw Object.assign(new Error('Invalid OTP'), { code: 'otp_invalid' });
  }

  // Consume — single use only
  await db.prepare(`DELETE FROM otp_store WHERE email = ?`).run(email);
  return true;
}
