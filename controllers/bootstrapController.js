import db from '../db/database.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { issueFetchToken } from '../utils/fetchToken.js';
import { generateAndStoreOtp, verifyOtp } from '../services/otpService.js';
import { sendOtpEmail } from '../services/mailerService.js';
import {
  srpGenerateEphemeral,
  srpStorePending,
  srpConsumePending,
  srpDeriveSession,
} from '../services/srpService.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function normalizeEmail(email) {
  return (typeof email === 'string' ? email : '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Ensure a user record exists; sets email_verified=1 if first time. */
async function ensureUser(email) {
  await db.prepare(`
    INSERT INTO users (email, email_verified)
    VALUES (?, 1)
    ON CONFLICT(email) DO UPDATE SET email_verified = 1
  `).run(email);
}

// ── GET /auth/check ───────────────────────────────────────────────────────────

export const check = asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.query.email);
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'invalid_email', message: 'Valid email query parameter required' });
  }

  const user = await db.prepare(`SELECT email FROM users WHERE email = ?`).get(email);
  if (!user) return res.json({ known: false });

  const algorithmRows = await db.prepare(`
    SELECT DISTINCT algorithm FROM keys WHERE email = ? AND status = 'active'
  `).all(email);
  const algorithms = algorithmRows.map((r) => r.algorithm);

  return res.json({ known: true, hasKeys: algorithms.length > 0, algorithms });
});

// ── POST /auth/bootstrap ──────────────────────────────────────────────────────

export const sendOtp = asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'invalid_email', message: 'Valid email is required' });
  }

  const otp = await generateAndStoreOtp(email);

  // Fire-and-forget — SMTP errors do not fail the request
  sendOtpEmail(email, otp).catch((err) =>
    console.error(`[bootstrap] Failed to send OTP email to ${email}:`, err.message)
  );

  return res.json({ message: 'OTP sent', expiresIn: 600 });
});

// ── POST /auth/bootstrap/verify ───────────────────────────────────────────────

export const verifyOtpAndIssueToken = asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const otp = req.body?.otp;

  if (!isValidEmail(email) || !otp) {
    return res.status(400).json({ error: 'invalid_request', message: 'email and otp are required' });
  }

  try {
    await verifyOtp(email, String(otp));
  } catch (err) {
    const statusMap = {
      otp_not_found: 404,
      otp_expired: 401,
      otp_attempts_exceeded: 401,
      otp_invalid: 401,
    };
    return res.status(statusMap[err.code] || 400).json({ error: err.code, message: err.message });
  }

  // Mark email as verified and create user record if it doesn't exist yet
  await ensureUser(email);

  const fetchToken = issueFetchToken(email);
  return res.json({ fetchToken, expiresIn: 300 });
});

// ── POST /auth/srp/init ───────────────────────────────────────────────────────

export const srpInit = asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const clientPublicEphemeral = req.body?.clientPublicEphemeral;

  if (!isValidEmail(email) || !clientPublicEphemeral) {
    return res.status(400).json({ error: 'invalid_request', message: 'email and clientPublicEphemeral are required' });
  }

  const user = await db.prepare(`SELECT srp_verifier, srp_salt FROM users WHERE email = ?`).get(email);
  if (!user || !user.srp_verifier) {
    return res.status(404).json({ error: 'srp_not_configured', message: 'SRP is not configured for this account' });
  }

  const serverEphemeral = srpGenerateEphemeral(user.srp_verifier);
  srpStorePending(email, serverEphemeral.secret, clientPublicEphemeral);

  return res.json({
    salt: user.srp_salt,
    serverPublicEphemeral: serverEphemeral.public,
  });
});

// ── POST /auth/srp/complete ───────────────────────────────────────────────────

export const srpComplete = asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const clientProof = req.body?.clientProof;

  if (!isValidEmail(email) || !clientProof) {
    return res.status(400).json({ error: 'invalid_request', message: 'email and clientProof are required' });
  }

  const session = srpConsumePending(email);
  if (!session) {
    return res.status(400).json({ error: 'srp_session_expired', message: 'SRP session not found or expired — restart from /auth/srp/init' });
  }

  const user = await db.prepare(`SELECT srp_verifier, srp_salt FROM users WHERE email = ?`).get(email);
  if (!user || !user.srp_verifier) {
    return res.status(404).json({ error: 'srp_not_configured', message: 'SRP is not configured for this account' });
  }

  let serverSession;
  try {
    serverSession = srpDeriveSession(
      session.serverEphemeralSecret,
      session.clientPublicEphemeral,
      user.srp_salt,
      email,
      user.srp_verifier,
      clientProof
    );
  } catch {
    return res.status(401).json({ error: 'proof_failed', message: 'SRP proof verification failed' });
  }

  const fetchToken = issueFetchToken(email);
  return res.json({ fetchToken, expiresIn: 300, serverProof: serverSession.proof });
});

// ── POST /auth/srp/setup ──────────────────────────────────────────────────────
// Auth: verifyAnyAuth (fetch token OR signed request)

export const srpSetup = asyncHandler(async (req, res) => {
  const email = req.identity.email; // set by middleware
  const srpVerifier = req.body?.srpVerifier;
  const srpSalt = req.body?.srpSalt;

  if (!srpVerifier || !srpSalt) {
    return res.status(400).json({ error: 'invalid_request', message: 'srpVerifier and srpSalt are required' });
  }

  await db.prepare(`
    UPDATE users SET srp_verifier = ?, srp_salt = ? WHERE email = ?
  `).run(srpVerifier, srpSalt, email);

  return res.json({ message: 'SRP credentials updated' });
});

// ── POST /auth/bootstrap/cancel-revocation ────────────────────────────────────
// Auth: verifySignedRequest

export const cancelRevocation = asyncHandler(async (req, res) => {
  const email = req.identity.email;
  const keyId = req.body?.keyId;

  if (!keyId) {
    return res.status(400).json({ error: 'invalid_request', message: 'keyId is required' });
  }

  const key = await db.prepare(`
    SELECT key_id, email, status FROM keys WHERE key_id = ?
  `).get(keyId);

  if (!key) {
    return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  }
  if (key.email !== email) {
    return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });
  }
  if (key.status !== 'revocation_pending') {
    return res.status(409).json({ error: 'not_pending_revocation', message: 'Key is not in revocation_pending state' });
  }

  await db.prepare(`
    UPDATE keys SET status = 'active', revoked_at = NULL WHERE key_id = ?
  `).run(keyId);

  return res.json({ keyId, status: 'active' });
});
