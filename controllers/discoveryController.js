import db from '../db/database.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const MAX_BATCH_EMAILS = 50;

function normalizeEmail(email) {
  return (typeof email === 'string' ? email : '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function preferredKeyFor(email) {
  return db.prepare(`
    SELECT key_id, algorithm, public_key, label
    FROM keys
    WHERE email = ?
      AND status = 'active'
      AND is_preferred = 1
      AND discoverable = 1
    LIMIT 1
  `).get(email);
}

// ── GET /keys/preference ──────────────────────────────────────────────────────
// Public — no auth required. Used by senders before encrypting.

export const getPreference = asyncHandler(async (req, res) => {
  const emailParam = req.query.email;
  const emailsParam = req.query.emails;

  // Single-email path
  if (emailParam && !emailsParam) {
    const email = normalizeEmail(emailParam);
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'invalid_email', message: 'Invalid email query parameter' });
    }

    const key = await preferredKeyFor(email);
    if (!key) {
      return res.status(404).json({ error: 'no_preferred_key', message: `No discoverable active key for ${email}` });
    }

    return res.json({
      keyId: key.key_id,
      algorithm: key.algorithm,
      publicKey: key.public_key,
      label: key.label ?? null,
    });
  }

  // Batch path — ?emails=a@x.com,b@x.com
  const rawEmails = emailsParam || emailParam;
  if (!rawEmails) {
    return res.status(400).json({ error: 'invalid_request', message: 'email or emails query parameter required' });
  }

  const emails = rawEmails
    .split(',')
    .map(normalizeEmail)
    .filter((e) => e.length > 0);

  if (emails.length === 0) {
    return res.status(400).json({ error: 'invalid_request', message: 'At least one email is required' });
  }
  if (emails.length > MAX_BATCH_EMAILS) {
    return res.status(400).json({ error: 'too_many_emails', message: `Maximum ${MAX_BATCH_EMAILS} emails per batch request` });
  }

  const invalidEmail = emails.find((e) => !isValidEmail(e));
  if (invalidEmail) {
    return res.status(400).json({ error: 'invalid_email', message: `Invalid email in batch: ${invalidEmail}` });
  }

  const results = await Promise.all(emails.map(async (email) => {
    const key = await preferredKeyFor(email);
    if (!key) return { email, found: false };
    return {
      email,
      found: true,
      keyId: key.key_id,
      algorithm: key.algorithm,
      publicKey: key.public_key,
      label: key.label ?? null,
    };
  }));

  return res.json({ results });
});

// ── GET /keys/revoked ─────────────────────────────────────────────────────────
// Public — no auth required. Lets senders check before encrypting.

export const getRevoked = asyncHandler(async (req, res) => {
  const rows = await db.prepare(`
    SELECT key_id, email, revoked_at FROM keys WHERE status = 'revoked'
  `).all();

  return res.json(rows.map((r) => ({
    keyId: r.key_id,
    email: r.email,
    revokedAt: r.revoked_at,
  })));
});
