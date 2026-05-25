import db from '../db/database.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const MAX_BATCH_EMAILS = 50;
const DEFAULT_REVOKED_LIMIT = 500;
const MAX_REVOKED_LIMIT = 1000;

function normalizeEmail(email) {
  return (typeof email === 'string' ? email : '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── GET /keys/preference ──────────────────────────────────────────────────────
// Public — no auth required. Used by senders before encrypting.

export const getPreference = asyncHandler(async (req, res) => {
  const emailParam  = req.query.email;
  const emailsParam = req.query.emails;

  // ── Single-email path ─────────────────────────────────────────────────────
  if (emailParam && !emailsParam) {
    const email = normalizeEmail(emailParam);
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'invalid_email', message: 'Invalid email query parameter' });
    }

    const key = await db.prepare(`
      SELECT key_id, algorithm, public_key, label
      FROM keys
      WHERE email = ?
        AND status = 'active'
        AND is_preferred = 1
        AND discoverable = 1
      LIMIT 1
    `).get(email);

    if (!key) {
      return res.status(404).json({
        error: 'no_preferred_key',
        message: `No discoverable active key for ${email}`,
      });
    }

    return res.json({
      keyId: key.key_id,
      algorithm: key.algorithm,
      publicKey: key.public_key,
      label: key.label ?? null,
    });
  }

  // ── Batch path — ?emails=a@x.com,b@x.com ─────────────────────────────────
  const rawEmails = emailsParam || emailParam;
  if (!rawEmails) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'email or emails query parameter required',
    });
  }

  const emails = rawEmails
    .split(',')
    .map(normalizeEmail)
    .filter((e) => e.length > 0);

  if (emails.length === 0) {
    return res.status(400).json({ error: 'invalid_request', message: 'At least one email is required' });
  }
  if (emails.length > MAX_BATCH_EMAILS) {
    return res.status(400).json({
      error: 'too_many_emails',
      message: `Maximum ${MAX_BATCH_EMAILS} emails per batch request`,
    });
  }

  const invalidEmail = emails.find((e) => !isValidEmail(e));
  if (invalidEmail) {
    return res.status(400).json({
      error: 'invalid_email',
      message: `Invalid email in batch: ${invalidEmail}`,
    });
  }

  // Single query for all emails instead of N parallel round-trips
  const rows = await db.prepare(`
    SELECT DISTINCT ON (email) email, key_id, algorithm, public_key, label
    FROM keys
    WHERE email = ANY(?)
      AND status = 'active'
      AND is_preferred = 1
      AND discoverable = 1
    ORDER BY email, created_at DESC
  `).all(emails);

  const keyByEmail = new Map(rows.map((r) => [r.email, r]));

  const results = emails.map((email) => {
    const key = keyByEmail.get(email);
    if (!key) return { email, found: false };
    return {
      email,
      found: true,
      keyId: key.key_id,
      algorithm: key.algorithm,
      publicKey: key.public_key,
      label: key.label ?? null,
    };
  });

  return res.json({ results });
});

// ── GET /keys/revoked ─────────────────────────────────────────────────────────
// Public — lets senders verify a key is still valid before encrypting.
//
// Supports cursor-based pagination:
//   ?since=<ISO-8601 timestamp>   — only return keys revoked after this time (default: epoch)
//   ?limit=N                      — max items per page (default 500, max 1000)
//
// Returns keyId + revokedAt (email omitted — look up via GET /keys/preference).

export const getRevoked = asyncHandler(async (req, res) => {
  const since = req.query.since || '1970-01-01T00:00:00.000Z';
  const limitRaw = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0
    ? Math.min(limitRaw, MAX_REVOKED_LIMIT)
    : DEFAULT_REVOKED_LIMIT;

  if (since && isNaN(Date.parse(since))) {
    return res.status(400).json({
      error: 'invalid_since',
      message: 'since must be a valid ISO-8601 date string',
    });
  }

  const rows = await db.prepare(`
    SELECT key_id, revoked_at
    FROM keys
    WHERE status = 'revoked'
      AND revoked_at > ?
    ORDER BY revoked_at ASC
    LIMIT ?
  `).all(since, limit);

  return res.json({
    revoked: rows.map((r) => ({
      keyId: r.key_id,
      revokedAt: r.revoked_at,
    })),
    // Cursor for next page: pass the last revokedAt as ?since= on the next request
    nextCursor: rows.length === limit ? rows[rows.length - 1].revoked_at : null,
  });
});
