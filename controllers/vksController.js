import db from '../db/database.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { pgpFormatArmor } from '../services/pgpService.js';

function normalizeFingerprint(fp) {
  return (typeof fp === 'string' ? fp : '').trim().toUpperCase().replace(/\s+/g, '');
}

function normalizeEmail(e) {
  return (typeof e === 'string' ? e : '').trim().toLowerCase();
}

// ── GET /vks/v1/by-fingerprint/:fingerprint ───────────────────────────────────
// Public — no auth required.
// Returns the raw armored OpenPGP public key for discoverable, active keys.
// Supports full 40-char fingerprint or short 16-char key ID (suffix match).

export const byFingerprint = asyncHandler(async (req, res) => {
  const fp = normalizeFingerprint(req.params.fingerprint);

  if (!fp || !/^[0-9A-F]{16,40}$/.test(fp)) {
    return res.status(400).json({
      error: 'invalid_fingerprint',
      message: 'Fingerprint must be a 16–40 character hex string',
    });
  }

  // Full fingerprint match first; fall back to suffix match for short key IDs
  const row = fp.length === 40
    ? await db.prepare(`
        SELECT public_key, algorithm, email
        FROM keys
        WHERE fingerprint = ? AND discoverable = 1
          AND status IN ('active', 'revocation_pending')
        LIMIT 1
      `).get(fp)
    : await db.prepare(`
        SELECT public_key, algorithm, email
        FROM keys
        WHERE fingerprint LIKE ? AND discoverable = 1
          AND status IN ('active', 'revocation_pending')
        LIMIT 1
      `).get(`%${fp}`);

  if (!row) {
    return res.status(404).json({
      error: 'key_not_found',
      message: 'No discoverable key found for that fingerprint',
    });
  }

  // Re-armor with Comment headers matching keys.openpgp.org format
  const armored = await pgpFormatArmor(row.public_key);
  res.set('Content-Type', 'application/pgp-keys');
  return res.send(armored);
});

// ── GET /vks/v1/by-email/:email ───────────────────────────────────────────────
// Public — no auth required.
// Returns all discoverable, active public keys for the given email address.
// Optional ?algorithm= query param filters by algorithm.
// OpenPGP keys are returned with Content-Type: application/pgp-keys.
// Mixed / non-PGP results are returned as JSON.

export const byEmail = asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const algorithmFilter = req.query.algorithm?.toLowerCase();

  if (!email || !/.+@.+/.test(email)) {
    return res.status(400).json({
      error: 'invalid_email',
      message: 'A valid email address is required',
    });
  }

  const validAlgorithms = new Set(['openpgp', 'smime', 'pqc']);
  if (algorithmFilter && !validAlgorithms.has(algorithmFilter)) {
    return res.status(400).json({
      error: 'invalid_algorithm',
      message: `algorithm must be one of: ${[...validAlgorithms].join(', ')}`,
    });
  }

  const rows = algorithmFilter
    ? await db.prepare(`
        SELECT key_id, algorithm, public_key, fingerprint, created_at
        FROM keys
        WHERE email = ? AND algorithm = ? AND discoverable = 1
          AND status IN ('active', 'revocation_pending')
        ORDER BY is_preferred DESC, created_at DESC
      `).all(email, algorithmFilter)
    : await db.prepare(`
        SELECT key_id, algorithm, public_key, fingerprint, created_at
        FROM keys
        WHERE email = ? AND discoverable = 1
          AND status IN ('active', 'revocation_pending')
        ORDER BY is_preferred DESC, created_at DESC
      `).all(email);

  if (!rows || rows.length === 0) {
    return res.status(404).json({
      error: 'key_not_found',
      message: 'No discoverable keys found for that email address',
    });
  }

  // If all results are OpenPGP keys, respond with re-armored key(s) concatenated.
  const allOpenPGP = rows.every((r) => r.algorithm === 'openpgp');
  if (allOpenPGP) {
    const armoredKeys = await Promise.all(rows.map((r) => pgpFormatArmor(r.public_key)));
    res.set('Content-Type', 'application/pgp-keys');
    return res.send(armoredKeys.join('\n'));
  }

  // Mixed or non-PGP — return JSON so the client can handle each algorithm
  return res.json({
    email,
    keys: rows.map((r) => ({
      keyId: r.key_id,
      algorithm: r.algorithm,
      fingerprint: r.fingerprint ?? null,
      publicKey: r.public_key,
      createdAt: r.created_at,
    })),
  });
});
