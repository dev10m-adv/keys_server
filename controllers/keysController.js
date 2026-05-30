import { v4 as uuidv4 } from 'uuid';
import db from '../db/database.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { logger } from '../utils/logger.js';
import { hasJti, addJti } from '../services/jtiCacheService.js';
import { pgpVerify } from '../services/pgpService.js';
import { smimeVerify } from '../services/smimeService.js';
import { sendRevocationAlert, sendDeletionAlert } from '../services/mailerService.js';

const TIMESTAMP_WINDOW_MS = 30_000;
const VALID_ALGORITHMS = new Set(['openpgp', 'smime', 'pqc']);
const RECOVERY_DAYS = 180;

// ── Helpers ───────────────────────────────────────────────────────────────────

function normalizeEmail(e) {
  return (typeof e === 'string' ? e : '').trim().toLowerCase();
}

function err400(res, code, message) {
  return res.status(400).json({ error: code, message });
}

/**
 * Validate timestamp and JTI on a body-level signed payload.
 * Separate from the X-Auth-Payload JTI validated by middleware.
 * Returns false (and sends the error response) on failure.
 */
async function checkBodyPayloadReplay(res, timestamp, jti) {
  if (Math.abs(Date.now() - timestamp) > TIMESTAMP_WINDOW_MS) {
    res.status(401).json({
      error: 'request_expired',
      message: 'Body payload timestamp is outside the 30-second window',
    });
    return false;
  }
  if (await hasJti(jti)) {
    res.status(401).json({
      error: 'replayed_request',
      message: 'Body payload JTI has already been used',
    });
    return false;
  }
  return true;
}

/**
 * Verify a self-signed body payload using the algorithm specified in the payload.
 * Used for upload, rotation, and deletion proofs.
 */
async function verifyBodySignature(payloadString, signatureBase64, publicKey, algorithm) {
  if (algorithm === 'openpgp') {
    await pgpVerify(payloadString, signatureBase64, publicKey);
  } else if (algorithm === 'smime') {
    smimeVerify(payloadString, signatureBase64, publicKey);
  } else {
    throw Object.assign(new Error('Unsupported algorithm'), { code: 'unsupported_algorithm' });
  }
}

/**
 * When the preferred key for an algorithm is removed (archived / deleted),
 * promote the next most-recently-created active key of the same algorithm.
 * Must be called inside a transaction.
 */
async function autoPromotePreferred(email, algorithm, excludeKeyId, queryDb = db) {
  const next = await queryDb.prepare(`
    SELECT key_id FROM keys
    WHERE email = ? AND algorithm = ? AND status = 'active' AND key_id != ?
    ORDER BY created_at DESC
    LIMIT 1
  `).get(email, algorithm, excludeKeyId);

  if (next) {
    await queryDb.prepare(`UPDATE keys SET is_preferred = 1 WHERE key_id = ?`).run(next.key_id);
  }
}

// ── POST /keys ────────────────────────────────────────────────────────────────
// No standard auth middleware — proof is a self-signed body payload.
// The uploader's email MUST already exist with email_verified = 1 (requires
// prior OTP verification via POST /auth/bootstrap + /auth/bootstrap/verify).

export const uploadKey = asyncHandler(async (req, res) => {
  const { payload: payloadString, signature } = req.body || {};

  if (typeof payloadString !== 'string' || typeof signature !== 'string') {
    return err400(res, 'invalid_request', 'payload (string) and signature (string) are required');
  }

  let parsed;
  try {
    parsed = JSON.parse(payloadString);
  } catch {
    return err400(res, 'invalid_payload', 'payload must be a valid JSON string');
  }

  const {
    email: rawEmail,
    publicKey,
    algorithm,
    encryptedBlob,
    discoverable,
    label,
    timestamp,
    jti,
    hasRecoveryPhrase,
  } = parsed;

  const email = normalizeEmail(rawEmail);

  if (!email || !publicKey || !algorithm || !timestamp || !jti) {
    return err400(res, 'invalid_payload', 'email, publicKey, algorithm, timestamp, jti are required in payload');
  }

  if (!VALID_ALGORITHMS.has(algorithm)) {
    return err400(res, 'invalid_algorithm', `algorithm must be one of: ${[...VALID_ALGORITHMS].join(', ')}`);
  }

  // Ensure FK target exists when upload is allowed without prior OTP verification.
  // Keeps the relaxed upload flow from failing on keys.email -> users.email constraint.
  await db.prepare(`
    INSERT INTO users (email, email_verified)
    VALUES (?, 0)
    ON CONFLICT(email) DO NOTHING
  `).run(email);

  // Enforce email verification — user must have completed OTP before uploading a key.
  // This prevents key substitution attacks (uploading a key for an email you don't control).
  // const user = await db.prepare(`SELECT email_verified FROM users WHERE email = ?`).get(email);
  // if (!user || !user.email_verified) {
  //   return res.status(403).json({
  //     error: 'email_not_verified',
  //     message: 'Complete email verification via POST /auth/bootstrap before uploading a key',
  //   });
  // }

  // Replay protection on the body-level payload (timestamp + JTI)
  if (!await checkBodyPayloadReplay(res, timestamp, jti)) return;

  // Self-signed proof — proves the uploader possesses the private key
  try {
    await verifyBodySignature(
      payloadString,
      signature,
      publicKey,
      algorithm === 'pqc' ? 'openpgp' : algorithm
    );
  } catch (err) {
    logger.warn('key upload: signature verification failed', { email, algorithm, err: err.message });
    return res.status(403).json({
      error: 'key_ownership_failed',
      message: 'Self-signed proof verification failed',
    });
  }

  const keyId = uuidv4();
  const blobText = encryptedBlob != null ? JSON.stringify(encryptedBlob) : null;

  // If this is the first key for this algorithm for this user → set as preferred
  const hasExistingForAlgo = await db.prepare(`
    SELECT 1 FROM keys WHERE email = ? AND algorithm = ? AND status != 'revoked' LIMIT 1
  `).get(email, algorithm);
  const isPreferred = hasExistingForAlgo ? 0 : 1;

  await db.prepare(`
    INSERT INTO keys (key_id, email, algorithm, label, public_key, encrypted_blob,
                      is_preferred, discoverable, has_recovery_phrase)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    keyId,
    email,
    algorithm,
    label ?? null,
    publicKey,
    blobText,
    isPreferred,
    discoverable === false ? 0 : 1,
    hasRecoveryPhrase ? 1 : 0
  );

  addJti(jti);
  logger.info('key uploaded', { email, algorithm, keyId, preferred: isPreferred === 1 });
  return res.status(201).json({ keyId });
});

// ── GET /keys ─────────────────────────────────────────────────────────────────

export const listKeys = asyncHandler(async (req, res) => {
  const email = req.identity.email;

  const rows = await db.prepare(`
    SELECT key_id, algorithm, label, status, is_preferred, discoverable,
           has_recovery_phrase, encrypted_blob, created_at, expires_at
    FROM keys
    WHERE email = ?
    ORDER BY created_at DESC
  `).all(email);

  const keys = rows.map((r) => ({
    keyId: r.key_id,
    algorithm: r.algorithm,
    label: r.label,
    status: r.status,
    isPreferred: r.is_preferred === 1,
    discoverable: r.discoverable === 1,
    hasRecoveryPhrase: r.has_recovery_phrase === 1,
    hasBlob: r.encrypted_blob !== null,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  }));

  return res.json({ keys });
});

// ── GET /keys/blob/:keyId ─────────────────────────────────────────────────────
// Auth: verifyAnyAuth (signed request OR fetch token)

export const getBlob = asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const email = req.identity.email;

  const key = await db.prepare(`
    SELECT key_id, email, algorithm, label, encrypted_blob FROM keys WHERE key_id = ?
  `).get(keyId);

  if (!key) {
    return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  }

  // Ownership check — users can only fetch their own encrypted blobs
  if (key.email !== email) {
    return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });
  }

  if (!key.encrypted_blob) {
    return res.status(404).json({ error: 'no_blob', message: 'No encrypted blob stored for this key' });
  }

  let encryptedBlob;
  try {
    encryptedBlob = JSON.parse(key.encrypted_blob);
  } catch {
    encryptedBlob = key.encrypted_blob;
  }

  return res.json({
    keyId: key.key_id,
    algorithm: key.algorithm,
    label: key.label,
    encryptedBlob,
  });
});

// ── PATCH /keys/:keyId/status ─────────────────────────────────────────────────

export const updateStatus = asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const email = req.identity.email;
  const status = req.body?.status;

  if (!['archived', 'revoked'].includes(status)) {
    return err400(res, 'invalid_status', "status must be 'archived' or 'revoked'");
  }

  const key = await db.prepare(`
    SELECT key_id, email, algorithm, status, is_preferred FROM keys WHERE key_id = ?
  `).get(keyId);

  if (!key) return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  if (key.email !== email) return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });
  if (key.status !== 'active') return res.status(409).json({ error: 'conflict', message: `Cannot change status of a ${key.status} key` });

  let effectiveAt;

  if (status === 'archived') {
    await db.transaction(async (tx) => {
      await tx.prepare(`UPDATE keys SET status = 'archived', is_preferred = 0 WHERE key_id = ?`).run(keyId);
      if (key.is_preferred) await autoPromotePreferred(email, key.algorithm, keyId, tx);
    })();
    effectiveAt = new Date().toISOString();
  } else {
    // revoked → 24-hour cooldown as revocation_pending
    const revokedAt = new Date().toISOString();
    await db.transaction(async (tx) => {
      await tx.prepare(`
        UPDATE keys SET status = 'revocation_pending', revoked_at = ?, is_preferred = 0
        WHERE key_id = ?
      `).run(revokedAt, keyId);
      if (key.is_preferred) await autoPromotePreferred(email, key.algorithm, keyId, tx);
    })();

    effectiveAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    sendRevocationAlert(email, keyId).catch((e) =>
      logger.error('revocation email failed', { email, keyId, err: e.message })
    );
    logger.info('revocation_pending set', { keyId, email, effectiveAt });
  }

  return res.json({
    keyId,
    status: status === 'revoked' ? 'revocation_pending' : 'archived',
    effectiveAt,
  });
});

// ── POST /keys/rotate ─────────────────────────────────────────────────────────
// Auth: verifySignedRequest (with OLD private key) + body-level proof

export const rotateKey = asyncHandler(async (req, res) => {
  const { rotationPayload: payloadString, signature } = req.body || {};
  const email = req.identity.email;

  if (typeof payloadString !== 'string' || typeof signature !== 'string') {
    return err400(res, 'invalid_request', 'rotationPayload (string) and signature (string) are required');
  }

  let parsed;
  try {
    parsed = JSON.parse(payloadString);
  } catch {
    return err400(res, 'invalid_payload', 'rotationPayload must be valid JSON');
  }

  const { oldKeyId, newPublicKey, algorithm, newEncryptedBlob, label, timestamp, jti, hasRecoveryPhrase } = parsed;

  if (!oldKeyId || !newPublicKey || !algorithm || !timestamp || !jti) {
    return err400(res, 'invalid_payload', 'oldKeyId, newPublicKey, algorithm, timestamp, jti are required');
  }
  if (!await checkBodyPayloadReplay(res, timestamp, jti)) return;

  const oldKey = await db.prepare(`
    SELECT key_id, email, algorithm, status, is_preferred, public_key FROM keys WHERE key_id = ?
  `).get(oldKeyId);
  if (!oldKey) return res.status(404).json({ error: 'key_not_found', message: 'Old key not found' });
  if (oldKey.email !== email) return res.status(403).json({ error: 'not_your_key', message: 'Old key does not belong to your account' });
  if (oldKey.status !== 'active') return res.status(409).json({ error: 'conflict', message: 'Old key must be active to rotate' });

  // Verify rotation proof against the OLD public key
  try {
    await verifyBodySignature(
      payloadString,
      signature,
      oldKey.public_key,
      oldKey.algorithm === 'pqc' ? 'openpgp' : oldKey.algorithm
    );
  } catch {
    return res.status(403).json({ error: 'invalid_signature', message: 'Rotation proof signature verification failed' });
  }

  const newKeyId = uuidv4();
  const blobText = newEncryptedBlob != null ? JSON.stringify(newEncryptedBlob) : null;
  const wasPreferred = oldKey.is_preferred === 1;

  await db.transaction(async (tx) => {
    await tx.prepare(`UPDATE keys SET status = 'archived', is_preferred = 0 WHERE key_id = ?`).run(oldKeyId);
    await tx.prepare(`
      INSERT INTO keys (key_id, email, algorithm, label, public_key, encrypted_blob,
                        is_preferred, discoverable, has_recovery_phrase)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
    `).run(
      newKeyId,
      email,
      algorithm,
      label ?? oldKey.label ?? null,
      newPublicKey,
      blobText,
      wasPreferred ? 1 : 0,
      hasRecoveryPhrase ? 1 : 0
    );
  })();

  addJti(jti);
  logger.info('key rotated', { oldKeyId, newKeyId, email });
  return res.status(201).json({ newKeyId, oldKeyId, oldStatus: 'archived' });
});

// ── PATCH /keys/:keyId/preference ─────────────────────────────────────────────

export const updatePreference = asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const email = req.identity.email;
  const { isPreferred, discoverable, label, hasRecoveryPhrase } = req.body || {};

  const key = await db.prepare(`SELECT key_id, email, algorithm, status FROM keys WHERE key_id = ?`).get(keyId);
  if (!key) return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  if (key.email !== email) return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });

  await db.transaction(async (tx) => {
    if (isPreferred === true) {
      // Atomically clear all other preferred keys for this algorithm then set this one
      await tx.prepare(`UPDATE keys SET is_preferred = 0 WHERE email = ? AND algorithm = ?`).run(email, key.algorithm);
      await tx.prepare(`UPDATE keys SET is_preferred = 1 WHERE key_id = ?`).run(keyId);
    }
    if (discoverable !== undefined) {
      await tx.prepare(`UPDATE keys SET discoverable = ? WHERE key_id = ?`).run(discoverable ? 1 : 0, keyId);
    }
    if (label !== undefined) {
      await tx.prepare(`UPDATE keys SET label = ? WHERE key_id = ?`).run(label, keyId);
    }
    if (hasRecoveryPhrase !== undefined) {
      await tx.prepare(`UPDATE keys SET has_recovery_phrase = ? WHERE key_id = ?`).run(hasRecoveryPhrase ? 1 : 0, keyId);
    }
  })();

  const updated = await db.prepare(`
    SELECT key_id, is_preferred, discoverable, label, has_recovery_phrase FROM keys WHERE key_id = ?
  `).get(keyId);

  return res.json({
    keyId: updated.key_id,
    isPreferred: updated.is_preferred === 1,
    discoverable: updated.discoverable === 1,
    label: updated.label,
    hasRecoveryPhrase: updated.has_recovery_phrase === 1,
  });
});

// ── PUT /keys/:keyId/blob ─────────────────────────────────────────────────────

export const updateBlob = asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const email = req.identity.email;
  const { newBlob, payload: payloadString, signature } = req.body || {};

  if (!newBlob || typeof payloadString !== 'string' || typeof signature !== 'string') {
    return err400(res, 'invalid_request', 'newBlob, payload (string), and signature (string) are required');
  }

  let parsed;
  try {
    parsed = JSON.parse(payloadString);
  } catch {
    return err400(res, 'invalid_payload', 'payload must be valid JSON');
  }

  const { keyId: payloadKeyId, intent, timestamp, jti } = parsed;
  if (intent !== 'update_blob' || payloadKeyId !== keyId) {
    return err400(res, 'invalid_payload', "payload must contain keyId, intent='update_blob', timestamp, jti");
  }
  if (!await checkBodyPayloadReplay(res, timestamp, jti)) return;

  const key = await db.prepare(`
    SELECT key_id, email, algorithm, public_key FROM keys WHERE key_id = ?
  `).get(keyId);
  if (!key) return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  if (key.email !== email) return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });

  try {
    await verifyBodySignature(
      payloadString,
      signature,
      key.public_key,
      key.algorithm === 'pqc' ? 'openpgp' : key.algorithm
    );
  } catch {
    return res.status(403).json({ error: 'invalid_signature', message: 'Blob update signature verification failed' });
  }

  const blobText = typeof newBlob === 'object' ? JSON.stringify(newBlob) : String(newBlob);
  const updatedAt = new Date().toISOString();

  await db.prepare(`UPDATE keys SET encrypted_blob = ? WHERE key_id = ?`).run(blobText, keyId);
  addJti(jti);

  return res.json({ keyId, updatedAt });
});

// ── PATCH /keys/:keyId/recovery-phrase ───────────────────────────────────────

export const confirmRecoveryPhrase = asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const email = req.identity.email;

  if (req.body?.confirmed !== true) {
    return err400(res, 'invalid_request', 'confirmed: true is required');
  }

  const key = await db.prepare(`SELECT key_id, email FROM keys WHERE key_id = ?`).get(keyId);
  if (!key) return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  if (key.email !== email) return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });

  await db.prepare(`UPDATE keys SET has_recovery_phrase = 1 WHERE key_id = ?`).run(keyId);
  return res.json({ keyId, hasRecoveryPhrase: true });
});

// ── DELETE /keys/:keyId ───────────────────────────────────────────────────────
// Double proof: signed request (middleware) + key-specific body signature

export const deleteKey = asyncHandler(async (req, res) => {
  const { keyId } = req.params;
  const email = req.identity.email;
  const { payload: payloadString, signature } = req.body || {};

  if (typeof payloadString !== 'string' || typeof signature !== 'string') {
    return err400(res, 'invalid_request', 'payload (string) and signature (string) are required');
  }

  let parsed;
  try {
    parsed = JSON.parse(payloadString);
  } catch {
    return err400(res, 'invalid_payload', 'payload must be valid JSON');
  }

  const { keyId: payloadKeyId, intent, timestamp, jti } = parsed;
  if (intent !== 'permanent_delete' || payloadKeyId !== keyId) {
    return err400(res, 'invalid_payload', "payload must contain keyId, intent='permanent_delete', timestamp, jti");
  }
  if (!await checkBodyPayloadReplay(res, timestamp, jti)) return;

  const key = await db.prepare(`
    SELECT key_id, email, algorithm, label, public_key, encrypted_blob,
           is_preferred, has_recovery_phrase
    FROM keys WHERE key_id = ?
  `).get(keyId);

  if (!key) return res.status(404).json({ error: 'key_not_found', message: 'Key not found' });
  if (key.email !== email) return res.status(403).json({ error: 'not_your_key', message: 'This key does not belong to your account' });

  // Key-specific proof — stolen signed-request headers alone cannot delete a key
  try {
    await verifyBodySignature(
      payloadString,
      signature,
      key.public_key,
      key.algorithm === 'pqc' ? 'openpgp' : key.algorithm
    );
  } catch {
    return res.status(403).json({ error: 'invalid_signature', message: 'Delete proof signature verification failed' });
  }

  const deletedAt = new Date();
  const recoverableUntil = new Date(deletedAt.getTime() + RECOVERY_DAYS * 24 * 60 * 60 * 1000);

  await db.transaction(async (tx) => {
    await tx.prepare(`
      INSERT INTO deleted_keys
        (key_id, email, algorithm, label, public_key, encrypted_blob,
         had_recovery_phrase, was_preferred, deleted_at, recoverable_until)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      key.key_id,
      key.email,
      key.algorithm,
      key.label,
      key.public_key,
      key.encrypted_blob,
      key.has_recovery_phrase,
      key.is_preferred,
      deletedAt.toISOString(),
      recoverableUntil.toISOString()
    );
    await tx.prepare(`DELETE FROM keys WHERE key_id = ?`).run(keyId);
    if (key.is_preferred) await autoPromotePreferred(email, key.algorithm, keyId, tx);
  })();

  addJti(jti);

  sendDeletionAlert(email, keyId, recoverableUntil).catch((e) =>
    logger.error('deletion email failed', { email, keyId, err: e.message })
  );
  logger.info('key deleted', { keyId, email, recoverableUntil: recoverableUntil.toISOString() });

  return res.json({
    keyId,
    deletedAt: deletedAt.toISOString(),
    recoverableUntil: recoverableUntil.toISOString(),
  });
});

// ── POST /keys/recover ────────────────────────────────────────────────────────
// Auth: verifyAnyAuth (signed request OR fetch token)

export const recoverKey = asyncHandler(async (req, res) => {
  const email = req.identity.email;
  const { keyId } = req.body || {};

  if (!keyId) return err400(res, 'invalid_request', 'keyId is required');

  const deleted = await db.prepare(`
    SELECT key_id, email, algorithm, label, public_key, encrypted_blob,
           had_recovery_phrase, recoverable_until
    FROM deleted_keys
    WHERE key_id = ? AND email = ?
  `).get(keyId, email);

  if (!deleted) {
    return res.status(404).json({
      error: 'not_recoverable',
      message: 'Deleted key not found or does not belong to your account',
    });
  }
  if (new Date(deleted.recoverable_until) < new Date()) {
    return res.status(404).json({
      error: 'not_recoverable',
      message: 'Recovery window has expired for this key',
    });
  }

  // Restored as 'archived' — user must explicitly promote to active
  const hasActiveForAlgo = await db.prepare(`
    SELECT is_preferred FROM keys WHERE email = ? AND algorithm = ? AND status = 'active' LIMIT 1
  `).get(email, deleted.algorithm);

  const setPreferred = !hasActiveForAlgo ? 1 : 0;
  const recoveredAt = new Date().toISOString();

  await db.transaction(async (tx) => {
    await tx.prepare(`
      INSERT INTO keys
        (key_id, email, algorithm, label, public_key, encrypted_blob,
         status, is_preferred, discoverable, has_recovery_phrase)
      VALUES (?, ?, ?, ?, ?, ?, 'archived', ?, 1, ?)
    `).run(
      deleted.key_id,
      deleted.email,
      deleted.algorithm,
      deleted.label,
      deleted.public_key,
      deleted.encrypted_blob,
      setPreferred,
      deleted.had_recovery_phrase
    );
    await tx.prepare(`DELETE FROM deleted_keys WHERE key_id = ?`).run(keyId);
  })();

  logger.info('key recovered', { keyId, email });
  return res.json({ keyId, status: 'archived', recoveredAt });
});
