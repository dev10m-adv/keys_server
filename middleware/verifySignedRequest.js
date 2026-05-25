import { sha256Hex } from '../utils/hashBody.js';
import { hasJti, addJti } from '../services/jtiCacheService.js';
import { verifySignature } from '../services/signatureService.js';
import { logger } from '../utils/logger.js';
import db from '../db/database.js';

const TIMESTAMP_WINDOW_MS = 30_000;
const VALID_ALGORITHMS = new Set(['openpgp', 'smime']);

/**
 * Stateless signed-request authentication middleware.
 *
 * Every protected route must include two headers:
 *   X-Auth-Payload   — base64url(JSON { email, method, path, bodyHash, timestamp, jti, sigAlgorithm })
 *   X-Auth-Signature — base64url(signature of the X-Auth-Payload string)
 *
 * On success sets req.identity = { email, sigAlgorithm, keyId }.
 */
export function verifySignedRequest(req, res, next) {
  _verify(req, res, next).catch(next);
}

async function _verify(req, res, next) {
  const rawPayloadB64 = req.headers['x-auth-payload'];
  const signatureB64  = req.headers['x-auth-signature'];

  if (!rawPayloadB64 || !signatureB64) {
    return res.status(401).json({
      error: 'missing_auth_headers',
      message: 'X-Auth-Payload and X-Auth-Signature headers are required',
    });
  }

  // 1. Decode payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(rawPayloadB64, 'base64url').toString('utf8'));
  } catch {
    return res.status(401).json({ error: 'invalid_auth_payload', message: 'Cannot parse X-Auth-Payload' });
  }

  const { email, method, path: payloadPath, bodyHash, timestamp, jti, sigAlgorithm } = payload;

  if (!email || !method || !payloadPath || !bodyHash || !timestamp || !jti || !sigAlgorithm) {
    return res.status(401).json({ error: 'invalid_auth_payload', message: 'Incomplete auth payload fields' });
  }

  if (!VALID_ALGORITHMS.has(sigAlgorithm)) {
    return res.status(401).json({
      error: 'unsupported_algorithm',
      message: `Unknown sigAlgorithm: ${sigAlgorithm}`,
    });
  }

  // 2. Method + path binding — prevents replay of a valid signed request to a different route
  if (req.method !== method) {
    return res.status(401).json({ error: 'method_mismatch', message: 'Payload method does not match request' });
  }
  const requestPath = req.originalUrl.split('?')[0];
  if (payloadPath !== requestPath) {
    return res.status(401).json({ error: 'path_mismatch', message: 'Payload path does not match request' });
  }

  // 3. Timestamp window (±30 s)
  if (Math.abs(Date.now() - timestamp) > TIMESTAMP_WINDOW_MS) {
    return res.status(401).json({
      error: 'request_expired',
      message: 'Request timestamp is outside the 30-second window',
    });
  }

  // 4. JTI replay check (memory + DB)
  if (await hasJti(jti)) {
    return res.status(401).json({
      error: 'replayed_request',
      message: 'This request JTI has already been used',
    });
  }

  // 5. Body hash check — prevents tampering with the body after signing
  const rawBody = req.rawBody || Buffer.alloc(0);
  if (sha256Hex(rawBody) !== bodyHash) {
    return res.status(401).json({
      error: 'body_tampered',
      message: 'Request body SHA-256 does not match payload.bodyHash',
    });
  }

  // 6. OpenPGP preference enforcement — if the user has ANY active OpenPGP key,
  //    S/MIME-signed requests are rejected to prevent algorithm downgrade attacks
  if (sigAlgorithm === 'smime') {
    const hasOpenpgp = await db.prepare(`
      SELECT 1 FROM keys WHERE email = ? AND algorithm = 'openpgp' AND status = 'active' LIMIT 1
    `).get(email.toLowerCase());
    if (hasOpenpgp) {
      return res.status(403).json({
        error: 'openpgp_required',
        message: 'An active OpenPGP key exists — only OpenPGP-signed requests are accepted',
      });
    }
  }

  // 7. Signature verification
  let verifiedKeyId;
  try {
    verifiedKeyId = await verifySignature(rawPayloadB64, signatureB64, email.toLowerCase(), sigAlgorithm);
  } catch (err) {
    logger.warn('signature verification failed', { email, sigAlgorithm, err: err.message });
    return res.status(403).json({ error: 'invalid_signature', message: err.message });
  }

  // 8. Mark JTI as used — only AFTER all checks pass so an invalid request
  //    cannot poison the cache and block legitimate retries
  addJti(jti);

  req.identity = { email: email.toLowerCase(), sigAlgorithm, keyId: verifiedKeyId };
  next();
}
