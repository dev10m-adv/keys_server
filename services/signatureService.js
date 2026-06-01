import db from '../db/database.js';
import { pgpVerify } from './pgpService.js';
import { smimeVerify } from './smimeService.js';

/**
 * Try the user's active keys for sigAlgorithm, preferring the preferred key
 * first. Returns the verified key's key_id on success.
 *
 * Throws a coded error when no key is found or verification fails.
 */
export async function verifySignature(payloadString, signatureBase64, email, sigAlgorithm) {
  const keyRecords = await db.prepare(`
    SELECT key_id, public_key FROM keys
    WHERE email = ? AND algorithm = ? AND status = 'active'
    ORDER BY is_preferred DESC, created_at DESC
  `).all(email, sigAlgorithm);

  if (!keyRecords || keyRecords.length === 0) {
    throw Object.assign(
      new Error(`No active ${sigAlgorithm} key found for ${email}`),
      { code: 'no_key_for_algorithm' }
    );
  }

  let lastError;
  for (const keyRecord of keyRecords) {
    try {
      if (sigAlgorithm === 'openpgp') {
        await pgpVerify(payloadString, signatureBase64, keyRecord.public_key);
      } else if (sigAlgorithm === 'smime') {
        smimeVerify(payloadString, signatureBase64, keyRecord.public_key);
      } else {
        throw Object.assign(new Error('Unsupported signing algorithm'), { code: 'unsupported_algorithm' });
      }

      return keyRecord.key_id;
    } catch (err) {
      if (err?.code === 'unsupported_algorithm') {
        throw err;
      }
      lastError = err;
    }
  }

  throw Object.assign(
    new Error(lastError?.message || `No active ${sigAlgorithm} key could verify the signature for ${email}`),
    { code: lastError?.code || 'invalid_signature' }
  );
}
