import db from '../db/database.js';
import { pgpVerify } from './pgpService.js';
import { smimeVerify } from './smimeService.js';

/**
 * Fetch the user's active preferred key for sigAlgorithm, then verify the
 * signature. Returns the verified key's key_id on success.
 *
 * Throws a coded error when no key is found or verification fails.
 */
export async function verifySignature(payloadString, signatureBase64, email, sigAlgorithm) {
  const keyRecord = await db.prepare(`
    SELECT key_id, public_key FROM keys
    WHERE email = ? AND algorithm = ? AND status = 'active' AND is_preferred = 1
    LIMIT 1
  `).get(email, sigAlgorithm);

  if (!keyRecord) {
    throw Object.assign(
      new Error(`No active preferred ${sigAlgorithm} key found for ${email}`),
      { code: 'no_key_for_algorithm' }
    );
  }

  if (sigAlgorithm === 'openpgp') {
    await pgpVerify(payloadString, signatureBase64, keyRecord.public_key);
  } else if (sigAlgorithm === 'smime') {
    smimeVerify(payloadString, signatureBase64, keyRecord.public_key);
  } else {
    throw Object.assign(new Error('Unsupported signing algorithm'), { code: 'unsupported_algorithm' });
  }

  return keyRecord.key_id;
}
