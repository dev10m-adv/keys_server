import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const forge = require('node-forge');

/**
 * Verify a detached RSA-SHA256 (PKCS#1 v1.5) signature over payloadString.
 *
 * signatureBase64  — base64url-encoded raw signature bytes
 * pemInput         — PEM certificate (-----BEGIN CERTIFICATE-----) or
 *                    PEM public key (-----BEGIN PUBLIC KEY-----)
 *
 * Throws with { code: 'invalid_signature' } when verification fails.
 */
export function smimeVerify(payloadString, signatureBase64, pemInput) {
  try {
    let publicKey;
    if (pemInput.includes('-----BEGIN CERTIFICATE-----')) {
      const cert = forge.pki.certificateFromPem(pemInput);
      publicKey = cert.publicKey;
    } else {
      publicKey = forge.pki.publicKeyFromPem(pemInput);
    }

    const md = forge.md.sha256.create();
    md.update(payloadString, 'utf8');

    // Node.js Buffer handles base64url natively; forge needs a binary string
    const sigBytes = Buffer.from(signatureBase64, 'base64url').toString('binary');

    const valid = publicKey.verify(md.digest().bytes(), sigBytes);
    if (!valid) {
      throw Object.assign(
        new Error('S/MIME signature verification failed'),
        { code: 'invalid_signature' }
      );
    }
    return true;
  } catch (err) {
    if (err.code === 'invalid_signature') throw err;
    throw Object.assign(
      new Error(`S/MIME verification failed: ${err.message}`),
      { code: 'invalid_signature' }
    );
  }
}
