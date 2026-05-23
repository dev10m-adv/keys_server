import * as openpgp from 'openpgp';

/**
 * Verify an OpenPGP signature over payloadString.
 *
 * signatureBase64 may be either:
 *   - a base64-encoded armored detached signature (-----BEGIN PGP SIGNATURE-----)
 *   - a base64-encoded armored signed message     (-----BEGIN PGP MESSAGE-----)
 *
 * armoredPublicKey is the full ASCII-armored OpenPGP public key.
 *
 * Throws with { code: 'invalid_signature' } when verification fails.
 */
export async function pgpVerify(payloadString, signatureBase64, armoredPublicKey) {
  try {
    const publicKey = await openpgp.readKey({ armoredKey: armoredPublicKey });
    const decoded = Buffer.from(signatureBase64, 'base64').toString('utf8');

    let result;
    if (decoded.includes('-----BEGIN PGP SIGNATURE-----')) {
      // Detached signature — verify against the plaintext payload
      const message = await openpgp.createMessage({ text: payloadString });
      const signature = await openpgp.readSignature({ armoredSignature: decoded });
      result = await openpgp.verify({ message, signature, verificationKeys: [publicKey] });
    } else {
      // Inline signed message — payload is embedded in the message
      const message = await openpgp.readMessage({ armoredMessage: decoded });
      result = await openpgp.verify({ message, verificationKeys: [publicKey] });
    }

    if (!result.signatures || result.signatures.length === 0) {
      throw new Error('No signatures in OpenPGP message');
    }

    // Throws if signature is invalid
    await result.signatures[0].verified;
    return true;
  } catch (err) {
    if (err.code === 'invalid_signature') throw err;
    throw Object.assign(
      new Error(`PGP verification failed: ${err.message}`),
      { code: 'invalid_signature' }
    );
  }
}
