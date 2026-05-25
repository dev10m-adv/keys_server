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
    const sigBytes = Buffer.from(signatureBase64, 'base64');
    const decoded = sigBytes.toString('utf8');

    let result;
    if (decoded.includes('-----BEGIN PGP SIGNATURE-----')) {
      // Armored detached signature
      const message = await openpgp.createMessage({ text: payloadString });
      const signature = await openpgp.readSignature({ armoredSignature: decoded });
      result = await openpgp.verify({ message, signature, verificationKeys: [publicKey] });
    } else if (decoded.includes('-----BEGIN PGP MESSAGE-----')) {
      // Armored inline signed message
      const message = await openpgp.readMessage({ armoredMessage: decoded });
      result = await openpgp.verify({ message, verificationKeys: [publicKey] });
    } else {
      // Raw binary detached signature (produced by OpenPGP.signBytes in the gomobile SDK).
      // Use createMessage({ binary }) so openpgp.js treats the payload as binary data
      // (no CRLF normalization). The SDK signs raw UTF-8 bytes; text-mode verification
      // would normalize newlines in the embedded PGP key block and break the digest.
      const message = await openpgp.createMessage({ binary: Buffer.from(payloadString, 'utf8') });
      const signature = await openpgp.readSignature({ binarySignature: new Uint8Array(sigBytes) });
      result = await openpgp.verify({ message, signature, verificationKeys: [publicKey] });
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
