import * as openpgp from 'openpgp';

/**
 * Return the uppercase hex fingerprint for an armored OpenPGP public key.
 * Returns null if the key cannot be parsed.
 */
export async function pgpGetFingerprint(armoredPublicKey) {
  try {
    const key = await openpgp.readKey({ armoredKey: armoredPublicKey });
    return key.getFingerprint().toUpperCase();
  } catch {
    return null;
  }
}

/**
 * Re-armor a public key with Comment headers matching the keys.openpgp.org format:
 *   Comment: XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
 *   Comment: Name <email>
 *
 * Strips any existing Version/Hash/Comment headers so the output is clean.
 * Returns the original armored string unchanged if parsing fails.
 */
export async function pgpFormatArmor(armoredPublicKey) {
  try {
    const key = await openpgp.readKey({ armoredKey: armoredPublicKey });

    // Fingerprint formatted as 10 groups of 4, double-space in the middle
    const fp = key.getFingerprint().toUpperCase();
    const groups = fp.match(/.{4}/g);
    const formattedFp = groups.slice(0, 5).join(' ') + '  ' + groups.slice(5).join(' ');

    const userIds = key.getUserIDs(); // e.g. ["Name <email>"]
    const primaryUid = userIds[0] ?? null;

    // key.armor() may include a Version header — strip all headers, keep only ours
    const raw = key.armor();
    const lines = raw.split('\n');
    const blankIdx = lines.findIndex((l, i) => i > 0 && l.trim() === '');
    const bodyLines = blankIdx >= 0 ? lines.slice(blankIdx) : lines.slice(1);

    return [
      lines[0],                                              // -----BEGIN PGP PUBLIC KEY BLOCK-----
      `Comment: ${formattedFp}`,
      ...(primaryUid ? [`Comment: ${primaryUid}`] : []),
      ...bodyLines,                                          // blank line + base64 + checksum + -----END-----
    ].join('\n');
  } catch {
    return armoredPublicKey;
  }
}

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
