import { createHash } from 'crypto';

/** SHA-256 hex digest of a Buffer or string. */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}
