import { createHmac, timingSafeEqual } from 'crypto';

const EXPIRY_SECONDS = 300;

function getSecret() {
  const s = process.env.FETCH_TOKEN_SECRET;
  if (!s) throw new Error('FETCH_TOKEN_SECRET environment variable is not set');
  return s;
}

/** Issue a short-lived fetch-only token signed with the server HMAC secret. */
export function issueFetchToken(email) {
  const secret = getSecret();
  const payload = {
    email: email.toLowerCase(),
    scope: 'blob_fetch_only',
    exp: Math.floor(Date.now() / 1000) + EXPIRY_SECONDS,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

/** Verify a fetch token and return its payload. Throws a coded error on failure. */
export function verifyFetchTokenValue(token) {
  const secret = getSecret();
  const dotIndex = token.lastIndexOf('.');
  if (dotIndex === -1) {
    throw Object.assign(new Error('Invalid token format'), { code: 'invalid_token' });
  }
  const payloadB64 = token.slice(0, dotIndex);
  const sig = token.slice(dotIndex + 1);

  const expected = createHmac('sha256', secret).update(payloadB64).digest('base64url');

  // Constant-time comparison — buffers must be same length for timingSafeEqual
  const sigBuf = Buffer.from(sig, 'base64url');
  const expBuf = Buffer.from(expected, 'base64url');
  const sigCheck = Buffer.alloc(expBuf.length);
  sigBuf.copy(sigCheck, 0, 0, Math.min(sigBuf.length, expBuf.length));

  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigCheck, expBuf)) {
    throw Object.assign(new Error('Invalid token'), { code: 'invalid_token' });
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw Object.assign(new Error('Malformed token payload'), { code: 'invalid_token' });
  }

  if (payload.scope !== 'blob_fetch_only') {
    throw Object.assign(new Error('Wrong token scope'), { code: 'invalid_token' });
  }
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    throw Object.assign(new Error('Token expired'), { code: 'token_expired' });
  }

  return payload; // { email, scope, exp }
}
