import { verifyFetchTokenValue } from '../utils/fetchToken.js';
import { verifySignedRequest } from './verifySignedRequest.js';

/**
 * Middleware: accepts only a fetch token (Authorization: FetchToken <token>).
 * Used for routes exclusively accessible via OTP/SRP bootstrap tokens.
 * Sets req.identity = { email, scope: 'blob_fetch_only' }.
 */
export function verifyFetchToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('FetchToken ')) {
    return res.status(401).json({
      error: 'missing_fetch_token',
      message: 'Authorization: FetchToken <token> header required',
    });
  }
  const token = authHeader.slice('FetchToken '.length).trim();
  try {
    const payload = verifyFetchTokenValue(token);
    req.identity = { email: payload.email, scope: payload.scope };
    next();
  } catch (err) {
    return res.status(401).json({ error: err.code || 'invalid_token', message: err.message });
  }
}

/**
 * Middleware: accepts EITHER a fetch token OR a full signed request.
 *
 * Used for:
 *   - GET /keys/blob/:keyId  (new device with OTP token, or existing device with signed request)
 *   - POST /keys/recover     (new device with OTP token, or existing device with signed request)
 *   - POST /auth/srp/setup   (post-OTP setup, or signed request from existing device)
 */
export function verifyAnyAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('FetchToken ')) {
    return verifyFetchToken(req, res, next);
  }
  return verifySignedRequest(req, res, next);
}
