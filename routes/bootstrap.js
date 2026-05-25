import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import * as bootstrap from '../controllers/bootstrapController.js';
import { verifySignedRequest } from '../middleware/verifySignedRequest.js';
import { verifyFetchToken } from '../middleware/verifyFetchToken.js';

// NOTE: express-rate-limit uses an in-memory store by default.
// For multi-instance deployments, replace with a Redis store:
//   npm install rate-limit-redis ioredis
//   store: new RedisStore({ ... })

const router = Router();

// ── Rate limiters ─────────────────────────────────────────────────────────────

// Max 3 OTP sends per email per 10 minutes
const otpSendLimit = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 3,
  keyGenerator: (req) => req.body?.email?.toLowerCase?.() || req.ip,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many OTP requests. Please wait 10 minutes.' },
});

// Max 10 OTP verify attempts per IP per 10 minutes
const otpVerifyLimit = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many verification attempts. Please wait 10 minutes.' },
});

// Max 20 check/discovery requests per IP per minute
const checkLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many requests. Please slow down.' },
});

// ── Public (no auth) ──────────────────────────────────────────────────────────

// Tells the client whether this is a known user (show recover flow) or new user (show setup flow)
router.get('/check', checkLimit, bootstrap.check);

// Send OTP to email address to prove mailbox ownership
router.post('/bootstrap', otpSendLimit, bootstrap.sendOtp);

// Verify OTP — issues a short-lived fetch token on success
router.post('/bootstrap/verify', otpVerifyLimit, bootstrap.verifyOtpAndIssueToken);

// ── SRP-6a routes — commented out ─────────────────────────────────────────────
// OTP + signed-request authentication is sufficient.
// Restore when SRP is needed (also restore controller imports/exports).

// router.post('/srp/init',     bootstrap.srpInit);
// router.post('/srp/complete', bootstrap.srpComplete);
// router.post('/srp/setup',    verifyAnyAuth, bootstrap.srpSetup);

// ── Authenticated ─────────────────────────────────────────────────────────────

// List keys with blobs available for recovery (fetch token from OTP)
router.get('/bootstrap/recoverable', verifyFetchToken, bootstrap.listRecoverableKeys);

// Cancel a pending key revocation within the 24-hour window (requires signed request)
router.post('/bootstrap/cancel-revocation', verifySignedRequest, bootstrap.cancelRevocation);

export default router;
