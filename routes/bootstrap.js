import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import * as bootstrap from '../controllers/bootstrapController.js';
import { verifySignedRequest } from '../middleware/verifySignedRequest.js';
import { verifyAnyAuth } from '../middleware/verifyFetchToken.js';

const router = Router();

// Rate limit OTP sends: max 3 per email per 10 minutes
const otpRateLimit = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 3,
  keyGenerator: (req) => req.body?.email?.toLowerCase?.() || req.ip,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many OTP requests. Please wait 10 minutes before trying again.' },
  skipSuccessfulRequests: false,
});

// ── Public (no auth) ──────────────────────────────────────────────────────────

// Tells the client whether this is a known user (show recover flow) or a new user (show setup flow)
router.get('/check', bootstrap.check);

// Send OTP to email address to prove mailbox ownership
router.post('/bootstrap', otpRateLimit, bootstrap.sendOtp);

// Verify OTP and receive a short-lived blob-fetch-only token
router.post('/bootstrap/verify', bootstrap.verifyOtpAndIssueToken);

// SRP-6a authentication (password proof without sending the password)
router.post('/srp/init',     bootstrap.srpInit);
router.post('/srp/complete', bootstrap.srpComplete);

// ── Authenticated ─────────────────────────────────────────────────────────────

// Register or update SRP credentials (requires fetch token or signed request)
router.post('/srp/setup', verifyAnyAuth, bootstrap.srpSetup);

// Cancel a pending key revocation within the 24-hour window (requires signed request)
router.post('/bootstrap/cancel-revocation', verifySignedRequest, bootstrap.cancelRevocation);

export default router;
