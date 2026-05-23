import { Router } from 'express';
import * as discovery from '../controllers/discoveryController.js';

const router = Router();

// ── Public (no auth) ──────────────────────────────────────────────────────────

// Senders call this to get a recipient's preferred public key before encrypting.
// Supports ?email=alice@x.com (single) and ?emails=a@x.com,b@x.com (batch, max 50).
router.get('/preference', discovery.getPreference);

// Revocation list — senders check this before encrypting to avoid keying to a revoked key
router.get('/revoked', discovery.getRevoked);

export default router;
