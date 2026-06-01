import { Router } from 'express';
import { byFingerprint, byEmail } from '../controllers/vksController.js';

const router = Router();

// Public key lookup — no authentication required
router.get('/v1/by-fingerprint/:fingerprint', byFingerprint);
router.get('/v1/by-email/:email', byEmail);

export default router;
