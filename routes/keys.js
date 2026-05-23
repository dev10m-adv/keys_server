import { Router } from 'express';
import * as keys from '../controllers/keysController.js';
import { verifySignedRequest } from '../middleware/verifySignedRequest.js';
import { verifyAnyAuth } from '../middleware/verifyFetchToken.js';

const router = Router();

// ── Upload first / new key ────────────────────────────────────────────────────
// No standard auth middleware here — auth is the self-signed body proof.
// The email must be verified (OTP bootstrap must have completed first).
router.post('/', keys.uploadKey);

// ── Protected — full signed request required ──────────────────────────────────

// List all key metadata for the authenticated user (no blobs, no public keys)
router.get('/', verifySignedRequest, keys.listKeys);

// Fetch an encrypted private key blob — accepts signed request OR fetch token
router.get('/blob/:keyId', verifyAnyAuth, keys.getBlob);

// Archive or initiate revocation of a key
router.patch('/:keyId/status', verifySignedRequest, keys.updateStatus);

// Rotate to a new key (signed with OLD key) + body-level rotation proof
router.post('/rotate', verifySignedRequest, keys.rotateKey);

// Update isPreferred, discoverable, label, or hasRecoveryPhrase flags
router.patch('/:keyId/preference', verifySignedRequest, keys.updatePreference);

// Swap the encrypted blob (password change) — requires body-level key signature
router.put('/:keyId/blob', verifySignedRequest, keys.updateBlob);

// Confirm the user has saved a recovery phrase for this key
router.patch('/:keyId/recovery-phrase', verifySignedRequest, keys.confirmRecoveryPhrase);

// Move key to deleted_keys table — double proof: signed request + key-specific body signature
router.delete('/:keyId', verifySignedRequest, keys.deleteKey);

// Restore a deleted key from deleted_keys — signed request OR fetch token (new device)
router.post('/recover', verifyAnyAuth, keys.recoverKey);

export default router;
