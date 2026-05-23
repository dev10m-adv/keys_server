# SecMail keys_server — Complete Update Prompt

## Repo
this

Current structure:
```
controllers/
db/
routes/
server.js
package.json
```

---

## What this server is

A Node.js key management server for SecMail — an end-to-end encrypted email
client. The server is intentionally blind — it never stores or processes
plaintext private keys. All cryptographic operations happen on the client
(Flutter app). The server's job is:

1. Store public keys and encrypted private key blobs
2. Serve key preference data to senders
3. Verify client identity via signed request payloads (no JWT, no sessions)
4. Handle new device bootstrap via OTP
5. Manage key metadata, status, and preference flags

---

## What needs to be added in this update

### 1. Multiple keys per user with full metadata

Each user can have multiple keys. Each key record must store:

```js
{
  keyId:             UUID (primary key, globally unique),
  email:             string (FK to users),
  algorithm:         'openpgp' | 'smime' | 'pqc',
  label:             string (user-defined name, optional),
  publicKey:         text (armoured PGP / PEM / base64),
  encryptedBlob:     text | null (AES-256-GCM wrapped private key — nullable if user chose local-only),
  status:            'active' | 'archived' | 'revoked' | 'revocation_pending' | 'soft_deleted',
  isPreferred:       boolean (only one active per algorithm per user),
  discoverable:      boolean (controls if key appears in public search),
  hasRecoveryPhrase: boolean (client sets this flag — server does not generate phrase),
  createdAt:         timestamp,
  expiresAt:         timestamp | null,
  hardDeleteAt:      timestamp | null (set when soft-deleted, hard delete after 7 days),
}
```

### 2. Users table with SRP support

```js
{
  email:              string (primary key),
  srpVerifier:        text,
  srpSalt:            text,
  preferredAlgorithm: 'openpgp' | 'smime' | 'pqc' (default: 'openpgp'),
  emailVerified:      boolean,
  createdAt:          timestamp,
}
```

### 3. Auth — signed request verification (replace any existing auth)

No JWT. No sessions. Every protected route is verified independently.

Client sends two headers with every request:

```
X-Auth-Payload:    base64url of JSON string:
                   {
                     email:          string,
                     method:         'GET'|'POST'|'PATCH'|'DELETE',
                     path:           string,
                     bodyHash:       sha256(rawBody) or sha256('') for no body,
                     timestamp:      number (Date.now()),
                     jti:            string (UUID v4, unique per request),
                     sigAlgorithm:   'openpgp' | 'smime'  ← which key type was used to sign
                   }

X-Auth-Signature:  base64url of signature over the X-Auth-Payload value,
                   signed with whichever private key the client has available
```

**Algorithm selection rule — client side:**
The client signs with whichever key type it currently has loaded in memory.
If the user has BOTH an OpenPGP key AND an S/MIME key registered, the client
MUST use the OpenPGP key to sign. OpenPGP is always preferred for auth when
both options are available. If the user only has S/MIME keys, S/MIME is used.

**Algorithm selection rule — server side:**
The server reads `sigAlgorithm` from the payload to know which verification
function to call. It then fetches the user's active preferred key of that
algorithm to get the public key for verification.

```
sigAlgorithm = 'openpgp' → fetch openpgp preferred key → pgpVerify()
sigAlgorithm = 'smime'   → fetch smime preferred key   → smimeVerify()
```

**OpenPGP preference enforcement:**
Before verifying, the server checks: does this user have ANY active OpenPGP key?
If yes AND sigAlgorithm = 'smime' → reject with 403 'openpgp_required'.
The client should never send smime-signed requests if an openpgp key exists —
this check is a server-side guard against misconfigured clients.

Verification middleware steps:
1. Decode and parse X-Auth-Payload
2. Check `|Date.now() - payload.timestamp| <= 30_000` — else 401 'request_expired'
3. Check `jti` not already in jti_cache — else 401 'replayed_request'
4. Store `jti` with 30-second TTL
5. Verify `sha256(rawBody) === payload.bodyHash` — else 401 'body_tampered'
6. If user has active openpgp key AND sigAlgorithm === 'smime' → 403 'openpgp_required'
7. Fetch active preferred public key for `payload.email` + `payload.sigAlgorithm`
8. Verify signature using the correct algorithm — else 403 'invalid_signature'
9. Set `req.identity = { email, sigAlgorithm, keyId: verifiedKeyId }`

Apply this middleware to all routes EXCEPT bootstrap routes.

Add to services/:
- `services/pgpService.js`   — pgpVerify() using openpgp npm package
- `services/smimeService.js` — smimeVerify() using node:crypto / node-forge

### 4. New device check route (GET, no auth)

```
GET /auth/check?email=alice@example.com

Purpose: Flutter calls this on first launch to ask "has this user ever
         communicated with this server before?"

Response if known user:
  { known: true, hasKeys: true, algorithms: ['openpgp', 'smime'] }

Response if unknown:
  { known: false }

This tells the client whether to show the "existing user — recover keys"
flow or the "new user — generate keys" flow. No auth required.
No sensitive data returned.
```

### 5. Bootstrap routes (no auth required)

#### POST /auth/bootstrap
Send OTP to user's email to prove mailbox ownership.
```
Body:     { email: string }
Behaviour:
  - Generate cryptographically random 6-digit OTP
  - Store bcrypt(otp) with 10-minute TTL and attempt counter
  - Send via SMTP/nodemailer to email address
  - Rate limit: max 3 requests per email per 10 minutes
Response: { message: 'OTP sent', expiresIn: 600 }
```

#### POST /auth/bootstrap/verify
Verify OTP and issue a one-time scoped fetch token.
```
Body:     { email: string, otp: string }
Behaviour:
  - Verify OTP against stored hash
  - Consume OTP (delete — single use only)
  - Issue a short-lived scoped token:
    { email, scope: 'blob_fetch_only', exp: now + 300s }
    Sign it with a server HMAC secret (not exposed to client)
  - This token authorises ONLY: GET /keys/blob/:keyId
  - All other routes reject it
Response: { fetchToken: string, expiresIn: 300 }
```

#### POST /auth/srp/init
Begin SRP-6a exchange (password proof without sending the password).
```
Body:     { email: string, clientPublicEphemeral: string }
Response: { salt: string, serverPublicEphemeral: string }
Use npm package: secure-remote-password
```

#### POST /auth/srp/complete
Complete SRP exchange and issue fetch token.
```
Body:     { email: string, clientProof: string }
Response: { fetchToken: string, expiresIn: 300 }
       or 401 { error: 'proof_failed' }
```

---

## Routes to implement

### Public — no auth required

#### GET /auth/check
See section 4 above.

#### GET /keys/preference
Senders call this to get a recipient's preferred key before encrypting.
```
Query:  ?email=alice@example.com
        OR ?emails=alice@example.com,bob@example.com  (batch — multiple emails)

Single response:
  { keyId, algorithm, publicKey, label }
  OR 404 if no discoverable active key

Batch response:
  {
    results: [
      { email: 'alice@...', keyId, algorithm, publicKey, label },
      { email: 'bob@...',   keyId, algorithm, publicKey, label },
      { email: 'carol@...', found: false },
    ]
  }

Rules:
  - Only return keys where discoverable=true AND status='active'
  - Only return the isPreferred=true key per email
  - Never return encryptedBlob
  - This is the route senders use before encrypting — must be fast
```

#### GET /keys/revoked
Return the revocation list so senders can check before encrypting.
```
Response: [{ keyId, email, revokedAt }]
Only keys where status='revoked' (not revocation_pending)
```

---

### Protected — signed request required

#### POST /keys — upload a new key

This route has special auth: the signature is verified against the SUBMITTED
public key (not the stored one), because this is the first upload. This is the
self-signed proof that the uploader owns the private key.

```
Body: {
  payload:   string,   // JSON { email, publicKey, algorithm, encryptedBlob,
                       //        discoverable, label, timestamp, jti,
                       //        hasRecoveryPhrase }
  signature: string,   // PGP sig of payload string, signed with the private key
                       // that corresponds to the submitted publicKey
}

Validation:
  1. pgpVerify(payload string, signature, body.publicKey from parsed payload)
     — proves submitter owns the private key for this public key
  2. db.isEmailVerified(email) — email must be verified first
  3. No duplicate keyId

Behaviour:
  - If this is the first key for this algorithm for this user, set isPreferred=true
  - Otherwise isPreferred=false (user sets preference separately)

Response: { keyId: string }
```

#### GET /keys/blob/:keyId
Fetch an encrypted private key blob.
```
Auth: signed request OR fetch token in header: Authorization: FetchToken <token>
      Verify fetch token scope = 'blob_fetch_only' and not expired

Ownership check — CRITICAL:
  The requested keyId must belong to the authenticated email.
  Look up the key record: if key.email !== req.identity.email → 403 'not_your_key'
  This prevents any user from fetching another user's encrypted blob
  even if they somehow know the keyId.

  For fetch token: the token contains the email —
  fetch_token.email must equal the key record's email.

  Rule: only the user who owns the encrypted blob can retrieve it.
  The signed request or OTP-issued fetch token already proves email ownership.
  The keyId ownership check is the second layer.

Response: { keyId, encryptedBlob, algorithm, label }
Note: encryptedBlob is the AES-256-GCM wrapped private key. Server cannot decrypt it.
      Client decrypts it with the user's password locally.
```

#### GET /keys
List all key metadata for the authenticated user.
```
Auth: signed request
Response: {
  keys: [
    {
      keyId, algorithm, label, status, isPreferred,
      discoverable, hasRecoveryPhrase, hasBlob: (encryptedBlob !== null),
      createdAt, expiresAt
      // never return publicKey or encryptedBlob in list view
    }
  ]
}
```

#### PATCH /keys/:keyId/status — archive or revoke
```
Auth: signed request
Body: { status: 'archived' | 'revoked', reason?: string }

archived → immediate, reversible
  - Set status = 'archived'
  - If this was isPreferred, auto-promote next active key of same algorithm
    to isPreferred (or leave none preferred if no other active keys)

revoked → starts 24-hour cooldown
  - Set status = 'revocation_pending'
  - Record revokedAt timestamp
  - Send email alert to user: "Your key revocation was requested.
    You have 24 hours to cancel this."
  - Background job: after 24h move to status='revoked',
    remove from public discovery

Response: { keyId, status, effectiveAt }
```

#### POST /auth/bootstrap/cancel-revocation
Cancel a pending revocation within the 24-hour window.
```
Auth: signed request (user still has key on another device)
Body: { keyId: string }
Behaviour: if status='revocation_pending' → revert to 'active'
Response: { keyId, status: 'active' }
```

#### POST /keys/rotate — rotate to a new key
```
Auth: signed request (signed with OLD private key)
Body: {
  rotationPayload: string,  // JSON { oldKeyId, newPublicKey, algorithm,
                            //        newEncryptedBlob, label, timestamp, jti,
                            //        hasRecoveryPhrase }
  signature: string,        // PGP sig of rotationPayload using OLD private key
}

Validation:
  - Fetch stored public key for oldKeyId
  - pgpVerify(rotationPayload, signature, oldPublicKey)
    — proves same person controls both old and new key
  - oldKeyId must have status='active'

Behaviour:
  - Store new key with isPreferred=true (if old key was preferred)
  - Move oldKeyId to status='archived'
  - New key inherits label from old key (can be overridden in payload)

Response: { newKeyId, oldKeyId, oldStatus: 'archived' }
```

#### PATCH /keys/:keyId/preference — update preference flags
```
Auth: signed request
Body: {
  isPreferred?:       boolean,
  discoverable?:      boolean,
  label?:             string,
  hasRecoveryPhrase?: boolean,
}

If isPreferred=true:
  - Set all other keys of the same algorithm for this user to isPreferred=false
  - Then set this key to isPreferred=true
  - Atomic — use a transaction

Response: { keyId, isPreferred, discoverable, label, hasRecoveryPhrase }
```

#### PUT /keys/:keyId/blob — update encrypted blob (password change)
```
Auth: signed request
Body: {
  newBlob:   string,   // new AES-256-GCM encrypted private key
  payload:   string,   // JSON { keyId, intent: 'update_blob', timestamp, jti }
  signature: string,   // PGP sig of payload with the key being updated
}
Behaviour: atomic swap — old blob replaced in a transaction
Response: { keyId, updatedAt }
```

#### PATCH /keys/:keyId/recovery-phrase
Mark that the user has saved a recovery phrase for this key.
```
Auth: signed request
Body: { confirmed: true }
Response: { keyId, hasRecoveryPhrase: true }
```

#### DELETE /keys/:keyId — move to deleted_keys table
```
Auth: signed request (double proof required — signed request + key-specific sig)
Body: {
  payload:   string,   // JSON { keyId, intent: 'permanent_delete', timestamp, jti }
  signature: string,   // PGP or S/MIME sig of payload with the key being deleted
}

Ownership check: keyId must belong to req.identity.email → else 403 'not_your_key'

Behaviour:
  - Copy the full key record into deleted_keys table (see schema below)
    including encryptedBlob — user can recover within 6 months
  - Remove the row from keys table immediately
  - If this was isPreferred, auto-promote next active key of same algorithm
    in a transaction with the deletion
  - Background job: hard-delete rows from deleted_keys after 180 days
  - Send email: "Your key was deleted. You can recover it within 6 months."

Response: { keyId, deletedAt, recoverableUntil (= deletedAt + 180 days) }
```

#### POST /keys/recover — restore a deleted key
```
Auth: signed request (user must be able to sign — has another active key)
      OR fetch token (user on new device with no keys yet — OTP bootstrap first)
Body: { keyId: string }

Behaviour:
  - Look up deleted_keys by keyId WHERE email = req.identity.email
  - If not found or recoverableUntil < now → 404 'not_recoverable'
  - Copy record back into keys table with status = 'archived'
    (archived, not active — user must explicitly promote if they want it active)
  - Remove from deleted_keys table
  - If no active key of this algorithm exists for user, auto-set isPreferred=true

Response: { keyId, status: 'archived', recoveredAt }
Note: restored as 'archived' so it can decrypt old mail but does not
      automatically become the signing/encryption key — user decides.
```

---

## DB schema (SQLite or PostgreSQL — use better-sqlite3 or pg)

```sql
CREATE TABLE users (
  email               TEXT PRIMARY KEY,
  srp_verifier        TEXT NOT NULL,
  srp_salt            TEXT NOT NULL,
  preferred_algorithm TEXT NOT NULL DEFAULT 'openpgp',
  email_verified      INTEGER NOT NULL DEFAULT 0,
  created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE keys (
  key_id              TEXT PRIMARY KEY,
  email               TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  algorithm           TEXT NOT NULL CHECK(algorithm IN ('openpgp','smime','pqc')),
  label               TEXT,
  public_key          TEXT NOT NULL,
  encrypted_blob      TEXT,
  status              TEXT NOT NULL DEFAULT 'active'
                      CHECK(status IN ('active','archived','revoked','revocation_pending')),
  -- Note: 'soft_deleted' is NOT a status here.
  -- Deleted keys move to the deleted_keys table entirely.
  is_preferred        INTEGER NOT NULL DEFAULT 0,
  discoverable        INTEGER NOT NULL DEFAULT 1,
  has_recovery_phrase INTEGER NOT NULL DEFAULT 0,
  created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at          DATETIME
);

-- Only one preferred key per algorithm per user
CREATE UNIQUE INDEX idx_one_preferred
  ON keys(email, algorithm)
  WHERE is_preferred = 1 AND status = 'active';

-- Fast discovery lookup
CREATE INDEX idx_discoverable
  ON keys(email, algorithm, discoverable, status);

-- Deleted keys — full record preserved for 6 months
-- User can recover within this window
CREATE TABLE deleted_keys (
  key_id              TEXT PRIMARY KEY,
  email               TEXT NOT NULL,
  algorithm           TEXT NOT NULL,
  label               TEXT,
  public_key          TEXT NOT NULL,
  encrypted_blob      TEXT,         -- blob preserved so user can recover and decrypt old mail
  had_recovery_phrase INTEGER NOT NULL DEFAULT 0,
  was_preferred       INTEGER NOT NULL DEFAULT 0,
  deleted_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
  recoverable_until   DATETIME NOT NULL  -- = deleted_at + 180 days
);

-- Index for recovery lookups by email
CREATE INDEX idx_deleted_by_email ON deleted_keys(email, recoverable_until);

-- Background job must run daily:
-- DELETE FROM deleted_keys WHERE recoverable_until < CURRENT_TIMESTAMP

CREATE TABLE otp_store (
  email       TEXT PRIMARY KEY,
  otp_hash    TEXT NOT NULL,
  attempts    INTEGER DEFAULT 0,
  expires_at  DATETIME NOT NULL
);

CREATE TABLE jti_cache (
  jti        TEXT PRIMARY KEY,
  seen_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- Clean up jti_cache every 60 seconds:
-- DELETE FROM jti_cache WHERE seen_at < datetime('now', '-30 seconds')
```

---

## Project structure to produce

```
keys_server/
├── server.js                          ← express setup, middleware, startup
├── package.json                       ← add: openpgp, node-forge,
│                                              secure-remote-password,
│                                              bcrypt, nodemailer, uuid, express
├── db/
│   ├── schema.sql                     ← full schema above
│   └── database.js                    ← DB connection + init
├── middleware/
│   ├── verifySignedRequest.js         ← algorithm-aware auth middleware
│   └── verifyFetchToken.js            ← blob-fetch-only scoped token check
├── controllers/
│   ├── bootstrapController.js         ← check, OTP, SRP, cancel-revocation
│   ├── keysController.js              ← upload, list, blob, rotate, delete, recover
│   └── discoveryController.js         ← preference (single + batch), revoked
├── routes/
│   ├── bootstrap.js                   ← /auth/* routes (no auth)
│   ├── keys.js                        ← /keys/* routes (protected)
│   └── discovery.js                   ← /keys/preference, /keys/revoked (public)
├── services/
│   ├── pgpService.js                  ← pgpVerify() using openpgp package
│   ├── smimeService.js                ← smimeVerify() using node-forge
│   ├── signatureService.js            ← dispatcher: picks pgp or smime verify
│   │                                    based on sigAlgorithm field
│   ├── srpService.js                  ← SRP-6a using secure-remote-password
│   ├── otpService.js                  ← generate, hash, verify, rate-limit OTP
│   ├── jtiCacheService.js             ← in-memory jti store with auto-eviction
│   └── backgroundJobs.js             ← purge deleted_keys after 180d,
│                                        revocation after 24h, jti cleanup
└── utils/
    └── hashBody.js                    ← sha256 helper for body verification
```

---

## Specific behaviours to implement carefully

### Batch preference query
`GET /keys/preference?emails=a@x.com,b@x.com,c@x.com`
- Accept up to 50 emails in one request
- Return one preferred discoverable active key per email
- If an email has no qualifying key, include `{ email, found: false }` in results
- This is what the Flutter app calls before composing an encrypted email to multiple recipients

### Auto-promote on archive/delete
When the preferred key is archived or deleted:
- Query for the next `status='active'` key of the same algorithm for that user, ordered by `created_at DESC`
- If found, set it as `is_preferred=1` in the same transaction
- If none found, leave no preferred key for that algorithm (senders get 404 for that algorithm)

### jti cache — in-memory implementation
```js
// services/jtiCacheService.js
const cache = new Map(); // jti -> expiresAt timestamp

export function hasJti(jti) {
  cleanup();
  return cache.has(jti);
}

export function addJti(jti) {
  cache.set(jti, Date.now() + 30_000);
}

function cleanup() {
  const now = Date.now();
  for (const [k, exp] of cache) {
    if (exp < now) cache.delete(k);
  }
}

// Also run cleanup on setInterval every 30s
setInterval(cleanup, 30_000);
```

### Signature verification services

```js
// services/pgpService.js
import { readMessage, readKey, verify, createMessage } from 'openpgp';

export async function pgpVerify(payloadString, signatureBase64, armouredPublicKey) {
  const publicKey = await readKey({ armoredKey: armouredPublicKey });
  const signature = await readMessage({
    armoredMessage: Buffer.from(signatureBase64, 'base64').toString()
  });
  const message = await createMessage({ text: payloadString });
  const result  = await verify({ message, signature, verificationKeys: publicKey });
  const { verified } = result.signatures[0];
  await verified; // throws if invalid
  return true;
}

// services/smimeService.js
import forge from 'node-forge';

export function smimeVerify(payloadString, signatureBase64, pemPublicKey) {
  // Verify a detached RSA-SHA256 signature (PKCS#1 v1.5)
  const publicKey  = forge.pki.publicKeyFromPem(pemPublicKey);
  const md         = forge.md.sha256.create();
  md.update(payloadString, 'utf8');
  const sigBytes   = forge.util.decode64(signatureBase64);
  const valid      = publicKey.verify(md.digest().bytes(), sigBytes);
  if (!valid) throw new Error('S/MIME signature verification failed');
  return true;
}

// services/signatureService.js
// Dispatcher — picks the right verifier based on sigAlgorithm in payload
import { pgpVerify }   from './pgpService.js';
import { smimeVerify } from './smimeService.js';
import db from '../db/database.js';

export async function verifySignature(payloadString, signatureBase64, email, sigAlgorithm) {
  // Fetch the user's active preferred key for this algorithm
  const keyRecord = db.prepare(`
    SELECT public_key FROM keys
    WHERE email = ? AND algorithm = ? AND status = 'active' AND is_preferred = 1
    LIMIT 1
  `).get(email, sigAlgorithm);

  if (!keyRecord) throw Object.assign(
    new Error(`No active ${sigAlgorithm} key found for ${email}`),
    { code: 'no_key_for_algorithm' }
  );

  if (sigAlgorithm === 'openpgp') {
    return pgpVerify(payloadString, signatureBase64, keyRecord.public_key);
  }
  if (sigAlgorithm === 'smime') {
    return smimeVerify(payloadString, signatureBase64, keyRecord.public_key);
  }
  throw Object.assign(new Error('Unsupported algorithm'), { code: 'unsupported_algorithm' });
}
```

### Error response format — consistent across all routes
```js
// All errors:
res.status(code).json({
  error:   'snake_case_code',   // machine-readable
  message: 'Human readable',    // user-facing
})

// Common codes:
// 401 request_expired
// 401 replayed_request
// 401 body_tampered
// 403 invalid_signature
// 403 key_ownership_failed   (self-signed proof failed on upload)
// 403 email_not_verified
// 404 key_not_found
// 404 no_preferred_key
// 429 rate_limited
// 409 conflict               (e.g. duplicate keyId)
```

---

## Security rules — must be followed exactly

1. Never store or log plaintext private keys
2. Never accept IMAP credentials — this server has nothing to do with IMAP
3. The `encryptedBlob` field is opaque — server never decrypts it
4. OTP stored as bcrypt hash only — never plaintext
5. SRP verifier stored — never the password or its hash
6. `jti` replay window is exactly 30 seconds — matches client timestamp window
7. Self-signed proof on key upload: signature verified against SUBMITTED pubkey,
   not stored pubkey (there is no stored pubkey yet at upload time)
8. Key rotation proof: new pubkey signed by OLD private key —
   verify against OLD stored pubkey before accepting new key
9. Delete requires BOTH a valid signed request AND a fresh key-specific signature
   over `{ keyId, intent: 'permanent_delete', timestamp, jti }`
   — stolen signed request alone cannot delete a key
10. Fetch token is scoped — only `GET /keys/blob/:keyId` accepts it,
    all other protected routes reject it and require a full signed request
11. Blob fetch ownership: keyId must belong to the authenticated email —
    users can only fetch their own encrypted blobs, never another user's
12. OpenPGP preferred for auth: if user has any active OpenPGP key,
    server rejects S/MIME-signed requests with 403 'openpgp_required'
13. Deleted keys are preserved in deleted_keys table for exactly 180 days —
    the encrypted blob is kept so the user can recover and still decrypt
    old mail that was encrypted to that key
14. After 180 days the deleted_keys row is hard-deleted by background job —
    this is permanent and unrecoverable

---

## npm packages to use

```json
{
  "dependencies": {
    "express":                  "^4.18.x",
    "openpgp":                  "^5.x",
    "node-forge":               "^1.x",
    "secure-remote-password":   "^0.3.x",
    "bcrypt":                   "^5.x",
    "nodemailer":               "^6.x",
    "uuid":                     "^9.x",
    "better-sqlite3":           "^9.x",
    "cors":                     "^2.x",
    "dotenv":                   "^16.x"
  }
}
```

---

## Environment variables (.env)

```
PORT=3000
DB_PATH=./db/secmail.db
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=noreply@secmail.app
FETCH_TOKEN_SECRET=<random 256-bit hex>
SERVER_BASE_URL=https://your-server.com
```

---

## What NOT to change or add

- No JWT at any point — the signed request IS the auth
- No user sessions or cookies
- No rate limiting beyond OTP (keep it simple — add express-rate-limit for OTP only)
- No email content processing — server never touches mail body
- No IMAP/SMTP for mail delivery — only SMTP for sending OTP emails
- No storing of any decryptable private key material
