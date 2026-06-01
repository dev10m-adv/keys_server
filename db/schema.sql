CREATE TABLE IF NOT EXISTS users (
  email               TEXT PRIMARY KEY,
  srp_verifier        TEXT,
  srp_salt            TEXT,
  preferred_algorithm TEXT NOT NULL DEFAULT 'openpgp',
  email_verified      INTEGER NOT NULL DEFAULT 0,
  created_at          TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS keys (
  key_id              TEXT PRIMARY KEY,
  email               TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  algorithm           TEXT NOT NULL CHECK(algorithm IN ('openpgp','smime','pqc')),
  label               TEXT,
  public_key          TEXT NOT NULL,
  fingerprint         TEXT,
  encrypted_blob      TEXT,
  status              TEXT NOT NULL DEFAULT 'active'
                      CHECK(status IN ('active','archived','revoked','revocation_pending')),
  is_preferred        INTEGER NOT NULL DEFAULT 0,
  discoverable        INTEGER NOT NULL DEFAULT 1,
  has_recovery_phrase INTEGER NOT NULL DEFAULT 0,
  created_at          TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  expires_at          TIMESTAMPTZ,
  revoked_at          TIMESTAMPTZ
);

-- Idempotent migration: add fingerprint column to existing tables
ALTER TABLE keys ADD COLUMN IF NOT EXISTS fingerprint TEXT;

-- Enforces at most one preferred active key per algorithm per user
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_preferred
  ON keys(email, algorithm)
  WHERE is_preferred = 1 AND status = 'active';

-- Fast discovery lookup
CREATE INDEX IF NOT EXISTS idx_discoverable
  ON keys(email, algorithm, discoverable, status);

-- VKS fingerprint lookup
CREATE INDEX IF NOT EXISTS idx_fingerprint
  ON keys(fingerprint)
  WHERE fingerprint IS NOT NULL;

-- Deleted keys — full record preserved for 6 months so the user can recover
-- and still decrypt old mail that was encrypted to that key
CREATE TABLE IF NOT EXISTS deleted_keys (
  key_id              TEXT PRIMARY KEY,
  email               TEXT NOT NULL,
  algorithm           TEXT NOT NULL,
  label               TEXT,
  public_key          TEXT NOT NULL,
  encrypted_blob      TEXT,
  had_recovery_phrase INTEGER NOT NULL DEFAULT 0,
  was_preferred       INTEGER NOT NULL DEFAULT 0,
  deleted_at          TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  recoverable_until   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deleted_by_email
  ON deleted_keys(email, recoverable_until);

CREATE TABLE IF NOT EXISTS otp_store (
  email       TEXT PRIMARY KEY,
  otp_hash    TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- In-memory JTI cache is the primary mechanism; this table is used by the
-- background job to evict old entries so the DB does not grow unbounded.
CREATE TABLE IF NOT EXISTS jti_cache (
  jti        TEXT PRIMARY KEY,
  seen_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
