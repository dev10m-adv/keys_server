// LEGACY — superseded by db/schema.sql (applied via initDatabase() in db/database.js).
// This file is no longer imported anywhere and will be removed in a future cleanup.
const pool = require("./index.js");

const initDb = async () => {
    // 1) Create tables if missing
    await pool.query(`
    CREATE TABLE IF NOT EXISTS "users_keys" (
      "EmailAddress" TEXT PRIMARY KEY,
      "x25519_pubkey" TEXT NOT NULL,
      "Ed25519_pubkey" TEXT NOT NULL
    );
  `);

    // 2) Upgrade existing table (add new columns safely)
    await pool.query(`
    ALTER TABLE "users_keys"
    ADD COLUMN IF NOT EXISTS "smime_certificate" TEXT;
  `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS "users_private_data" (
      "EmailAddress" TEXT NOT NULL,
      "key_type" TEXT NOT NULL,
      "cipher" TEXT NOT NULL,
      "kdf" TEXT NOT NULL,
      "kdf_iteration" INTEGER NOT NULL,
      "kdf_key_length" INTEGER NOT NULL,
      "salt" TEXT NOT NULL,
      "nonce" TEXT NOT NULL,
      "cipher_text" TEXT NOT NULL,
      "mac" TEXT NOT NULL,
      "created_at" TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY ("EmailAddress", "key_type")
    );
  `
    );

    await pool.query(`
    ALTER TABLE "users_private_data"
    ADD COLUMN IF NOT EXISTS "mac" TEXT;
  `);

    await pool.query(`
    CREATE TABLE IF NOT EXISTS "users_crypto_flags" (
      "EmailAddress" TEXT PRIMARY KEY,
      "cryptoKeysGenerated" BOOLEAN NOT NULL,
      "algorithm" TEXT NOT NULL,
      "generated_at" TEXT NOT NULL,
      "uploaded_public_key" BOOLEAN NOT NULL,
      "uploaded_private_key" BOOLEAN NOT NULL
    );
  `);

    console.log("Database schema ensured (including upgrades).");
};

module.exports = initDb;
