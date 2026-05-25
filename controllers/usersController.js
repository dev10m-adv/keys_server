// // usersController.js
// const pool = require("../db/index.js");

// const asyncHandler = (fn) => (req, res, next) =>
//   Promise.resolve(fn(req, res, next)).catch(next);

// const isNonEmptyString = (v) => typeof v === "string" && v.trim().length > 0;

// const isValidEmail = (email) => {
//   if (!isNonEmptyString(email)) return false;
//   return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
// };

// const normalizeEmail = (email) => email.trim().toLowerCase();

// const badRequest = (res, message, details) =>
//   res.status(400).json({ error: message, ...(details ? { details } : {}) });

// const notFound = (res, message) => res.status(404).json({ error: message });

// const parsePositiveInt = (value) => {
//   if (typeof value === "number") {
//     if (!Number.isFinite(value)) return null;
//     const n = Math.trunc(value);
//     return n > 0 ? n : null;
//   }
//   if (typeof value === "string") {
//     const cleaned = value.trim().replace(/,/g, "");
//     if (!/^\d+$/.test(cleaned)) return null;
//     const n = Number(cleaned);
//     if (!Number.isFinite(n) || n <= 0) return null;
//     return Math.trunc(n);
//   }
//   return null;
// };

// /**
//  * Upload / update public keys (+ optional smime cert)
//  */
// const uploadKeys = asyncHandler(async (req, res) => {
//   const { EmailAddress, x25519_pubkey, Ed25519_pubkey, smime_certificate } =
//     req.body || {};

//   if (!isValidEmail(EmailAddress)) return badRequest(res, "Invalid EmailAddress");
//   if (!isNonEmptyString(x25519_pubkey) || !isNonEmptyString(Ed25519_pubkey)) {
//     return badRequest(res, "Missing fields", {
//       required: ["x25519_pubkey", "Ed25519_pubkey"],
//     });
//   }

//   const email = normalizeEmail(EmailAddress);

//   const query = `
//     INSERT INTO "users_keys" ("EmailAddress", "x25519_pubkey", "Ed25519_pubkey", "smime_certificate")
//     VALUES ($1, $2, $3, $4)
//     ON CONFLICT ("EmailAddress")
//     DO UPDATE SET
//       "x25519_pubkey" = EXCLUDED."x25519_pubkey",
//       "Ed25519_pubkey" = EXCLUDED."Ed25519_pubkey",
//       "smime_certificate" = EXCLUDED."smime_certificate"
//     RETURNING "EmailAddress", "x25519_pubkey", "Ed25519_pubkey", "smime_certificate";
//   `;

//   const values = [
//     email,
//     x25519_pubkey.trim(),
//     Ed25519_pubkey.trim(),
//     isNonEmptyString(smime_certificate) ? smime_certificate : null,
//   ];

//   const result = await pool.query(query, values);
//   return res.status(201).json(result.rows[0]);
// });

// /**
//  * Get public keys by email
//  * GET /email?email=user@example.com
//  */

//       // final response = await apiService.get(
//       //   _fetchPublicKeyRoute(),
//       //   queryParameters: {'emails': emails.join(',')},
//       //   );
// const getKeysByEmail = asyncHandler(async (req, res) => {
//   const emailRaw = req.query?.emails; // expecting comma-separated emails
//   const emails = emailRaw?.split(',').map(normalizeEmail) || [];

//   if (emails.length === 0 || emails.some((email) => !isValidEmail(email))) {
//     return badRequest(res, "Invalid email query param");
//   }

//   const query = `
//     SELECT "x25519_pubkey", "Ed25519_pubkey", "smime_certificate"
//     FROM "users_keys"
//     WHERE "EmailAddress" = ANY($1)
//   `;
//   const result = await pool.query(query, [emails]);

//   if (result.rows.length === 0) return notFound(res, "Email not found");
//   return res.json(result.rows);

// });

// /**
//  * Update S/MIME certificate
//  */
// const updateSMIMECertificate = asyncHandler(async (req, res) => {
//   const { EmailAddress, smime_certificate } = req.body || {};

//   if (!isValidEmail(EmailAddress)) return badRequest(res, "Invalid EmailAddress");
//   if (!isNonEmptyString(smime_certificate))
//     return badRequest(res, "Missing smime_certificate");

//   const email = normalizeEmail(EmailAddress);

//   const query = `
//     UPDATE "users_keys"
//     SET "smime_certificate" = $1
//     WHERE "EmailAddress" = $2
//     RETURNING "EmailAddress", "x25519_pubkey", "Ed25519_pubkey", "smime_certificate";
//   `;

//   const result = await pool.query(query, [smime_certificate, email]);
//   if (result.rows.length === 0) return notFound(res, "Email not found");
//   return res.json(result.rows[0]);
// });

// /**
//  * Get S/MIME certificate by email
//  * GET /smime_certificate?email=user@example.com
//  */
// const getCertificateByEmail = asyncHandler(async (req, res) => {
//   const emailRaw = req.query?.emails;
//   const emails = emailRaw?.split(',').map(normalizeEmail) || [];

//   if (emails.length === 0 || emails.some((email) => !isValidEmail(email))) {
//     return badRequest(res, "Invalid email query param");
//   }

//   const query = `
//     SELECT "smime_certificate"
//     FROM "users_keys"
//     WHERE "EmailAddress" = ANY($1)
//   `;
//   const result = await pool.query(query, [emails]);

//   if (result.rows.length === 0) return notFound(res, "Email not found");
//   return res.json(result.rows);
// });

// /**
//  * Upload encrypted private blob (private key / cert / etc.)
//  * Supports both kdf_iteration and kdf_iterations from frontend.
//  */
// const uploadPrivateKeyAndCertificate = asyncHandler(async (req, res) => {
//   // keep logs if you want debugging; remove in production if sensitive
//   console.log("Received uploadPrivateKeyAndCertificate request with body:");
//   console.log(req.body);

//   const body = req.body || {};

//   const EmailAddress = body.EmailAddress;
//   const key_type = body.key_type;
//   const cipher = body.cipher;
//   const kdf = body.kdf;

//   // ✅ accept both names
//   const kdf_iteration_raw = body.kdf_iteration ?? body.kdf_iterations;
//   const kdf_key_length_raw = body.kdf_key_length;

//   const salt = body.salt;
//   const nonce = body.nonce;
//   const cipher_text = body.cipher_text;
//   const mac = body.mac;
//   const created_at = body.created_at;

//   if (!isValidEmail(EmailAddress)) return badRequest(res, "Invalid EmailAddress");
//   if (!isNonEmptyString(key_type)) return badRequest(res, "Missing key_type");
//   if (!isNonEmptyString(cipher)) return badRequest(res, "Missing cipher");
//   if (!isNonEmptyString(kdf)) return badRequest(res, "Missing kdf");

//   const iter = parsePositiveInt(kdf_iteration_raw);
//   if (iter == null) return badRequest(res, "Invalid kdf_iteration");

//   const keyLen = parsePositiveInt(kdf_key_length_raw);
//   if (keyLen == null) return badRequest(res, "Invalid kdf_key_length");

//   if (!isNonEmptyString(salt)) return badRequest(res, "Missing salt");
//   if (!isNonEmptyString(nonce)) return badRequest(res, "Missing nonce");
//   if (!isNonEmptyString(cipher_text)) return badRequest(res, "Missing cipher_text");
//   if (!isNonEmptyString(mac)) return badRequest(res, "Missing mac");

//   const email = normalizeEmail(EmailAddress);

//   const query = `
//     INSERT INTO "users_private_data"
//       ("EmailAddress", "key_type", "cipher", "kdf", "kdf_iteration", "kdf_key_length", "salt", "nonce", "cipher_text", "mac", "created_at")
//     VALUES
//       ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($11, NOW()))
//     ON CONFLICT ("EmailAddress", "key_type")
//     DO UPDATE SET
//       "cipher" = EXCLUDED."cipher",
//       "kdf" = EXCLUDED."kdf",
//       "kdf_iteration" = EXCLUDED."kdf_iteration",
//       "kdf_key_length" = EXCLUDED."kdf_key_length",
//       "salt" = EXCLUDED."salt",
//       "nonce" = EXCLUDED."nonce",
//       "cipher_text" = EXCLUDED."cipher_text",
//       "mac" = EXCLUDED."mac",
//       "created_at" = EXCLUDED."created_at"
//     RETURNING
//       "EmailAddress", "key_type", "cipher", "kdf", "kdf_iteration", "kdf_key_length",
//       "salt", "nonce", "cipher_text", "mac", "created_at";
//   `;

//   // ✅ 11 values for $1..$11 (your current file was missing mac in values) :contentReference[oaicite:1]{index=1}
//   const values = [
//     email, // $1
//     key_type.trim(), // $2
//     cipher.trim(), // $3
//     kdf.trim(), // $4
//     iter, // $5
//     keyLen, // $6
//     salt, // $7
//     nonce, // $8
//     cipher_text, // $9
//     mac, // $10
//     created_at || null, // $11
//   ];

//   const result = await pool.query(query, values);
//   return res.status(201).json(result.rows[0]);
// });

// /**
//  * Get private encrypted blob by email
//  * GET /private_key?email=user@example.com
//  * Optional: &key_type=openpgp
//  */
// const getPrivateDataByEmail = asyncHandler(async (req, res) => {
//   console.log("Received getPrivateDataByEmail request with query:");
//   console.log(req.query);
//   const emailRaw = req.query?.email;
//   const keyType = req.query?.key_type;

//   if (!isValidEmail(emailRaw)) return badRequest(res, "Invalid email query param");
//   const email = normalizeEmail(emailRaw);

//   const hasKeyType = isNonEmptyString(keyType);

//   const query = hasKeyType
//     ? `
//       SELECT "key_type", "cipher", "kdf", "kdf_iteration", "kdf_key_length",
//              "salt", "nonce", "cipher_text", "mac", "created_at"
//       FROM "users_private_data"
//       WHERE "EmailAddress" = $1 AND "key_type" = $2
//       LIMIT 1
//     `
//     : `
//       SELECT "key_type", "cipher", "kdf", "kdf_iteration", "kdf_key_length",
//              "salt", "nonce", "cipher_text", "mac", "created_at"
//       FROM "users_private_data"
//       WHERE "EmailAddress" = $1
//       LIMIT 1
//     `;

//   const values = hasKeyType ? [email, keyType.trim()] : [email];
//   const result = await pool.query(query, values);

//   if (result.rows.length === 0) return notFound(res, "Private data not found");
//   return res.json(result.rows[0]);
// });

// /**
//  * Upload crypto flags
//  */
// const uploadCryptoFlags = asyncHandler(async (req, res) => {
//   const {
//     EmailAddress,
//     cryptoKeysGenerated,
//     algorithm,
//     generated_at,
//     uploaded_public_key,
//     uploaded_private_key,
//   } = req.body || {};

//   if (!isValidEmail(EmailAddress)) return badRequest(res, "Invalid EmailAddress");
//   if (typeof cryptoKeysGenerated !== "boolean")
//     return badRequest(res, "cryptoKeysGenerated must be boolean");
//   if (!isNonEmptyString(algorithm)) return badRequest(res, "Missing algorithm");
//   if (!isNonEmptyString(generated_at)) return badRequest(res, "Missing generated_at");
//   if (typeof uploaded_public_key !== "boolean")
//     return badRequest(res, "uploaded_public_key must be boolean");
//   if (typeof uploaded_private_key !== "boolean")
//     return badRequest(res, "uploaded_private_key must be boolean");

//   const email = normalizeEmail(EmailAddress);

//   const query = `
//     INSERT INTO "users_crypto_flags"
//       ("EmailAddress", "cryptoKeysGenerated", "algorithm", "generated_at", "uploaded_public_key", "uploaded_private_key")
//     VALUES
//       ($1, $2, $3, $4, $5, $6)
//     ON CONFLICT ("EmailAddress")
//     DO UPDATE SET
//       "cryptoKeysGenerated" = EXCLUDED."cryptoKeysGenerated",
//       "algorithm" = EXCLUDED."algorithm",
//       "generated_at" = EXCLUDED."generated_at",
//       "uploaded_public_key" = EXCLUDED."uploaded_public_key",
//       "uploaded_private_key" = EXCLUDED."uploaded_private_key"
//     RETURNING
//       "EmailAddress", "cryptoKeysGenerated", "algorithm", "generated_at", "uploaded_public_key", "uploaded_private_key";
//   `;

//   const values = [
//     email,
//     cryptoKeysGenerated,
//     algorithm.trim(),
//     generated_at,
//     uploaded_public_key,
//     uploaded_private_key,
//   ];

//   const result = await pool.query(query, values);
//   return res.status(201).json(result.rows[0]);
// });

// /**
//  * Get crypto flags by email
//  * GET /crypto_flags?email=user@example.com
//  */
// const getCryptoFlagsByEmail = asyncHandler(async (req, res) => {
//   const emailRaw = req.query?.email;

//   if (!isValidEmail(emailRaw)) return badRequest(res, "Invalid email query param");
//   const email = normalizeEmail(emailRaw);

//   const query = `
//     SELECT "cryptoKeysGenerated", "algorithm", "generated_at", "uploaded_public_key", "uploaded_private_key"
//     FROM "users_crypto_flags"
//     WHERE "EmailAddress" = $1
//   `;
//   const result = await pool.query(query, [email]);

//   if (result.rows.length === 0) return notFound(res, "Crypto flags not found");
//   return res.json(result.rows[0]);
// });

// const deleteUserPrivateData = asyncHandler(async (req, res) => {
//   const emailRaw = req.query?.email;
//   const keyType = req.query?.key_type;

//   if (!isValidEmail(emailRaw)) return badRequest(res, "Invalid email query param");
//   const email = normalizeEmail(emailRaw);

//   const query = keyType
//     ? `
//       DELETE FROM "users_private_data"
//       WHERE "EmailAddress" = $1 AND "key_type" = $2
//     `
//     : `
//       DELETE FROM "users_private_data"
//       WHERE "EmailAddress" = $1
//     `;

//   const values = keyType ? [email, keyType.trim()] : [email];
//   const result = await pool.query(query, values);

//   if (result.rowCount === 0) return notFound(res, "Private data not found");
//   return res.status(204).send();
// });


// const deleteUserCryptoFlags = asyncHandler(async (req, res) => {
//   const emailRaw = req.query?.email;
//   const keyType = req.query?.key_type;

//   if (!isValidEmail(emailRaw)) return badRequest(res, "Invalid email query param");
//   const email = normalizeEmail(emailRaw);
//   const query = `
//     DELETE FROM "users_crypto_flags"
//     WHERE "EmailAddress" = $1
//   `;
//   const values = [email];
//   const result = await pool.query
//   (query, values);

//   if (result.rowCount === 0) return notFound(res, "Crypto flags not found");
//   return res.status(204).send();
// });

// module.exports = {
//   uploadKeys,
//   getKeysByEmail,
//   updateSMIMECertificate,
//   getCertificateByEmail,
//   uploadPrivateKeyAndCertificate,
//   getPrivateDataByEmail,
//   uploadCryptoFlags,
//   getCryptoFlagsByEmail,
//   deleteUserPrivateData,
//   deleteUserCryptoFlags,
// };
