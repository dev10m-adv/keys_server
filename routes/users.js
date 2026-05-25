// // users.js
// const express = require("express");
// const router = express.Router();

// const {
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
// } = require("../controllers/usersController.js");

// router.get("/test", (req, res) => res.send("User routes are working"));

// // Public keys
// router.post("/", uploadKeys);
// router.get("/email", getKeysByEmail);

// // S/MIME certificate
// router.put("/smime_certificate", updateSMIMECertificate);
// router.get("/smime_certificate", getCertificateByEmail);

// // Private encrypted blob
// router.post("/private_key", uploadPrivateKeyAndCertificate);
// router.get("/private_key", getPrivateDataByEmail);

// // Crypto flags
// router.post("/crypto_flags", uploadCryptoFlags);
// router.get("/crypto_flags", getCryptoFlagsByEmail);

// /// Delete all private data for a user (for GDPR compliance)
// router.delete("/private_data", deleteUserPrivateData);
// router.delete("/crypto_flags", deleteUserCryptoFlags);

// module.exports = router;
