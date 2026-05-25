// LEGACY — superseded by db/database.js (ESM adapter with ? → $N conversion).
// This file is no longer imported anywhere and will be removed in a future cleanup.
// index.js
const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "crypto_keys",
  password: process.env.DB_PASSWORD || "postgres",
  port: Number(process.env.DB_PORT) || 5432,
  max: Number(process.env.DB_POOL_MAX) || 10,
  idleTimeoutMillis: Number(process.env.DB_POOL_IDLE_TIMEOUT_MS) || 30000,
  connectionTimeoutMillis: Number(process.env.DB_POOL_CONN_TIMEOUT_MS) || 10000,
});

pool.on("connect", () => console.log("PostgreSQL pool connected"));
pool.on("error", (err) => console.error("PostgreSQL pool error:", err));

module.exports = pool;
