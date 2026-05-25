import 'dotenv/config';
import express from 'express';
import cors from 'cors';

import bootstrapRoutes from './routes/bootstrap.js';
import keysRoutes from './routes/keys.js';
import discoveryRoutes from './routes/discovery.js';
import health from './routes/health.js';
import { startBackgroundJobs } from './services/backgroundJobs.js';
import { initDatabase } from './db/database.js';

const app = express();

// ── CORS ──────────────────────────────────────────────────────────────────────
const corsOrigins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    // Allow non-browser clients (no Origin header) and wildcard local dev.
    if (!origin || corsOrigins.includes('*') || corsOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error(`CORS blocked origin: ${origin}`));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Auth-Payload',
    'X-Auth-Signature',
  ],
  exposedHeaders: ['Content-Type'],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ── Raw body capture for signed-request body-hash verification ────────────────
// Must be applied BEFORE express.json() so the raw Buffer is available to the
// verifySignedRequest middleware via req.rawBody.
app.use(
  express.json({
    limit: process.env.JSON_LIMIT || '1mb',
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ── Request logging (debug) ──────────────────────────────────────────────────
const requestLoggingEnabled =
  process.env.REQUEST_LOGGING === 'true' || process.env.NODE_ENV !== 'production';

if (requestLoggingEnabled) {
  app.use((req, res, next) => {
    const startedAt = Date.now();
    const requestId = Math.random().toString(36).slice(2, 10);

    const safeHeaders = {
      origin: req.headers.origin,
      'content-type': req.headers['content-type'],
      'user-agent': req.headers['user-agent'],
      authorization: req.headers.authorization ? '[redacted]' : undefined,
      'x-auth-payload': req.headers['x-auth-payload'] ? '[redacted]' : undefined,
      'x-auth-signature': req.headers['x-auth-signature'] ? '[redacted]' : undefined,
    };

    console.log(
      `[req:${requestId}] -> ${req.method} ${req.originalUrl} ip=${req.ip} headers=${JSON.stringify(safeHeaders)}`
    );

    res.on('finish', () => {
      const durationMs = Date.now() - startedAt;
      console.log(
        `[req:${requestId}] <- ${res.statusCode} ${req.method} ${req.originalUrl} ${durationMs}ms`
      );
    });

    next();
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────
//
// Discovery routes are mounted at /keys but come BEFORE the protected keys
// router so that /keys/preference and /keys/revoked (no auth) are matched first.
app.use('/auth', bootstrapRoutes);
app.use('/keys', discoveryRoutes);
app.use('/keys', keysRoutes);
app.use('/health', health); // Health check route

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'not_found', message: 'Route not found' });
});

// ── Centralized error handler ─────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[error]', err.message, err.stack?.split('\n')[1]?.trim() ?? '');
  res.status(500).json({ error: 'server_error', message: 'An internal server error occurred' });
});

// ── Startup ───────────────────────────────────────────────────────────────────
const PORT = Number(process.env.PORT) || 3000;

try {
  await initDatabase();
  await startBackgroundJobs();

  app.listen(PORT, () => {
    console.log(`SecMail keys server listening on http://localhost:${PORT}`);
    console.log(`PostgreSQL: ${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'secmail'}`);
    if (!process.env.FETCH_TOKEN_SECRET) {
      console.warn('[WARN] FETCH_TOKEN_SECRET is not set — OTP/SRP fetch tokens will fail');
    }
    if (!process.env.SMTP_HOST) {
      console.warn('[WARN] SMTP_HOST is not set — OTPs will be printed to console instead of emailed');
    }
  });
} catch (err) {
  console.error('[startup] Failed to initialize server:', err);
  process.exit(1);
}
