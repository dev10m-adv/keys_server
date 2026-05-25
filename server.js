import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import bootstrapRoutes from './routes/bootstrap.js';
import keysRoutes from './routes/keys.js';
import discoveryRoutes from './routes/discovery.js';
import health from './routes/health.js';
import { startBackgroundJobs } from './services/backgroundJobs.js';
import { initDatabase, closePool } from './db/database.js';
import { logger, requestLogger } from './utils/logger.js';

const app = express();

// ── Security headers (helmet) ─────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // API server — CSP is not applicable
  crossOriginEmbedderPolicy: false,
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
const corsOrigins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

if (process.env.NODE_ENV === 'production' && corsOrigins.includes('*')) {
  logger.warn('CORS_ORIGINS is set to wildcard (*) in production — set it to explicit origins');
}

const corsOptions = {
  origin(origin, callback) {
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
// Applied BEFORE express.json() so req.rawBody is available to verifySignedRequest.
app.use(
  express.json({
    limit: process.env.JSON_LIMIT || '1mb',
    verify: (req, _res, buf) => { req.rawBody = buf; },
  })
);

// ── Structured request logging ────────────────────────────────────────────────
app.use(requestLogger);

// ── Global rate limit ─────────────────────────────────────────────────────────
// Broad safety net; individual routes apply stricter limits where needed.
// NOTE: uses in-memory store — for multi-instance deployments, swap for Redis:
//   npm install rate-limit-redis ioredis
const globalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many requests, please slow down.' },
  skip: (req) => req.path === '/health', // health checks bypass the global limit
});

app.use(globalRateLimit);

// ── Routes ────────────────────────────────────────────────────────────────────
//
// Discovery routes are mounted at /keys BEFORE the protected keys router so that
// /keys/preference and /keys/revoked (no auth) are matched first.
app.use('/auth',   bootstrapRoutes);
app.use('/keys',   discoveryRoutes);
app.use('/keys',   keysRoutes);
app.use('/health', health);

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'not_found', message: 'Route not found' });
});

// ── Centralized error handler ─────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  logger.error('unhandled error', { message: err.message, stack: err.stack?.split('\n')[1]?.trim() });
  res.status(500).json({ error: 'server_error', message: 'An internal server error occurred' });
});

// ── Startup ───────────────────────────────────────────────────────────────────
const PORT = Number(process.env.PORT) || 3000;

try {
  await initDatabase();
  await startBackgroundJobs();
} catch (err) {
  logger.fatal('startup failed', { err: err.message });
  process.exit(1);
}

const server = app.listen(PORT, () => {
  logger.info('server started', {
    port: PORT,
    env: process.env.NODE_ENV || 'development',
    db: `${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'secmail'}`,
  });

  if (!process.env.FETCH_TOKEN_SECRET) {
    logger.warn('FETCH_TOKEN_SECRET is not set — OTP/fetch tokens will fail');
  }
  if (!process.env.SMTP_HOST) {
    logger.warn('SMTP_HOST is not set — OTPs will be printed to console instead of emailed');
  }
  if (process.env.NODE_ENV !== 'production') {
    logger.warn('NODE_ENV is not "production" — running in development mode');
  }
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
async function shutdown(signal) {
  logger.info('shutdown initiated', { signal });

  // Stop accepting new connections; wait for in-flight requests to finish
  server.close(async () => {
    logger.info('HTTP server closed');
    try {
      await closePool();
      logger.info('DB pool closed');
    } catch (err) {
      logger.error('error closing DB pool', { err: err.message });
    }
    process.exit(0);
  });

  // Force-exit if graceful shutdown takes longer than 10 seconds
  setTimeout(() => {
    logger.error('graceful shutdown timed out — forcing exit');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  logger.error('unhandled promise rejection', { reason: String(reason) });
});

process.on('uncaughtException', (err) => {
  logger.fatal('uncaught exception', { err: err.message, stack: err.stack });
  process.exit(1);
});
