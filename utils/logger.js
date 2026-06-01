import { createRequire } from 'module';

const LEVELS = { fatal: 60, error: 50, warn: 40, info: 30, debug: 20, trace: 10 };
const currentLevel = LEVELS[process.env.LOG_LEVEL] ?? 30;
const isProd = process.env.NODE_ENV === 'production';

function write(level, msg, extra = {}) {
  if (LEVELS[level] < currentLevel) return;
  if (isProd) {
    process.stdout.write(
      JSON.stringify({ time: new Date().toISOString(), level, msg, ...extra }) + '\n'
    );
  } else {
    const tag = `[${new Date().toISOString()}] ${level.toUpperCase().padEnd(5)}`;
    const extras = Object.keys(extra).length ? ' ' + JSON.stringify(extra) : '';
    process.stdout.write(`${tag} ${msg}${extras}\n`);
  }
}

export const logger = {
  fatal: (msg, extra = {}) => write('fatal', msg, extra),
  error: (msg, extra = {}) => write('error', msg, extra),
  warn: (msg, extra = {}) => write('warn', msg, extra),
  info: (msg, extra = {}) => write('info', msg, extra),
  debug: (msg, extra = {}) => write('debug', msg, extra),
};

/** Express middleware — logs request start and finish as structured JSON. */
export function requestLogger(req, res, next) {
  const startedAt = Date.now();
  const requestId = Math.random().toString(36).slice(2, 10);
  req.requestId = requestId;
  logger.info('request received', {
    requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    origin: req.headers.origin,
    userAgent: req.headers['user-agent'],
    hasAuth: !!(
      req.headers.authorization ||
      req.headers['x-auth-payload']
    ),
  });

  res.on('finish', () => {
    const lvl = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    logger[lvl]('request completed', {
      requestId,
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - startedAt,
    });
  });

  next();
}
