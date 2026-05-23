/**
 * Wraps an async Express handler so that rejected promises are forwarded to
 * the next() error handler instead of crashing the process.
 * Required for Express 4 (Express 5 handles this natively).
 */
export const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
