import { pingDatabase } from '../db/database.js';
import { asyncHandler } from '../utils/asyncHandler.js';

export const healthCheck = asyncHandler(async (_req, res) => {
  try {
    await pingDatabase();
  } catch (err) {
    return res.status(503).json({
      status: 'error',
      db: 'unreachable',
      message: err.message,
    });
  }
  res.status(200).json({ status: 'ok', db: 'connected' });
});
