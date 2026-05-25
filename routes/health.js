import { Router } from 'express';
import * as discovery from '../controllers/healthController.js';

const router = Router();

router.get('/', discovery.healthCheck);

export default router;
