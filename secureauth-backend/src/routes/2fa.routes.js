import express from 'express';
import { setup2FA, verify2FA } from '../controllers/2fa.controller.js';

const router = express.Router();

router.post('/setup', setup2FA);
router.post('/verify', verify2FA);

export default router;
