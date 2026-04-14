import { Router } from 'express';
import {
  enrollMFA,
  verifyMFA,
  logout,
  refreshMFASession,
} from '../controllers/auth.controller.js';

const router = Router();

/**
 * POST /auth/mfa/enroll
 * Enroll a user in MFA
 * Returns QR code as base64 data URL
 */
router.post('/mfa/enroll', enrollMFA);

/**
 * POST /auth/mfa/verify
 * Verify MFA token and establish session
 * Returns session token and sets secure cookie
 */
router.post('/mfa/verify', verifyMFA);

/**
 * POST /auth/logout
 * Clear session and log out user
 */
router.post('/logout', logout);

/**
 * POST /auth/mfa/refresh
 * Refresh MFA session to keep user logged in
 */
router.post('/mfa/refresh', refreshMFASession);

export default router;
