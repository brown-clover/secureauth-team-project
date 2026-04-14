import express from 'express';
import { verifyToken } from '../middleware/auth.middleware.js';

const router = express.Router();

router.get('/dashboard', verifyToken, (req, res) => {
  res.json({
    message: 'Welcome to dashboard',
    user: req.user,
  });
});

export default router;
