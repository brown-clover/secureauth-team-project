import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes.js';
import {
  sessionCleanupMiddleware,
  regenerateSessionToken,
} from './middleware/auth.middleware.js';

const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Session management middleware
app.use(sessionCleanupMiddleware(30)); // 30 minutes inactivity timeout
app.use(regenerateSessionToken);

app.get('/', (req, res) => {
  res.send('SecureAuth API running...');
});

// Auth routes (MFA enrollment, verification, logout, refresh)
app.use('/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date() });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

export default app;
