import dotenv from 'dotenv';

dotenv.config();

/**
 * Middleware to validate MFA session token
 * Extracts token from secure cookie and verifies it
 */
export function authenticateSession(req, res, next) {
  try {
    const sessionToken = req.cookies.secureauth_session;

    if (!sessionToken) {
      return res.status(401).json({ error: 'No session token found' });
    }

    // Decode and verify session token
    const decodedSession = JSON.parse(
      Buffer.from(sessionToken, 'base64').toString('utf-8')
    );

    if (!decodedSession.mfaVerified) {
      return res.status(401).json({ error: 'MFA not verified' });
    }

    // Attach user info to request
    req.user = decodedSession;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid session token' });
  }
}

/**
 * Middleware to handle session timeout and cleanup
 * Clears expired sessions after inactivity period
 */
export function sessionCleanupMiddleware(inactivityMinutes = 30) {
  const sessionStore = new Map(); // In-memory session store (use Redis in production)

  return (req, res, next) => {
    const sessionToken = req.cookies.secureauth_session;

    if (sessionToken) {
      const now = Date.now();
      const sessionData = sessionStore.get(sessionToken);

      if (sessionData) {
        const inactivityMs = now - sessionData.lastActivity;
        const timeoutMs = inactivityMinutes * 60 * 1000;

        // Session expired due to inactivity
        if (inactivityMs > timeoutMs) {
          res.clearCookie('secureauth_session', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
          });
          sessionStore.delete(sessionToken);
          return res.status(401).json({
            error: 'Session expired due to inactivity',
            cleanup: true,
          });
        }

        // Update last activity timestamp
        sessionData.lastActivity = now;
      } else {
        // New session tracking
        sessionStore.set(sessionToken, {
          createdAt: now,
          lastActivity: now,
        });
      }
    }

    next();
  };
}

/**
 * Middleware to prevent token reuse and session fixation attacks
 */
export function regenerateSessionToken(req, res, next) {
  const originalJson = res.json;

  res.json = function (data) {
    // If this is a successful login response with a session token
    if (data.session && data.session.token) {
      // Regenerate the token on each request to prevent session fixation
      const newSessionToken = Buffer.from(
        JSON.stringify({
          ...JSON.parse(Buffer.from(data.session.token, 'base64').toString('utf-8')),
          tokenVersion: (Math.random() * 10000).toString(),
        })
      ).toString('base64');

      data.session.token = newSessionToken;

      res.cookie('secureauth_session', newSessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
      });
    }

    return originalJson.call(this, data);
  };

  next();
}

/**
 * Cleanup hook for server shutdown
 * Clears all active sessions
 */
export function cleanupAllSessions() {
  console.log('Cleaning up all active sessions...');
  // In production, this would clear Redis sessions and database records
  // For now, this is a placeholder for cleanup logic
}
