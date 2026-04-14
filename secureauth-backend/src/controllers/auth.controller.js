import { generateMFASecret, verifyMFAToken, verifyBackupCode } from '../services/mfa.service.js';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Controller for MFA enrollment
 * Returns QR code as base64 image
 */
export async function enrollMFA(req, res) {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Generate MFA secret and QR code (base64 data URL)
    const mfaData = await generateMFASecret(email);

    res.status(200).json({
      message: 'MFA secret generated successfully',
      qrCode: mfaData.qrCode, // base64 encoded PNG image
      otpauthUrl: mfaData.otpauthUrl,
      secret: mfaData.secret,
      backupCodes: mfaData.backup_codes,
    });
  } catch (error) {
    console.error('MFA enrollment error:', error);
    res.status(500).json({ error: error.message });
  }
}

/**
 * Controller for MFA verification and session establishment
 */
export async function verifyMFA(req, res) {
  try {
    const { email, token, mfaSecret } = req.body;

    if (!email || !token || !mfaSecret) {
      return res.status(400).json({ error: 'Email, token, and mfaSecret are required' });
    }

    // Verify the TOTP token
    const isValid = verifyMFAToken(token, mfaSecret);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid MFA token' });
    }

    // Create a per-request Supabase client with user session
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    // Verify user exists and set session
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate session token
    const sessionToken = Buffer.from(
      JSON.stringify({ userId: user.id, email: email, mfaVerified: true })
    ).toString('base64');

    // Set secure session cookie
    res.cookie('secureauth_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.status(200).json({
      message: 'MFA verified successfully',
      user: { id: user.id, email: user.email },
      session: { token: sessionToken },
    });
  } catch (error) {
    console.error('MFA verification error:', error);
    res.status(500).json({ error: error.message });
  }
}

/**
 * Controller for session cleanup and logout
 */
export async function logout(req, res) {
  try {
    // Clear session cookie
    res.clearCookie('secureauth_session', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    // Optional: Invalidate session in database if you track active sessions
    // await supabase
    //   .from('sessions')
    //   .delete()
    //   .eq('sessionToken', req.cookies.secureauth_session);

    res.status(200).json({
      message: 'Logged out successfully',
      session: null,
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: error.message });
  }
}

/**
 * Controller for MFA token refresh (keep session alive)
 */
export async function refreshMFASession(req, res) {
  try {
    const { email, mfaSecret } = req.body;

    if (!email || !mfaSecret) {
      return res.status(400).json({ error: 'Email and mfaSecret are required' });
    }

    // Optionally verify user still exists
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Refresh session token
    const sessionToken = Buffer.from(
      JSON.stringify({ userId: user.id, email: email, mfaVerified: true })
    ).toString('base64');

    res.cookie('secureauth_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: 'Session refreshed',
      session: { token: sessionToken },
    });
  } catch (error) {
    console.error('Session refresh error:', error);
    res.status(500).json({ error: error.message });
  }
}
