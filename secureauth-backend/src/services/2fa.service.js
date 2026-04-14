import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import jwt from 'jsonwebtoken';
import db from '../config/db.js';

export const generateQRCode = async (userId) => {
  const [rows] = await db.query(
    'SELECT temp_2fa_secret FROM users WHERE id = ?',
    [userId]
  );

  const secret = rows[0].temp_2fa_secret;

  const otpauth = speakeasy.otpauthURL({
    secret,
    label: 'SecureAuthApp',
    encoding: 'base32'
  });

  const qr = await qrcode.toDataURL(otpauth);

  return qr;
};


export const verifyOTP = async ({ tempToken, otp }) => {
    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
  
    const [rows] = await db.query(
      'SELECT * FROM users WHERE id = ?',
      [decoded.id]
    );
  
    const user = rows[0];
  
    const verified = speakeasy.totp.verify({
      secret: user.temp_2fa_secret || user.totp_secret,
      encoding: 'base32',
      token: otp
    });
  
    if (!verified) {
      throw new Error('Invalid OTP');
    }
  
    // 🔐 Enable 2FA if first time
    if (!user.twofa_enabled) {
      await db.query(
        `UPDATE users 
         SET twofa_enabled = true,
             totp_secret = temp_2fa_secret,
             temp_2fa_secret = NULL
         WHERE id = ?`,
        [user.id]
      );
    }
  
    // 🔑 ISSUE FINAL TOKEN
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  
    return { token };
  };
  