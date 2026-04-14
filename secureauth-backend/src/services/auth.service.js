import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import db from '../config/db.js';
import speakeasy from 'speakeasy';

export const registerUser = async ({ email, password }) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );

  if (rows.length > 0) {
    throw new Error('User already exists');
  }

  const password_hash = await bcrypt.hash(password, 10);

  // 🔐 generate temp secret (for setup)
  const secret = speakeasy.generateSecret({ length: 20 });

  const [result] = await db.query(
    `INSERT INTO users (email, password_hash, totp_secret, twofa_enabled, temp_2fa_secret)
     VALUES (?, ?, ?, ?, ?)`,
    [email, password_hash, '', false, secret.base32]
  );

  return {
    id: result.insertId,
    email,
    otpauth_url: secret.otpauth_url
  };
};





export const loginUser = async ({ email, password }) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );

  if (rows.length === 0) throw new Error('Invalid credentials');

  const user = rows[0];

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) throw new Error('Invalid credentials');

  if (user.twofa_enabled) {
    const tempToken = jwt.sign(
      { id: user.id, email: user.email, temp: true },
      process.env.JWT_SECRET,
      { expiresIn: '5m' }
    );

    return {
      requires_2fa: true,
      tempToken
    };
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  return { token };
};


