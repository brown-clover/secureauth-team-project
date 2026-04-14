import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import db from '../config/db.js';

export const registerUser = async ({ email, password }) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );

  if (rows.length > 0) {
    throw new Error('User already exists');
  }

  const password_hash = await bcrypt.hash(password, 10);

  const [result] = await db.query(
    `INSERT INTO users (email, password_hash, totp_secret, twofa_enabled)
     VALUES (?, ?, ?, ?)`,
    [email, password_hash, '', false]
  );

  return {
    id: result.insertId,
    email,
  };
};


export const loginUser = async ({ email, password }) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );

  if (rows.length === 0) {
    throw new Error('Invalid credentials');
  }

  const user = rows[0];

  const isMatch = await bcrypt.compare(password, user.password_hash);

  if (!isMatch) {
    throw new Error('Invalid credentials');
  }

  // 🔐 IF 2FA ENABLED → STOP HERE
  if (user.twofa_enabled) {
    const tempToken = jwt.sign(
      { id: user.id, email: user.email, temp: true },
      process.env.JWT_SECRET,
      { expiresIn: '5m' }
    );

    return {
      requires_2fa: true,
      tempToken,
      message: 'OTP verification required'
    };
  }

  // ✅ ONLY users WITHOUT 2FA get full token
  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  return { token };
};


export const completeLoginAfter2FA = async (user) => {
  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  return { token };
};
