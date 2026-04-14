import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

/**
 * Generate TOTP secret and QR code as base64 data URL
 */
export async function generateMFASecret(email) {
  try {
    const secret = speakeasy.generateSecret({
      name: `SecureAuth (${email})`,
      issuer: 'SecureAuth',
      length: 32,
    });

    // Convert otpauth_url to base64 QR code data URL
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      qrCode: qrDataUrl, // returns data:image/png;base64,...
      otpauthUrl: secret.otpauth_url,
      backup_codes: generateBackupCodes(),
    };
  } catch (error) {
    throw new Error(`MFA secret generation failed: ${error.message}`);
  }
}

/**
 * Verify TOTP token against secret
 */
export function verifyMFAToken(token, secret) {
  try {
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2, // Allow 2 time windows (30 seconds each way)
    });

    return verified;
  } catch (error) {
    throw new Error(`MFA token verification failed: ${error.message}`);
  }
}

/**
 * Generate backup codes for account recovery
 */
export function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = Array.from({ length: 6 }, () =>
      String.fromCharCode(65 + Math.floor(Math.random() * 26))
    ).join('');
    codes.push(code);
  }
  return codes;
}

/**
 * Verify backup code (removes it from list after use)
 */
export function verifyBackupCode(token, backupCodes) {
  const index = backupCodes.indexOf(token.toUpperCase());
  if (index > -1) {
    backupCodes.splice(index, 1); // Remove used code
    return true;
  }
  return false;
}
