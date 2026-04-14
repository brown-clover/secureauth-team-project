import { generateQRCode, verifyOTP } from '../services/2fa.service.js';
import jwt from 'jsonwebtoken';

export const setup2FA = async (req, res) => {
    try {
      const { tempToken } = req.body;
  
      const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
  
      const qr = await generateQRCode(decoded.id);
  
      res.json({ qr });
    } catch (err) {
      console.error(err); // 👈 ADD THIS
      res.status(400).json({ message: err.message }); // 👈 SHOW REAL ERROR
    }
  };
  


export const verify2FA = async (req, res) => {
  try {
    const { tempToken, otp } = req.body;

    const result = await verifyOTP({ tempToken, otp });

    res.json(result);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};
