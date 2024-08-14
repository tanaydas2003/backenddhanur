const express = require('express');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const router = express.Router();
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

module.exports = (pool) => {
  router.post(
    '/forgot-password',
    [
      body('userType').isIn(['individual', 'organization']).withMessage('Invalid user type'),
      body('email').isEmail().withMessage('Invalid email address')
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { userType, email } = req.body;

      try {
        let user;
        if (userType === 'individual') {
          const individualUser = await pool.query('SELECT * FROM individual_users WHERE email = $1', [email]);
          if (individualUser.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
          }
          user = individualUser.rows[0];
        } else if (userType === 'organization') {
          const organizationUser = await pool.query('SELECT * FROM organization_users WHERE email = $1', [email]);
          if (organizationUser.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
          }
          user = organizationUser.rows[0];
        } else {
          return res.status(400).json({ message: 'Invalid user type' });
        }
        const otp = generateOTP();
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Your OTP Code for Password Reset',
          text: `Your OTP code is ${otp}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Error sending OTP:', error);
            return res.status(500).json({ message: 'Error sending OTP' });
          }
          console.log('Email sent: ' + info.response);
          const otpToken = jwt.sign({ email, otp }, process.env.JWT_SECRET, { expiresIn: '10m' });

          res.status(200).json({ message: 'OTP sent to your email', otpToken });
        });
      } catch (error) {
        console.error('Error during forgot password:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    }
  );

  router.post(
    '/reset-password',
    [
      body('email').isEmail().withMessage('Invalid email address'),
      body('userType').isIn(['individual', 'organization']).withMessage('Invalid user type'),
      body('otp').isLength({ min: 6, max: 6 }).withMessage('Invalid OTP'),
      body('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, userType, otp, newPassword } = req.body;

      try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.email !== email || decoded.otp !== otp) {
          return res.status(400).json({ message: 'Invalid OTP' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_SALT_ROUNDS));
        let user;
        if (userType === 'individual') {
          user = await pool.query('UPDATE individual_users SET password = $1 WHERE email = $2 RETURNING *', [hashedPassword, email]);
        } else if (userType === 'organization') {
          user = await pool.query('UPDATE organization_users SET password = $1 WHERE email = $2 RETURNING *', [hashedPassword, email]);
        }

        if (user.rows.length > 0) {
          res.status(200).json({ message: 'Password reset successful' });
        } else {
          res.status(400).json({ message: 'User not found' });
        }
      } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    }
  );

  return router;
};
