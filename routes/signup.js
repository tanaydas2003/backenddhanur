const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const router = express.Router();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later.' }
});

router.use(limiter);

router.use(morgan('combined'));

module.exports = (pool) => {
  router.post(
    '/',
    [
      body('userType').isIn(['individual', 'organization']).withMessage('Invalid user type'),
      body('email').isEmail().withMessage('Invalid email address'),
      body('password')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
        .custom((value) => {
          if (value === value.toUpperCase()) {
            throw new Error('Password must not contain all capital letters');
          }
          if (/\d{2,}/.test(value)) {
            throw new Error('Password must not contain serial numbers');
          }
          return true;
        }),
      body('firstName').optional().isString(),
      body('lastName').optional().isString(),
      body('phoneNo').optional().isString(),
      body('dob').optional().isISO8601().withMessage('Date of birth must be a valid date'),
      body('orgName').optional().isString(),
      body('adminFullName').optional().isString(),
      body('orgWebsite').optional().isURL()
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const {
        userType,
        email,
        password,
        firstName,
        lastName,
        phoneNo,
        dob,
        orgName,
        adminFullName,
        orgWebsite
      } = req.body;

      try {
        const table = userType === 'individual' ? 'individual_users' : 'organization_users';
        const userExists = await pool.query(`SELECT * FROM ${table} WHERE email = $1`, [email]);
        if (userExists.rows.length > 0) {
          return res.status(400).json({ message: `${userType.charAt(0).toUpperCase() + userType.slice(1)} user already exists` });
        }

        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS));
        let newUser;

        if (userType === 'individual') {
          newUser = await pool.query(
            'INSERT INTO individual_users (email, password, first_name, last_name, phone_no, dob) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [email, hashedPassword, firstName, lastName, phoneNo, dob]
          );
        } else if (userType === 'organization') {
          const newOrgUser = await pool.query(
            'INSERT INTO organization_users (email, password) VALUES ($1, $2) RETURNING user_id',
            [email, hashedPassword]
          );
          const userId = newOrgUser.rows[0].user_id;
          newUser = await pool.query(
            `INSERT INTO organizations (organization_id, user_id, org_name, admin_full_name, phone_no, org_website) 
             VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5) 
             RETURNING organization_id, user_id, org_name, admin_full_name, phone_no, org_website`,
            [userId, orgName, adminFullName, phoneNo, orgWebsite]
          );
        } else {
          return res.status(400).json({ message: 'Invalid user type' });
        }

        res.status(201).json(newUser.rows[0]);
      } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
      }
    }
  );

  return router;
};