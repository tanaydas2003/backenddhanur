

const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

require('dotenv').config();

const router = express.Router();

module.exports = (pool) => {
  // Local login route
  router.post('/',
    [
      body('userType').isIn(['individual', 'organization']).withMessage('Invalid user type'),
      body('email').isEmail().withMessage('Invalid email address'),
      body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { userType, email, password } = req.body;

      try {
        let user;
        if (userType === 'individual') {
          const individualUser = await pool.query('SELECT * FROM individual_users WHERE email = $1', [email]);
          if (individualUser.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
          }
          user = individualUser.rows[0];
        } 
        else if (userType === 'organization') {
          const organizationUser = await pool.query('SELECT * FROM organization_users WHERE email = $1', [email]);
          if (organizationUser.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
          }
          user = organizationUser.rows[0];
        } 
        else {
          return res.status(400).json({ message: 'Invalid user type' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, userType }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token, userType });
      } 
      catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    }
  );

  // Google OAuth strategy
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/login/google/callback',
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const userResult = await pool.query('SELECT * FROM individual_users WHERE google_id = $1', [profile.id]);
      let user = userResult.rows[0];

      if (!user) {
        const newUserResult = await pool.query(
          'INSERT INTO individual_users (google_id, first_name, last_name, email, password) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [profile.id, profile.name.givenName, profile.name.familyName || 'not_available', profile.emails[0].value, 'google']
      );
        user = newUserResult.rows[0];
      }

      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));

  // GitHub OAuth strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/login/github/callback',
},
async (accessToken, refreshToken, profile, done) => {
  try {
    const userResult = await pool.query('SELECT * FROM individual_users WHERE github_id = $1', [profile.id]);
    let user = userResult.rows[0];

    if (!user) {
      const displayName = profile.displayName || profile.username || 'Unknown';
      const email = (profile.emails && profile.emails[0]) ? profile.emails[0].value : 'no-email@github.com';
      const newUserResult = await pool.query(
        'INSERT INTO individual_users (github_id, first_name, last_name, email, password) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [profile.id, displayName, 'not_available', email, 'github']
      );
      user = newUserResult.rows[0];
    }

    done(null, user);
  } catch (err) {
    done(err, null);
  }
}
));

  // Routes for OAuth
  router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    res.redirect('http://localhost:3001'); // Redirect to your frontend after successful login
  });

  router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
  router.get('/github/callback', passport.authenticate('github', { failureRedirect: '/' }), (req, res) => {
    res.redirect('http://localhost:3001'); // Redirect to your frontend after successful login
  });

  return router;
};
