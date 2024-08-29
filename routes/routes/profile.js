const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

module.exports = (pool) => {
  // Middleware to check JWT token
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    console.log('Auth Header:', authHeader); // Log the full authorization header
  
    if (token == null) {
      console.log('No token provided');
      return res.sendStatus(401); // If no token
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.log('Token verification error:', err);
        return res.sendStatus(403); // If token is not valid
      }
      console.log('Token is valid, user:', user);
      req.user = user;
      next();
    });
  };
  

  // Profile route
  router.get('/', authenticateToken, async (req, res) => {
    const { id, userType } = req.user;

    try {
      let query = '';
      let params = [id];
      let result;

      if (userType === 'individual') {
        query = 'SELECT email, first_name AS full_name, dob, phone_no FROM individual_users WHERE id = $1';
        result = await pool.query(query, params);
      } else if (userType === 'organization') {
        // Fetch email from organization_users and organization details from organizations
        query = `
          SELECT ou.email, o.org_name, o.admin_full_name, o.phone_no, o.org_website 
          FROM organization_users ou
          JOIN organizations o ON ou.id = o.id
          WHERE ou.id = $1
        `;
        result = await pool.query(query, params);
      }

      console.log('Query Result:', result.rows); // Log the query result
      if (result && result.rows.length > 0) {
        res.status(200).json(result.rows[0]); // Return the organization details along with the email
      } else {
        res.status(404).json({ message: 'Profile not found' });
      }
    } catch (error) {
      console.error('Error fetching profile:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });


  return router;
};