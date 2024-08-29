require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const signupRoute = require('./routes/signup');
const loginRoute = require('./routes/login');
const forgotPasswordRoute = require('./routes/forgot');
const profileRoute = require('./routes/profile');
const path = require('path');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false,
  },
});

// CORS configuration
app.use(cors({
  origin: 'http://localhost:3001',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: true,
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Serialization of the user for the session
passport.serializeUser((user, done) => {
  console.log("Serializing user:", user); 
  // done(null, user.id); // Assuming user object has an 'id' property
  done(null, { id: user.id, userType: user.userType });
});

// Deserialization of the user from the session
// passport.deserializeUser((id, done) => {
//   pool.query('SELECT * FROM individual_users WHERE id = $1', [id], (err, results) => {
//     if (err) {
//       return done(err);
//     }
//     done(null, results.rows[0]); // Assuming user data is returned in rows[0]
//   });
// });



// passport.deserializeUser((id, done) => {
//   // First, check if the user exists in individual_users
//   pool.query('SELECT * FROM individual_users WHERE id = $1', [id], (err, results) => {
//     if (err) {
//       return done(err);
//     }

//     if (results.rows.length > 0) {
//       // User found in individual_users
//       return done(null, { ...results.rows[0], userType: 'individual' });
//     }

//     // If not found in individual_users, check in organization_users
//     pool.query('SELECT * FROM organization_users WHERE id = $1', [id], (err, results) => {
//       if (err) {
//         return done(err);
//       }

//       if (results.rows.length > 0) {
//         // User found in organization_users
//         return done(null, { ...results.rows[0], userType: 'organization' });
//       }

//       // If the user is not found in either table, return an error
//       return done(new Error('User not found'), null);
//     });
//   });
// });

passport.deserializeUser((userSession, done) => {
  const { id, userType } = userSession;
  let query = '';
  if (userType === 'individual') {
    query = 'SELECT * FROM individual_users WHERE id = $1';
  } else if (userType === 'organization') {
    query = 'SELECT * FROM organization_users WHERE id = $1';
  }

  pool.query(query, [id], (err, results) => {
    if (err) {
      return done(err);
    }
    if (results.rows.length > 0) {
      return done(null, { ...results.rows[0], userType });
    } else {
      return done(new Error('User not found'), null);
    }
  });
});


// Include your existing routes
app.use('/signup', signupRoute(pool));
app.use('/login', loginRoute(pool)); // OAuth routes are now included here
app.use('/auth', forgotPasswordRoute(pool));
app.use('/profile', profileRoute(pool));
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, './routes/privacy.html'));
}); 
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, './routes/terms.html'));
}); 

// Handle preflight requests
app.options('*', cors());

// Connect to the database
pool.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
  } else {
    console.log('Successfully connected to the database');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

