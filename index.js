
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


const app = express();
const port = process.env.PORT || 3000;


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

app.use(cors({
  origin: 'http://localhost:3001',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: true,
}));


app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id); 
});


passport.deserializeUser((id, done) => {
  pool.query('SELECT * FROM individual_users WHERE id = $1', [id], (err, results) => {
    if (err) {
      return done(err);
    }
    done(null, results.rows[0]);
  });
});

app.use('/signup', signupRoute(pool));
app.use('/login', loginRoute(pool)); 
app.use('/auth', forgotPasswordRoute(pool));


app.options('*', cors());


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
