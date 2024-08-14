
require('dotenv').config();
const { Pool } = require('pg');

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

const createTables = async () => {
  const client = await pool.connect();
  try {
    await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";');

    // Create individual_users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS individual_users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        phone_no VARCHAR(20) NOT NULL,
        dob DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create organization_users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS organization_users (
        user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create organizations table with uniqueid as the primary key
    await client.query(`
      CREATE TABLE IF NOT EXISTS organizations (
        organization_id UUID NOT NULL DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL,
        uniqueid VARCHAR(100) GENERATED ALWAYS AS (organization_id::text || '-' || user_id::text) STORED PRIMARY KEY,
        org_name VARCHAR(255) NOT NULL,
        admin_full_name VARCHAR(255) NOT NULL,
        phone_no VARCHAR(20) NOT NULL,
        org_website VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_user_id FOREIGN KEY(user_id) REFERENCES organization_users(user_id)
      );
    `);

    console.log('Tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
  } finally {
    client.release();
  }
};

createTables().catch(err => console.error('Error executing script:', err));



