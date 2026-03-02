const { Pool } = require('pg');

const pool = new Pool({
  host: 'carwash-dev-pg.ctg2geqy269w.ap-south-1.rds.amazonaws.com',
  port: 5432,
  database: 'car_wash',
  user: 'carwash_app',
  password: 'J6Un&J5Ljy#uT3sWZ5',
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('connect', () => {
  console.log('Connected to PostgreSQL');
});

pool.on('error', (err) => {
  console.error('Database connection error:', err.message, err.stack);
});

// Simple query - auto release
const query = async (text, params) => {
  let client;
  try {
    client = await pool.connect();
    const result = await client.query(text, params);
    return result;
  } catch (error) {
    console.error('Query error:', error.message, error.stack);
    throw error;
  } finally {
    if (client) client.release();
  }
};

// Get client for transactions - MUST call release() after use
const getClient = () => pool.connect();

// Release client back to pool
const releaseClient = (client) => {
  if (client) client.release();
};

module.exports = {
  query,
  getClient,
  releaseClient,
  pool,
};
