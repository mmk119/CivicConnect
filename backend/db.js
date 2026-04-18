// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();

// Create connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000, // TiDB uses 4000
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // --- THIS IS THE FIX ---
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    }
});

// Test connection (optional)
async function testConnection() {
    try {
        const [rows] = await pool.query('SELECT 1 + 1 AS solution');
        console.log('✅ Database connection test successful:', rows[0].solution === 2);
    } catch (err) {
        // Detailed error logging to help you debug on Render
        console.error('❌ Database connection failed:', err.message);
    }
}

testConnection();

// Export the pool for use in other files
module.exports = pool;
