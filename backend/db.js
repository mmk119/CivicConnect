// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();

// Create connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test connection (optional)
async function testConnection() {
    try {
        const [rows] = await pool.query('SELECT 1 + 1 AS solution');
        console.log('✅ Database connection test successful:', rows[0].solution === 2);
    } catch (err) {
        console.error('❌ Database connection failed:', err);
    }
}

testConnection();

// Export the pool for use in other files
module.exports = pool;