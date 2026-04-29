// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();

const useSsl = String(process.env.DB_SSL || '').toLowerCase() === 'true';
const rejectUnauthorized = String(process.env.DB_SSL_REJECT_UNAUTHORIZED || 'true').toLowerCase() !== 'false';

const poolConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT) || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

if (useSsl) {
    poolConfig.ssl = {
        minVersion: 'TLSv1.2',
        rejectUnauthorized
    };
}

const pool = mysql.createPool(poolConfig);

async function testConnection() {
    try {
        const [rows] = await pool.query('SELECT 1 + 1 AS solution');
        console.log('Database connection test successful:', rows[0].solution === 2);
    } catch (err) {
        console.error('Database connection failed:', err);
    }
}

if (process.env.NODE_ENV !== 'test') {
    testConnection();
}

module.exports = pool;
