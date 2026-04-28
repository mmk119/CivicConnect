/* eslint-disable no-undef */
require('dotenv').config();

console.log("JWT Secret:", process.env.JWT_SECRET);

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const crypto = require('crypto');
const util = require('util');
const winston = require("winston");
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: "logs/server.log", level: "info" }),
        new winston.transports.File({ filename: "logs/error.log", level: "error" })
    ],
});

console.log = (...args) => logger.info(util.format(...args));
console.error = (...args) => logger.error(util.format(...args));
logger.info("Server is starting...");

const app = express();
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
app.use(express.static(path.join(__dirname, '../frontend')));

const morgan = require("morgan");
app.use(morgan("combined"));

const helmet = require("helmet");
app.use(helmet());

const rateLimit = require("express-rate-limit");
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
});
app.use(limiter);

app.use(express.json());
const allowedOrigins = [
    'http://localhost:3000',
    'https://civicconnect-2.onrender.com',
    'http://127.0.0.1:5500',
    'https://CivicConnect-516m.onrender.com'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.error('Blocked by CORS:', origin);
            callback(new Error('CORS not allowed from this origin: ' + origin));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'https://CivicConnect-516m.onrender.com');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    next();
});

const oAuth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI
);

oAuth2Client.setCredentials({
    refresh_token: process.env.REFRESH_TOKEN
});

console.log('OAuth2 client initialized with refresh token from environment');

async function refreshAccessToken() {
    try {
        oAuth2Client.setCredentials({
            refresh_token: process.env.REFRESH_TOKEN
        });
        const { credentials } = await oAuth2Client.refreshAccessToken();
        console.log('Access token refreshed');
        return credentials.access_token;
    } catch (err) {
        console.error('Error refreshing access token:', err);
        throw err;
    }
}

async function createTransporter() {
    try {
        const accessToken = await refreshAccessToken();
        return nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: 'OAuth2',
                user: process.env.EMAIL_USER,
                clientId: process.env.CLIENT_ID,
                clientSecret: process.env.CLIENT_SECRET,
                refreshToken: process.env.REFRESH_TOKEN,
                accessToken: accessToken,
            },
        });
    } catch (err) {
        console.error('Error creating transporter:', err);
        throw err;
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ error: 'Admin privileges required.' });
    }
    next();
}

async function writeAuditLog(adminId, action, targetType, targetId, details = '') {
    try {
        await db.execute(
            `INSERT INTO AuditLogs (admin_id, action, target_type, target_id, details)
             VALUES (?, ?, ?, ?, ?)`,
            [adminId || null, action, targetType, targetId || null, details]
        );
    } catch (err) {
        console.error('Audit log failed:', err.message);
    }
}

function csvEscape(value) {
    if (value === null || value === undefined) return '';
    const text = String(value).replace(/"/g, '""');
    return /[",\n\r]/.test(text) ? `"${text}"` : text;
}

// ===== AUTH ROUTES =====

app.post('/api/register', async (req, res) => {
    const { name, email, password, role, volunteer, ngo } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    let connection;
    try {
        connection = await db.getConnection();
        await connection.beginTransaction();

        const [existingUsers] = await connection.execute(
            'SELECT user_id FROM Users WHERE email = ?', [email]
        );

        if (existingUsers.length > 0) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString('hex');

        const [userResult] = await connection.execute(
            `INSERT INTO Users (name, email, password_hash, role, Verified, verification_token) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [name, email, hashedPassword, role, 'NO', verificationToken]
        );

        const userId = userResult.insertId;

        if (role === 'Volunteer') {
            if (!volunteer?.city || !volunteer?.dob) {
                throw new Error('Missing city or date of birth for volunteer');
            }
            await connection.execute(
                `INSERT INTO Volunteers (user_id, phone, city, skills, Date_of_Birth) VALUES (?, ?, ?, ?, ?)`,
                [userId, volunteer.phone || null, volunteer.city, volunteer.skills || null, volunteer.dob]
            );
        }

        if (role === 'NGO') {
            if (!ngo?.name || !ngo?.description || !ngo?.address) {
                throw new Error('Missing NGO name, description, or address');
            }
            const [ngoResult] = await connection.execute(
                `INSERT INTO NGOs (name, description, address, user_id) VALUES (?, ?, ?, ?)`,
                [ngo.name, ngo.description, ngo.address, userId]
            );
            await connection.execute(
                `UPDATE Users SET ngo_id = ? WHERE user_id = ?`,
                [ngoResult.insertId, userId]
            );
        }

        await connection.commit();
        connection.release();

        try {
            const backendBaseUrl = process.env.BACKEND_URL || `http://localhost:${PORT}`;
            const verificationLink = `${backendBaseUrl}/api/verify-email?token=${verificationToken}`;
            const transporter = await createTransporter();
            await transporter.sendMail({
                from: `CivicConnect <${process.env.EMAIL_USER}>`,
                to: email,
                subject: 'Email Verification',
                html: `<p>Hello ${name},</p><p>Please verify your email:</p><a href="${verificationLink}">Verify Email</a>`
            });
        } catch (emailErr) {
            console.error('Email sending failed (ignored):', emailErr.message);
        }

        return res.status(201).json({ message: 'Registration successful. Check your email to verify your account.' });

    } catch (err) {
        console.error('REGISTER ERROR:', err.message);
        if (connection) {
            await connection.rollback();
            connection.release();
        }
        return res.status(500).json({ error: err.message });
    }
});

app.get('/api/verify-email', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Invalid or missing token' });
    try {
        const [users] = await db.execute('SELECT * FROM Users WHERE verification_token = ?', [token]);
        if (users.length === 0) return res.status(400).json({ error: 'Invalid token' });
        await db.execute(
            "UPDATE Users SET Verified = 'YES', verification_token = NULL WHERE verification_token = ?",
            [token]
        );
        res.json({ message: 'Email verified successfully. You can now log in.' });
    } catch (err) {
        console.error('Verification error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Login request body:', req.body);
    try {
        const [users] = await db.execute('SELECT * FROM Users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const user = users[0];
        if (user.Verified !== 'YES') {
            return res.status(403).json({ error: 'Please verify your email before logging in.' });
        }
        if (user.account_status === 'banned') {
            return res.status(403).json({ error: 'Your account has been banned. Please contact the administrator.' });
        }
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        let redirectPath;
        switch (user.role.toLowerCase()) {
            case 'ngo': redirectPath = 'dashboard.html'; break;
            case 'volunteer': redirectPath = 'opportunities.html'; break;
            case 'admin': redirectPath = 'admin-dashboard.html'; break;
            default: redirectPath = '/';
        }

        const token = jwt.sign(
            { user_id: user.user_id, email: user.email, role: user.role, ngo_id: user.ngo_id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );

        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: { id: user.user_id, name: user.name, email: user.email, role: user.role, ngo_id: user.ngo_id },
            redirect: redirectPath
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.post('/api/request-password-reset', async (req, res) => {
    const { email } = req.body;
    try {
        const [users] = await db.execute('SELECT * FROM Users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'Email not found' });
        }

        const user = users[0];
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;

        await db.execute(
            'UPDATE Users SET reset_token = ?, reset_token_expiry = ? WHERE user_id = ?',
            [resetToken, resetTokenExpiry, user.user_id]
        );

        const frontendBaseUrl = process.env.FRONTEND_URL || 'https://civicconnect-2.onrender.com';
        const resetLink = `${frontendBaseUrl}/reset-password.html?token=${resetToken}`;
        const transporter = await createTransporter();

        await transporter.sendMail({
            from: `CivicConnect <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset',
            html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <h2>Password Reset Request</h2>
                    <p>You requested a password reset for your CivicConnect account.</p>
                    <p>Please click the button below to set a new password. This link is valid for 1 hour.</p>
                    <a href="${resetLink}" style="background-color: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                    <p>If you did not request this, please ignore this email.</p>
                    <hr style="border: none; border-top: 1px solid #eee;" />
                    <p style="font-size: 12px; color: #666;">If the button doesn't work, copy and paste this link:<br>${resetLink}</p>
                </div>
            `
        });

        res.status(200).json({ message: 'Password reset link sent to your email.' });
    } catch (err) {
        console.error('Error requesting password reset:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIX 1: reset-password route with proper CAST for bigint expiry comparison
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required.' });
    }

    try {
        const now = Date.now();
        console.log('Reset attempt — token:', token, 'now:', now);

        const [users] = await db.execute(
            'SELECT * FROM users WHERE reset_token = ? AND CAST(reset_token_expiry AS UNSIGNED) > ?',
            [token, now]
        );

        console.log('Users matched:', users.length);

        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.execute(
            'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?',
            [hashedPassword, users[0].user_id]
        );

        return res.status(200).json({ message: 'Password reset successfully. You can now log in.' });

    } catch (err) {
        console.error('Reset password error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ===== OPPORTUNITIES =====

const opportunityFields = [
    'Education',
    'Health',
    'Environment',
    'Community',
    'Elderly Care',
    'Children & Youth',
    'Disability Support',
    'Food Distribution',
    'Other'
];

// FIX 2: /api/opportunities/search MUST be before /api/opportunities/:id
app.get('/api/opportunities/search', async (req, res) => {
    const { location = '', keyword = '', field = '' } = req.query;
    try {
        const query = `
            SELECT opportunity_id, title, field, description, start_date, end_date, location, ngo_id
            FROM Opportunities
            WHERE location LIKE ?
              AND (title LIKE ? OR description LIKE ?)
              AND (? = '' OR field = ?)
            ORDER BY start_date ASC
        `;
        const [results] = await db.execute(query, [`%${location}%`, `%${keyword}%`, `%${keyword}%`, field, field]);
        res.json(results);
    } catch (err) {
        console.error("Error fetching opportunities:", err);
        res.status(500).json({ error: "Failed to fetch opportunities." });
    }
});

// FIX 3: has_applied now correctly looks up volunteer_id instead of using user_id directly
app.get('/api/opportunities/all', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    let volunteer_id = null;

    try {
        if (token && token !== "dev-mode") {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const [vol] = await db.execute(
                'SELECT volunteer_id FROM volunteers WHERE user_id = ?',
                [decoded.user_id]
            );
            if (vol.length > 0) volunteer_id = vol[0].volunteer_id;
        }

        const [opportunities] = await db.execute(`
            SELECT 
                o.*,
                n.name AS ngo_name,
                n.logo AS ngo_logo,
                (
                    SELECT COUNT(*)
                    FROM Applications a
                    WHERE a.opportunity_id = o.opportunity_id
                      AND a.status = 'accepted'
                ) AS accepted_count,
                ${volunteer_id
                    ? `EXISTS(SELECT 1 FROM Applications WHERE volunteer_id = ? AND opportunity_id = o.opportunity_id) AS has_applied,
                       EXISTS(SELECT 1 FROM SavedOpportunities WHERE volunteer_id = ? AND opportunity_id = o.opportunity_id) AS is_saved`
                    : '0 AS has_applied, 0 AS is_saved'}
            FROM Opportunities o
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            ORDER BY o.start_date ASC
        `, volunteer_id ? [volunteer_id, volunteer_id] : []);

        res.json(opportunities);
    } catch (err) {
        console.error("Error fetching opportunities:", err);
        res.status(500).json({ error: "Failed to fetch opportunities." });
    }
});

app.get("/api/opportunities", authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ message: "Only NGO accounts can manage opportunities." });
    }

    const ngoId = req.user.ngo_id;
    try {
        const [rows] = await db.execute(`
            SELECT o.*,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id
                         AND a.status = 'accepted'
                   ) AS accepted_count
            FROM Opportunities o
            WHERE o.ngo_id = ?
        `, [ngoId]);
        res.json(rows);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ message: "Internal server error." });
    }
});

app.post('/api/opportunities/ins', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: "Only NGO accounts can create opportunities." });
    }

    const { title, field, description, start_date, end_date, hours_required, capacity, location } = req.body;
    const ngo_id = req.user.ngo_id;
    const hoursRequired = Number(hours_required);
    const volunteerCapacity = Number(capacity);

    if (!title || !field || !description || !start_date || !end_date || !hours_required || !capacity || !location) {
        return res.status(400).json({ error: "All fields are required." });
    }

    if (!opportunityFields.includes(field)) {
        return res.status(400).json({ error: "Invalid opportunity field." });
    }

    if (!Number.isInteger(hoursRequired) || hoursRequired < 1) {
        return res.status(400).json({ error: "Hours required must be a positive whole number." });
    }

    if (!Number.isInteger(volunteerCapacity) || volunteerCapacity < 1) {
        return res.status(400).json({ error: "Volunteer capacity must be a positive whole number." });
    }

    try {
        const [ngoRows] = await db.execute(
            'SELECT approval_status FROM NGOs WHERE ngo_id = ?',
            [ngo_id]
        );

        if (ngoRows.length === 0) {
            return res.status(404).json({ error: "NGO profile not found." });
        }

        if (ngoRows[0].approval_status !== 'approved') {
            return res.status(403).json({
                error: "Your NGO account must be approved by an admin before posting opportunities."
            });
        }

        const query = `INSERT INTO Opportunities (title, field, description, start_date, end_date, hours_required, capacity, location, ngo_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const [result] = await db.execute(query, [title, field, description, start_date, end_date, hoursRequired, volunteerCapacity, location, ngo_id]);
        console.log("Opportunity saved:", result.insertId);
        res.status(201).json({ message: "Opportunity submitted successfully!", id: result.insertId });
    } catch (err) {
        console.error("Error inserting opportunity:", err);
        res.status(500).json({ error: "Failed to submit opportunity." });
    }
});

// FIX 4: DELETE ran the query twice and used wrong check — now uses affectedRows
app.delete('/api/opportunities/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: "Only NGO accounts can delete opportunities." });
    }

    const { id } = req.params;
    try {
        const [result] = await db.execute(
            "DELETE FROM Opportunities WHERE opportunity_id = ? AND ngo_id = ?",
            [id, req.user.ngo_id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Opportunity not found." });
        }
        console.log(`Opportunity deleted: ID ${id}`);
        res.json({ message: "Opportunity deleted successfully!" });
    } catch (err) {
        console.error("Error deleting opportunity:", err);
        res.status(500).json({ error: "Failed to delete opportunity." });
    }
});

app.get('/api/opportunities/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.execute(
            `SELECT o.*, n.name AS ngo_name, n.logo AS ngo_logo,
                    (
                        SELECT COUNT(*)
                        FROM Applications a
                        WHERE a.opportunity_id = o.opportunity_id
                          AND a.status = 'accepted'
                    ) AS accepted_count
             FROM Opportunities o
             JOIN NGOs n ON o.ngo_id = n.ngo_id
             WHERE o.opportunity_id = ?`,
            [id]
        );
        if (results.length === 0) {
            return res.status(404).json({ error: "Opportunity not found." });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Error fetching opportunity:", err);
        res.status(500).json({ error: "Failed to fetch opportunity." });
    }
});

// ===== APPLICATIONS =====

app.get('/api/ngo-public/:ngo_id', async (req, res) => {
    const { ngo_id } = req.params;

    try {
        const [ngos] = await db.execute(`
            SELECT
                n.ngo_id,
                n.name,
                n.description,
                n.address,
                n.logo,
                n.created_at,
                u.email,
                COUNT(DISTINCT o.opportunity_id) AS opportunities_posted,
                COUNT(DISTINCT CASE WHEN a.attendance_confirmed = 'YES' THEN a.volunteer_id END) AS total_volunteers_helped,
                COALESCE(SUM(CASE WHEN a.attendance_confirmed = 'YES' THEN a.hours_completed ELSE 0 END), 0) AS total_hours_hosted
            FROM NGOs n
            JOIN Users u ON n.user_id = u.user_id
            LEFT JOIN Opportunities o ON n.ngo_id = o.ngo_id
            LEFT JOIN Applications a ON o.opportunity_id = a.opportunity_id
            WHERE n.ngo_id = ? AND n.approval_status = 'approved'
            GROUP BY n.ngo_id, n.name, n.description, n.address, n.logo, n.created_at, u.email
        `, [ngo_id]);

        if (ngos.length === 0) {
            return res.status(404).json({ error: 'NGO profile not found.' });
        }

        const [opportunities] = await db.execute(`
            SELECT opportunity_id, title, field, description, location, start_date, end_date, hours_required, capacity
            FROM Opportunities
            WHERE ngo_id = ?
            ORDER BY start_date DESC
        `, [ngo_id]);

        res.json({ ...ngos[0], opportunities });
    } catch (err) {
        console.error('Error fetching public NGO profile:', err);
        res.status(500).json({ error: 'Failed to fetch NGO profile.' });
    }
});

app.post('/api/applications', authenticateToken, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const { opportunity_id } = req.body;
    const user_id = req.user.user_id;

    if (!opportunity_id || isNaN(opportunity_id)) {
        return res.status(400).json({ success: false, error: "Valid opportunity ID is required." });
    }

    try {
        const [opportunity] = await db.execute(
            `SELECT opportunity_id, title, end_date, capacity,
                    (
                        SELECT COUNT(*)
                        FROM Applications
                        WHERE opportunity_id = ?
                          AND status = 'accepted'
                    ) AS accepted_count
             FROM Opportunities
             WHERE opportunity_id = ?`,
            [opportunity_id, opportunity_id]
        );
        if (opportunity.length === 0) {
            return res.status(404).json({ success: false, error: "Opportunity not found" });
        }

        if (Number(opportunity[0].capacity) > 0 && Number(opportunity[0].accepted_count) >= Number(opportunity[0].capacity)) {
            return res.status(400).json({ success: false, error: "This opportunity is full and no longer accepts applications." });
        }

        if (opportunity[0].end_date) {
            const endDate = new Date(opportunity[0].end_date);
            endDate.setHours(23, 59, 59, 999);
            if (endDate < new Date()) {
                return res.status(400).json({
                    success: false,
                    error: "This opportunity has passed and can no longer accept applications."
                });
            }
        }

        const [volunteer] = await db.execute(
            'SELECT v.volunteer_id FROM Volunteers v WHERE v.user_id = ?', [user_id]
        );
        if (volunteer.length === 0) {
            return res.status(403).json({ success: false, error: "Only volunteers can apply to opportunities" });
        }

        const volunteer_id = volunteer[0].volunteer_id;

        const [existing] = await db.execute(
            `SELECT 1 FROM Applications WHERE volunteer_id = ? AND opportunity_id = ? LIMIT 1`,
            [volunteer_id, opportunity_id]
        );
        if (existing.length > 0) {
            return res.status(409).json({ success: false, error: "You've already applied to this opportunity" });
        }

        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            const [result] = await connection.execute(
                `INSERT INTO Applications (volunteer_id, opportunity_id, status) VALUES (?, ?, 'pending')`,
                [volunteer_id, opportunity_id]
            );

            const [user] = await connection.execute(
                'SELECT email, name FROM Users WHERE user_id = ?', [user_id]
            );

            if (user.length > 0) {
                const transporter = await createTransporter();
                transporter.sendMail({
                    from: `CivicConnect <${process.env.EMAIL_USER}>`,
                    to: user[0].email,
                    subject: 'Application Submitted',
                    html: `<p>Hi ${user[0].name},</p><p>Your application for <strong>${opportunity[0].title}</strong> was received!</p><p>Status: <strong>Pending</strong></p>`
                }).catch(e => console.error('Email failed:', e));
            }

            await connection.commit();
            connection.release();

            return res.status(201).json({ success: true, application_id: result.insertId, message: "Application submitted successfully" });

        } catch (transactionError) {
            await connection.rollback();
            connection.release();
            throw transactionError;
        }

    } catch (err) {
        console.error("Application error:", err);
        let errorMessage = "Failed to submit application";
        if (err.code === 'ER_NO_REFERENCED_ROW_2') {
            errorMessage = "Invalid data reference - please check your account status";
        }
        return res.status(500).json({ success: false, error: errorMessage });
    }
});

app.post('/api/saved-opportunities', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).json({ error: 'Only volunteers can save opportunities.' });
    }

    const { opportunity_id } = req.body;
    if (!opportunity_id || isNaN(opportunity_id)) {
        return res.status(400).json({ error: 'Valid opportunity ID is required.' });
    }

    try {
        const [volunteers] = await db.execute(
            'SELECT volunteer_id FROM Volunteers WHERE user_id = ?',
            [req.user.user_id]
        );

        if (volunteers.length === 0) {
            return res.status(403).json({ error: 'Volunteer profile not found.' });
        }

        await db.execute(
            `INSERT IGNORE INTO SavedOpportunities (volunteer_id, opportunity_id) VALUES (?, ?)`,
            [volunteers[0].volunteer_id, opportunity_id]
        );

        res.status(201).json({ message: 'Opportunity saved.' });
    } catch (err) {
        console.error('Error saving opportunity:', err);
        res.status(500).json({ error: 'Failed to save opportunity.' });
    }
});

app.delete('/api/saved-opportunities/:opportunity_id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).json({ error: 'Only volunteers can remove saved opportunities.' });
    }

    try {
        const [volunteers] = await db.execute(
            'SELECT volunteer_id FROM Volunteers WHERE user_id = ?',
            [req.user.user_id]
        );

        if (volunteers.length === 0) {
            return res.status(403).json({ error: 'Volunteer profile not found.' });
        }

        await db.execute(
            `DELETE FROM SavedOpportunities WHERE volunteer_id = ? AND opportunity_id = ?`,
            [volunteers[0].volunteer_id, req.params.opportunity_id]
        );

        res.json({ message: 'Saved opportunity removed.' });
    } catch (err) {
        console.error('Error removing saved opportunity:', err);
        res.status(500).json({ error: 'Failed to remove saved opportunity.' });
    }
});

// FIX 5: Application status values match DB enum (lowercase)
app.patch('/api/applications/:application_id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: 'Only NGO accounts can update application status.' });
    }

    const { application_id } = req.params;
    const { status } = req.body;
    const validStatuses = ['pending', 'accepted', 'rejected'];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status update.' });
    }

    try {
        const [application] = await db.execute(`
            SELECT a.opportunity_id, a.volunteer_id, u.email, u.name, o.capacity
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            WHERE a.application_id = ? AND o.ngo_id = ?
        `, [application_id, req.user.ngo_id]);

        if (application.length === 0) {
            return res.status(404).json({ error: 'Application not found' });
        }

        if (status === 'accepted') {
            const [capacityRows] = await db.execute(`
                SELECT COUNT(*) AS accepted_count
                FROM Applications
                WHERE opportunity_id = ?
                  AND status = 'accepted'
                  AND application_id <> ?
            `, [application[0].opportunity_id, application_id]);

            if (
                Number(application[0].capacity) > 0 &&
                Number(capacityRows[0].accepted_count) >= Number(application[0].capacity)
            ) {
                return res.status(400).json({ error: 'This opportunity has reached its volunteer capacity.' });
            }
        }

        await db.execute(
            `UPDATE Applications SET status = ? WHERE application_id = ?`,
            [status, application_id]
        );

        const transporter = await createTransporter();
        await transporter.sendMail({
            from: `CivicConnect <${process.env.EMAIL_USER}>`,
            to: application[0].email,
            subject: `Application ${status.toUpperCase()}`,
            html: `<p>Dear ${application[0].name},</p><p>Your application has been <strong>${status}</strong>.</p>`
        });

        res.json({ message: `Application ${status} successfully.` });
    } catch (err) {
        console.error('Error updating application status:', err);
        res.status(500).json({ error: 'Failed to update application status.' });
    }
});

app.patch('/api/applications/:application_id/attendance', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: 'Only NGO accounts can confirm volunteer attendance.' });
    }

    const { application_id } = req.params;
    const requestedHours = Number(req.body.hours_completed);

    if (!Number.isInteger(requestedHours) || requestedHours < 1) {
        return res.status(400).json({ error: 'Completed hours must be a positive whole number.' });
    }

    try {
        const [applications] = await db.execute(`
            SELECT
                a.application_id,
                a.status,
                a.attendance_confirmed,
                o.end_date,
                o.hours_required
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE a.application_id = ? AND o.ngo_id = ?
        `, [application_id, req.user.ngo_id]);

        if (applications.length === 0) {
            return res.status(404).json({ error: 'Application not found for this NGO.' });
        }

        const application = applications[0];

        if (application.status !== 'accepted') {
            return res.status(400).json({ error: 'Only accepted applications can receive volunteering hours.' });
        }

        if (application.attendance_confirmed === 'YES') {
            return res.status(409).json({ error: 'Attendance has already been confirmed for this application.' });
        }

        const endDate = new Date(application.end_date);
        endDate.setHours(23, 59, 59, 999);
        if (endDate >= new Date()) {
            return res.status(400).json({ error: 'Attendance can only be confirmed after the opportunity has ended.' });
        }

        const maxHours = Number(application.hours_required) || requestedHours;
        if (requestedHours > maxHours) {
            return res.status(400).json({ error: `Completed hours cannot be more than ${maxHours}.` });
        }

        await db.execute(`
            UPDATE Applications
            SET attendance_confirmed = 'YES',
                hours_completed = ?,
                attendance_confirmed_at = NOW()
            WHERE application_id = ?
        `, [requestedHours, application_id]);

        res.json({ message: `Attendance confirmed. ${requestedHours} volunteering hours added.` });
    } catch (err) {
        console.error('Error confirming attendance:', err);
        res.status(500).json({ error: 'Failed to confirm attendance.' });
    }
});

app.get('/api/volunteer/applications', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).json({ error: 'Only volunteers can view application history.' });
    }

    try {
        const [volunteers] = await db.execute(
            'SELECT volunteer_id FROM Volunteers WHERE user_id = ?',
            [req.user.user_id]
        );

        if (volunteers.length === 0) {
            return res.json([]);
        }

        const [applications] = await db.execute(`
            SELECT
                a.application_id,
                a.status,
                a.applied_at,
                o.opportunity_id,
                o.title,
                o.description,
                o.field,
                o.location,
                o.start_date,
                o.end_date,
                o.hours_required,
                a.hours_completed,
                a.attendance_confirmed,
                a.attendance_confirmed_at,
                n.name AS ngo_name
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            WHERE a.volunteer_id = ?
            ORDER BY a.applied_at DESC
        `, [volunteers[0].volunteer_id]);

        res.json(applications);
    } catch (err) {
        console.error('Error fetching volunteer application history:', err);
        res.status(500).json({ error: 'Failed to fetch application history.' });
    }
});

app.get('/api/applicants', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: 'Only NGO accounts can view applicants.' });
    }

    const ngo_id = req.user.ngo_id;

    try {
        const [opps] = await db.execute(
            `SELECT opportunity_id FROM Opportunities WHERE ngo_id = ?`, [ngo_id]
        );
        if (opps.length === 0) {
            return res.json([]);
        }
        const ids = opps.map(o => o.opportunity_id);
        const placeholders = ids.map(_ => '?').join(',');

        const [applicants] = await db.execute(`
            SELECT
                a.application_id AS id,
                u.user_id,
                u.name,
                u.email,
                v.city,
                v.skills,
                a.status,
                a.hours_completed,
                a.attendance_confirmed,
                a.attendance_confirmed_at,
                o.title AS opportunity_name,
                o.end_date,
                o.hours_required,
                COALESCE((
                    SELECT SUM(a2.hours_completed)
                    FROM Applications a2
                    WHERE a2.volunteer_id = v.volunteer_id
                      AND a2.attendance_confirmed = 'YES'
                ), 0) AS total_hours,
                (
                    SELECT GROUP_CONCAT(CONCAT(o2.title, ' (', a2.hours_completed, ' hrs)') ORDER BY o2.end_date DESC SEPARATOR '||')
                    FROM Applications a2
                    JOIN Opportunities o2 ON a2.opportunity_id = o2.opportunity_id
                    WHERE a2.volunteer_id = v.volunteer_id
                      AND a2.attendance_confirmed = 'YES'
                ) AS completed_history
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE a.opportunity_id IN (${placeholders})
        `, ids);

        res.json(applicants);
    } catch (err) {
        console.error('Error fetching applicants:', err);
        res.status(500).json({ error: 'Failed to fetch applicants.', details: err.message });
    }
});

// ===== FILE UPLOAD =====

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, '../uploads/'); },
    filename: (req, file, cb) => { cb(null, Date.now() + path.extname(file.originalname)); }
});
const upload = multer({ storage: storage });

app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded." });
    res.json({ message: "File uploaded successfully!", filename: req.file.filename });
});

app.get('/api/files', (req, res) => {
    fs.readdir('../uploads/', (err, files) => {
        if (err) return res.status(500).json({ error: "Failed to retrieve files." });
        res.json(files);
    });
});

app.delete('/api/files/:filename', (req, res) => {
    const { filename } = req.params;
    const filePath = `uploads/${filename}`;
    if (fs.existsSync(filePath)) {
        fs.unlink(filePath, (err) => {
            if (err) return res.status(500).json({ error: "Failed to delete file." });
            res.json({ message: "File deleted successfully!" });
        });
    } else {
        res.status(404).json({ error: "File not found." });
    }
});

// ===== ADMIN =====

app.get('/api/admin/overview', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [[userCounts]] = await db.execute(`
            SELECT
                COUNT(*) AS total_users,
                SUM(role = 'Volunteer') AS volunteers,
                SUM(role = 'NGO') AS ngos,
                SUM(role = 'Admin') AS admins,
                SUM(account_status = 'banned') AS banned_users
            FROM Users
        `);
        const [[ngoCounts]] = await db.execute(`
            SELECT
                SUM(approval_status = 'pending') AS pending_ngos,
                SUM(approval_status = 'approved') AS approved_ngos,
                SUM(approval_status = 'rejected') AS rejected_ngos
            FROM NGOs
        `);
        const [[opportunityCounts]] = await db.execute(`
            SELECT
                COUNT(*) AS total_opportunities,
                SUM(end_date >= CURDATE()) AS upcoming_opportunities,
                SUM(end_date < CURDATE()) AS passed_opportunities
            FROM Opportunities
        `);
        const [[applicationCounts]] = await db.execute(`
            SELECT
                COUNT(*) AS total_applications,
                SUM(status = 'pending') AS pending_applications,
                SUM(status = 'accepted') AS accepted_applications,
                SUM(status = 'rejected') AS rejected_applications,
                COALESCE(SUM(CASE WHEN attendance_confirmed = 'YES' THEN hours_completed ELSE 0 END), 0) AS confirmed_hours
            FROM Applications
        `);
        const [popularFields] = await db.execute(`
            SELECT field, COUNT(*) AS total
            FROM Opportunities
            GROUP BY field
            ORDER BY total DESC, field ASC
        `);
        const [monthlyApplications] = await db.execute(`
            SELECT DATE_FORMAT(applied_at, '%Y-%m') AS month, COUNT(*) AS total
            FROM Applications
            GROUP BY month
            ORDER BY month DESC
            LIMIT 6
        `);
        const [topVolunteers] = await db.execute(`
            SELECT u.name, u.email, COALESCE(SUM(a.hours_completed), 0) AS total_hours
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            WHERE a.attendance_confirmed = 'YES'
            GROUP BY u.user_id, u.name, u.email
            ORDER BY total_hours DESC
            LIMIT 5
        `);
        const [topNgos] = await db.execute(`
            SELECT n.name, COUNT(o.opportunity_id) AS total_opportunities
            FROM NGOs n
            LEFT JOIN Opportunities o ON n.ngo_id = o.ngo_id
            GROUP BY n.ngo_id, n.name
            ORDER BY total_opportunities DESC
            LIMIT 5
        `);

        res.json({
            stats: {
                ...userCounts,
                ...ngoCounts,
                ...opportunityCounts,
                ...applicationCounts
            },
            popularFields,
            monthlyApplications,
            topVolunteers,
            topNgos
        });
    } catch (err) {
        console.error('Admin overview error:', err);
        res.status(500).json({ error: 'Failed to load admin overview.' });
    }
});

app.get('/api/admin/notifications', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [[pendingNgos]] = await db.execute(`SELECT COUNT(*) AS count FROM NGOs WHERE approval_status = 'pending'`);
        const [[pendingApplications]] = await db.execute(`SELECT COUNT(*) AS count FROM Applications WHERE status = 'pending'`);
        const [[unconfirmedHours]] = await db.execute(`
            SELECT COUNT(*) AS count
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE a.status = 'accepted'
              AND a.attendance_confirmed = 'NO'
              AND o.end_date < CURDATE()
        `);
        const [[newOpportunities]] = await db.execute(`
            SELECT COUNT(*) AS count
            FROM Opportunities
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        `);

        res.json([
            { type: 'NGO approval', count: pendingNgos.count, message: `${pendingNgos.count} NGOs waiting for approval` },
            { type: 'Applications', count: pendingApplications.count, message: `${pendingApplications.count} pending volunteer applications` },
            { type: 'Hours', count: unconfirmedHours.count, message: `${unconfirmedHours.count} accepted applications need hour confirmation` },
            { type: 'Opportunities', count: newOpportunities.count, message: `${newOpportunities.count} opportunities posted this week` }
        ]);
    } catch (err) {
        console.error('Admin notifications error:', err);
        res.status(500).json({ error: 'Failed to load notifications.' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    const { search = '', role = '', status = '' } = req.query;
    try {
        const [users] = await db.execute(`
            SELECT user_id, name, email, role, Verified, account_status, ngo_id, created_at
            FROM Users
            WHERE (? = '' OR name LIKE ? OR email LIKE ?)
              AND (? = '' OR role = ?)
              AND (? = '' OR account_status = ?)
            ORDER BY created_at DESC
        `, [search, `%${search}%`, `%${search}%`, role, role, status, status]);
        res.json(users);
    } catch (err) {
        console.error('Admin users error:', err);
        res.status(500).json({ error: "Failed to fetch users" });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        if (Number(req.params.id) === Number(req.user.user_id)) {
            return res.status(400).json({ error: 'You cannot delete your own admin account.' });
        }

        const [result] = await db.execute('DELETE FROM Users WHERE user_id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        await writeAuditLog(req.user.user_id, 'delete_user', 'User', req.params.id, 'Admin deleted a user account.');
        res.json({ message: "User deleted" });
    } catch (err) {
        console.error('Admin delete user error:', err);
        res.status(500).json({ error: "Deletion failed" });
    }
});

app.patch('/api/admin/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        if (!['active', 'banned'].includes(status)) {
            return res.status(400).json({ error: "Invalid status" });
        }

        if (Number(id) === Number(req.user.user_id) && status === 'banned') {
            return res.status(400).json({ error: 'You cannot ban your own admin account.' });
        }

        const [result] = await db.execute('UPDATE Users SET account_status = ? WHERE user_id = ?', [status, id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        await writeAuditLog(req.user.user_id, `set_user_${status}`, 'User', id, `Admin changed account status to ${status}.`);
        res.json({ message: 'Account status updated' });
    } catch (err) {
        console.error('Admin user status error:', err);
        res.status(500).json({ error: "Status update failed" });
    }
});

app.get('/api/admin/ngos', authenticateToken, requireAdmin, async (req, res) => {
    const { status = '', search = '' } = req.query;
    try {
        let query = `
            SELECT n.ngo_id, n.name, n.description, n.address, n.logo, n.approval_status,
                   n.rejection_reason, n.created_at, u.email, u.account_status
            FROM NGOs n
            JOIN Users u ON n.user_id = u.user_id
            WHERE (? = '' OR n.approval_status = ?)
              AND (? = '' OR n.name LIKE ? OR u.email LIKE ? OR n.address LIKE ?)
            ORDER BY FIELD(n.approval_status, 'pending', 'approved', 'rejected'), n.created_at DESC
        `;

        let ngos;
        try {
            [ngos] = await db.execute(query, [status, status, search, `%${search}%`, `%${search}%`, `%${search}%`]);
        } catch (err) {
            if (err.code !== 'ER_BAD_FIELD_ERROR') throw err;

            query = `
                SELECT n.ngo_id, n.name, n.description, n.address, n.logo, n.approval_status,
                       NULL AS rejection_reason, n.created_at, u.email, u.account_status
                FROM NGOs n
                JOIN Users u ON n.user_id = u.user_id
                WHERE (? = '' OR n.approval_status = ?)
                  AND (? = '' OR n.name LIKE ? OR u.email LIKE ? OR n.address LIKE ?)
                ORDER BY FIELD(n.approval_status, 'pending', 'approved', 'rejected'), n.created_at DESC
            `;
            [ngos] = await db.execute(query, [status, status, search, `%${search}%`, `%${search}%`, `%${search}%`]);
        }

        res.json(ngos);
    } catch (err) {
        console.error('Admin NGOs error:', err);
        res.status(500).json({ error: "Failed to fetch NGOs" });
    }
});

app.get('/api/admin/ngos/pending', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [ngos] = await db.execute(`
            SELECT n.ngo_id, n.name, n.description, n.address, u.email
            FROM NGOs n
            JOIN Users u ON n.user_id = u.user_id
            WHERE n.approval_status = 'pending'
            ORDER BY n.created_at ASC
        `);
        res.json(ngos);
    } catch (err) {
        console.error('Admin pending NGOs error:', err);
        res.status(500).json({ error: "Failed to fetch NGOs" });
    }
});

app.post('/api/admin/ngos/:ngo_id/approve', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { ngo_id } = req.params;
        let result;
        try {
            [result] = await db.execute(
                `UPDATE NGOs SET approval_status = 'approved', rejection_reason = NULL WHERE ngo_id = ?`,
                [ngo_id]
            );
        } catch (err) {
            if (err.code !== 'ER_BAD_FIELD_ERROR') throw err;
            [result] = await db.execute(
                `UPDATE NGOs SET approval_status = 'approved' WHERE ngo_id = ?`,
                [ngo_id]
            );
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'NGO not found.' });
        }

        await writeAuditLog(req.user.user_id, 'approve_ngo', 'NGO', ngo_id, 'Admin approved NGO account.');
        res.json({ message: "NGO approved successfully" });
    } catch (err) {
        console.error('Admin approve NGO error:', err);
        res.status(500).json({ error: "Approval failed" });
    }
});

app.post('/api/admin/ngos/:ngo_id/reject', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { ngo_id } = req.params;
        const reason = String(req.body.reason || '').trim();
        let result;
        try {
            [result] = await db.execute(
                `UPDATE NGOs SET approval_status = 'rejected', rejection_reason = ? WHERE ngo_id = ?`,
                [reason || null, ngo_id]
            );
        } catch (err) {
            if (err.code !== 'ER_BAD_FIELD_ERROR') throw err;
            [result] = await db.execute(
                `UPDATE NGOs SET approval_status = 'rejected' WHERE ngo_id = ?`,
                [ngo_id]
            );
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'NGO not found.' });
        }

        await writeAuditLog(req.user.user_id, 'reject_ngo', 'NGO', ngo_id, reason || 'Admin rejected NGO account.');
        res.json({ message: "NGO rejected successfully" });
    } catch (err) {
        console.error('Admin reject NGO error:', err);
        res.status(500).json({ error: "Rejection failed" });
    }
});

app.get('/api/admin/opportunities', authenticateToken, requireAdmin, async (req, res) => {
    const { search = '', field = '', status = '' } = req.query;
    try {
        const [opportunities] = await db.execute(`
            SELECT o.*, n.name AS ngo_name,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id
                   ) AS application_count
            FROM Opportunities o
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            WHERE (? = '' OR o.title LIKE ? OR o.description LIKE ? OR o.location LIKE ? OR n.name LIKE ?)
              AND (? = '' OR o.field = ?)
              AND (? = '' OR (? = 'upcoming' AND o.end_date >= CURDATE()) OR (? = 'passed' AND o.end_date < CURDATE()))
            ORDER BY o.created_at DESC
        `, [search, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, field, field, status, status, status]);
        res.json(opportunities);
    } catch (err) {
        console.error('Admin opportunities error:', err);
        res.status(500).json({ error: 'Failed to fetch opportunities.' });
    }
});

app.delete('/api/admin/opportunities/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [result] = await db.execute('DELETE FROM Opportunities WHERE opportunity_id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Opportunity not found.' });
        }

        await writeAuditLog(req.user.user_id, 'delete_opportunity', 'Opportunity', req.params.id, 'Admin deleted an opportunity.');
        res.json({ message: 'Opportunity deleted successfully.' });
    } catch (err) {
        console.error('Admin delete opportunity error:', err);
        res.status(500).json({ error: 'Failed to delete opportunity.' });
    }
});

app.get('/api/admin/applications', authenticateToken, requireAdmin, async (req, res) => {
    const { status = '', search = '' } = req.query;
    try {
        const [applications] = await db.execute(`
            SELECT a.application_id, a.status, a.applied_at, a.attendance_confirmed,
                   a.hours_completed, a.attendance_confirmed_at,
                   o.title AS opportunity_title, o.field, o.hours_required,
                   n.name AS ngo_name,
                   u.name AS volunteer_name, u.email AS volunteer_email
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            WHERE (? = '' OR a.status = ?)
              AND (? = '' OR o.title LIKE ? OR n.name LIKE ? OR u.name LIKE ? OR u.email LIKE ?)
            ORDER BY a.applied_at DESC
        `, [status, status, search, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`]);
        res.json(applications);
    } catch (err) {
        console.error('Admin applications error:', err);
        res.status(500).json({ error: 'Failed to fetch applications.' });
    }
});

app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [logs] = await db.execute(`
            SELECT l.*, u.name AS admin_name, u.email AS admin_email
            FROM AuditLogs l
            LEFT JOIN Users u ON l.admin_id = u.user_id
            ORDER BY l.created_at DESC
            LIMIT 100
        `);
        res.json(logs);
    } catch (err) {
        console.error('Admin audit logs error:', err);
        res.status(500).json({ error: 'Failed to fetch audit logs.' });
    }
});

app.get('/api/admin/export/:type', authenticateToken, requireAdmin, async (req, res) => {
    const { type } = req.params;
    const exports = {
        users: {
            filename: 'users.csv',
            query: `SELECT user_id, name, email, role, Verified, account_status, created_at FROM Users ORDER BY created_at DESC`
        },
        ngos: {
            filename: 'ngos.csv',
            query: `SELECT n.ngo_id, n.name, u.email, n.address, n.approval_status, n.rejection_reason, n.created_at FROM NGOs n JOIN Users u ON n.user_id = u.user_id ORDER BY n.created_at DESC`
        },
        opportunities: {
            filename: 'opportunities.csv',
            query: `SELECT o.opportunity_id, o.title, o.field, o.location, o.start_date, o.end_date, o.hours_required, n.name AS ngo_name, o.created_at FROM Opportunities o JOIN NGOs n ON o.ngo_id = n.ngo_id ORDER BY o.created_at DESC`
        },
        applications: {
            filename: 'applications.csv',
            query: `SELECT a.application_id, u.name AS volunteer_name, u.email AS volunteer_email, o.title AS opportunity_title, n.name AS ngo_name, a.status, a.applied_at, a.attendance_confirmed, a.hours_completed FROM Applications a JOIN Volunteers v ON a.volunteer_id = v.volunteer_id JOIN Users u ON v.user_id = u.user_id JOIN Opportunities o ON a.opportunity_id = o.opportunity_id JOIN NGOs n ON o.ngo_id = n.ngo_id ORDER BY a.applied_at DESC`
        },
        hours: {
            filename: 'volunteer_hours.csv',
            query: `SELECT u.name AS volunteer_name, u.email, COALESCE(SUM(a.hours_completed), 0) AS confirmed_hours FROM Volunteers v JOIN Users u ON v.user_id = u.user_id LEFT JOIN Applications a ON v.volunteer_id = a.volunteer_id AND a.attendance_confirmed = 'YES' GROUP BY u.user_id, u.name, u.email ORDER BY confirmed_hours DESC`
        }
    };

    if (!exports[type]) {
        return res.status(400).json({ error: 'Invalid export type.' });
    }

    try {
        const [rows] = await db.execute(exports[type].query);
        const headers = rows.length > 0 ? Object.keys(rows[0]) : [];
        const csv = [
            headers.map(csvEscape).join(','),
            ...rows.map(row => headers.map(header => csvEscape(row[header])).join(','))
        ].join('\n');

        await writeAuditLog(req.user.user_id, `export_${type}`, 'Export', type, `Admin exported ${type}.`);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${exports[type].filename}"`);
        res.send(csv);
    } catch (err) {
        console.error('Admin export error:', err);
        res.status(500).json({ error: 'Failed to export data.' });
    }
});

// ===== NGO PROFILE =====

app.get('/api/ngo-profile', authenticateToken, async (req, res) => {
    try {
        const ngoId = req.user.ngo_id;
        if (!ngoId) return res.status(400).json({ success: false, message: "NGO ID is required" });

        const [ngo] = await db.execute(`
            SELECT NGOs.name, Users.email, NGOs.description, NGOs.address, NGOs.logo, NGOs.approval_status
            FROM NGOs
            JOIN Users ON Users.ngo_id = NGOs.ngo_id
            WHERE NGOs.ngo_id = ?
        `, [ngoId]);

        if (ngo.length > 0) {
            return res.json({
                name: ngo[0].name,
                email: ngo[0].email,
                description: ngo[0].description,
                address: ngo[0].address,
                logo: ngo[0].logo,
                approval_status: ngo[0].approval_status
            });
        }

        res.status(404).json({ success: false, message: "NGO profile not found" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.post('/api/update-ngo-profile', authenticateToken, async (req, res) => {
    const { name, email, description, address } = req.body;
    const ngoId = req.user.ngo_id;
    if (!ngoId) return res.status(400).json({ success: false, message: "NGO ID is required" });

    let connection;
    try {
        connection = await db.getConnection();
        await connection.beginTransaction();
        await connection.execute(
            `UPDATE NGOs SET name = ?, description = ?, address = ? WHERE ngo_id = ?`,
            [name, description, address, ngoId]
        );
        await connection.execute(`UPDATE Users SET email = ? WHERE ngo_id = ?`, [email, ngoId]);
        await connection.commit();
        res.json({ success: true, message: "NGO profile updated successfully!" });
    } catch (err) {
        if (connection) await connection.rollback();
        console.error("Error updating NGO profile:", err);
        res.status(500).json({ success: false, message: "Server error" });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/upload-ngo-logo', authenticateToken, upload.single('ngoLogo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });
    const logoUrl = `/uploads/${req.file.filename}`;
    try {
        await db.execute(`UPDATE NGOs SET logo = ? WHERE ngo_id = ?`, [logoUrl, req.user.ngo_id]);
        res.json({ success: true, logo: logoUrl });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// ===== VOLUNTEER PROFILE =====

app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.user_id;
        const [results] = await db.execute(`
            SELECT 
                u.user_id, u.name, u.email,
                v.volunteer_id, v.phone, v.city, v.skills, v.interests, 
                v.image_url, v.Date_of_Birth, v.experiences,
                COALESCE((
                    SELECT SUM(a.hours_completed)
                    FROM Applications a
                    WHERE a.volunteer_id = v.volunteer_id
                      AND a.attendance_confirmed = 'YES'
                ), 0) AS total_hours
            FROM Users u
            LEFT JOIN Volunteers v ON u.user_id = v.user_id
            WHERE u.user_id = ?
        `, [userId]);

        if (results.length === 0) return res.status(404).json({ error: 'User not found' });

        const d = results[0];
        res.json({
            name: d.name,
            email: d.email,
            phone: d.phone || 'Not provided',
            city: d.city || 'Not provided',
            skills: d.skills ? d.skills.split(',').map(s => s.trim()) : [],
            experiences: d.experiences ? d.experiences.split(',').map(e => e.trim()) : [],
            imageUrl: d.image_url || 'default-profile.jpg',
            dateOfBirth: d.Date_of_Birth ? new Date(d.Date_of_Birth).toLocaleDateString() : 'Not provided',
            totalHours: Number(d.total_hours) || 0
        });
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).json({ error: 'Failed to fetch profile data' });
    }
});

app.post('/api/update-profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.user_id;
        const { name, email, phone, skills, experiences } = req.body;
        if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

        const connection = await db.getConnection();
        await connection.beginTransaction();
        try {
            await connection.execute('UPDATE Users SET name = ?, email = ? WHERE user_id = ?', [name, email, userId]);
            await connection.execute(
                `UPDATE Volunteers SET phone = ?, skills = ?, experiences = ? WHERE user_id = ?`,
                [phone || null, skills ? skills.join(', ') : null, experiences ? experiences.join(', ') : null, userId]
            );
            await connection.commit();
            connection.release();
            res.json({ message: 'Profile updated successfully' });
        } catch (transactionError) {
            await connection.rollback();
            connection.release();
            throw transactionError;
        }
    } catch (err) {
        console.error('Error updating profile:', err);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

const profilePicsDir = path.join(__dirname, '../uploads/profile-pictures');
const profilePicStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync(profilePicsDir)) fs.mkdirSync(profilePicsDir, { recursive: true });
        cb(null, profilePicsDir);
    },
    filename: (req, file, cb) => {
        const userId = req.user.user_id;
        const ext = path.extname(file.originalname);
        cb(null, `profile-${userId}${ext}`);
    }
});
const uploadProfilePic = multer({
    storage: profilePicStorage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only image files are allowed!'), false);
    },
    limits: { fileSize: 5 * 1024 * 1024 }
});

app.post('/api/upload-profile-picture', authenticateToken, uploadProfilePic.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        if (!fs.existsSync(req.file.path)) throw new Error('File was not saved to disk');

        const imageUrl = `/uploads/profile-pictures/${req.file.filename}`;
        await db.execute('UPDATE Volunteers SET image_url = ? WHERE user_id = ?', [imageUrl, req.user.user_id]);
        res.json({ message: 'Profile picture uploaded successfully', imageUrl });
    } catch (err) {
        console.error('Upload error:', err);
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: err.message || 'Failed to upload profile picture' });
    }
});

// ===== MISC =====

app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: "Access granted to protected resource", user: req.user });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/landingpage.html'));
});

const PORT = Number(process.env.PORT) || 3000;
const server = app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

server.on('error', (err) => {
    console.error('Server failed to start:', err);
    process.exit(1);
});
