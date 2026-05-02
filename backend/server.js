require('./config/env');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const { createCorsOptions } = require('./config/cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const crypto = require('crypto');
const util = require('util');
const { createAuthenticateToken, requireAdmin } = require('./middleware/auth');
const registerMiscRoutes = require('./routes/misc.routes');
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
const frontendDir = path.join(__dirname, '../frontend');
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
app.use(express.static(frontendDir));

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
app.use(cors(createCorsOptions()));

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

const authenticateToken = createAuthenticateToken(jwt, process.env.JWT_SECRET);

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

function cleanText(value, maxLength) {
    return String(value || '').trim().slice(0, maxLength);
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function parseRating(value) {
    const rating = Number(value);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) return null;
    return rating;
}

function normalizeList(value, maxItems = 12, maxLength = 80) {
    const values = Array.isArray(value)
        ? value
        : String(value || '').split(',');
    return values
        .map(item => cleanText(item, maxLength))
        .filter(Boolean)
        .slice(0, maxItems);
}

function normalizeQuestions(value) {
    const questions = Array.isArray(value)
        ? value
        : String(value || '').split(/\r?\n/);
    return questions
        .map(question => cleanText(question, 180))
        .filter(Boolean)
        .slice(0, 5);
}

function readJsonArray(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function normalizeApplicationAnswers(questions, answers) {
    const questionList = readJsonArray(questions);
    if (questionList.length === 0) return null;
    const answerList = Array.isArray(answers) ? answers : [];

    return JSON.stringify(questionList.map((question, index) => ({
        question,
        answer: cleanText(answerList[index], 800)
    })));
}

function opportunityMatchReasons(opportunity, volunteer) {
    if (!volunteer) return [];
    const reasons = [];
    const preferredFields = normalizeList(volunteer.preferred_fields).map(item => item.toLowerCase());
    const preferredCities = normalizeList(volunteer.preferred_cities).map(item => item.toLowerCase());
    const availableDays = normalizeList(volunteer.available_days).map(item => item.toUpperCase());
    const opportunityDays = normalizeList(opportunity.schedule_days).map(item => item.toUpperCase());

    if (preferredFields.includes(String(opportunity.field || '').toLowerCase())) {
        reasons.push('Matches your preferred field');
    }
    if (preferredCities.some(city => String(opportunity.location || '').toLowerCase().includes(city))) {
        reasons.push('Matches your preferred city');
    }
    if (opportunityDays.some(day => availableDays.includes(day))) {
        reasons.push('Matches your available days');
    }

    return reasons;
}

function authCookieOptions() {
    const isProduction = process.env.NODE_ENV === 'production';
    return {
        httpOnly: true,
        secure: String(process.env.COOKIE_SECURE || isProduction).toLowerCase() === 'true',
        sameSite: process.env.COOKIE_SAMESITE || (isProduction ? 'none' : 'lax'),
        maxAge: Number(process.env.COOKIE_MAX_AGE_MS) || 60 * 60 * 1000
    };
}

function dateEndOfDay(value) {
    const date = dateFromInput(value);
    if (!date) return null;
    date.setHours(23, 59, 59, 999);
    return date;
}

function opportunityLifecycle(opportunity) {
    const storedStatus = opportunity.status || 'open';
    if (storedStatus === 'completed' || storedStatus === 'archived' || storedStatus === 'closed') return storedStatus;
    const start = dateFromInput(opportunity.start_date);
    const end = dateEndOfDay(opportunity.end_date);
    const now = new Date();
    if (start && end && now >= start && now <= end) return 'in_progress';
    return storedStatus;
}

function withOpportunityLifecycle(opportunity) {
    const acceptedCount = Number(opportunity.accepted_count) || 0;
    const resolvedAcceptedCount = Number(opportunity.resolved_accepted_count) || 0;
    const needsAttendanceReview = acceptedCount > resolvedAcceptedCount;
    return {
        ...opportunity,
        lifecycle_status: opportunityLifecycle(opportunity),
        needs_attendance_review: needsAttendanceReview
    };
}

async function opportunityFinalizeSummary(opportunityId, ngoId) {
    const [rows] = await db.execute(`
        SELECT
            o.opportunity_id,
            o.status,
            o.end_date,
            COUNT(CASE WHEN a.status = 'accepted' THEN 1 END) AS accepted_count,
            COUNT(CASE WHEN a.status = 'accepted'
                        AND (a.attendance_confirmed = 'YES' OR a.completion_status = 'no_show')
                  THEN 1 END) AS resolved_count
        FROM Opportunities o
        LEFT JOIN Applications a ON a.opportunity_id = o.opportunity_id
        WHERE o.opportunity_id = ? AND o.ngo_id = ?
        GROUP BY o.opportunity_id, o.status, o.end_date
    `, [opportunityId, ngoId]);
    return rows[0] || null;
}

const uploadRoot = path.join(__dirname, '../uploads');
const generalUploadsDir = uploadRoot;
const ngoLogosDir = path.join(uploadRoot, 'ngo-logos');
const profilePicsDir = path.join(uploadRoot, 'profile-pictures');
const allowedUploadTypes = new Map([
    ['image/jpeg', '.jpg'],
    ['image/png', '.png'],
    ['image/webp', '.webp'],
    ['application/pdf', '.pdf']
]);
const allowedImageTypes = new Map([
    ['image/jpeg', '.jpg'],
    ['image/png', '.png'],
    ['image/webp', '.webp']
]);

function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function safeUploadName(file, allowedTypes) {
    const ext = allowedTypes.get(file.mimetype);
    return `${Date.now()}-${crypto.randomUUID()}${ext}`;
}

function fileFilterFor(allowedTypes) {
    return (req, file, cb) => {
        const ext = path.extname(file.originalname || '').toLowerCase();
        const expectedExt = allowedTypes.get(file.mimetype);
        if (!expectedExt || (ext && ext !== expectedExt && !(expectedExt === '.jpg' && ext === '.jpeg'))) {
            return cb(new Error('File type is not allowed.'), false);
        }
        cb(null, true);
    };
}

// ===== AUTH ROUTES =====

app.post('/api/register', async (req, res) => {
    const name = cleanText(req.body.name, 120);
    const email = cleanText(req.body.email, 254).toLowerCase();
    const { password, role, volunteer, ngo } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'A valid email address is required.' });
    }

    if (String(password).length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters.' });
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

        res.cookie('cc_token', token, authCookieOptions());
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
    const email = cleanText(req.body.email, 254).toLowerCase();
    const genericMessage = 'If an account exists for that email, a password reset link has been sent.';

    if (!email || !emailRegex.test(email)) {
        return res.status(400).json({ error: 'A valid email address is required.' });
    }

    try {
        const [users] = await db.execute('SELECT * FROM Users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(200).json({ message: genericMessage });
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

        res.status(200).json({ message: genericMessage });
    } catch (err) {
        console.error('Error requesting password reset:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIX 1: reset-password route with proper CAST for bigint expiry comparison
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword || String(newPassword).length < 8) {
        return res.status(400).json({ error: 'A valid token and password of at least 8 characters are required.' });
    }

    try {
        const now = Date.now();
        const [users] = await db.execute(
            'SELECT * FROM Users WHERE reset_token = ? AND CAST(reset_token_expiry AS UNSIGNED) > ?',
            [token, now]
        );

        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.execute(
            'UPDATE Users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?',
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

const scheduleDayCodes = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];

function parseScheduleDays(value) {
    const source = Array.isArray(value)
        ? value
        : String(value || '').split(',');
    const days = [...new Set(source.map(day => String(day).trim().toUpperCase()).filter(Boolean))];
    if (days.length === 0 || days.some(day => !scheduleDayCodes.includes(day))) return null;
    return days;
}

function isValidTime(value) {
    return /^([01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$/.test(String(value || ''));
}

function minutesFromTime(value) {
    if (!isValidTime(value)) return null;
    const [hours, minutes] = String(value).split(':').map(Number);
    return hours * 60 + minutes;
}

function dateFromInput(value) {
    const match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!match) return null;
    const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
    return Number.isNaN(date.getTime()) ? null : date;
}

function calculateScheduleHours(startDateValue, endDateValue, days, startTime, endTime) {
    const startDate = dateFromInput(startDateValue);
    const endDate = dateFromInput(endDateValue);
    if (!startDate || !endDate || endDate < startDate) return null;

    const startMinutes = minutesFromTime(startTime);
    const endMinutes = minutesFromTime(endTime);
    if (startMinutes === null || endMinutes === null) return null;

    const minutesPerSession = endMinutes - startMinutes;
    if (minutesPerSession <= 0) return null;

    const jsDayToCode = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
    let sessions = 0;
    const cursor = new Date(startDate);
    while (cursor <= endDate) {
        if (days.includes(jsDayToCode[cursor.getDay()])) sessions += 1;
        cursor.setDate(cursor.getDate() + 1);
    }

    if (sessions < 1) return null;
    return Math.round((sessions * minutesPerSession / 60) * 100) / 100;
}

function normalizeHours(value) {
    const hours = Number(value);
    if (!Number.isFinite(hours)) return null;
    return Math.round(hours * 100) / 100;
}

function formatHours(value) {
    const hours = normalizeHours(value) || 0;
    return Number.isInteger(hours) ? String(hours) : String(hours).replace(/0+$/, '').replace(/\.$/, '');
}

// FIX 2: /api/opportunities/search MUST be before /api/opportunities/:id
app.get('/api/opportunities/search', async (req, res) => {
    const { location = '', keyword = '', field = '' } = req.query;
    try {
        const query = `
            SELECT opportunity_id, title, field, description, start_date, end_date,
                   schedule_days, start_time, end_time, hours_required, location, ngo_id
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
    let volunteerProfile = null;

    try {
        if (token && token !== "dev-mode") {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const [vol] = await db.execute(
                `SELECT volunteer_id, available_days, available_start_time, available_end_time, preferred_fields, preferred_cities
                 FROM Volunteers
                 WHERE user_id = ?`,
                [decoded.user_id]
            );
            if (vol.length > 0) {
                volunteer_id = vol[0].volunteer_id;
                volunteerProfile = vol[0];
            }
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
                (
                    SELECT COUNT(*)
                    FROM Applications a
                    WHERE a.opportunity_id = o.opportunity_id
                      AND a.status = 'accepted'
                      AND (a.attendance_confirmed = 'YES' OR a.completion_status = 'no_show')
                ) AS resolved_accepted_count,
                ${volunteer_id
                    ? `EXISTS(SELECT 1 FROM Applications WHERE volunteer_id = ? AND opportunity_id = o.opportunity_id) AS has_applied,
                       EXISTS(SELECT 1 FROM SavedOpportunities WHERE volunteer_id = ? AND opportunity_id = o.opportunity_id) AS is_saved`
                    : '0 AS has_applied, 0 AS is_saved'}
            FROM Opportunities o
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            WHERE o.status NOT IN ('completed', 'archived')
            ORDER BY o.start_date ASC
        `, volunteer_id ? [volunteer_id, volunteer_id] : []);

        res.json(opportunities.map(opportunity => {
            const matchReasons = opportunityMatchReasons(opportunity, volunteerProfile);
            return {
                ...withOpportunityLifecycle(opportunity),
                is_good_match: matchReasons.length >= 2,
                match_reasons: matchReasons
            };
        }));
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
                   ) AS accepted_count,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id
                         AND a.status = 'accepted'
                         AND (a.attendance_confirmed = 'YES' OR a.completion_status = 'no_show')
                   ) AS resolved_accepted_count,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id
                         AND a.status = 'pending'
                   ) AS pending_count,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id
                         AND a.status = 'rejected'
                   ) AS rejected_count
            FROM Opportunities o
            WHERE o.ngo_id = ?
        `, [ngoId]);
        res.json(rows.map(withOpportunityLifecycle));
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ message: "Internal server error." });
    }
});

app.post('/api/opportunities/ins', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: "Only NGO accounts can create opportunities." });
    }

    const { title, field, description, start_date, end_date, schedule_days, start_time, end_time, capacity, location } = req.body;
    const ngo_id = req.user.ngo_id;
    const volunteerCapacity = Number(capacity);
    const selectedDays = parseScheduleDays(schedule_days);
    const questions = normalizeQuestions(req.body.application_questions);

    if (!title || !field || !description || !start_date || !end_date || !capacity || !location || !selectedDays || !start_time || !end_time) {
        return res.status(400).json({ error: "All fields are required." });
    }

    if (!opportunityFields.includes(field)) {
        return res.status(400).json({ error: "Invalid opportunity field." });
    }

    if (!isValidTime(start_time) || !isValidTime(end_time)) {
        return res.status(400).json({ error: "Start and end time must be valid." });
    }

    const scheduleHours = calculateScheduleHours(start_date, end_date, selectedDays, start_time, end_time);
    if (!scheduleHours || scheduleHours < 0.25) {
        return res.status(400).json({ error: "Your selected days and timing must create at least one volunteering session." });
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

        const query = `
            INSERT INTO Opportunities
                (title, field, description, start_date, end_date, schedule_days, start_time, end_time, hours_required, capacity, location, application_questions, ngo_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
        `;
        const [result] = await db.execute(query, [
            title,
            field,
            description,
            start_date,
            end_date,
            selectedDays.join(','),
            start_time,
            end_time,
            scheduleHours,
            volunteerCapacity,
            location,
            questions.length ? JSON.stringify(questions) : null,
            ngo_id
        ]);
        console.log("Opportunity saved:", result.insertId);
        res.status(201).json({ message: "Opportunity submitted successfully!", id: result.insertId });
    } catch (err) {
        console.error("Error inserting opportunity:", err);
        res.status(500).json({ error: "Failed to submit opportunity." });
    }
});

app.patch('/api/opportunities/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: "Only NGO accounts can update opportunities." });
    }

    const { title, field, description, start_date, end_date, schedule_days, start_time, end_time, capacity, location } = req.body;
    const opportunityId = Number(req.params.id);
    const volunteerCapacity = Number(capacity);
    const selectedDays = parseScheduleDays(schedule_days);
    const questions = normalizeQuestions(req.body.application_questions);

    if (!Number.isInteger(opportunityId) || opportunityId < 1) {
        return res.status(400).json({ error: "Valid opportunity ID is required." });
    }

    if (!title || !field || !description || !start_date || !end_date || !capacity || !location || !selectedDays || !start_time || !end_time) {
        return res.status(400).json({ error: "All fields are required." });
    }

    if (!opportunityFields.includes(field)) {
        return res.status(400).json({ error: "Invalid opportunity field." });
    }

    if (!isValidTime(start_time) || !isValidTime(end_time)) {
        return res.status(400).json({ error: "Start and end time must be valid." });
    }

    const scheduleHours = calculateScheduleHours(start_date, end_date, selectedDays, start_time, end_time);
    if (!scheduleHours || scheduleHours < 0.25) {
        return res.status(400).json({ error: "Your selected days and timing must create at least one volunteering session." });
    }

    if (!Number.isInteger(volunteerCapacity) || volunteerCapacity < 1) {
        return res.status(400).json({ error: "Volunteer capacity must be a positive whole number." });
    }

    try {
        const [result] = await db.execute(`
            UPDATE Opportunities
            SET title = ?, field = ?, description = ?, start_date = ?, end_date = ?,
                schedule_days = ?, start_time = ?, end_time = ?, hours_required = ?,
                capacity = ?, location = ?, application_questions = ?,
                status = CASE WHEN status = 'completed' OR status = 'archived' THEN status ELSE 'open' END
            WHERE opportunity_id = ? AND ngo_id = ?
        `, [
            title,
            field,
            description,
            start_date,
            end_date,
            selectedDays.join(','),
            start_time,
            end_time,
            scheduleHours,
            volunteerCapacity,
            location,
            questions.length ? JSON.stringify(questions) : null,
            opportunityId,
            req.user.ngo_id
        ]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Opportunity not found." });
        }

        res.json({ message: "Opportunity updated successfully.", id: opportunityId });
    } catch (err) {
        console.error("Error updating opportunity:", err);
        res.status(500).json({ error: "Failed to update opportunity." });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('cc_token', authCookieOptions());
    res.json({ success: true });
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

app.patch('/api/opportunities/:id/close', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: "Only NGO accounts can close opportunities." });
    }

    const opportunityId = Number(req.params.id);
    if (!Number.isInteger(opportunityId) || opportunityId < 1) {
        return res.status(400).json({ error: "Valid opportunity ID is required." });
    }

    try {
        const [result] = await db.execute(`
            UPDATE Opportunities
            SET status = 'closed'
            WHERE opportunity_id = ?
              AND ngo_id = ?
              AND status IN ('open', 'in_progress')
        `, [opportunityId, req.user.ngo_id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Opportunity not found or cannot be closed." });
        }

        res.json({ message: "Applications closed for this opportunity." });
    } catch (err) {
        console.error("Error closing opportunity:", err);
        res.status(500).json({ error: "Failed to close opportunity." });
    }
});

app.patch('/api/opportunities/:id/finalize', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: "Only NGO accounts can finalize opportunities." });
    }

    const opportunityId = Number(req.params.id);
    if (!Number.isInteger(opportunityId) || opportunityId < 1) {
        return res.status(400).json({ error: "Valid opportunity ID is required." });
    }

    try {
        const summary = await opportunityFinalizeSummary(opportunityId, req.user.ngo_id);
        if (!summary) {
            return res.status(404).json({ error: "Opportunity not found." });
        }

        const endDate = dateEndOfDay(summary.end_date);
        if (endDate && endDate > new Date()) {
            return res.status(400).json({ error: "You can finalize after the opportunity end date." });
        }

        if (Number(summary.accepted_count) > Number(summary.resolved_count)) {
            return res.status(400).json({
                error: "Resolve attendance for every accepted volunteer before finalizing."
            });
        }

        await db.execute(`
            UPDATE Opportunities
            SET status = 'completed',
                finalized_at = COALESCE(finalized_at, NOW())
            WHERE opportunity_id = ? AND ngo_id = ?
        `, [opportunityId, req.user.ngo_id]);

        res.json({ message: "Opportunity finalized as completed." });
    } catch (err) {
        console.error("Error finalizing opportunity:", err);
        res.status(500).json({ error: "Failed to finalize opportunity." });
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

app.get('/api/opportunities/:id/feedback', async (req, res) => {
    const { id } = req.params;
    try {
        const [[summary]] = await db.execute(`
            SELECT
                COUNT(*) AS total_reviews,
                ROUND(AVG(rating), 1) AS average_rating
            FROM OpportunityFeedback
            WHERE opportunity_id = ?
        `, [id]);

        const [reviews] = await db.execute(`
            SELECT
                ofb.opportunity_feedback_id,
                ofb.rating,
                ofb.comment,
                ofb.impact_story,
                ofb.created_at,
                u.name AS volunteer_name
            FROM OpportunityFeedback ofb
            JOIN Volunteers v ON ofb.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            WHERE ofb.opportunity_id = ?
            ORDER BY ofb.created_at DESC
        `, [id]);

        res.json({
            total_reviews: Number(summary.total_reviews) || 0,
            average_rating: summary.average_rating || null,
            reviews
        });
    } catch (err) {
        console.error('Error fetching opportunity feedback:', err);
        res.status(500).json({ error: 'Failed to fetch opportunity feedback.' });
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
            SELECT opportunity_id, title, field, description, location, start_date, end_date,
                   schedule_days, start_time, end_time, hours_required, capacity
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
            `SELECT opportunity_id, title, end_date, capacity, application_questions,
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

        const applicationAnswers = normalizeApplicationAnswers(
            opportunity[0].application_questions,
            req.body.application_answers
        );

        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            const [result] = await connection.execute(
                `INSERT INTO Applications (volunteer_id, opportunity_id, status, application_answers) VALUES (?, ?, 'pending', ?)`,
                [volunteer_id, opportunity_id, applicationAnswers]
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

        try {
            const transporter = await createTransporter();
            await transporter.sendMail({
                from: `CivicConnect <${process.env.EMAIL_USER}>`,
                to: application[0].email,
                subject: `Application ${status.toUpperCase()}`,
                html: `<p>Dear ${escapeHtml(application[0].name)},</p><p>Your application has been <strong>${status}</strong>.</p>`
            });
        } catch (emailErr) {
            console.error('Application status email failed:', emailErr.message);
        }

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
    const requestedHours = normalizeHours(req.body.hours_completed);

    if (!requestedHours || requestedHours < 0.25) {
        return res.status(400).json({ error: 'Completed hours must be at least 0.25.' });
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

        const maxHours = normalizeHours(application.hours_required) || requestedHours;
        if (requestedHours > maxHours) {
            return res.status(400).json({ error: `Completed hours cannot be more than ${maxHours}.` });
        }

        await db.execute(`
            UPDATE Applications
            SET attendance_confirmed = 'YES',
                completion_status = 'attended',
                hours_completed = ?,
                attendance_confirmed_at = NOW(),
                completed_at = COALESCE(completed_at, NOW()),
                certificate_id = COALESCE(certificate_id, UUID())
            WHERE application_id = ?
        `, [requestedHours, application_id]);

        res.json({ message: `Attendance confirmed. ${requestedHours} volunteering hours added.` });
    } catch (err) {
        console.error('Error confirming attendance:', err);
        res.status(500).json({ error: 'Failed to confirm attendance.' });
    }
});

app.patch('/api/applications/:application_id/no-show', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: 'Only NGO accounts can mark no-shows.' });
    }

    const applicationId = Number(req.params.application_id);
    if (!Number.isInteger(applicationId) || applicationId < 1) {
        return res.status(400).json({ error: 'Valid application ID is required.' });
    }

    try {
        const [applications] = await db.execute(`
            SELECT a.application_id, a.status, a.attendance_confirmed
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE a.application_id = ? AND o.ngo_id = ?
        `, [applicationId, req.user.ngo_id]);

        if (applications.length === 0) {
            return res.status(404).json({ error: 'Application not found for this NGO.' });
        }

        if (applications[0].status !== 'accepted') {
            return res.status(400).json({ error: 'Only accepted applications can be marked no-show.' });
        }

        if (applications[0].attendance_confirmed === 'YES') {
            return res.status(409).json({ error: 'Attendance was already confirmed.' });
        }

        await db.execute(`
            UPDATE Applications
            SET completion_status = 'no_show',
                hours_completed = 0,
                completed_at = COALESCE(completed_at, NOW())
            WHERE application_id = ?
        `, [applicationId]);

        res.json({ message: 'Volunteer marked as no-show.' });
    } catch (err) {
        console.error('Error marking no-show:', err);
        res.status(500).json({ error: 'Failed to mark no-show.' });
    }
});

app.patch('/api/applications/:application_id/withdraw', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).json({ error: 'Only volunteers can withdraw applications.' });
    }

    const applicationId = Number(req.params.application_id);
    if (!Number.isInteger(applicationId) || applicationId < 1) {
        return res.status(400).json({ error: 'Valid application ID is required.' });
    }

    try {
        const [volunteers] = await db.execute(
            'SELECT volunteer_id FROM Volunteers WHERE user_id = ?',
            [req.user.user_id]
        );
        if (volunteers.length === 0) {
            return res.status(404).json({ error: 'Volunteer profile not found.' });
        }

        const [result] = await db.execute(`
            UPDATE Applications
            SET status = 'withdrawn'
            WHERE application_id = ?
              AND volunteer_id = ?
              AND status = 'pending'
        `, [applicationId, volunteers[0].volunteer_id]);

        if (result.affectedRows === 0) {
            return res.status(400).json({ error: 'Only pending applications can be withdrawn.' });
        }

        res.json({ message: 'Application withdrawn successfully.' });
    } catch (err) {
        console.error('Error withdrawing application:', err);
        res.status(500).json({ error: 'Failed to withdraw application.' });
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
                a.completion_status,
                a.applied_at,
                o.opportunity_id,
                o.title,
                o.description,
                o.field,
                o.location,
                o.start_date,
                o.end_date,
                o.hours_required,
                o.schedule_days,
                o.start_time,
                o.end_time,
                a.hours_completed,
                a.attendance_confirmed,
                a.attendance_confirmed_at,
                a.completed_at,
                a.certificate_id,
                n.name AS ngo_name,
                ofb.opportunity_feedback_id,
                ofb.rating AS opportunity_feedback_rating,
                ofb.comment AS opportunity_feedback_comment,
                ofb.impact_story AS opportunity_feedback_impact_story,
                vfb.volunteer_feedback_id,
                vfb.rating AS volunteer_feedback_rating,
                vfb.endorsement_title AS volunteer_feedback_title,
                vfb.comment AS volunteer_feedback_comment,
                vfb.strengths AS volunteer_feedback_strengths,
                COALESCE(vfb.show_on_profile, 0) AS volunteer_feedback_show_on_profile
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            LEFT JOIN OpportunityFeedback ofb ON a.application_id = ofb.application_id
            LEFT JOIN VolunteerFeedback vfb ON a.application_id = vfb.application_id
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
    const opportunityId = Number(req.query.opportunity_id);

    if (!Number.isInteger(opportunityId) || opportunityId < 1) {
        return res.status(400).json({ error: 'A valid opportunity_id is required.' });
    }

    try {
        const [opps] = await db.execute(
            `SELECT opportunity_id FROM Opportunities WHERE ngo_id = ? AND opportunity_id = ?`,
            [ngo_id, opportunityId]
        );
        if (opps.length === 0) {
            return res.status(404).json({ error: 'Opportunity not found for this NGO.' });
        }

        const [applicants] = await db.execute(`
            SELECT
                a.application_id AS id,
                u.user_id,
                u.name,
                u.email,
                v.city,
                v.skills,
                a.status,
                a.completion_status,
                a.application_answers,
                a.hours_completed,
                a.attendance_confirmed,
                a.attendance_confirmed_at,
                ofb.opportunity_feedback_id,
                ofb.rating AS opportunity_feedback_rating,
                ofb.comment AS opportunity_feedback_comment,
                ofb.impact_story AS opportunity_feedback_impact_story,
                vfb.volunteer_feedback_id,
                vfb.rating AS volunteer_feedback_rating,
                vfb.endorsement_title AS volunteer_feedback_title,
                vfb.comment AS volunteer_feedback_comment,
                vfb.strengths AS volunteer_feedback_strengths,
                COALESCE(vfb.show_on_profile, 0) AS volunteer_feedback_show_on_profile,
                o.title AS opportunity_name,
                o.end_date,
                o.hours_required,
                o.schedule_days,
                o.start_time,
                o.end_time,
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
                ) AS completed_history,
                (
                    SELECT GROUP_CONCAT(
                        CONCAT_WS('~~',
                            vfbp.endorsement_title,
                            vfbp.rating,
                            vfbp.comment,
                            COALESCE(vfbp.strengths, ''),
                            np.name,
                            op.title
                        )
                        ORDER BY vfbp.created_at DESC
                        SEPARATOR '||'
                    )
                    FROM VolunteerFeedback vfbp
                    JOIN NGOs np ON vfbp.ngo_id = np.ngo_id
                    JOIN Applications ap ON vfbp.application_id = ap.application_id
                    JOIN Opportunities op ON ap.opportunity_id = op.opportunity_id
                    WHERE vfbp.volunteer_id = v.volunteer_id
                      AND vfbp.show_on_profile = 1
                ) AS profile_endorsements
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            LEFT JOIN OpportunityFeedback ofb ON a.application_id = ofb.application_id
            LEFT JOIN VolunteerFeedback vfb ON a.application_id = vfb.application_id
            WHERE a.opportunity_id = ?
            ORDER BY a.applied_at DESC
        `, [opportunityId]);

        res.json(applicants);
    } catch (err) {
        console.error('Error fetching applicants:', err);
        res.status(500).json({ error: 'Failed to fetch applicants.', details: err.message });
    }
});

app.post('/api/feedback/opportunity/:application_id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).json({ error: 'Only volunteers can review opportunities.' });
    }

    const rating = parseRating(req.body.rating);
    const comment = cleanText(req.body.comment, 1200);
    const impactStory = cleanText(req.body.impact_story, 800);

    if (!rating || comment.length < 10) {
        return res.status(400).json({ error: 'Please add a 1-5 rating and at least 10 characters of feedback.' });
    }

    try {
        const [rows] = await db.execute(`
            SELECT a.application_id, a.volunteer_id, a.opportunity_id, a.status, a.attendance_confirmed
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            WHERE a.application_id = ? AND v.user_id = ?
        `, [req.params.application_id, req.user.user_id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Completed application not found.' });
        }

        const application = rows[0];
        if (application.status !== 'accepted' || application.attendance_confirmed !== 'YES') {
            return res.status(400).json({ error: 'Feedback opens after the NGO confirms your attendance.' });
        }

        const [existing] = await db.execute(
            'SELECT opportunity_feedback_id FROM OpportunityFeedback WHERE application_id = ?',
            [application.application_id]
        );
        if (existing.length > 0) {
            return res.status(409).json({ error: 'You already submitted feedback for this opportunity.' });
        }

        await db.execute(`
            INSERT INTO OpportunityFeedback (application_id, volunteer_id, opportunity_id, rating, comment, impact_story)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [application.application_id, application.volunteer_id, application.opportunity_id, rating, comment, impactStory || null]);

        res.json({ message: 'Your opportunity feedback was saved.' });
    } catch (err) {
        console.error('Error saving opportunity feedback:', err);
        res.status(500).json({ error: 'Failed to save opportunity feedback.' });
    }
});

app.post('/api/feedback/volunteer/:application_id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'NGO' || !req.user.ngo_id) {
        return res.status(403).json({ error: 'Only NGO accounts can endorse volunteers.' });
    }

    const rating = parseRating(req.body.rating);
    const title = cleanText(req.body.endorsement_title, 120);
    const comment = cleanText(req.body.comment, 1200);
    const strengths = cleanText(req.body.strengths, 800);

    if (!rating || title.length < 3 || comment.length < 10) {
        return res.status(400).json({ error: 'Please add a rating, short endorsement title, and meaningful feedback.' });
    }

    try {
        const [rows] = await db.execute(`
            SELECT a.application_id, a.volunteer_id, a.status, a.attendance_confirmed, o.ngo_id
            FROM Applications a
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE a.application_id = ? AND o.ngo_id = ?
        `, [req.params.application_id, req.user.ngo_id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Completed application not found for this NGO.' });
        }

        const application = rows[0];
        if (application.status !== 'accepted' || application.attendance_confirmed !== 'YES') {
            return res.status(400).json({ error: 'Volunteer feedback opens after attendance is confirmed.' });
        }

        const [existing] = await db.execute(
            'SELECT volunteer_feedback_id FROM VolunteerFeedback WHERE application_id = ?',
            [application.application_id]
        );
        if (existing.length > 0) {
            return res.status(409).json({ error: 'You already submitted feedback for this volunteer.' });
        }

        await db.execute(`
            INSERT INTO VolunteerFeedback (application_id, ngo_id, volunteer_id, rating, endorsement_title, comment, strengths)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [application.application_id, req.user.ngo_id, application.volunteer_id, rating, title, comment, strengths || null]);

        res.json({ message: 'Volunteer feedback was saved.' });
    } catch (err) {
        console.error('Error saving volunteer feedback:', err);
        res.status(500).json({ error: 'Failed to save volunteer feedback.' });
    }
});

app.patch('/api/feedback/volunteer/:feedback_id/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).json({ error: 'Only volunteers can add endorsements to their profile.' });
    }

    const feedbackId = Number(req.params.feedback_id);
    if (!Number.isInteger(feedbackId) || feedbackId < 1) {
        return res.status(400).json({ error: 'Valid feedback ID is required.' });
    }

    try {
        const [rows] = await db.execute(`
            SELECT vfb.volunteer_feedback_id
            FROM VolunteerFeedback vfb
            JOIN Volunteers v ON vfb.volunteer_id = v.volunteer_id
            WHERE vfb.volunteer_feedback_id = ?
              AND v.user_id = ?
        `, [feedbackId, req.user.user_id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Endorsement not found for this volunteer.' });
        }

        await db.execute(
            'UPDATE VolunteerFeedback SET show_on_profile = 1 WHERE volunteer_feedback_id = ?',
            [feedbackId]
        );

        res.json({ message: 'Endorsement added to your profile.' });
    } catch (err) {
        console.error('Error adding endorsement to profile:', err);
        res.status(500).json({ error: 'Failed to add endorsement to profile.' });
    }
});

app.post('/api/feedback/:type/:id/report', authenticateToken, async (req, res) => {
    const { type, id } = req.params;
    const config = {
        opportunity: { table: 'OpportunityFeedback', column: 'opportunity_feedback_id' },
        volunteer: { table: 'VolunteerFeedback', column: 'volunteer_feedback_id' }
    };

    if (!config[type]) {
        return res.status(400).json({ error: 'Invalid feedback type.' });
    }

    const reason = cleanText(req.body.reason, 255);
    const details = cleanText(req.body.details, 1000);
    if (reason.length < 3) {
        return res.status(400).json({ error: 'Please choose a report reason.' });
    }

    try {
        const item = config[type];
        const [rows] = await db.execute(
            `SELECT ${item.column} FROM ${item.table} WHERE ${item.column} = ?`,
            [id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Feedback not found.' });
        }

        await db.execute(`
            INSERT INTO FeedbackReports (feedback_type, feedback_id, reporter_user_id, reason, details)
            VALUES (?, ?, ?, ?, ?)
        `, [type, id, req.user.user_id, reason, details || null]);

        res.status(201).json({ message: 'Report submitted for admin review.' });
    } catch (err) {
        console.error('Feedback report error:', err);
        res.status(500).json({ error: 'Failed to report feedback.' });
    }
});

// ===== FILE UPLOAD =====

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        ensureDir(generalUploadsDir);
        cb(null, generalUploadsDir);
    },
    filename: (req, file, cb) => {
        cb(null, safeUploadName(file, allowedUploadTypes));
    }
});
const upload = multer({
    storage,
    fileFilter: fileFilterFor(allowedUploadTypes),
    limits: { fileSize: 5 * 1024 * 1024 }
});

app.post('/api/upload', authenticateToken, requireAdmin, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded." });
    res.json({ message: "File uploaded successfully!", filename: req.file.filename });
});

app.get('/api/files', authenticateToken, requireAdmin, (req, res) => {
    fs.readdir(generalUploadsDir, (err, files) => {
        if (err) return res.status(500).json({ error: "Failed to retrieve files." });
        res.json(files);
    });
});

app.delete('/api/files/:filename', authenticateToken, requireAdmin, (req, res) => {
    const filename = path.basename(req.params.filename);
    const uploadDir = path.resolve(generalUploadsDir);
    const filePath = path.resolve(uploadDir, filename);
    if (!filePath.startsWith(uploadDir + path.sep)) {
        return res.status(400).json({ error: "Invalid filename." });
    }
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
                   ) AS application_count,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id AND a.status = 'accepted'
                   ) AS accepted_count,
                   (
                       SELECT COUNT(*)
                       FROM Applications a
                       WHERE a.opportunity_id = o.opportunity_id
                         AND a.status = 'accepted'
                         AND (a.attendance_confirmed = 'YES' OR a.completion_status = 'no_show')
                   ) AS resolved_accepted_count
            FROM Opportunities o
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            WHERE (? = '' OR o.title LIKE ? OR o.description LIKE ? OR o.location LIKE ? OR n.name LIKE ?)
              AND (? = '' OR o.field = ?)
              AND (? = '' OR (? = 'upcoming' AND o.end_date >= CURDATE()) OR (? = 'passed' AND o.end_date < CURDATE())
                          OR o.status = ?)
            ORDER BY o.created_at DESC
        `, [search, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, field, field, status, status, status]);
        res.json(opportunities.map(withOpportunityLifecycle));
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
            SELECT a.application_id, a.status, a.completion_status, a.applied_at, a.attendance_confirmed,
                   a.hours_completed, a.attendance_confirmed_at,
                   o.title AS opportunity_title, o.field, o.hours_required,
                   o.schedule_days, o.start_time, o.end_time,
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

app.get('/api/admin/feedback', authenticateToken, requireAdmin, async (req, res) => {
    const { type = '', search = '' } = req.query;
    const searchTerm = `%${search}%`;

    try {
        const [opportunityFeedback] = await db.execute(`
            SELECT
                'opportunity' AS feedback_type,
                ofb.opportunity_feedback_id AS feedback_id,
                ofb.rating,
                NULL AS title,
                ofb.comment,
                ofb.impact_story AS extra_note,
                ofb.review_status,
                ofb.reviewed_at,
                ofb.created_at,
                COALESCE(fr.open_reports, 0) AS open_reports,
                u.name AS author_name,
                u.email AS author_email,
                o.title AS opportunity_title,
                n.name AS ngo_name,
                NULL AS volunteer_name
            FROM OpportunityFeedback ofb
            JOIN Volunteers v ON ofb.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            JOIN Opportunities o ON ofb.opportunity_id = o.opportunity_id
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            LEFT JOIN (
                SELECT feedback_id, COUNT(*) AS open_reports
                FROM FeedbackReports
                WHERE feedback_type = 'opportunity' AND status = 'open'
                GROUP BY feedback_id
            ) fr ON fr.feedback_id = ofb.opportunity_feedback_id
            WHERE (? IN ('', 'opportunity'))
              AND (? = '' OR u.name LIKE ? OR u.email LIKE ? OR o.title LIKE ? OR n.name LIKE ? OR ofb.comment LIKE ?)
            ORDER BY COALESCE(fr.open_reports, 0) DESC, ofb.rating ASC, ofb.created_at DESC
        `, [type, search, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm]);

        const [volunteerFeedback] = await db.execute(`
            SELECT
                'volunteer' AS feedback_type,
                vfb.volunteer_feedback_id AS feedback_id,
                vfb.rating,
                vfb.endorsement_title AS title,
                vfb.comment,
                vfb.strengths AS extra_note,
                vfb.review_status,
                vfb.reviewed_at,
                vfb.created_at,
                COALESCE(fr.open_reports, 0) AS open_reports,
                n.name AS author_name,
                u_ngo.email AS author_email,
                o.title AS opportunity_title,
                n.name AS ngo_name,
                u_vol.name AS volunteer_name
            FROM VolunteerFeedback vfb
            JOIN NGOs n ON vfb.ngo_id = n.ngo_id
            JOIN Users u_ngo ON n.user_id = u_ngo.user_id
            JOIN Volunteers v ON vfb.volunteer_id = v.volunteer_id
            JOIN Users u_vol ON v.user_id = u_vol.user_id
            JOIN Applications a ON vfb.application_id = a.application_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            LEFT JOIN (
                SELECT feedback_id, COUNT(*) AS open_reports
                FROM FeedbackReports
                WHERE feedback_type = 'volunteer' AND status = 'open'
                GROUP BY feedback_id
            ) fr ON fr.feedback_id = vfb.volunteer_feedback_id
            WHERE (? IN ('', 'volunteer'))
              AND (? = '' OR n.name LIKE ? OR u_ngo.email LIKE ? OR u_vol.name LIKE ? OR o.title LIKE ? OR vfb.comment LIKE ?)
            ORDER BY COALESCE(fr.open_reports, 0) DESC, vfb.rating ASC, vfb.created_at DESC
        `, [type, search, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm]);

        res.json([...opportunityFeedback, ...volunteerFeedback]
            .sort((a, b) => (Number(b.open_reports) - Number(a.open_reports)) || (Number(a.rating) - Number(b.rating)) || (new Date(b.created_at) - new Date(a.created_at))));
    } catch (err) {
        console.error('Admin feedback error:', err);
        res.status(500).json({ error: 'Failed to fetch feedback.' });
    }
});

app.patch('/api/admin/feedback/:type/:id/review', authenticateToken, requireAdmin, async (req, res) => {
    const { type, id } = req.params;
    const config = {
        opportunity: { table: 'OpportunityFeedback', column: 'opportunity_feedback_id', target: 'OpportunityFeedback' },
        volunteer: { table: 'VolunteerFeedback', column: 'volunteer_feedback_id', target: 'VolunteerFeedback' }
    };

    if (!config[type]) {
        return res.status(400).json({ error: 'Invalid feedback type.' });
    }

    try {
        const item = config[type];
        const [result] = await db.execute(
            `UPDATE ${item.table} SET review_status = 'reviewed', reviewed_at = NOW() WHERE ${item.column} = ?`,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Feedback not found.' });
        }

        await db.execute(
            `UPDATE FeedbackReports SET status = 'reviewed', reviewed_at = NOW() WHERE feedback_type = ? AND feedback_id = ? AND status = 'open'`,
            [type, id]
        );
        await writeAuditLog(req.user.user_id, 'review_feedback', item.target, id, `Admin marked ${type} feedback as reviewed.`);
        res.json({ message: 'Feedback marked as reviewed.' });
    } catch (err) {
        console.error('Admin review feedback error:', err);
        res.status(500).json({ error: 'Failed to review feedback.' });
    }
});

app.delete('/api/admin/feedback/:type/:id', authenticateToken, requireAdmin, async (req, res) => {
    const { type, id } = req.params;
    const config = {
        opportunity: {
            table: 'OpportunityFeedback',
            column: 'opportunity_feedback_id',
            target: 'OpportunityFeedback'
        },
        volunteer: {
            table: 'VolunteerFeedback',
            column: 'volunteer_feedback_id',
            target: 'VolunteerFeedback'
        }
    };

    if (!config[type]) {
        return res.status(400).json({ error: 'Invalid feedback type.' });
    }

    try {
        const item = config[type];
        const [result] = await db.execute(
            `DELETE FROM ${item.table} WHERE ${item.column} = ?`,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Feedback not found.' });
        }

        await writeAuditLog(req.user.user_id, 'delete_feedback', item.target, id, `Admin deleted ${type} feedback after moderation review.`);
        res.json({ message: 'Feedback deleted successfully.' });
    } catch (err) {
        console.error('Admin delete feedback error:', err);
        res.status(500).json({ error: 'Failed to delete feedback.' });
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
            query: `SELECT o.opportunity_id, o.title, o.field, o.location, o.start_date, o.end_date, o.schedule_days, o.start_time, o.end_time, o.hours_required, n.name AS ngo_name, o.created_at FROM Opportunities o JOIN NGOs n ON o.ngo_id = n.ngo_id ORDER BY o.created_at DESC`
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

const ngoLogoStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        ensureDir(ngoLogosDir);
        cb(null, ngoLogosDir);
    },
    filename: (req, file, cb) => {
        cb(null, safeUploadName(file, allowedImageTypes));
    }
});
const uploadNgoLogo = multer({
    storage: ngoLogoStorage,
    fileFilter: fileFilterFor(allowedImageTypes),
    limits: { fileSize: 3 * 1024 * 1024 }
});

app.post('/api/upload-ngo-logo', authenticateToken, uploadNgoLogo.single('ngoLogo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });
    const logoUrl = `/uploads/ngo-logos/${req.file.filename}`;
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
                v.available_days, v.available_start_time, v.available_end_time,
                v.preferred_fields, v.preferred_cities,
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
        const [endorsements] = d.volunteer_id ? await db.execute(`
            SELECT
                vfb.volunteer_feedback_id,
                vfb.rating,
                vfb.endorsement_title,
                vfb.comment,
                vfb.strengths,
                n.name AS ngo_name,
                o.title AS opportunity_title,
                vfb.created_at
            FROM VolunteerFeedback vfb
            JOIN NGOs n ON vfb.ngo_id = n.ngo_id
            JOIN Applications a ON vfb.application_id = a.application_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE vfb.volunteer_id = ?
              AND vfb.show_on_profile = 1
            ORDER BY vfb.created_at DESC
        `, [d.volunteer_id]) : [[]];

        res.json({
            name: d.name,
            email: d.email,
            phone: d.phone || 'Not provided',
            city: d.city || 'Not provided',
            skills: d.skills ? d.skills.split(',').map(s => s.trim()) : [],
            experiences: d.experiences ? d.experiences.split(',').map(e => e.trim()) : [],
            availableDays: d.available_days ? d.available_days.split(',').map(s => s.trim()) : [],
            availableStartTime: d.available_start_time ? String(d.available_start_time).slice(0, 5) : '',
            availableEndTime: d.available_end_time ? String(d.available_end_time).slice(0, 5) : '',
            preferredFields: d.preferred_fields ? d.preferred_fields.split(',').map(s => s.trim()) : [],
            preferredCities: d.preferred_cities ? d.preferred_cities.split(',').map(s => s.trim()) : [],
            imageUrl: d.image_url || 'default-profile.jpg',
            dateOfBirth: d.Date_of_Birth ? new Date(d.Date_of_Birth).toLocaleDateString() : 'Not provided',
            totalHours: Number(d.total_hours) || 0,
            profileEndorsements: endorsements
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
        const availableDays = normalizeList(req.body.availableDays).map(day => day.toUpperCase()).filter(day => ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'].includes(day));
        const preferredFields = normalizeList(req.body.preferredFields);
        const preferredCities = normalizeList(req.body.preferredCities);
        const availableStartTime = isValidTime(req.body.availableStartTime) ? req.body.availableStartTime : null;
        const availableEndTime = isValidTime(req.body.availableEndTime) ? req.body.availableEndTime : null;
        if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

        const connection = await db.getConnection();
        await connection.beginTransaction();
        try {
            await connection.execute('UPDATE Users SET name = ?, email = ? WHERE user_id = ?', [name, email, userId]);
            await connection.execute(
                `UPDATE Volunteers
                 SET phone = ?, skills = ?, experiences = ?,
                     available_days = ?, available_start_time = ?, available_end_time = ?,
                     preferred_fields = ?, preferred_cities = ?
                 WHERE user_id = ?`,
                [
                    phone || null,
                    skills ? skills.join(', ') : null,
                    experiences ? experiences.join(', ') : null,
                    availableDays.length ? availableDays.join(',') : null,
                    availableStartTime,
                    availableEndTime,
                    preferredFields.length ? preferredFields.join(', ') : null,
                    preferredCities.length ? preferredCities.join(', ') : null,
                    userId
                ]
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

const profilePicStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        ensureDir(profilePicsDir);
        cb(null, profilePicsDir);
    },
    filename: (req, file, cb) => {
        const userId = req.user.user_id;
        const ext = allowedImageTypes.get(file.mimetype);
        cb(null, `profile-${userId}${ext}`);
    }
});
const uploadProfilePic = multer({
    storage: profilePicStorage,
    fileFilter: fileFilterFor(allowedImageTypes),
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

app.get('/api/certificates/:application_id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Volunteer') {
        return res.status(403).send('Only volunteers can view certificates.');
    }

    try {
        const [rows] = await db.execute(`
            SELECT
                a.application_id,
                a.certificate_id,
                a.hours_completed,
                a.attendance_confirmed_at,
                u.name AS volunteer_name,
                o.title AS opportunity_title,
                o.start_date,
                o.end_date,
                n.name AS ngo_name
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            WHERE a.application_id = ?
              AND v.user_id = ?
              AND a.status = 'accepted'
              AND a.attendance_confirmed = 'YES'
        `, [req.params.application_id, req.user.user_id]);

        if (rows.length === 0) {
            return res.status(404).send('Certificate not found.');
        }

        const certificate = rows[0];
        const certificateId = certificate.certificate_id || `pending-${certificate.application_id}`;
        const verifyUrl = `${req.protocol}://${req.get('host')}/api/certificates/verify/${encodeURIComponent(certificateId)}`;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CivicConnect Certificate</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Georgia, serif; background: #f5f7fb; color: #10253d; }
    .certificate { width: min(900px, calc(100% - 32px)); padding: 56px; border: 10px solid #1285f3; background: #fff; text-align: center; box-shadow: 0 20px 60px rgba(16,37,61,.18); }
    .brand { color: #ff6800; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    h1 { font-size: 2.6rem; margin: 18px 0; }
    .name { font-size: 2rem; color: #1285f3; margin: 22px 0; }
    p { font-size: 1.1rem; line-height: 1.7; }
    .meta { margin-top: 28px; color: #61758a; }
    .verify { margin-top: 24px; padding-top: 18px; border-top: 1px solid #dbe6f3; font-family: Arial, sans-serif; font-size: .95rem; color: #4f6378; }
    .signatures { display: flex; gap: 40px; justify-content: center; margin-top: 34px; font-family: Arial, sans-serif; }
    .signature { min-width: 220px; border-top: 1px solid #10253d; padding-top: 8px; }
    .print { margin-top: 28px; padding: 12px 18px; border: 0; border-radius: 10px; color: #fff; background: #1285f3; font-weight: 800; cursor: pointer; }
    @media print { body { background: #fff; } .print { display: none; } .certificate { box-shadow: none; } }
  </style>
</head>
<body>
  <main class="certificate">
    <div class="brand">CivicConnect</div>
    <h1>Certificate of Volunteering</h1>
    <p>This certifies that</p>
    <div class="name">${escapeHtml(cleanText(certificate.volunteer_name, 200))}</div>
    <p>completed <strong>${formatHours(certificate.hours_completed)} volunteer hours</strong> for <strong>${escapeHtml(cleanText(certificate.opportunity_title, 200))}</strong> with <strong>${escapeHtml(cleanText(certificate.ngo_name, 200))}</strong>.</p>
    <p class="meta">Opportunity dates: ${String(certificate.start_date).slice(0, 10)} to ${String(certificate.end_date).slice(0, 10)}</p>
    <div class="signatures">
      <div class="signature">${escapeHtml(cleanText(certificate.ngo_name, 200))}</div>
      <div class="signature">CivicConnect Admin</div>
    </div>
    <div class="verify">
      Certificate ID: <strong>${escapeHtml(certificateId)}</strong><br>
      Verify: ${escapeHtml(verifyUrl)}
    </div>
    <button class="print" onclick="window.print()">Print / Save as PDF</button>
  </main>
</body>
</html>`);
    } catch (err) {
        console.error('Certificate error:', err);
        res.status(500).send('Failed to generate certificate.');
    }
});

app.get('/api/certificates/verify/:certificate_id', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT
                a.certificate_id,
                a.hours_completed,
                a.attendance_confirmed_at,
                u.name AS volunteer_name,
                o.title AS opportunity_title,
                n.name AS ngo_name
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            JOIN NGOs n ON o.ngo_id = n.ngo_id
            WHERE a.certificate_id = ?
              AND a.status = 'accepted'
              AND a.attendance_confirmed = 'YES'
        `, [req.params.certificate_id]);

        if (rows.length === 0) {
            return res.status(404).json({ valid: false, error: 'Certificate not found.' });
        }

        const certificate = rows[0];
        res.json({
            valid: true,
            certificate_id: certificate.certificate_id,
            volunteer_name: certificate.volunteer_name,
            opportunity_title: certificate.opportunity_title,
            ngo_name: certificate.ngo_name,
            hours_completed: normalizeHours(certificate.hours_completed) || 0,
            issued_at: certificate.attendance_confirmed_at
        });
    } catch (err) {
        console.error('Certificate verification error:', err);
        res.status(500).json({ valid: false, error: 'Failed to verify certificate.' });
    }
});

// ===== MISC =====

registerMiscRoutes(app, { authenticateToken, frontendDir });

const PORT = Number(process.env.PORT) || 3000;

if (require.main === module) {
    const server = app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });

    server.on('error', (err) => {
        console.error('Server failed to start:', err);
        process.exit(1);
    });
}

module.exports = app;
