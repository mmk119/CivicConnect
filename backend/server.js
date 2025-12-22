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

// Redirect console logs to Winston
console.log = (msg) => logger.info(msg);
console.error = (msg) => logger.error(msg);
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
    windowMs: 15 * 60 * 1000, // 15 mins
    max: 100, // Limit each IP to 100 requests
});
app.use(limiter);

// Middleware setup
app.use(express.json());
const allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'https://handsconnect-516m.onrender.com'
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl or internal server calls)
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
    res.header('Access-Control-Allow-Origin', 'https://handsconnect-516m.onrender.com'); // Your Render frontend
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    next();
  });
  
// OAuth2 setup
const oAuth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI
);

// Initialize with refresh token from .env
oAuth2Client.setCredentials({
    refresh_token: process.env.REFRESH_TOKEN
});

console.log('OAuth2 client initialized with refresh token from environment');


async function refreshAccessToken() {
    try {
        // Always use the refresh token from .env
        oAuth2Client.setCredentials({
            refresh_token: process.env.REFRESH_TOKEN
        });

        // Get new access token
        const { credentials } = await oAuth2Client.refreshAccessToken();
        console.log('Access token refreshed');

        return credentials.access_token;
    } catch (err) {
        console.error('Error refreshing access token:', err);
        throw err;
    }
}


// Email transporter setup - Simplified
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
                refreshToken: process.env.REFRESH_TOKEN, // Direct from .env
                accessToken: accessToken,
            },
        });
    } catch (err) {
        console.error('Error creating transporter:', err);
        throw err;
    }
}


// Authentication middleware
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

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { name, email, password, role, volunteer, ngo } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    let connection;
    try {
        connection = await db.getConnection();
        await connection.beginTransaction();

        const [users] = await connection.execute('SELECT * FROM Users WHERE email = ?', [email]);
        if (users.length > 0) {
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
                `INSERT INTO Volunteers (user_id, phone, city, skills, Date_of_Birth) 
                 VALUES (?, ?, ?, ?, ?)`,
                [userId, volunteer.phone || null, volunteer.city, volunteer.skills || null, volunteer.dob]
            );
        }
        else if (role === 'NGO') {
            if (!ngo?.name || !ngo?.description || !ngo?.address) {
                throw new Error('Missing NGO name, description, or address');
            }

            const [ngoResult] = await connection.execute(
                `INSERT INTO NGOs (name, description, address, user_id) 
                 VALUES (?, ?, ?, ?)`,
                [ngo.name, ngo.description, ngo.address, userId]
            );

            const ngoId = ngoResult.insertId;

            await connection.execute(
                'UPDATE Users SET ngo_id = ? WHERE user_id = ?',
                [ngoId, userId]
            );
        }

        await connection.commit();
        connection.release();

        const verificationLink = `https://handsconnect-516m.onrender.com/api/verify-email?token=${verificationToken}`;
        const transporter = await createTransporter();

        await transporter.sendMail({
            from: `HandsConnect <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Email Verification',
            html: `<p>Click the link to verify your email: <a href="${verificationLink}">Verify Email</a></p>`
        });

        res.status(201).json({ message: 'Registration successful. Check your email to verify your account.' });
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({
            error: err.message || 'Internal server error'
        });
    }
});

// Email verification endpoint
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

// Login endpoint
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

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        let redirectPath;
        switch (user.role.toLowerCase()) {
            case 'ngo':
                redirectPath = 'dashboard.html';
                break;
            case 'volunteer':
                redirectPath = 'opportunities.html';
                break;
            case 'admin':
                redirectPath = 'admin-dashboard.html';
                break;
            default:
                redirectPath = '/';
        }

        const token = jwt.sign(
            {
                user_id: user.user_id,
                email: user.email,
                role: user.role,
                ngo_id: user.ngo_id
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );

        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: {
                id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role,
                ngo_id: user.ngo_id
            },
            redirect: redirectPath
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Password reset request endpoint
app.post('/api/request-password-reset', async (req, res) => {
    const { email } = req.body;

    try {
        const [users] = await db.execute('SELECT * FROM Users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'Email not found' });
        }

        const user = users[0];
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

        await db.execute(
            'UPDATE Users SET reset_token = ?, reset_token_expiry = ? WHERE user_id = ?',
            [resetToken, resetTokenExpiry, user.user_id]
        );

        const resetLink = `https://handsconnect-516m.onrender.com/reset-password.html?token=${resetToken}`;
        const transporter = await createTransporter();

        await transporter.sendMail({
            from: `HandsConnect <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset',
            html: `<p>Click the link to reset your password: <a href="${resetLink}">Reset Password</a></p>`
        });

        res.status(200).json({ message: 'Password reset link sent to your email.' });
    } catch (err) {
        console.error('Error requesting password reset:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Password reset endpoint
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const [users] = await db.execute('SELECT * FROM Users WHERE reset_token = ? AND reset_token_expiry > ?', [token, Date.now()]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        const user = users[0];
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.execute(
            'UPDATE Users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?',
            [hashedPassword, user.user_id]
        );

        res.status(200).json({ message: 'Password reset successful. You can now log in with your new password.' });
    } catch (err) {
        console.error('Error resetting password:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== APPLY FUNCTIONALITY ===== //

// Enhanced GET /api/opportunities (now includes application status)
app.get('/api/opportunities/all', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    let user_id = null;

    try {
        if (token && token !== "dev-mode") {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            user_id = decoded.user_id;
        }

        const [opportunities] = await db.execute(`
            SELECT 
                o.*,
                ${user_id ?
                `EXISTS(
                        SELECT 1 FROM Applications 
                        WHERE volunteer_id = ? AND opportunity_id = o.opportunity_id
                    ) AS has_applied` :
                '0 AS has_applied'}
            FROM Opportunities o
            ORDER BY o.start_date ASC
        `, user_id ? [user_id] : []);

        res.json(opportunities);
    } catch (err) {
        console.error("Error fetching opportunities:", err);
        res.status(500).json({ error: "Failed to fetch opportunities." });
    }
});

// Handle Apply button submissions
app.post('/api/applications', authenticateToken, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');

    const { opportunity_id } = req.body;
    const user_id = req.user.user_id; // From JWT token

    if (!opportunity_id || isNaN(opportunity_id)) {
        return res.status(400).json({
            success: false,
            error: "Valid opportunity ID is required."
        });
    }

    try {
        // Verify the opportunity exists
        const [opportunity] = await db.execute(
            'SELECT opportunity_id, title FROM Opportunities WHERE opportunity_id = ?',
            [opportunity_id]
        );

        if (opportunity.length === 0) {
            return res.status(404).json({
                success: false,
                error: "Opportunity not found"
            });
        }

        // Get volunteer_id from Users -> Volunteers relationship
        const [volunteer] = await db.execute(
            'SELECT v.volunteer_id FROM Volunteers v WHERE v.user_id = ?',
            [user_id]
        );

        if (volunteer.length === 0) {
            return res.status(403).json({
                success: false,
                error: "Only volunteers can apply to opportunities"
            });
        }

        const volunteer_id = volunteer[0].volunteer_id;

        // Check for duplicate application
        const [existing] = await db.execute(
            `SELECT 1 FROM Applications 
             WHERE volunteer_id = ? AND opportunity_id = ? LIMIT 1`,
            [volunteer_id, opportunity_id]
        );

        if (existing.length > 0) {
            return res.status(409).json({
                success: false,
                error: "You've already applied to this opportunity"
            });
        }

        // Start transaction
        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            // Insert new application
            const [result] = await connection.execute(
                `INSERT INTO Applications (volunteer_id, opportunity_id, status) 
                 VALUES (?, ?, 'pending')`,
                [volunteer_id, opportunity_id]
            );

            // Get user details for email
            const [user] = await connection.execute(
                'SELECT email, name FROM Users WHERE user_id = ?',
                [user_id]
            );

            // Send email notification (non-blocking)
            if (user.length > 0) {
                const transporter = await createTransporter();
                transporter.sendMail({
                    from: `HandsConnect <${process.env.EMAIL_USER}>`,
                    to: user[0].email,
                    subject: 'Application Submitted',
                    html: `
                        <p>Hi ${user[0].name},</p>
                        <p>Your application for <strong>${opportunity[0].title}</strong> was received!</p>
                        <p>Status: <strong>Pending</strong></p>
                    `
                }).catch(emailError => {
                    console.error('Email sending failed:', emailError);
                });
            }

            await connection.commit();
            connection.release();

            return res.status(201).json({
                success: true,
                application_id: result.insertId,
                message: "Application submitted successfully"
            });

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

        return res.status(500).json({
            success: false,
            error: errorMessage
        });
    }
});
// ===== END APPLY FUNCTIONALITY ===== //

// Opportunities endpoints
app.get("/api/opportunities", authenticateToken, async (req, res) => {
    const ngoId = req.user.ngo_id;
    try {
        const [rows] = await db.execute(
            `SELECT * FROM Opportunities WHERE ngo_id = ?`,
            [ngoId]
        );
        res.json(rows);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ message: "Internal server error." });
    }
});
app.post('/api/opportunities/ins', async (req, res) => {
    const { title, description, start_date, end_date, location, ngo_id } = req.body;

    if (!title || !description || !start_date || !end_date || !location) {
        return res.status(400).json({ error: "All fields are required." });
    }

    try {
        const query = `
            INSERT INTO Opportunities (title, description, start_date, end_date, location, ngo_id)
            VALUES (?, ?, ?, ?, ?, ?)`;
        const [result] = await db.execute(query, [title, description, start_date, end_date, location, ngo_id]);

        console.log("✅ Opportunity saved:", {
            id: result.insertId,
            title,
            description,
            start_date,
            end_date,
            location,
        });

        res.status(201).json({ message: "Opportunity submitted successfully!", id: result.insertId });
    } catch (err) {
        console.error("❌ Error inserting opportunity:", err);
        res.status(500).json({ error: "Failed to submit opportunity." });
    }
});

app.delete('/api/opportunities/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const [results] = await db.execute("DELETE FROM Opportunities WHERE opportunity_id = ?", [id]);
        if (results.length === 0) {
            return res.status(404).json({ error: "Opportunity not found." });
        }

        const [result] = await db.execute("DELETE FROM Opportunities WHERE opportunity_id = ?", [id]);
        console.log(`✅ Opportunity deleted: ID ${id}`);
        res.json({ message: "Opportunity deleted successfully!" });

    } catch (err) {
        console.error("❌ Error deleting opportunity:", err);
        res.status(500).json({ error: "Failed to delete opportunity." });
    }
});

app.get('/api/opportunities/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [results] = await db.execute(
            `SELECT 
                 o.*, 
                 n.name AS ngo_name 
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
        console.error("❌ Error fetching opportunity:", err);
        res.status(500).json({ error: "Failed to fetch opportunity." });
    }
});

app.get('/api/opportunities/search', async (req, res) => {
    const { location, keyword } = req.query;
    try {
        const query = `
            SELECT opportunity_id, title, description, start_date, end_date, location, ngo_id
            FROM Opportunities
            WHERE location LIKE ? AND (title LIKE ? OR description LIKE ?)
            ORDER BY start_date ASC
        `;
        const [results] = await db.execute(query, [`%${location}%`, `%${keyword}%`, `%${keyword}%`]);

        res.json(results);
    } catch (err) {
        console.error("❌ Error fetching opportunities:", err);
        res.status(500).json({ error: "Failed to fetch opportunities." });
    }
});

// File handling setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, '../uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });
app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded." });
    }
    console.log("✅ File uploaded:", req.file.filename);
    res.json({ message: "File uploaded successfully!", filename: req.file.filename });
});

app.get('/api/files', (req, res) => {
    fs.readdir('../uploads/', (err, files) => {
        if (err) {
            console.error("❌ Error reading files:", err);
            return res.status(500).json({ error: "Failed to retrieve files." });
        }
        res.json(files);
    });
});

app.delete('/api/files/:filename', (req, res) => {
    const { filename } = req.params;
    const filePath = `uploads/${filename}`;

    if (fs.existsSync(filePath)) {
        fs.unlink(filePath, (err) => {
            if (err) {
                console.error("❌ Error deleting file:", err);
                return res.status(500).json({ error: "Failed to delete file." });
            }
            console.log(`✅ File deleted: ${filename}`);
            res.json({ message: "File deleted successfully!" });
        });
    } else {
        res.status(404).json({ error: "File not found." });
    }
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        message: "Access granted to protected resource",
        user: req.user
    });
});

// Admin endpoints
app.get('/api/admin/users', async (req, res) => {
    try {
        const [users] = await db.execute('SELECT * FROM Users');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch users" });
    }
});

app.post('/api/admin/ngos/:ngo_id/approve', async (req, res) => {
    try {
        const { ngo_id } = req.params;
        await db.execute(
            'UPDATE NGOs SET approval_status = "approved" WHERE ngo_id = ?',
            [ngo_id]
        );
        res.json({ message: "NGO approved successfully" });
    } catch (err) {
        res.status(500).json({ error: "Approval failed" });
    }
});

app.post('/api/admin/ngos/:ngo_id/reject', async (req, res) => {
    try {
        const { ngo_id } = req.params;
        await db.execute(
            'UPDATE NGOs SET approval_status = "rejected" WHERE ngo_id = ?',
            [ngo_id]
        );
        res.json({ message: "NGO rejected successfully" });
    } catch (err) {
        res.status(500).json({ error: "Rejection failed" });
    }
});

app.get('/api/admin/ngos/pending', async (req, res) => {
    try {
        const [ngos] = await db.execute(
            'SELECT ngo_id, name, description FROM NGOs WHERE approval_status = "pending"'
        );
        res.json(ngos);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch NGOs" });
    }
});

app.delete('/api/admin/users/:id', async (req, res) => {
    try {
        await db.execute('DELETE FROM Users WHERE user_id = ?', [req.params.id]);
        res.json({ message: "User deleted" });
    } catch (err) {
        res.status(500).json({ error: "Deletion failed" });
    }
});

app.patch('/api/admin/users/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!['active', 'banned'].includes(status)) {
            return res.status(400).json({ error: "Invalid status" });
        }

        await db.execute(
            'UPDATE Users SET account_status = ? WHERE user_id = ?',
            [status, id]
        );

        res.json({ message: 'Account status updated' });
    } catch (err) {
        res.status(500).json({ error: "Status update failed" });
    }
});

app.get('/api/applicants', authenticateToken, async (req, res) => {
    const ngo_id = req.query.ngo_id;
    if (!ngo_id) {
        return res.status(400).json({ error: 'ngo_id query parameter is required' });
      }
    try {
        const [opps] = await db.execute(
            `SELECT opportunity_id FROM Opportunities WHERE ngo_id = ?`,
            [ngo_id]
          );
          if (opps.length === 0) {
            return res.status(404).json({ error: 'No opportunities found for this NGO.' });
          }
          const ids = opps.map(o => o.opportunity_id);
          const placeholders = ids.map(_ => '?').join(',');
      
          // 2. join Applications → Volunteers → Users → Opportunities
          const [applicants] = await db.execute(
            `
            SELECT
              a.application_id   AS id,
              u.user_id,
              u.name,
              u.email,
              v.city,
              v.skills,
              a.status,
              o.title            AS opportunity_name
            FROM Applications a
            JOIN Volunteers v    ON a.volunteer_id = v.volunteer_id
            JOIN Users u         ON v.user_id       = u.user_id
            JOIN Opportunities o ON a.opportunity_id = o.opportunity_id
            WHERE a.opportunity_id IN (${placeholders})
            `,
            ids
          );
      
          res.json(applicants);
      
    } catch (err) {
        console.error('Error fetching applicants:', err);
       res.status(500).json({
         error: 'Failed to fetch applicants.',
         details: err.message
       });
    }
});

app.patch('/api/applications/:application_id', authenticateToken, async (req, res) => {
    const { application_id } = req.params;
    const { status } = req.body;
    const validStatuses = ['Pending','Accepted','Rejected'];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status update.' });
    }

    try {
        const [application] = await db.execute(`
            SELECT a.opportunity_id, a.volunteer_id, u.email, u.name
            FROM Applications a
            JOIN Volunteers v ON a.volunteer_id = v.volunteer_id
            JOIN Users u ON v.user_id = u.user_id
            WHERE a.application_id = ?
        `, [application_id]);

        if (application.length === 0) {
            return res.status(404).json({ error: 'Application not found' });
        }

        await db.execute(`
            UPDATE Applications 
            SET status = ? 
            WHERE application_id = ?
        `, [status, application_id]);

        // Send email notification
        const transporter = await createTransporter();
        await transporter.sendMail({
            from: `HandsConnect <${process.env.EMAIL_USER}>`,
            to: application[0].email,
            subject: `Application ${status.toUpperCase()}`,
            html: `<p>Dear ${application[0].name},</p>
                   <p>Your application for the opportunity has been ${status}.</p>`
        });

        res.json({ message: `Application ${status} successfully.` });
    } catch (err) {
        console.error('Error updating application status:', err);
        res.status(500).json({ error: 'Failed to update application status.' });
    }
});

app.get('/api/ngo-profile', authenticateToken, async (req, res) => {
    try {
        // Use the ngo_id provided in the query string or from req.user (if you want to enforce matching)
        const ngoId = req.user.ngo_id;

        if (!ngoId) {
            return res.status(400).json({ success: false, message: "NGO ID is required" });
        }

        const [ngo] = await db.execute(`
        SELECT 
                NGOs.name, 
                Users.email, 
                NGOs.description, 
                NGOs.address, 
                NGOs.logo
            FROM NGOs
            JOIN Users ON Users.ngo_id = NGOs.ngo_id
            WHERE NGOs.ngo_id = ?
      `, [ngoId]);

        if (ngo.length > 0) {
            const ngoProfile = {
                name: ngo[0].name,
                email: ngo[0].email,
                description: ngo[0].description,
                address: ngo[0].address,
                logo: ngo[0].logo
            };
            return res.json(ngoProfile);
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

    if (!ngoId) {
        return res.status(400).json({ success: false, message: "NGO ID is required" });
    }

    let connection;
    try {
        connection = await db.getConnection();
        await connection.beginTransaction();

        // Update NGO details
        await connection.execute(`
            UPDATE NGOs
            SET name = ?, description = ?, address = ?
            WHERE ngo_id = ?
        `, [name, description, address, ngoId]);

        // Update email in Users table
        await connection.execute(`
            UPDATE Users
            SET email = ?
            WHERE ngo_id = ?
        `, [email, ngoId]);

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
app.post('/api/upload-ngo-logo',
    authenticateToken,
    upload.single('ngoLogo'),
    async (req, res) => {
        if (!req.file) {
            return res.status(400).json({ success: false, message: "No file uploaded" });
        }

        const logoUrl = `/uploads/${req.file.filename}`;

        try {
            await db.execute(`
          UPDATE NGOs
          SET logo = ?
          WHERE ngo_id = ?
        `, [logoUrl, req.user.ngo_id]);

            res.json({ success: true, logo: logoUrl });
        } catch (err) {
            console.error(err);
            res.status(500).json({ success: false, message: "Server error" });
        }
    });


// Health check
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/landingpage.html'));
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});

// ===== VOLUNTEER PROFILE ENDPOINTS ===== //

// Get volunteer profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.user_id;

        // Get user and volunteer data in a single query with a JOIN
        const [results] = await db.execute(`
            SELECT 
                u.user_id, u.name, u.email,
                v.volunteer_id, v.phone, v.city, v.skills, v.interests, 
                v.image_url, v.Date_of_Birth, v.experiences
            FROM Users u
            LEFT JOIN Volunteers v ON u.user_id = v.user_id
            WHERE u.user_id = ?
        `, [userId]);

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const profileData = results[0];

        // Format the response to match what the frontend expects
        const response = {
            name: profileData.name,
            email: profileData.email,
            phone: profileData.phone || 'Not provided',
            city: profileData.city || 'Not provided',
            skills: profileData.skills ? profileData.skills.split(',').map(s => s.trim()) : [],
            experiences: profileData.experiences ? profileData.experiences.split(',').map(e => e.trim()) : [],
            imageUrl: profileData.image_url || 'default-profile.jpg',
            dateOfBirth: profileData.Date_of_Birth ? new Date(profileData.Date_of_Birth).toLocaleDateString() : 'Not provided'
        };

        res.json(response);
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).json({ error: 'Failed to fetch profile data' });
    }
});

// Update volunteer profile
app.post('/api/update-profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.user_id;
        const { name, email, phone, skills, experiences } = req.body;

        // Validate required fields
        if (!name || !email) {
            return res.status(400).json({ error: 'Name and email are required' });
        }

        // Start transaction
        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            // Update Users table
            await connection.execute(
                'UPDATE Users SET name = ?, email = ? WHERE user_id = ?',
                [name, email, userId]
            );

            // Update Volunteers table
            await connection.execute(
                `UPDATE Volunteers 
                 SET phone = ?, skills = ?, experiences = ?
                 WHERE user_id = ?`,
                [
                    phone || null,
                    skills ? skills.join(', ') : null,
                    experiences ? experiences.join(', ') : null,
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

// 1. First, create the absolute path to the upload directory
const profilePicsDir = path.join(__dirname, '../uploads/profile-pictures');

// 2. Update multer storage configuration
const profilePicStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Create directory if it doesn't exist
        if (!fs.existsSync(profilePicsDir)) {
            fs.mkdirSync(profilePicsDir, { recursive: true });
        }
        cb(null, profilePicsDir); // Use absolute path
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
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// 3. Update the endpoint to match frontend field name
app.post('/api/upload-profile-picture',
    authenticateToken,
    uploadProfilePic.single('file'), // Changed to 'file' to match frontend
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'No file uploaded' });
            }

            // Debug log to verify file saving
            console.log('File saved to:', req.file.path);
            console.log('File details:', {
                originalname: req.file.originalname,
                size: req.file.size,
                mimetype: req.file.mimetype
            });

            // Verify file was actually saved
            if (!fs.existsSync(req.file.path)) {
                throw new Error('File was not saved to disk');
            }

            const imageUrl = `/uploads/profile-pictures/${req.file.filename}`;

            // Update the image URL in the database
            await db.execute(
                'UPDATE Volunteers SET image_url = ? WHERE user_id = ?',
                [imageUrl, req.user.user_id]
            );

            res.json({
                message: 'Profile picture uploaded successfully',
                imageUrl
            });
        } catch (err) {
            console.error('Upload error:', err);

            // If file was saved but other error occurred, clean up
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }

            res.status(500).json({
                error: err.message || 'Failed to upload profile picture',
                details: process.env.NODE_ENV === 'development' ? err.stack : undefined
            });
        }
    }
);


