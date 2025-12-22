/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
require('dotenv').config();
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use('/uploads', express.static('uploads'));

app.use(express.json());
app.use(cors());

// Middleware to ensure authentication
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: "Invalid or expired token." });
        }
        req.user = decoded;
        next();
    });
}

// Login Route (Dummy authentication for now)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    const users = [{ email: 'user@domain.com', password: 'password123' }];
    const user = users.find(u => u.email === email && u.password === password);

    if (user) {
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
        res.json({ message: 'Login successful!', token });
    } else {
        res.status(401).json({ error: 'Invalid email or password' });
    }
});

// Store opportunities in MySQL
app.post('/api/opportunities', async(req, res) => {
    const { title, description, date, location } = req.body;

    if (!title || !description || !date || !location) {
        return res.status(400).json({ error: "All fields are required." });
    }

    try {
        const query = "INSERT INTO opportunities (title, description, date, location) VALUES (?, ?, ?, ?)";
        const [result] = await db.execute(query, [title, description, date, location]);

        res.status(201).json({ message: "Opportunity submitted successfully!", id: result.insertId });
    } catch (err) {
        res.status(500).json({ error: "Failed to submit opportunity." });
    }
});

// Fetch all opportunities from MySQL
app.get('/api/opportunities', async(req, res) => {
    try {
        const [results] = await db.execute("SELECT * FROM opportunities");
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch opportunities." });
    }
});

// DELETE an opportunity
app.delete('/api/opportunities/:id', async(req, res) => {
    const { id } = req.params;

    try {
        const [results] = await db.execute("SELECT * FROM opportunities WHERE id = ?", [id]);

        if (results.length === 0) {
            return res.status(404).json({ error: "Opportunity not found." });
        }

        await db.execute("DELETE FROM opportunities WHERE id = ?", [id]);

        res.json({ message: "Opportunity deleted successfully!" });
    } catch (err) {
        res.status(500).json({ error: "Failed to delete opportunity." });
    }
});

// File upload handling
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
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
    res.json({ message: "File uploaded successfully!", filename: req.file.filename });
});

app.get('/api/files', (req, res) => {
    fs.readdir('uploads/', (err, files) => {
        if (err) {
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
                return res.status(500).json({ error: "Failed to delete file." });
            }
            res.json({ message: "File deleted successfully!" });
        });
    } else {
        res.status(404).json({ error: "File not found." });
    }
});

app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: "Access granted to protected resource", user: req.user });
});

app.get('/', (req, res) => {
    res.send('Server is running!');
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});