const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;

// MySQL connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'your_password',  // Replace with your MySQL root password
    database: 'opportunity_applications'
});

db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('MySQL Connected...');
});

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public'));

// File upload configuration using multer
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');  // Folder to store uploaded resumes
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);  // File name format
    }
});

const upload = multer({ storage: storage });

// API to handle the form submission
app.post('/apply', upload.single('resume'), (req, res) => {
    const { availability, skills } = req.body;
    const resumePath = req.file ? req.file.path : null;

    const query = 'INSERT INTO applications (availability, skills, resume_path) VALUES (?, ?, ?)';
    db.query(query, [availability, skills, resumePath], (err, result) => {
        if (err) {
            return res.status(500).send('Error submitting application');
        }
        res.send('Application submitted successfully');
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
