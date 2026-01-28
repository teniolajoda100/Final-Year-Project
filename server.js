const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');

const app = express();
const PORT = 3000;

/* ================================
   DATABASE CONNECTION
   ================================ */

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'cvision',
    password: 'REMOVED_SECRET',
    port: 5432,
});

/* ================================
   MIDDLEWARE
   ================================ */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'cvision-secret-key',
    resave: false,
    saveUninitialized: false
}));

app.use(express.static(path.join(__dirname)));

/* ================================
   ROUTES
   ================================ */

// Homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

// Handle signup
app.post('/signup', async (req, res) => {
    const { fullName, email, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users (full_name, email, password_hash, role)
             VALUES ($1, $2, $3, $4)
             RETURNING id`,
            [fullName, email, hashedPassword, role]
        );

        req.session.userId = result.rows[0].id;
        req.session.role = role;

        res.redirect('/dashboard');

    } catch (err) {
        console.error(err);
        res.status(500).send('Error creating account');
    }
});

// Dashboard routing based on role
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/signup');
    }

    if (req.session.role === 'recruiter') {
        res.sendFile(path.join(__dirname, 'dashboard-recruiter.html'));
    } else {
        res.sendFile(path.join(__dirname, 'dashboard-user.html'));
    }
});

/* ================================
   SERVER START
   ================================ */

app.listen(PORT, () => {
    console.log(`CVision running at http://localhost:${PORT}`);
});
