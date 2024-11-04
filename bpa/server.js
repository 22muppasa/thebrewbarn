// server.js

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key'; // Use environment variables in production

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Mock Database (Replace with a real database in production)
const users = []; // This should be replaced with a database like MongoDB, PostgreSQL, etc.

// Sign-Up Route
app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user
    const newUser = { id: Date.now(), email, password: hashedPassword };
    users.push(newUser);

    res.status(201).json({ message: 'User created successfully.' });
});

// Sign-In Route
app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;

    // Find the user
    const user = users.find(user => user.email === email);
    if (!user) {
        return res.status(400).json({ message: 'Invalid email or password.' });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid email or password.' });
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
});

// Protected Route Example
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({ message: `Welcome, user with ID: ${req.user.id}` });
});

// Middleware to Authenticate Token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
