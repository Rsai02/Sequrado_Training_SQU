const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const path = require('path');

const app = express();
const port = 3000;

// MySQL connection
const db = mysql.createConnection({
  host: '192.168.56.102',  // Windows server IP
  user: 'appuser',
  password: '1234',         // Your DB password
  database: 'appdb'
});

// Connect to DB
db.connect(err => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL database.');
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname))); // Serves index.html and static files

// Signup route
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required.' });
  }

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (results.length > 0) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    const hash = bcrypt.hashSync(password, 10);
    db.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash], (err) => {
      if (err) return res.status(500).json({ message: 'Failed to create user.' });
      res.status(200).json({ message: 'Signup successful. Please sign in.' });
    });
  });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (results.length === 0) {
      return res.status(401).json({ message: 'User not found.' });
    }

    const user = results[0];
    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Incorrect password.' });
    }

    res.status(200).json({ message: 'Login successful', user_id: user.id, username: user.username });
  });
});

// Action route (Buy/Sell)
app.post('/action', (req, res) => {
  const { user_id, username, action_type, details } = req.body;

  if (!user_id || !username || !action_type || !details) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }

  db.query(
    'INSERT INTO actions (user_id, username, action_type, details) VALUES (?, ?, ?, ?)',
    [user_id, username, action_type, details],
    (err) => {
      if (err) return res.status(500).json({ message: 'Failed to record action.' });
      res.status(200).json({ message: 'Action recorded successfully.' });
    }
  );
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
