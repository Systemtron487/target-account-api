const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const db = new sqlite3.Database('./database.sqlite');
const SECRET_KEY = 'your_secret_key_here'; 

db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // Companies table
  db.run(`
    CREATE TABLE IF NOT EXISTS companies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      match_score REAL NOT NULL,
      status TEXT DEFAULT 'Not Target'
    )
  `);

  // Insert initial user (username: user1, password: pass123)
  db.run(
    `INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`,
    ['user1', bcrypt.hashSync('pass123', 10)]
  );

  // Insert sample companies
  db.run(`
    INSERT OR IGNORE INTO companies (name, match_score) VALUES
    ('Amazon', 0.92),
    ('Microsoft', 0.87),
    ('Google', 0.95),
    ('Tesla', 0.78)
  `);
});

// Authentication 
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

// 1. Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  });
});

// 2. Get all companies 
app.get('/accounts', authenticateToken, (req, res) => {
  db.all('SELECT id, name, match_score, status FROM companies', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 3. Update company status 
app.post('/accounts/:id/status', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['Target', 'Not Target'].includes(status)) {
    return res.status(400).json({ message: 'Status must be "Target" or "Not Target"' });
  }

  db.run(
    'UPDATE companies SET status = ? WHERE id = ?',
    [status, id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ message: 'Company not found' });
      res.json({ message: 'Status updated successfully' });
    }
  );
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});