const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();
const db = mysql.createConnection({host: 'localhost', user: 'root', password: 'root123'});

// VULNERABLE: Hardcoded JWT secret
const jwtSecret = 'my-super-secret-key-123';
const jwt = require('jsonwebtoken');

// VULNERABLE: CORS wildcard
const cors = require('cors');
app.use(cors({ origin: '*', credentials: true }));

// VULNERABLE: Debug mode
app.use(require('errorhandler')());

// AI-generated vulnerable endpoints
app.get('/user', (req, res) => {
  // VULNERABLE: SQL injection
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

app.post('/search', (req, res) => {
  // VULNERABLE: SQL injection via template literal
  const q = `SELECT * FROM products WHERE name LIKE '%${req.body.search}%'`;
  db.query(q, (err, results) => {
    res.json(results);
  });
});

app.get('/page', (req, res) => {
  // VULNERABLE: XSS
  res.send(`<div>${req.query.content}</div>`);
});

app.get('/render', (req, res) => {
  // VULNERABLE: XSS via innerHTML
  const html = `<h1>Welcome ${req.query.name}</h1>`;
  res.send(`<script>document.body.innerHTML = '${html}';</script>`);
});

app.get('/file', (req, res) => {
  // VULNERABLE: Path traversal
  const path = './uploads/' + req.query.filename;
  fs.readFile(path, (err, data) => {
    res.send(data);
  });
});

app.post('/run', (req, res) => {
  // VULNERABLE: Command injection
  exec('ping ' + req.body.host, (err, stdout) => {
    res.send(stdout);
  });
});

app.post('/eval', (req, res) => {
  // VULNERABLE: eval with user input
  const result = eval(req.body.code);
  res.json({ result });
});

app.get('/redirect', (req, res) => {
  // VULNERABLE: Open redirect
  res.redirect(req.query.url);
});

app.get('/hash', (req, res) => {
  // VULNERABLE: Insecure crypto
  const hash = crypto.createHash('md5').update(req.query.data).digest('hex');
  res.json({ hash });
});

app.get('/token', (req, res) => {
  // VULNERABLE: Weak random for token
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

app.post('/webhook', (req, res) => {
  // VULNERABLE: SSRF
  fetch(req.body.url).then(r => r.text()).then(body => res.send(body));
});

// VULNERABLE: Hardcoded secrets
const API_KEY = "sk-live-abc123def456ghi789";
const SECRET_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// VULNERABLE: Default credentials
const adminUser = 'admin';
const adminPassword = 'admin';

// VULNERABLE: Logging sensitive data
app.use((req, res, next) => {
  console.log('Request body:', JSON.stringify(req.body));
  console.log('Authorization header:', req.headers.authorization);
  next();
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
