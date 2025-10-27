// BACKEND - cleaned & robust JSON responses + trimmed inputs + better token handling
require('dotenv').config();

const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();

// Middlewares
app.use(cors({
  origin: 'http://localhost:1234', // Tillåt requests från Parcel dev server
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());

// ---- ENV + DB ----
const jwtSecret = process.env.JWT_SECRET;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;
const dbHost = process.env.DB_HOST;
const dbName = process.env.DB_NAME;
const dbPort = process.env.DB_PORT;

const db = mysql.createConnection({
  host: dbHost,
  user: dbUser,
  password: dbPassword,
  database: dbName,
  port: dbPort
});

console.log('DB host/port/name:', dbHost, dbPort, dbName);

db.connect(err => {
  if (err) {
    console.error('Kunde inte ansluta till databasen:', err);
    process.exit(1);
  }
  console.log('Ansluten till databasen');
});

// ---- Helpers ----
const peek = (s, n = 12) => (typeof s === 'string' ? s.slice(0, n) : String(s).slice(0, n));

// JWT-verifieringsmiddleware
const verifyToken = (req, res, next) => {
  const hdr = req.headers['authorization'] || '';
  console.log('[verifyToken] Authorization header:', hdr);
  
  const parts = hdr.split(' ');
  const bearer = parts.length === 2 && /^Bearer$/i.test(parts[0]) ? parts[1] : null;

  if (!bearer) {
    console.log('[verifyToken] No bearer token found');
    return res.status(403).json({ auth: false, message: 'Ingen token tillhandahållen.' });
  }

  jwt.verify(bearer, jwtSecret, (err, decoded) => {
    if (err) {
      console.log('[verifyToken] Token verification failed:', err.message);
      return res.status(401).json({ auth: false, message: 'Ogiltig token.' });
    }
    console.log('[verifyToken] Token verified successfully for user:', decoded.username);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  });
};

// ---- Routes ----

// Register
app.post('/register', (req, res) => {
  let { username, password, mail } = req.body || {};
  username = String(username || '').trim();
  mail = String(mail || '').trim();
  password = String(password || '').trim();

  if (!username || !password || !mail) {
    return res.status(400).json({ error: 'username, password och mail krävs' });
  }

  const account_created = new Date();

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Fel vid hashning av lösenord:', err.message);
      return res.status(500).json({ error: 'Ett fel uppstod vid hashning av lösenordet' });
    }

    const query = 'INSERT INTO users (username, password, mail, account_created) VALUES (?, ?, ?, ?)';
    db.query(query, [username, hash, mail, account_created], (err) => {
      if (err) {
        console.error('DB-fel vid registrering:', err.code || err.message);
        return res.status(500).json({ error: 'Ett fel uppstod vid registrering av användare' });
      }
      res.status(201).json({ message: 'Användare skapad' });
    });
  });
});

// Logga in användare
app.post('/login', (req, res) => {
  let { username, password } = req.body || {};
  username = String(username || '').trim();
  password = String(password || '').trim();

  if (!username || !password) {
    return res.status(400).json({ error: 'Användarnamn och lösenord krävs' });
  }

  const query = 'SELECT id, username, password FROM users WHERE username = ? LIMIT 1';
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('DB error /login:', err.code || err.message);
      return res.status(500).json({ error: 'Ett fel uppstod vid inloggning' });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: 'Felaktigt lösenord eller användarnamn' });
    }

    const user = results[0];
    const storedHash = String(user.password || '');
    console.log('[login] user:', user.username, '| hashLen:', storedHash.length, '| hashPeek:', peek(storedHash));

    bcrypt.compare(password, storedHash, (cmpErr, isMatch) => {
      if (cmpErr) {
        console.error('bcrypt error:', cmpErr.message);
        return res.status(500).json({ error: 'Ett fel uppstod vid jämförelse av lösenord' });
      }
      console.log('[login] compare result:', isMatch ? 'MATCH' : 'NO MATCH');

      if (!isMatch) {
        return res.status(401).json({ error: 'Felaktigt lösenord eller användarnamn' });
      }

      const token = jwt.sign({ id: user.id, username: user.username }, jwtSecret, { expiresIn: 86400 });
      console.log('[login] Token created for user:', user.username);
      res.status(200).json({ auth: true, token });
    });
  });
});

// Validera
app.get('/validate', verifyToken, (req, res) => {
  console.log('[/validate] Successful validation for user:', req.username);
  return res.status(200).json({ username: req.username || 'Okänd' });
});

// Catch-all för att logga 404s
app.use((req, res, next) => {
  console.log('[404] Route not found:', req.method, req.path);
  res.status(404).json({ error: 'Route not found' });
});

// ---- Start ----
const PORT = process.env.PORT || 3005;
app.listen(PORT, () => {
  console.log(`Server körs på port ${PORT}`);
});