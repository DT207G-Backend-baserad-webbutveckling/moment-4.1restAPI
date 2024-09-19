const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const bcrypt = require('bcrypt');

app.use(bodyParser.json());
app.use(cors());

// MySQL connection
require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;
const dbHost = process.env.DB_HOST;
const dbName = process.env.DB_NAME;

const db = mysql.createConnection({
    host: dbHost,
    user: dbUser,
    password: dbPassword,
    database: dbName
});


db.connect(err => {
    if (err) {
        console.error('Kunde inte ansluta till databasen:', err);
        process.exit();
    }
    console.log('Ansluten till databasen');
});

// JWT-verifieringsmiddleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send({ auth: false, message: 'Ingen token tillhandahållen.' });

    jwt.verify(token.split(' ')[1], jwtSecret, (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Misslyckades med att autentisera token.' });
        req.userId = decoded.id;
        next();
    });
};

// Validera token (server-side route)
app.get('/validate', verifyToken, (req, res) => {
    // Om token är giltig, returnera användarens information (t.ex. användarnamn)
    res.status(200).send({ username: 'Ditt användarnamn' });
});

app.get('/protected.html', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        // Om ingen token, omdirigera till inloggningssidan
        return res.redirect('/login.html');
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            // Om token är ogiltig, omdirigera till inloggningssidan
            return res.redirect('/login.html');
        }
        // Om token är giltig, rendera undersidan
        res.sendFile(path.join(__dirname, 'protected.html'));
    });
});


