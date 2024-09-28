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
const dbPort = process.env.DB_PORT;
const db = mysql.createConnection({
    host: dbHost,
    user: dbUser,
    password: dbPassword,
    database: dbName,
    port: dbPort

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

// Registrera användare
app.post('/register', (req, res) => {
    const { username, password, mail } = req.body;
    const account_created = new Date();

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).send('Ett fel uppstod vid hashning av lösenordet');

        const query = 'INSERT INTO users (username, password, mail, account_created) VALUES (?, ?, ?, ?)';
        db.query(query, [username, hash, mail, account_created], (err, result) => {
            if (err) return res.status(500).send('Ett fel uppstod vid registrering av användare');
            res.status(201).send({ message: 'Användare skapad' });
        });
    });
});

// Logga in användare
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).send('Ett fel uppstod vid inloggning');
        if (results.length === 0) return res.status(404).send('Användare hittades inte');

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Ett fel uppstod vid jämförelse av lösenord');
            if (!isMatch) return res.status(401).send('Felaktigt lösenord');

            const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: 86400 }); // 24 timmar
            res.status(200).send({ auth: true, token });
        });
    });
});

