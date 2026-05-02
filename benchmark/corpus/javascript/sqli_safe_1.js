// SAFE: parameterized query with placeholder prevents SQL injection
const mysql = require('mysql2');
const express = require('express');
const app = express();

const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.listen(3000);
