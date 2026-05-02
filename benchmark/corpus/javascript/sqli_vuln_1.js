// VULN: CWE-89 — SQL injection via string concatenation in query
const mysql = require('mysql2');
const express = require('express');
const app = express();

const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = 'SELECT * FROM users WHERE id = ' + userId;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.listen(3000);
