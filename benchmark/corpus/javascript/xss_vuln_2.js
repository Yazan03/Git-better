// VULN: CWE-79 — Reflected XSS via res.send() with unescaped user input
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send('<html><body><h2>Results for: ' + query + '</h2></body></html>');
});

app.listen(3000);
