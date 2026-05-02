// VULN: CWE-22 — Path traversal via path.join() with user-controlled filename
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const BASE_DIR = '/var/www/files';

app.get('/download', (req, res) => {
    const filename = req.query.file;
    const filepath = path.join(BASE_DIR, filename);
    fs.readFile(filepath, (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

app.listen(3000);
