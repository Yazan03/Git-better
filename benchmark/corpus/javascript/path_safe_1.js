// SAFE: resolved path must stay within BASE_DIR
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const BASE_DIR = path.resolve('/var/www/files');

app.get('/download', (req, res) => {
    const filename = req.query.file;
    const filepath = path.resolve(path.join(BASE_DIR, filename));
    if (!filepath.startsWith(BASE_DIR + path.sep)) {
        return res.status(403).send('Access denied');
    }
    fs.readFile(filepath, (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

app.listen(3000);
