// SAFE: execFile() passes args as an array — no shell interpretation
const { execFile } = require('child_process');
const express = require('express');
const app = express();

const ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'example.com'];

app.get('/ping', (req, res) => {
    const host = req.query.host;
    if (!ALLOWED_HOSTS.includes(host)) {
        return res.status(400).send('Host not allowed');
    }
    execFile('ping', ['-c', '1', host], (error, stdout) => {
        res.send(stdout);
    });
});

app.listen(3000);
