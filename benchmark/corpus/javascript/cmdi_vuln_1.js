// VULN: CWE-78 — Command injection via exec() with unsanitised user input
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 1 ' + host, (error, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

app.listen(3000);
