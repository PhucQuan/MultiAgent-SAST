// vulnerable_express.js
// A test Node.js/Express application with known vulnerabilities for Aegis-SAST testing.
const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const axios = require('axios');
const app = express();
app.use(express.json());

// 1. Command Injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // SINK: exec( - Command Injection
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// 2. SQL Injection
const mysql = require('mysql');
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const db = mysql.createConnection({});
    // SINK: .query( - SQL Injection
    db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, results) => {
        res.json(results);
    });
});

// 3. XSS
app.get('/search', (req, res) => {
    const term = req.query.q;
    // SINK: res.send( - XSS  
    res.send(`<h1>Results for: ${term}</h1>`);
});

// 4. SSRF
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    // SINK: axios.get( - SSRF
    const response = await axios.get(url);
    res.send(response.data);
});

// 5. Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // SINK: fs.readFile( - Path Traversal
    fs.readFile(`./uploads/${filename}`, 'utf8', (err, data) => {
        res.send(data);
    });
});

// 6. Open Redirect
app.get('/goto', (req, res) => {
    const next = req.query.next;
    // SINK: res.redirect( - Open Redirect
    res.redirect(next);
});

app.listen(3000);
