const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    
    // VULNERABLE: Command Injection via shell execution
    // Taint Source: req.query.ip
    // Taint Sink: exec()
    exec(`ping -c 4 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(error.message);
            return;
        }
        res.send(stdout);
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
