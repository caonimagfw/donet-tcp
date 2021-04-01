"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const net_1 = require("net");
const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const app = express();
const KEY = fs.readFileSync(process.argv[1], { encoding: 'utf-8' });
function encrypt(buffer, iv) {
    var decipher = crypto.createCipheriv('aes-256-cbc', KEY, iv);
    var dec = Buffer.concat([decipher.update(buffer), decipher.final()]);
    return dec;
}
function decrypt(buffer, iv) {
    var decipher = crypto.createCipheriv('aes-256-cbc', KEY, iv);
    var dec = Buffer.concat([decipher.update(buffer), decipher.final()]);
    return dec;
}
function connect(host, port) {
    return new Promise((resolve, reject) => {
        const client = net_1.default.connect({ host: host, port: port }, () => {
            resolve(client);
        });
    });
}
function sendAndWait(client, data) {
    return new Promise((resolve, reject) => {
        client.write(data);
        client.on('data', (data) => {
            client.end();
            resolve(data);
        });
        client.on('end', () => {
            reject();
        });
    });
}
app.post('/tls', async (req, res) => {
    const split = req.body.split('|');
    if (split.length < 4) {
        const buffer = new Buffer([0x00]);
        res.send(buffer);
        return;
    }
    const proxyStream = await connect(split[0], parseInt(split[1]));
    const iv = Buffer.from(split[3], 'base64');
    const encryptedInput = Buffer.from(split[2], 'base64');
    const decryptedInput = decrypt(encryptedInput, iv);
    const decryptedOutput = await sendAndWait(proxyStream, decryptedInput);
    const encryptedOutput = encrypt(decryptedOutput, iv);
    res.send(encryptedOutput);
});
app.listen(3000, () => {
    console.log('Listening on port 3000');
});
//# sourceMappingURL=server.js.map