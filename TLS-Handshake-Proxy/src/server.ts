import net from 'net'

const crypto = require('crypto')
const express = require('express')
const fs = require('fs')

const app = express()
const KEY: string = fs.readFileSync(process.argv[1], { encoding: 'utf-8' })
 
function encrypt(buffer: Buffer, iv: Buffer): Buffer {
  var decipher = crypto.createCipheriv('aes-256-cbc', KEY, iv)
  var dec = Buffer.concat([decipher.update(buffer) , decipher.final()]);
  return dec;
}

function decrypt(buffer: Buffer, iv: Buffer): Buffer {
  var decipher = crypto.createCipheriv('aes-256-cbc', KEY, iv)
  var dec = Buffer.concat([decipher.update(buffer) , decipher.final()]);
  return dec;
}

function connect(host: string, port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const client = net.connect({ host: host, port: port }, () => {
      resolve(client)
    })
  })
}

function sendAndWait(client: net.Socket, data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    client.write(data)
    client.on('data', (data: Buffer) => {
      client.end()
      resolve(data)
    })
    client.on('end', () => {
      reject()
    })
  })
}

app.post('/tls', async (req, res) => {
  const split: string[] = req.body.split('|')
  if(split.length < 4) {
    const buffer = new Buffer([0x00])
    res.send(buffer)
    return
  }

  const proxyStream: net.Socket = await connect(split[0], parseInt(split[1]))
  const iv: Buffer = Buffer.from(split[3], 'base64')

  const encryptedInput = Buffer.from(split[2], 'base64')
  const decryptedInput: Buffer = decrypt(encryptedInput, iv)

  const decryptedOutput: Buffer = await sendAndWait(proxyStream, decryptedInput)
  const encryptedOutput: Buffer = encrypt(decryptedOutput, iv)

  res.send(encryptedOutput.toString('base64'))
})


app.listen(3000, () => {
  console.log('Listening on port 3000')
})