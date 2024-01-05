const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(express.json());

let secret = '';

app.post('/receiveWebhook', (req, res) => {
  if (req.headers['x-hook-secret']) {
    console.log('Establishing a webhook...');
    secret = req.headers['x-hook-secret'];
    fs.writeFile('./secret.txt', secret)
      .then(() => {
        console.log('Secret is saved to file');
        res.setHeader('x-hook-secret', secret);
        res.sendStatus(200);
      })
      .catch(() => console.log('Error occured while saving secret to file'));
  } else if (req.headers['x-hook-signature']) {
    if (!secret) {
      try {
        secret = fs.readFileSync('./secret.txt', 'utf-8');
      } catch (err) {
        console.log('Error occured while reading secret from file');
        return res.sendStatus(500);
      }
    }

    const computedSignature = crypto
      .createHmac('SHA256', secret)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (
      !crypto.timingSafeEqual(
        Buffer.from(req.headers['x-hook-signature']),
        Buffer.from(computedSignature)
      )
    ) {
      res.sendStatus(401);
    } else {
      res.sendStatus(200);
      console.log(`Events on ${Date()}:`);
      console.log(req.body.events);
    }
  } else {
    console.log('Something went wrong!');
  }
});

app.listen(8080, () => {
  console.log('Server is launched on port 8080');
});
