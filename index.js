const express = require('express');
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Health check route
app.get('/', (req, res) => {
  res.send({ status: 'OAuth Signer Ready' });
});

app.post('/sign', (req, res) => {
  const {
    method,
    url,
    params,
    consumer_key,
    consumer_secret,
    token,
    token_secret
  } = req.body;

  const oauth = OAuth({
    consumer: { key: consumer_key, secret: consumer_secret },
    signature_method: 'HMAC-SHA1',
    hash_function(base_string, key) {
      return crypto
        .createHmac('sha1', key)
        .update(base_string)
        .digest('base64');
    }
  });

  const request_data = {
    url,
    method,
    data: params
  };

  const authHeader = oauth.toHeader(
    oauth.authorize(request_data, { key: token, secret: token_secret })
  );

  res.json({ Authorization: authHeader.Authorization });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ OAuth signer server running on port ${PORT}`);
});
