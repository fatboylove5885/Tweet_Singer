// tweetBot.js
const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const qs = require("querystring");
const app = express();
app.use(express.json());

function percentEncode(str) {
  return encodeURIComponent(str)
    .replace(/\!/g, "%21")
    .replace(/\'/g, "%27")
    .replace(/\*/g, "%2A")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29");
}

function generateSignature(method, baseUrl, params, consumerSecret, tokenSecret) {
  const sortedKeys = Object.keys(params).sort();
  const paramString = sortedKeys
    .map((k) => `${percentEncode(k)}=${percentEncode(params[k])}`)
    .join("&");
  const signatureBase = `${method}&${percentEncode(baseUrl)}&${percentEncode(
    paramString
  )}`;
  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(
    tokenSecret
  )}`;
  return crypto.createHmac("sha1", signingKey).update(signatureBase).digest("base64");
}

app.post("/tweet", async (req, res) => {
  const {
    status,
    consumer_key,
    consumer_secret,
    access_token,
    access_token_secret,
  } = req.body;

  if (
    !status ||
    !consumer_key ||
    !consumer_secret ||
    !access_token ||
    !access_token_secret
  ) {
    return res
      .status(400)
      .json({ error: "Missing required keys or status in request body" });
  }

  const method = "POST";
  const url = "https://api.twitter.com/1.1/statuses/update.json";

  const oauth = {
    oauth_consumer_key: consumer_key,
    oauth_nonce: crypto.randomBytes(16).toString("hex"),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_token: access_token,
    oauth_version: "1.0",
  };

  const params = {
    ...oauth,
    status,
  };

  oauth.oauth_signature = generateSignature(
    method,
    url,
    params,
    consumer_secret,
    access_token_secret
  );

  const authHeader =
    "OAuth " +
    Object.keys(oauth)
      .map(
        (k) => `${percentEncode(k)}="${percentEncode(oauth[k])}"`
      )
      .join(", ");

  try {
    const response = await axios.post(
      url,
      qs.stringify({ status }),
      {
        headers: {
          Authorization: authHeader,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );
    res.status(200).json({ success: true, tweet_id: response.data.id_str });
  } catch (err) {
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`TweetBot server running on port ${PORT}`);
});
