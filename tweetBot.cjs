const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const qs = require("querystring");

const app = express();
app.use(express.json());

// Proper OAuth 1.0 percent encoding
function percentEncode(str) {
  return encodeURIComponent(str)
    .replace(/\!/g, "%21")
    .replace(/\'/g, "%27")
    .replace(/\*/g, "%2A")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29");
}

// Generate OAuth 1.0a Signature
function generateSignature(method, baseUrl, params, consumerSecret, tokenSecret) {
  const sortedKeys = Object.keys(params).sort();
  const paramString = sortedKeys
    .map((k) => `${percentEncode(k)}=${percentEncode(params[k])}`)
    .join("&");
  const signatureBase = `${method}&${percentEncode(baseUrl)}&${percentEncode(paramString)}`;
  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;
  return crypto.createHmac("sha1", signingKey).update(signatureBase).digest("base64");
}

// === TWEET ENDPOINT ===
app.post("/tweet", async (req, res) => {
  try {
    const {
      status,
      consumer_key,
      consumer_secret,
      access_token,
      access_token_secret,
      in_reply_to_status_id
    } = req.body;

    if (!status || !consumer_key || !consumer_secret || !access_token || !access_token_secret) {
      return res.status(400).json({ error: "Missing required fields in request body." });
    }

    const method = "POST";
    const url = "https://api.twitter.com/1.1/statuses/update.json";

    // Build OAuth parameters
    const oauth = {
      oauth_consumer_key: consumer_key,
      oauth_nonce: crypto.randomBytes(16).toString("hex"),
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_token: access_token,
      oauth_version: "1.0",
    };

    // Params used for signature
    const paramsForSig = {
      ...oauth,
      status,
      ...(in_reply_to_status_id ? { in_reply_to_status_id } : {})
    };

    oauth.oauth_signature = generateSignature(
      method,
      url,
      paramsForSig,
      consumer_secret,
      access_token_secret
    );

    const authHeader = "OAuth " + Object.entries(oauth)
      .map(([k, v]) => `${percentEncode(k)}="${percentEncode(v)}"`).join(", ");

    // Final POST body
    const postBody = {
      status,
      ...(in_reply_to_status_id ? { in_reply_to_status_id } : {})
    };

    // Send tweet or reply
    const response = await axios.post(url, qs.stringify(postBody), {
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });

    return res.status(200).json({
      success: true,
      tweet_id: response.data.id_str,
      text: response.data.text,
      user: response.data.user?.screen_name || "unknown"
    });

  } catch (error) {
    console.error("❌ Twitter API error:", error.response?.data || error.message);
    return res.status(500).json({
      error: error.response?.data?.errors || error.message || "Unknown server error"
    });
  }
});

// Boot server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ TweetBot server running on port ${PORT}`);
});
