require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

app.use(bodyParser.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

const APP_URL = process.env.APP_URL;
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID;
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;

let pkceVerifier = null;

function base64url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function makeCodeVerifier() {
  return base64url(crypto.randomBytes(32));
}

function makeCodeChallenge(verifier) {
  return base64url(crypto.createHash("sha256").update(verifier).digest());
}

app.get("/", (req, res) => {
  res.send("Link Detector çalışıyor");
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/auth/kick", (req, res) => {
  try {
    pkceVerifier = makeCodeVerifier();
    const codeChallenge = makeCodeChallenge(pkceVerifier);
    const state = crypto.randomBytes(16).toString("hex");

    const redirectUri = `${APP_URL}/callback`;

    const authUrl =
      "https://id.kick.com/oauth/authorize?" +
      new URLSearchParams({
        response_type: "code",
        client_id: KICK_CLIENT_ID,
        redirect_uri: redirectUri,
        scope: "user:read channel:read",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
      }).toString();

    res.redirect(authUrl);
  } catch (err) {
    console.error("AUTH URL ERROR:", err);
    res.status(500).send("Auth başlatılamadı");
  }
});

app.get("/callback", async (req, res) => {
  try {
    const code = req.query.code;

    if (!code) {
      return res.status(400).send("Code yok");
    }

    if (!pkceVerifier) {
      return res.status(400).send("PKCE verifier yok");
    }

    const redirectUri = `${APP_URL}/callback`;

    const tokenRes = await fetch("https://id.kick.com/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: KICK_CLIENT_ID,
        client_secret: KICK_CLIENT_SECRET,
        redirect_uri: redirectUri,
        code_verifier: pkceVerifier,
        code: code,
      }),
    });

    const tokenData = await tokenRes.json();
    console.log("TOKEN RESPONSE:", JSON.stringify(tokenData, null, 2));

    await pool.query(`
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        id SERIAL PRIMARY KEY,
        raw_data TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(
      `INSERT INTO oauth_tokens (raw_data) VALUES ($1)`,
      [JSON.stringify(tokenData)]
    );

    res.send("Kick yetkilendirme tamamlandı. Token kaydedildi.");
  } catch (error) {
    console.error("CALLBACK ERROR:", error);
    res.status(500).send("Callback hatası: " + error.message);
  }
});

app.get("/subscribe/chat", async (req, res) => {
  try {
    const appTokenRes = await fetch("https://id.kick.com/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: KICK_CLIENT_ID,
        client_secret: KICK_CLIENT_SECRET,
      }),
    });

    const appTokenData = await appTokenRes.json();
    const accessToken = appTokenData.access_token;

    if (!accessToken) {
      return res.status(400).send("App access token alınamadı: " + JSON.stringify(appTokenData));
    }

    const subRes = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify({
  event: {
    name: "chat.message.sent",
    version: 1
  }
})

    const subData = await subRes.text();
    console.log("SUBSCRIBE RESPONSE:", subData);
    res.send("Abonelik isteği gönderildi: " + subData);
  } catch (error) {
    console.error("SUBSCRIBE ERROR:", error);
    res.status(500).send("Subscribe hatası: " + error.message);
  }
});

app.post("/webhook/kick", async (req, res) => {
  try {
    const payload = req.body || {};
    const message = JSON.stringify(payload);

    console.log("WEBHOOK HEADERS:", JSON.stringify(req.headers, null, 2));
    console.log("WEBHOOK BODY:", JSON.stringify(payload, null, 2));

    await pool.query(`
      CREATE TABLE IF NOT EXISTS links (
        id SERIAL PRIMARY KEY,
        raw_data TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(
      `INSERT INTO links (raw_data) VALUES ($1)`,
      [message]
    );

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Webhook error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log(`Server ${PORT} portunda çalışıyor`);

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS links (
        id SERIAL PRIMARY KEY,
        raw_data TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        id SERIAL PRIMARY KEY,
        raw_data TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("Tablolar hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
