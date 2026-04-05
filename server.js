require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
app.use(bodyParser.json());

const APP_URL = process.env.APP_URL;
const DATABASE_URL = process.env.DATABASE_URL;
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID;
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;
const KICK_CHANNEL_SLUG = process.env.KICK_CHANNEL_SLUG; // örn: hsndmn1907

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

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

function extractLinks(text) {
  if (!text || typeof text !== "string") return [];
  const matches = text.match(/https?:\/\/[^\s]+/gi);
  return matches || [];
}

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      id SERIAL PRIMARY KEY,
      raw_data TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS links (
      id SERIAL PRIMARY KEY,
      message_text TEXT,
      extracted_links TEXT,
      raw_data TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

async function getAppAccessToken() {
  const tokenRes = await fetch("https://id.kick.com/oauth/token", {
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

  const tokenData = await tokenRes.json();

  if (!tokenData.access_token) {
    throw new Error("App access token alınamadı: " + JSON.stringify(tokenData));
  }

  return tokenData.access_token;
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

    await ensureTables();

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

app.get("/find/broadcaster", async (req, res) => {
  try {
    if (!KICK_CHANNEL_SLUG) {
      return res.status(400).send("KICK_CHANNEL_SLUG env değişkeni yok");
    }

    const accessToken = await getAppAccessToken();

    const channelRes = await fetch(
      `https://api.kick.com/public/v1/channels?slug=${encodeURIComponent(KICK_CHANNEL_SLUG)}`,
      {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/json",
        },
      }
    );

    const text = await channelRes.text();
    console.log("CHANNEL RESPONSE:", text);
    res.send(text);
  } catch (error) {
    console.error("FIND BROADCASTER ERROR:", error);
    res.status(500).send("Broadcaster bulma hatası: " + error.message);
  }
});

app.get("/subscribe/chat", async (req, res) => {
  try {
    if (!KICK_CHANNEL_SLUG) {
      return res.status(400).send("KICK_CHANNEL_SLUG env değişkeni yok");
    }

    const accessToken = await getAppAccessToken();

    const channelRes = await fetch(
      `https://api.kick.com/public/v1/channels?slug=${encodeURIComponent(KICK_CHANNEL_SLUG)}`,
      {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/json",
        },
      }
    );

    const channelData = await channelRes.json();
    console.log("CHANNEL JSON:", JSON.stringify(channelData, null, 2));

    let broadcasterUserId = null;

    if (Array.isArray(channelData?.data) && channelData.data.length > 0) {
      broadcasterUserId = channelData.data[0].broadcaster_user_id;
    } else if (channelData?.data?.broadcaster_user_id) {
      broadcasterUserId = channelData.data.broadcaster_user_id;
    } else if (channelData?.broadcaster_user_id) {
      broadcasterUserId = channelData.broadcaster_user_id;
    }

    if (!broadcasterUserId) {
      return res
        .status(400)
        .send("broadcaster_user_id bulunamadı: " + JSON.stringify(channelData));
    }

    const subRes = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json",
      },
      body: JSON.stringify({
        broadcaster_user_id: broadcasterUserId,
        events: [
          {
            name: "chat.message.sent",
            version: 1,
          },
        ],
      }),
    });

    const subText = await subRes.text();
    console.log("SUBSCRIBE RESPONSE:", subText);

    res.send(
      "Abonelik isteği gönderildi. broadcaster_user_id=" +
        broadcasterUserId +
        " | cevap=" +
        subText
    );
  } catch (error) {
    console.error("SUBSCRIBE ERROR:", error);
    res.status(500).send("Subscribe hatası: " + error.message);
  }
});

app.post("/webhook/kick", async (req, res) => {
  try {
    const payload = req.body || {};

    console.log("WEBHOOK HEADERS:", JSON.stringify(req.headers, null, 2));
    console.log("WEBHOOK BODY:", JSON.stringify(payload, null, 2));

    const possibleText =
      payload?.content ||
      payload?.message?.content ||
      payload?.message ||
      payload?.data?.content ||
      payload?.data?.message?.content ||
      "";

    const links = extractLinks(possibleText);

    await ensureTables();

    await pool.query(
      `INSERT INTO links (message_text, extracted_links, raw_data) VALUES ($1, $2, $3)`,
      [
        possibleText || null,
        JSON.stringify(links),
        JSON.stringify(payload),
      ]
    );

    res.status(200).json({ success: true, found_links: links });
  } catch (error) {
    console.error("WEBHOOK ERROR:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/links", async (req, res) => {
  try {
    await ensureTables();

    const result = await pool.query(`
      SELECT id, message_text, extracted_links, created_at
      FROM links
      ORDER BY id DESC
      LIMIT 50
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("LINKS LIST ERROR:", error);
    res.status(500).send("Links listeleme hatası: " + error.message);
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log(`Server ${PORT} portunda çalışıyor`);

  try {
    await ensureTables();
    console.log("Tablolar hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
