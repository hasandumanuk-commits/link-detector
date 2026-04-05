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
const KICK_CHANNEL_SLUG = process.env.KICK_CHANNEL_SLUG;

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

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
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

  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS message_text TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS extracted_links TEXT`);
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
  res.send(`
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Link Detector</title>
        <style>
          * { box-sizing: border-box; }
          body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(180deg, #0b0f17 0%, #111827 100%);
            color: white;
          }
          .wrap {
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 24px;
          }
          .hero {
            background: #151b24;
            border: 1px solid #2a3240;
            border-radius: 20px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.25);
          }
          .badge {
            display: inline-block;
            background: rgba(139, 92, 246, 0.15);
            color: #c4b5fd;
            border: 1px solid rgba(139, 92, 246, 0.35);
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 16px;
            letter-spacing: 0.5px;
          }
          h1 {
            margin: 0 0 12px 0;
            font-size: 38px;
          }
          .desc {
            color: #aab3c2;
            font-size: 16px;
            line-height: 1.7;
            max-width: 760px;
          }
          .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-top: 28px;
          }
          .card {
            background: #11161f;
            border: 1px solid #273142;
            border-radius: 16px;
            padding: 18px;
          }
          .card-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
          }
          .card-text {
            color: #9ca3af;
            line-height: 1.6;
            font-size: 14px;
            min-height: 66px;
          }
          .btn {
            display: inline-block;
            margin-top: 14px;
            background: #8b5cf6;
            color: white;
            text-decoration: none;
            padding: 10px 14px;
            border-radius: 10px;
            font-size: 14px;
            font-weight: bold;
          }
          .btn.secondary {
            background: #1c2431;
            border: 1px solid #334155;
          }
          .footer-box {
            background: #151b24;
            border: 1px solid #2a3240;
            border-radius: 18px;
            padding: 24px;
          }
          .footer-title {
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 10px;
          }
          .footer-text {
            color: #9ca3af;
            line-height: 1.7;
          }
          .list {
            margin: 14px 0 0 0;
            padding-left: 18px;
            color: #cbd5e1;
            line-height: 1.9;
          }
          a { color: inherit; }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="hero">
            <div class="badge">LINK DETECTOR DASHBOARD</div>
            <h1>Link Detector</h1>
            <div class="desc">
              Kick chat üzerinden gelen linkleri yakalamak, saklamak ve panelde göstermek için hazırlanan yönetim ekranı.
              Şu an panel ve veritabanı tarafı çalışıyor. Webhook abonelik kısmı daha sonra netleştirilecek.
            </div>

            <div class="grid">
              <div class="card">
                <div class="card-title">Panel</div>
                <div class="card-text">
                  Veritabanına düşen kayıtları kart görünümünde açar.
                </div>
                <a class="btn" href="/links">Panele Git</a>
              </div>

              <div class="card">
                <div class="card-title">JSON Verisi</div>
                <div class="card-text">
                  Ham kayıtları JSON olarak gösterir. Teknik kontrol için iyi.
                </div>
                <a class="btn secondary" href="/links/json">JSON Aç</a>
              </div>

              <div class="card">
                <div class="card-title">Sağlık Kontrolü</div>
                <div class="card-text">
                  Servisin ayakta olup olmadığını kontrol eder.
                </div>
                <a class="btn secondary" href="/health">Health Aç</a>
              </div>

              <div class="card">
                <div class="card-title">Broadcaster Kontrolü</div>
                <div class="card-text">
                  Kick kanal slug bilgisinden broadcaster user id bilgisini çeker.
                </div>
                <a class="btn secondary" href="/find/broadcaster">Kontrol Et</a>
              </div>
            </div>
          </div>

          <div class="footer-box">
            <div class="footer-title">Şu an çalışan parçalar</div>
            <div class="footer-text">
              Aşağıdaki kısımlar hazır durumda:
            </div>
            <ul class="list">
              <li>Render deploy çalışıyor</li>
              <li>Postgres bağlantısı çalışıyor</li>
              <li>Link kayıt paneli çalışıyor</li>
              <li>JSON listeleme çalışıyor</li>
              <li>OAuth temel akışı çalışıyor</li>
            </ul>
          </div>
        </div>
      </body>
    </html>
  `);
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
        scope: "user:read channel:read events:subscribe",
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
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
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

app.post("/links/delete/:id", async (req, res) => {
  try {
    await ensureTables();

    const id = req.params.id;

    await pool.query(`DELETE FROM links WHERE id = $1`, [id]);

    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Silme hatası: " + error.message);
  }
});

app.get("/links/raw/:id", async (req, res) => {
  try {
    await ensureTables();

    const id = req.params.id;

    const result = await pool.query(
      `SELECT id, raw_data, created_at FROM links WHERE id = $1 LIMIT 1`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).send("Kayıt bulunamadı");
    }

    const row = result.rows[0];

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>Ham Veri #${row.id}</title>
          <style>
            body {
              margin: 0;
              font-family: Arial, sans-serif;
              background: #0f1115;
              color: white;
              padding: 24px;
            }
            .wrap {
              max-width: 1000px;
              margin: 0 auto;
            }
            .top {
              margin-bottom: 20px;
            }
            .btn {
              display: inline-block;
              background: #8b5cf6;
              color: white;
              text-decoration: none;
              padding: 10px 14px;
              border-radius: 10px;
              margin-right: 10px;
            }
            .card {
              background: #181c23;
              border: 1px solid #2b3240;
              border-radius: 14px;
              padding: 18px;
            }
            pre {
              white-space: pre-wrap;
              word-break: break-word;
              background: #11151b;
              border: 1px solid #232935;
              border-radius: 10px;
              padding: 14px;
              line-height: 1.6;
              overflow-x: auto;
            }
          </style>
        </head>
        <body>
          <div class="wrap">
            <div class="top">
              <a class="btn" href="/links">Panele Dön</a>
              <a class="btn" href="/">Ana Sayfa</a>
            </div>
            <div class="card">
              <h2>Kayıt #${row.id}</h2>
              <p>Tarih: ${new Date(row.created_at).toLocaleString("tr-TR")}</p>
              <pre>${escapeHtml(row.raw_data)}</pre>
            </div>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send("Ham veri hatası: " + error.message);
  }
});

app.get("/links/json", async (req, res) => {
  try {
    await ensureTables();

    const result = await pool.query(`
      SELECT id, message_text, extracted_links, raw_data, created_at
      FROM links
      ORDER BY id DESC
      LIMIT 100
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("LINKS JSON ERROR:", error);
    res.status(500).send("Links json hatası: " + error.message);
  }
});

app.get("/subscribe/chat", async (req, res) => {
  try {
    const accessToken = await getAppAccessToken();

    const broadcasterUserId = 93350154;

    const payload = {
      broadcaster_user_id: broadcasterUserId,
      events: [
        {
          name: "chat.message.sent",
          version: 1
        }
      ]
    };

    const subRes = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const bodyText = await subRes.text();

    res.status(subRes.status).send(
      "STATUS=" + subRes.status +
      " | BODY=" + bodyText +
      " | PAYLOAD=" + JSON.stringify(payload)
    );
  } catch (error) {
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

    const search = (req.query.search || "").trim();

    let result;

    if (search) {
      result = await pool.query(
        `
        SELECT id, message_text, extracted_links, raw_data, created_at
        FROM links
        WHERE
          CAST(id AS TEXT) ILIKE $1
          OR COALESCE(message_text, '') ILIKE $1
          OR COALESCE(extracted_links, '') ILIKE $1
          OR COALESCE(raw_data, '') ILIKE $1
        ORDER BY id DESC
        LIMIT 100
        `,
        [`%${search}%`]
      );
    } else {
      result = await pool.query(`
        SELECT id, message_text, extracted_links, raw_data, created_at
        FROM links
        ORDER BY id DESC
        LIMIT 100
      `);
    }

    const countResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links`);
    const totalCount = countResult.rows[0].total;
    const rows = result.rows;

    const cards = rows
      .map((row, index) => {
        let parsedLinks = [];
        try {
          parsedLinks = JSON.parse(row.extracted_links || "[]");
        } catch (e) {
          parsedLinks = [];
        }

        const firstLink = parsedLinks[0] || "";
        const messageText = row.message_text || "Mesaj yok";
        const timeText = new Date(row.created_at).toLocaleString("tr-TR");

        return `
          <div class="feed-card">
            <div class="feed-left">
              <div class="dot dot-${index % 5}"></div>
              <div class="time-block">
                <div class="time">${timeText}</div>
                <div class="subtime">Kayıt #${row.id}</div>
              </div>
            </div>

            <div class="feed-main">
              <div class="user-row">
                <div class="user-name">Link Kaydı</div>
                <div class="user-badge">ID ${row.id}</div>
              </div>

              <div class="message-line">${escapeHtml(messageText)}</div>

              <div class="link-line">
                ${
                  firstLink
                    ? `<a href="${escapeHtml(firstLink)}" target="_blank">${escapeHtml(firstLink)}</a>`
                    : `<span class="muted">Link bulunamadı</span>`
                }
              </div>

              ${
                parsedLinks.length > 1
                  ? `
                  <div class="extra-links">
                    ${parsedLinks
                      .slice(1)
                      .map(
                        (link) =>
                          `<a href="${escapeHtml(link)}" target="_blank" class="mini-link">${escapeHtml(link)}</a>`
                      )
                      .join("")}
                  </div>
                `
                  : ""
              }
            </div>

            <div class="feed-actions">
              <a href="/links/raw/${row.id}" class="icon-btn" title="Ham Veriyi Gör">↗</a>

              <form method="POST" action="/links/delete/${row.id}" onsubmit="return confirm('Bu kaydı silmek istiyor musun?')">
                <button type="submit" class="icon-btn danger" title="Sil">✕</button>
              </form>
            </div>
          </div>
        `;
      })
      .join("");

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>Link Detector Panel</title>
          <style>
            * { box-sizing: border-box; }

            body {
              margin: 0;
              font-family: Arial, sans-serif;
              color: #e5eefc;
              background:
                radial-gradient(circle at top left, rgba(0, 255, 170, 0.08), transparent 28%),
                radial-gradient(circle at top right, rgba(64, 120, 255, 0.08), transparent 25%),
                linear-gradient(180deg, #071019 0%, #040811 100%);
            }

            a {
              color: inherit;
              text-decoration: none;
            }

            .app-shell {
              display: flex;
              min-height: 100vh;
              gap: 14px;
              padding: 14px;
            }

            .sidebar {
              width: 72px;
              background: rgba(8, 16, 28, 0.92);
              border: 1px solid rgba(72, 91, 122, 0.28);
              border-radius: 20px;
              padding: 14px 10px;
              display: flex;
              flex-direction: column;
              align-items: center;
              gap: 12px;
              box-shadow: 0 12px 30px rgba(0,0,0,0.28);
            }

            .side-logo {
              width: 42px;
              height: 42px;
              border-radius: 14px;
              background: linear-gradient(135deg, #0dcf83, #0b6cff);
              display: flex;
              align-items: center;
              justify-content: center;
              font-weight: bold;
              color: white;
              box-shadow: 0 0 18px rgba(13, 207, 131, 0.25);
            }

            .side-btn {
              width: 42px;
              height: 42px;
              border-radius: 14px;
              border: 1px solid rgba(73, 95, 130, 0.35);
              background: #0a1320;
              color: #d3def5;
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 15px;
            }

            .side-btn.active {
              background: linear-gradient(135deg, #0dcf83, #0d9b75);
              color: #05140f;
              font-weight: bold;
            }

            .content {
              flex: 1;
              display: grid;
              grid-template-columns: 1fr 250px;
              gap: 14px;
            }

            .main {
              min-width: 0;
            }

            .topbar {
              background: rgba(8, 16, 28, 0.92);
              border: 1px solid rgba(72, 91, 122, 0.28);
              border-radius: 20px;
              padding: 16px 18px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 16px;
              margin-bottom: 14px;
              box-shadow: 0 12px 30px rgba(0,0,0,0.22);
            }

            .brand-title {
              font-size: 18px;
              font-weight: 700;
              margin-bottom: 3px;
            }

            .brand-sub {
              color: #7b8aa8;
              font-size: 12px;
            }

            .top-actions {
              display: flex;
              gap: 10px;
              flex-wrap: wrap;
              align-items: center;
              justify-content: flex-end;
            }

            .stat-pill {
              min-width: 108px;
              background: #0b1421;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 16px;
              padding: 10px 14px;
              text-align: center;
            }

            .stat-label {
              color: #7b8aa8;
              font-size: 11px;
              margin-bottom: 3px;
            }

            .stat-value {
              font-size: 18px;
              font-weight: 700;
            }

            .top-btn {
              background: #0b1421;
              border: 1px solid rgba(73, 95, 130, 0.35);
              color: white;
              border-radius: 14px;
              padding: 10px 14px;
              font-weight: 700;
              cursor: pointer;
            }

            .top-btn.green {
              background: linear-gradient(135deg, #0dcf83, #0d9b75);
              color: #04150f;
              border: none;
            }

            .search-panel,
            .filter-panel,
            .feed-card,
            .right-card {
              background: rgba(8, 16, 28, 0.92);
              border: 1px solid rgba(72, 91, 122, 0.28);
              box-shadow: 0 12px 30px rgba(0,0,0,0.22);
            }

            .search-panel,
            .filter-panel {
              border-radius: 18px;
              padding: 14px;
              margin-bottom: 12px;
            }

            .search-row {
              display: flex;
              gap: 10px;
              flex-wrap: wrap;
              align-items: center;
            }

            .search-box {
              flex: 1;
              min-width: 260px;
              display: flex;
              align-items: center;
              gap: 10px;
              background: #07111c;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 14px;
              padding: 12px 14px;
            }

            .search-input {
              flex: 1;
              background: transparent;
              border: none;
              outline: none;
              color: white;
              font-size: 14px;
            }

            .search-btn,
            .clear-btn {
              border: none;
              cursor: pointer;
              border-radius: 12px;
              padding: 12px 14px;
              font-weight: 700;
            }

            .search-btn {
              background: #8b5cf6;
              color: white;
            }

            .clear-btn {
              background: #141f2f;
              color: #dce8ff;
              border: 1px solid rgba(73, 95, 130, 0.35);
            }

            .chip-row {
              display: flex;
              flex-wrap: wrap;
              gap: 10px;
            }

            .chip {
              padding: 9px 12px;
              border-radius: 999px;
              background: #0b1421;
              border: 1px solid rgba(73, 95, 130, 0.35);
              font-size: 12px;
              color: #b6c4df;
            }

            .chip.green { color: #79f0b6; border-color: rgba(13, 207, 131, 0.35); }
            .chip.pink { color: #f4a5d6; border-color: rgba(255, 95, 162, 0.35); }
            .chip.orange { color: #ffc078; border-color: rgba(255, 160, 60, 0.35); }
            .chip.blue { color: #88c7ff; border-color: rgba(72, 163, 255, 0.35); }

            .feed-list {
              display: flex;
              flex-direction: column;
              gap: 12px;
            }

            .feed-card {
              border-radius: 18px;
              padding: 16px;
              display: grid;
              grid-template-columns: 150px 1fr 70px;
              gap: 16px;
              align-items: start;
            }

            .feed-left {
              display: flex;
              gap: 10px;
              align-items: center;
            }

            .dot {
              width: 12px;
              height: 12px;
              border-radius: 999px;
              margin-top: 2px;
              box-shadow: 0 0 14px currentColor;
            }

            .dot-0 { color: #7c3aed; background: #7c3aed; }
            .dot-1 { color: #06b6d4; background: #06b6d4; }
            .dot-2 { color: #22c55e; background: #22c55e; }
            .dot-3 { color: #f97316; background: #f97316; }
            .dot-4 { color: #ec4899; background: #ec4899; }

            .time-block {
              min-width: 0;
            }

            .time {
              font-size: 12px;
              color: #dbe6fa;
              font-weight: 700;
              line-height: 1.5;
            }

            .subtime {
              font-size: 11px;
              color: #74839f;
            }

            .feed-main {
              min-width: 0;
            }

            .user-row {
              display: flex;
              align-items: center;
              gap: 10px;
              flex-wrap: wrap;
              margin-bottom: 10px;
            }

            .user-name {
              font-weight: 700;
              font-size: 15px;
            }

            .user-badge {
              padding: 5px 9px;
              border-radius: 999px;
              background: rgba(13, 207, 131, 0.12);
              border: 1px solid rgba(13, 207, 131, 0.28);
              color: #78efb5;
              font-size: 11px;
              font-weight: 700;
            }

            .message-line {
              color: #e9f1ff;
              font-size: 14px;
              margin-bottom: 8px;
              word-break: break-word;
            }

            .link-line a {
              color: #74c4ff;
              font-size: 14px;
              font-weight: 700;
              word-break: break-all;
            }

            .extra-links {
              margin-top: 10px;
              display: flex;
              flex-wrap: wrap;
              gap: 8px;
            }

            .mini-link {
              font-size: 11px;
              color: #b5c6e7;
              background: #0c1624;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 999px;
              padding: 6px 10px;
            }

            .feed-actions {
              display: flex;
              flex-direction: column;
              gap: 10px;
              align-items: flex-end;
            }

            .feed-actions form {
              margin: 0;
            }

            .icon-btn {
              width: 38px;
              height: 38px;
              border-radius: 12px;
              border: 1px solid rgba(73, 95, 130, 0.35);
              background: #0b1421;
              color: #dce8ff !important;
              display: flex;
              align-items: center;
              justify-content: center;
              font-weight: 700;
              cursor: pointer;
            }

            .icon-btn.danger {
              color: #ff9baa !important;
              border-color: rgba(220, 38, 38, 0.35);
            }

            .muted {
              color: #7d8ba6;
            }

            .empty-box {
              background: rgba(8, 16, 28, 0.92);
              border: 1px solid rgba(72, 91, 122, 0.28);
              border-radius: 18px;
              padding: 26px;
              color: #8fa0bf;
              text-align: center;
            }

            .right {
              display: flex;
              flex-direction: column;
              gap: 14px;
            }

            .right-card {
              border-radius: 18px;
              padding: 16px;
            }

            .right-title {
              font-size: 13px;
              color: #8fa0bf;
              margin-bottom: 12px;
            }

            .panel-buttons {
              display: grid;
              grid-template-columns: repeat(2, 1fr);
              gap: 10px;
            }

            .mini-panel-btn {
              background: #0b1421;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 14px;
              padding: 12px;
              text-align: center;
              color: #dbe6fa;
              font-weight: 700;
            }

            @media (max-width: 1100px) {
              .content {
                grid-template-columns: 1fr;
              }
              .right {
                order: -1;
              }
            }

            @media (max-width: 800px) {
              .app-shell {
                display: block;
                padding: 10px;
              }
              .sidebar {
                width: 100%;
                flex-direction: row;
                justify-content: center;
                margin-bottom: 10px;
              }
              .feed-card {
                grid-template-columns: 1fr;
              }
              .feed-actions {
                flex-direction: row;
                justify-content: flex-start;
              }
            }
          </style>
        </head>
        <body>
          <div class="app-shell">
            <div class="sidebar">
              <div class="side-logo">K</div>
              <div class="side-btn active">≡</div>
              <a class="side-btn" href="/">⌂</a>
              <a class="side-btn" href="/links">⎘</a>
              <a class="side-btn" href="/links/json">J</a>
              <a class="side-btn" href="/health">H</a>
            </div>

            <div class="content">
              <div class="main">
                <div class="topbar">
                  <div>
                    <div class="brand-title">KickSight Link Detector</div>
                    <div class="brand-sub">Realtime Kick Intelligence</div>
                  </div>

                  <div class="top-actions">
                    <div class="stat-pill">
                      <div class="stat-label">Toplam Link</div>
                      <div class="stat-value">${totalCount}</div>
                    </div>
                    <a class="top-btn green" href="/">Bağlı</a>
                    <a class="top-btn" href="/links">Yenile</a>
                    <a class="top-btn" href="/links/json" target="_blank">Çıktı</a>
                  </div>
                </div>

                <div class="search-panel">
                  <form class="search-row" method="GET" action="/links">
                    <div class="search-box">
                      <span>⌕</span>
                      <input
                        class="search-input"
                        type="text"
                        name="search"
                        placeholder="Link, mesaj veya kullanıcı adı ara..."
                        value="${escapeHtml(search)}"
                      />
                    </div>
                    <button class="search-btn" type="submit">Ara</button>
                    <a class="clear-btn" href="/links">Temizle</a>
                  </form>
                </div>

                <div class="filter-panel">
                  <div class="chip-row">
                    <div class="chip">Tüm Linkler</div>
                    <div class="chip blue">#gündem</div>
                    <div class="chip green">#futbol</div>
                    <div class="chip pink">#drama</div>
                    <div class="chip orange">#yemek</div>
                    <div class="chip blue">#haber</div>
                  </div>
                </div>

                ${
                  rows.length > 0
                    ? `<div class="feed-list">${cards}</div>`
                    : `<div class="empty-box">Henüz kayıt yok. Webhook gelince burada görünecek.</div>`
                }
              </div>

              <div class="right">
                <div class="right-card">
                  <div class="right-title">Paneller</div>
                  <div class="panel-buttons">
                    <a class="mini-panel-btn" href="/links">Liste</a>
                    <a class="mini-panel-btn" href="/links/json">JSON</a>
                    <a class="mini-panel-btn" href="/health">Health</a>
                    <a class="mini-panel-btn" href="/find/broadcaster">Kick</a>
                  </div>
                </div>

                <div class="right-card">
                  <div class="right-title">Durum</div>
                  <div class="chip-row">
                    <div class="chip green">Render Aktif</div>
                    <div class="chip blue">DB Bağlı</div>
                    <div class="chip pink">Webhook Bekliyor</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error("LINKS PAGE ERROR:", error);
    res.status(500).send("Links sayfası hatası: " + error.message);
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log(\`Server \${PORT} portunda çalışıyor\`);

  try {
    await ensureTables();
    console.log("Tablolar hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
