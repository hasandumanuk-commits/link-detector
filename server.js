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
          * {
            box-sizing: border-box;
          }
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
          a {
            color: inherit;
          }
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

app.get("/links", async (req, res) => {
  try {
    await ensureTables();

    const search = (req.query.search || "").trim();

let result;

if (search) {
  result = await pool.query(
    `
    SELECT id, message_text, extracted_links, created_at
    FROM links
    WHERE
      CAST(id AS TEXT) ILIKE $1
      OR COALESCE(message_text, '') ILIKE $1
      OR COALESCE(extracted_links, '') ILIKE $1
    ORDER BY id DESC
    LIMIT 100
    `,
    [`%${search}%`]
  );
} else {
  result = await pool.query(`
    SELECT id, message_text, extracted_links, created_at
    FROM links
    ORDER BY id DESC
    LIMIT 100
  `);
}

    const rows = result.rows;

    const cards = rows
      .map((row) => {
        let parsedLinks = [];
        try {
          parsedLinks = JSON.parse(row.extracted_links || "[]");
        } catch (e) {
          parsedLinks = [];
        }

        const linksHtml =
          parsedLinks.length > 0
            ? parsedLinks
                .map(
                  (link) =>
                    `<a href="${escapeHtml(link)}" target="_blank">${escapeHtml(link)}</a>`
                )
                .join("<br>")
            : "<span class='muted'>Link bulunamadı</span>";

        return `
          <div class="card">
            <div class="top">
              <div><strong>ID:</strong> ${row.id}</div>
              <div><strong>Tarih:</strong> ${new Date(row.created_at).toLocaleString("tr-TR")}</div>
            </div>

            <div class="section">
              <div class="label">Mesaj</div>
              <div class="text">${escapeHtml(row.message_text || "") || "<span class='muted'>Boş</span>"}</div>
            </div>

            <div class="section">
              <div class="label">Bulunan Linkler</div>
              <div class="text">${linksHtml}</div>
            <div class="section action-row">
  <a href="/links/raw/${row.id}" class="raw-btn">Ham Veriyi Gör</a>

  <form method="POST" action="/links/delete/${row.id}" onsubmit="return confirm('Bu kaydı silmek istiyor musun?')">
    <button type="submit" class="delete-btn">Sil</button>
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
            body {
              margin: 0;
              font-family: Arial, sans-serif;
              background: #0f1115;
              color: #fff;
            }
            .wrap {
              max-width: 1100px;
              margin: 0 auto;
              padding: 24px;
            }
            .header {
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 16px;
              margin-bottom: 24px;
              flex-wrap: wrap;
            }
            .title {
              font-size: 28px;
              font-weight: 700;
            }
            .sub {
              color: #9ca3af;
              margin-top: 8px;
            }
            .actions a {
              display: inline-block;
              background: #8b5cf6;
              color: white;
              text-decoration: none;
              padding: 10px 14px;
              border-radius: 10px;
              margin-right: 10px;
            }
            .search-form {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-top: 14px;
}
.search-input {
  background: #11151b;
  border: 1px solid #232935;
  color: white;
  border-radius: 10px;
  padding: 10px 12px;
  min-width: 260px;
}
.search-btn {
  background: #8b5cf6;
  color: white;
  border: none;
  border-radius: 10px;
  padding: 10px 14px;
  cursor: pointer;
  font-weight: bold;
}
.clear-btn {
  display: inline-block;
  background: #1c2431;
  color: white !important;
  text-decoration: none;
  border: 1px solid #334155;
  border-radius: 10px;
  padding: 10px 14px;
  font-weight: bold;
}
            .card {
              background: #181c23;
              border: 1px solid #2b3240;
              border-radius: 14px;
              padding: 18px;
              margin-bottom: 16px;
            }
            .top {
              display: flex;
              justify-content: space-between;
              gap: 16px;
              flex-wrap: wrap;
              margin-bottom: 16px;
              color: #cbd5e1;
            }
            .section {
              margin-bottom: 14px;
            }
            .label {
              color: #8b5cf6;
              font-size: 13px;
              font-weight: 700;
              margin-bottom: 8px;
              text-transform: uppercase;
            }
            .text {
              background: #11151b;
              border: 1px solid #232935;
              border-radius: 10px;
              padding: 12px;
              line-height: 1.6;
              word-break: break-word;
            }
            .muted {
              color: #9ca3af;
            }
            .empty {
              background: #181c23;
              border: 1px solid #2b3240;
              border-radius: 14px;
              padding: 24px;
              color: #9ca3af;
            }
            .raw-btn {
.delete-btn {
  display: inline-block;
  background: #dc2626;
  color: white !important;
  text-decoration: none;
  padding: 10px 14px;
  border-radius: 10px;
  font-size: 14px;
  font-weight: bold;
  border: none;
  cursor: pointer;
}
.action-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
  display: inline-block;
  background: #8b5cf6;
  color: white !important;
  text-decoration: none;
  padding: 10px 14px;
  border-radius: 10px;
  font-size: 14px;
  font-weight: bold;
}
            a {
              color: #a78bfa;
            }
          </style>
        </head>
        <body>
          <div class="wrap">
            <div class="header">
              <div>
                <div class="title">Link Detector Panel</div>
                <div class="sub">Son 100 kayıt burada görünür.</div>
              </div>
              <div class="actions">
                <a href="/links/json" target="_blank">JSON Gör</a>
                <a href="/" target="_blank">Ana Sayfa</a>
              </div>
            </div>

            <form class="search-form" method="GET" action="/links">
  <input
    class="search-input"
    type="text"
    name="search"
    placeholder="ID, mesaj veya link ara"
    value="${escapeHtml(search)}"
  />
  <button class="search-btn" type="submit">Ara</button>
  <a class="clear-btn" href="/links">Temizle</a>
</form>

            ${
              rows.length > 0
                ? cards
                : "<div class='empty'>Henüz kayıt yok. Webhook gelince burada görünecek.</div>"
            }
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
  console.log(`Server ${PORT} portunda çalışıyor`);

  try {
    await ensureTables();
    console.log("Tablolar hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
