require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const APP_URL = process.env.APP_URL;
const DATABASE_URL = process.env.DATABASE_URL;
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID;
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;
const KICK_CHANNEL_SLUG = process.env.KICK_CHANNEL_SLUG;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: SESSION_SECRET || "default_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    },
  })
);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

let pkceVerifier = null;

function requireAuth(req, res, next) {
  if (req.session && req.session.isAuthenticated) {
    return next();
  }
  return res.redirect("/login");
}

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
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function getDomain(link) {
  try {
    const url = new URL(link);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function detectRisk(links, messageText = "") {
  const text = `${messageText} ${Array.isArray(links) ? links.join(" ") : ""}`.toLowerCase();

  const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly", "shorturl"];
  const invites = ["discord.gg", "discord.com/invite", "t.me", "telegram.me", "wa.me"];
  const adultish = ["onlyfans", "porn", "xxx", "escort", "nsfw", "18+"];
  const suspicious = ["free skin", "nitro", "gift", "airdrop", "casino", "bet", "hack", "crack"];

  if (adultish.some((k) => text.includes(k))) return "Yüksek Risk";
  if (shorteners.some((k) => text.includes(k))) return "Şüpheli";
  if (suspicious.some((k) => text.includes(k))) return "Şüpheli";
  if (invites.some((k) => text.includes(k))) return "Davet Linki";
  return "Normal";
}

function csvEscape(value) {
  const s = String(value ?? "");
  return `"${s.replace(/"/g, '""')}"`;
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
      link_domain TEXT,
      risk_level TEXT DEFAULT 'Normal',
      review_status TEXT DEFAULT 'Beklemede',
      moderator_note TEXT,
      is_deleted BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS message_text TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS extracted_links TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS link_domain TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS risk_level TEXT DEFAULT 'Normal'`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'Beklemede'`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS moderator_note TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE`);
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

app.get("/login", (req, res) => {
  if (req.session && req.session.isAuthenticated) {
    return res.redirect("/links");
  }

  const error = req.query.error ? "Kullanıcı adı veya şifre yanlış." : "";

  res.send(`
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Giriş Yap</title>
        <style>
          * { box-sizing: border-box; }
          body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
            background:
              radial-gradient(circle at top left, rgba(255, 230, 80, 0.10), transparent 28%),
              radial-gradient(circle at top right, rgba(16, 42, 110, 0.22), transparent 30%),
              linear-gradient(180deg, #08152f 0%, #041126 55%, #020814 100%);
            color: white;
          }
          .card {
            width: 100%;
            max-width: 420px;
            background: rgba(8, 16, 28, 0.94);
            border: 1px solid rgba(72, 91, 122, 0.28);
            border-radius: 22px;
            padding: 28px;
            box-shadow: 0 12px 30px rgba(0,0,0,0.28);
          }
          h1 { margin: 0 0 8px 0; font-size: 30px; }
          .sub { color: #b7c5e0; margin-bottom: 22px; }
          .input {
            width: 100%;
            background: #07111c;
            border: 1px solid rgba(73, 95, 130, 0.35);
            border-radius: 14px;
            padding: 14px;
            color: white;
            margin-bottom: 12px;
            outline: none;
          }
          .btn {
            width: 100%;
            border: none;
            border-radius: 14px;
            padding: 14px;
            font-weight: 700;
            cursor: pointer;
            background: linear-gradient(135deg, #ffd84d, #facc15);
            color: #0b1b44;
          }
          .error {
            background: rgba(220, 38, 38, 0.12);
            border: 1px solid rgba(220, 38, 38, 0.32);
            color: #ffb4b4;
            padding: 12px;
            border-radius: 12px;
            margin-bottom: 14px;
          }
        </style>
      </head>
      <body>
        <form class="card" method="POST" action="/login">
          <h1>HasanD Link Detector</h1>
          <div class="sub">Panele girmek için giriş yap.</div>
          ${error ? `<div class="error">${error}</div>` : ""}
          <input class="input" type="text" name="username" placeholder="Kullanıcı adı" required />
          <input class="input" type="password" name="password" placeholder="Şifre" required />
          <button class="btn" type="submit">Giriş Yap</button>
        </form>
      </body>
    </html>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAuthenticated = true;
    return res.redirect("/links");
  }

  return res.redirect("/login?error=1");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/", requireAuth, (req, res) => {
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
          h1 { margin: 0 0 12px 0; font-size: 38px; }
          .desc { color: #aab3c2; font-size: 16px; line-height: 1.7; max-width: 760px; }
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
          .card-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
          .card-text { color: #9ca3af; line-height: 1.6; font-size: 14px; min-height: 66px; }
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
          .footer-title { font-size: 20px; font-weight: bold; margin-bottom: 10px; }
          .footer-text { color: #9ca3af; line-height: 1.7; }
          .list { margin: 14px 0 0 0; padding-left: 18px; color: #cbd5e1; line-height: 1.9; }
          a { color: inherit; }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="hero">
            <div class="badge">HASAND LINK DETECTOR</div>
            <h1>Kontrol Merkezi</h1>
            <div class="desc">
              Link kayıtları, risk etiketleri, moderasyon notları ve export araçları burada.
            </div>

            <div class="grid">
              <div class="card">
                <div class="card-title">Panel</div>
                <div class="card-text">Tüm kayıtları gelişmiş görünümde açar.</div>
                <a class="btn" href="/links">Panele Git</a>
              </div>

              <div class="card">
                <div class="card-title">JSON</div>
                <div class="card-text">Ham kayıtların JSON çıktısı.</div>
                <a class="btn secondary" href="/links/json">JSON Aç</a>
              </div>

              <div class="card">
                <div class="card-title">CSV</div>
                <div class="card-text">Kayıtları CSV olarak indir.</div>
                <a class="btn secondary" href="/links/export/csv">CSV Aç</a>
              </div>

              <div class="card">
                <div class="card-title">Çıkış</div>
                <div class="card-text">Panel oturumunu güvenli şekilde kapat.</div>
                <a class="btn secondary" href="/logout">Çıkış Yap</a>
              </div>
            </div>
          </div>

          <div class="footer-box">
            <div class="footer-title">Durum</div>
            <div class="footer-text">
              Panel hazır. Webhook tarafı geldiğinde kayıtlar otomatik düşecek.
            </div>
            <ul class="list">
              <li>Login aktif</li>
              <li>Panel aktif</li>
              <li>Risk etiketi aktif</li>
              <li>Durum ve not sistemi aktif</li>
              <li>Soft delete aktif</li>
            </ul>
          </div>
        </div>
      </body>
    </html>
  `);
});

app.get("/health", requireAuth, (req, res) => {
  res.json({ ok: true });
});

app.get("/auth/kick", requireAuth, (req, res) => {
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

app.get("/callback", requireAuth, async (req, res) => {
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

app.get("/find/broadcaster", requireAuth, async (req, res) => {
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
    res.send(text);
  } catch (error) {
    console.error("FIND BROADCASTER ERROR:", error);
    res.status(500).send("Broadcaster bulma hatası: " + error.message);
  }
});

app.get("/subscribe/chat", requireAuth, async (req, res) => {
  try {
    const accessToken = await getAppAccessToken();

    const broadcasterUserId = 93350154;

    const payload = {
      broadcaster_user_id: broadcasterUserId,
      events: [
        {
          name: "chat.message.sent",
          version: 1,
        },
      ],
    };

    const subRes = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
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

    const possibleText =
      payload?.content ||
      payload?.message?.content ||
      payload?.message ||
      payload?.data?.content ||
      payload?.data?.message?.content ||
      "";

    const links = extractLinks(possibleText);
    const firstDomain = links.length ? getDomain(links[0]) : "";
    const riskLevel = detectRisk(links, possibleText);

    await ensureTables();

    await pool.query(
      `
      INSERT INTO links (
        message_text,
        extracted_links,
        raw_data,
        link_domain,
        risk_level,
        review_status,
        moderator_note,
        is_deleted
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `,
      [
        possibleText || null,
        JSON.stringify(links),
        JSON.stringify(payload),
        firstDomain || null,
        riskLevel,
        "Beklemede",
        null,
        false,
      ]
    );

    res.status(200).json({ success: true, found_links: links });
  } catch (error) {
    console.error("WEBHOOK ERROR:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/links/delete/:id", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const id = req.params.id;
    await pool.query(`UPDATE links SET is_deleted = TRUE WHERE id = $1`, [id]);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Silme hatası: " + error.message);
  }
});

app.post("/links/restore/:id", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const id = req.params.id;
    await pool.query(`UPDATE links SET is_deleted = FALSE WHERE id = $1`, [id]);
    res.redirect("/links?deleted=1");
  } catch (error) {
    res.status(500).send("Geri alma hatası: " + error.message);
  }
});

app.post("/links/status/:id", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const id = req.params.id;
    const allowed = ["Onaylandı", "Reddedildi", "Beklemede"];
    const status = allowed.includes(req.body.status) ? req.body.status : "Beklemede";

    await pool.query(`UPDATE links SET review_status = $1 WHERE id = $2`, [status, id]);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Durum güncelleme hatası: " + error.message);
  }
});

app.post("/links/note/:id", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const id = req.params.id;
    const note = (req.body.note || "").trim().slice(0, 500);

    await pool.query(`UPDATE links SET moderator_note = $1 WHERE id = $2`, [note || null, id]);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Not kaydetme hatası: " + error.message);
  }
});

app.get("/links/raw/:id", requireAuth, async (req, res) => {
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
            .wrap { max-width: 1000px; margin: 0 auto; }
            .top { margin-bottom: 20px; }
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

app.get("/links/json", requireAuth, async (req, res) => {
  try {
    await ensureTables();

    const result = await pool.query(`
      SELECT id, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, moderator_note, is_deleted, created_at
      FROM links
      ORDER BY id DESC
      LIMIT 200
    `);

    res.json(result.rows);
  } catch (error) {
    res.status(500).send("Links json hatası: " + error.message);
  }
});

app.get("/links/export/csv", requireAuth, async (req, res) => {
  try {
    await ensureTables();

    const result = await pool.query(`
      SELECT id, message_text, extracted_links, link_domain, risk_level, review_status, moderator_note, is_deleted, created_at
      FROM links
      ORDER BY id DESC
      LIMIT 1000
    `);

    const header = [
      "id",
      "message_text",
      "extracted_links",
      "link_domain",
      "risk_level",
      "review_status",
      "moderator_note",
      "is_deleted",
      "created_at",
    ].join(",");

    const rows = result.rows.map((row) =>
      [
        csvEscape(row.id),
        csvEscape(row.message_text),
        csvEscape(row.extracted_links),
        csvEscape(row.link_domain),
        csvEscape(row.risk_level),
        csvEscape(row.review_status),
        csvEscape(row.moderator_note),
        csvEscape(row.is_deleted),
        csvEscape(row.created_at),
      ].join(",")
    );

    const csv = [header, ...rows].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=links-export.csv");
    res.send(csv);
  } catch (error) {
    res.status(500).send("CSV export hatası: " + error.message);
  }
});

app.get("/links", requireAuth, async (req, res) => {
  try {
    await ensureTables();

    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
    const statusFilter = typeof req.query.status === "string" ? req.query.status.trim() : "";
    const riskFilter = typeof req.query.risk === "string" ? req.query.risk.trim() : "";
    const deletedFilter = req.query.deleted === "1";

    const whereParts = [];
    const values = [];
    let idx = 1;

    if (search) {
      whereParts.push(`
        (
          CAST(id AS TEXT) ILIKE $${idx}
          OR COALESCE(message_text, '') ILIKE $${idx}
          OR COALESCE(extracted_links, '') ILIKE $${idx}
          OR COALESCE(raw_data, '') ILIKE $${idx}
          OR COALESCE(link_domain, '') ILIKE $${idx}
          OR COALESCE(moderator_note, '') ILIKE $${idx}
        )
      `);
      values.push(`%${search}%`);
      idx++;
    }

    if (statusFilter) {
      whereParts.push(`COALESCE(review_status, 'Beklemede') = $${idx}`);
      values.push(statusFilter);
      idx++;
    }

    if (riskFilter) {
      whereParts.push(`COALESCE(risk_level, 'Normal') = $${idx}`);
      values.push(riskFilter);
      idx++;
    }

    whereParts.push(`COALESCE(is_deleted, FALSE) = $${idx}`);
    values.push(deletedFilter);
    idx++;

    const whereSql = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

    const result = await pool.query(
      `
      SELECT id, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, moderator_note, is_deleted, created_at
      FROM links
      ${whereSql}
      ORDER BY id DESC
      LIMIT 100
      `,
      values
    );

    const totalCountResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links WHERE COALESCE(is_deleted, FALSE) = FALSE`);
    const deletedCountResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links WHERE COALESCE(is_deleted, FALSE) = TRUE`);
    const todayCountResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND created_at::date = CURRENT_DATE
    `);

    const domainStatResult = await pool.query(`
      SELECT COALESCE(link_domain, '') AS link_domain, COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      GROUP BY link_domain
      ORDER BY total DESC, link_domain ASC
      LIMIT 1
    `);

    const totalCount = totalCountResult.rows[0]?.total || 0;
    const deletedCount = deletedCountResult.rows[0]?.total || 0;
    const todayCount = todayCountResult.rows[0]?.total || 0;
    const topDomain = domainStatResult.rows[0]?.link_domain || "-";
    const rows = result.rows;

    const cards = rows
      .map((row, index) => {
        let parsedLinks = [];
        try {
          parsedLinks = JSON.parse(row.extracted_links || "[]");
        } catch {
          parsedLinks = [];
        }

        const firstLink = parsedLinks[0] || "";
        const messageText = row.message_text || "Mesaj yok";
        const timeText = new Date(row.created_at).toLocaleString("tr-TR");
        const domainText = row.link_domain || (firstLink ? getDomain(firstLink) : "-");
        const riskLevel = row.risk_level || "Normal";
        const reviewStatus = row.review_status || "Beklemede";
        const noteText = row.moderator_note || "";

        const riskClass =
          riskLevel === "Yüksek Risk"
            ? "risk-high"
            : riskLevel === "Şüpheli"
            ? "risk-mid"
            : riskLevel === "Davet Linki"
            ? "risk-invite"
            : "risk-normal";

        const statusClass =
          reviewStatus === "Onaylandı"
            ? "status-approved"
            : reviewStatus === "Reddedildi"
            ? "status-rejected"
            : "status-pending";

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
                <div class="badge-lite ${riskClass}">${escapeHtml(riskLevel)}</div>
                <div class="badge-lite ${statusClass}">${escapeHtml(reviewStatus)}</div>
              </div>

              <div class="meta-row">
                <span class="meta-chip">Domain: ${escapeHtml(domainText || "-")}</span>
                <span class="meta-chip">Silinmiş: ${row.is_deleted ? "Evet" : "Hayır"}</span>
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

              <div class="tools-grid">
                <form method="POST" action="/links/status/${row.id}" class="inline-form">
                  <select name="status" class="select">
                    <option ${reviewStatus === "Beklemede" ? "selected" : ""}>Beklemede</option>
                    <option ${reviewStatus === "Onaylandı" ? "selected" : ""}>Onaylandı</option>
                    <option ${reviewStatus === "Reddedildi" ? "selected" : ""}>Reddedildi</option>
                  </select>
                  <button type="submit" class="mini-btn">Kaydet</button>
                </form>

                <form method="POST" action="/links/note/${row.id}" class="inline-form note-form">
                  <input
                    type="text"
                    name="note"
                    class="note-input"
                    value="${escapeHtml(noteText)}"
                    placeholder="Moderatör notu"
                  />
                  <button type="submit" class="mini-btn">Not</button>
                </form>
              </div>
            </div>

            <div class="feed-actions">
              <a href="/links/raw/${row.id}" class="icon-btn" title="Ham Veriyi Gör">↗</a>
              ${
                row.is_deleted
                  ? `
                    <form method="POST" action="/links/restore/${row.id}">
                      <button type="submit" class="icon-btn restore" title="Geri Al">⟲</button>
                    </form>
                  `
                  : `
                    <form method="POST" action="/links/delete/${row.id}" onsubmit="return confirm('Bu kaydı çöpe taşımak istiyor musun?')">
                      <button type="submit" class="icon-btn danger" title="Çöpe Taşı">✕</button>
                    </form>
                  `
              }
            </div>
          </div>
        `;
      })
      .join("");

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>HasanD Link Detector</title>
          <style>
            * { box-sizing: border-box; }
            body {
              margin: 0;
              font-family: Arial, sans-serif;
              color: #f5f7fb;
              background:
                radial-gradient(circle at top left, rgba(255, 230, 80, 0.10), transparent 28%),
                radial-gradient(circle at top right, rgba(16, 42, 110, 0.22), transparent 30%),
                linear-gradient(180deg, #08152f 0%, #041126 55%, #020814 100%);
            }
            a { color: inherit; text-decoration: none; }

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
              background: linear-gradient(135deg, #ffd84d, #1d4ed8);
              display: flex;
              align-items: center;
              justify-content: center;
              font-weight: bold;
              color: #041126;
              box-shadow: 0 0 18px rgba(255, 216, 77, 0.28);
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
              background: linear-gradient(135deg, #ffd84d, #facc15);
              color: #0b1b44;
              font-weight: bold;
            }

            .content {
              flex: 1;
              display: grid;
              grid-template-columns: 1fr 270px;
              gap: 14px;
            }

            .topbar, .search-panel, .filter-panel, .feed-card, .right-card {
              background: rgba(8, 16, 28, 0.92);
              border: 1px solid rgba(72, 91, 122, 0.28);
              box-shadow: 0 12px 30px rgba(0,0,0,0.22);
            }

            .topbar {
              border-radius: 20px;
              padding: 16px 18px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 16px;
              margin-bottom: 14px;
            }

            .brand-title {
              font-size: 18px;
              font-weight: 700;
              margin-bottom: 3px;
            }

            .brand-sub {
              color: #c8d4ef;
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
            }

            .top-btn.green {
              background: linear-gradient(135deg, #ffd84d, #facc15);
              color: #0b1b44;
              border: none;
            }

            .search-panel, .filter-panel, .right-card {
              border-radius: 18px;
              padding: 14px;
              margin-bottom: 12px;
            }

            .search-row, .chip-row {
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

            .search-input, .select, .note-input {
              background: transparent;
              border: none;
              outline: none;
              color: white;
              font-size: 14px;
            }

            .search-input { flex: 1; }

            .search-btn, .clear-btn, .mini-btn {
              border: none;
              cursor: pointer;
              border-radius: 12px;
              padding: 12px 14px;
              font-weight: 700;
            }

            .search-btn, .mini-btn {
              background: #6d28d9;
              color: white;
            }

            .clear-btn {
              background: #141f2f;
              color: #dce8ff;
              border: 1px solid rgba(73, 95, 130, 0.35);
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
              grid-template-columns: 160px 1fr 70px;
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

            .time { font-size: 12px; color: #dbe6fa; font-weight: 700; line-height: 1.5; }
            .subtime { font-size: 11px; color: #74839f; }

            .user-row {
              display: flex;
              align-items: center;
              gap: 10px;
              flex-wrap: wrap;
              margin-bottom: 10px;
            }

            .user-name { font-weight: 700; font-size: 15px; }

            .user-badge {
              padding: 5px 9px;
              border-radius: 999px;
              background: rgba(255, 216, 77, 0.12);
              border: 1px solid rgba(255, 216, 77, 0.32);
              color: #ffe27a;
              font-size: 11px;
              font-weight: 700;
            }

            .badge-lite {
              padding: 5px 9px;
              border-radius: 999px;
              font-size: 11px;
              font-weight: 700;
              border: 1px solid transparent;
            }

            .risk-normal { background: rgba(34, 197, 94, 0.12); color: #86efac; border-color: rgba(34, 197, 94, 0.25); }
            .risk-mid { background: rgba(249, 115, 22, 0.12); color: #fdba74; border-color: rgba(249, 115, 22, 0.25); }
            .risk-high { background: rgba(220, 38, 38, 0.12); color: #fca5a5; border-color: rgba(220, 38, 38, 0.25); }
            .risk-invite { background: rgba(59, 130, 246, 0.12); color: #93c5fd; border-color: rgba(59, 130, 246, 0.25); }

            .status-approved { background: rgba(34, 197, 94, 0.12); color: #86efac; border-color: rgba(34, 197, 94, 0.25); }
            .status-rejected { background: rgba(220, 38, 38, 0.12); color: #fca5a5; border-color: rgba(220, 38, 38, 0.25); }
            .status-pending { background: rgba(234, 179, 8, 0.12); color: #fde68a; border-color: rgba(234, 179, 8, 0.25); }

            .meta-row {
              display: flex;
              flex-wrap: wrap;
              gap: 8px;
              margin-bottom: 10px;
            }

            .meta-chip {
              font-size: 11px;
              background: #0c1624;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 999px;
              padding: 6px 10px;
              color: #b5c6e7;
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

            .tools-grid {
              display: grid;
              grid-template-columns: 1fr;
              gap: 10px;
              margin-top: 14px;
            }

            .inline-form {
              display: flex;
              gap: 8px;
              flex-wrap: wrap;
              align-items: center;
            }

            .select, .note-input {
              background: #07111c;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 12px;
              padding: 10px 12px;
              min-width: 150px;
            }

            .note-input {
              flex: 1;
              min-width: 180px;
            }

            .feed-actions {
              display: flex;
              flex-direction: column;
              gap: 10px;
              align-items: flex-end;
            }

            .feed-actions form { margin: 0; }

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

            .icon-btn.restore {
              color: #9ae6b4 !important;
              border-color: rgba(34, 197, 94, 0.35);
            }

            .muted { color: #7d8ba6; }

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

            .right-card { border-radius: 18px; padding: 16px; }
            .right-title { font-size: 13px; color: #8fa0bf; margin-bottom: 12px; }

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
              .content { grid-template-columns: 1fr; }
              .right { order: -1; }
            }

            @media (max-width: 800px) {
              .app-shell { display: block; padding: 10px; }
              .sidebar {
                width: 100%;
                flex-direction: row;
                justify-content: center;
                margin-bottom: 10px;
              }
              .feed-card { grid-template-columns: 1fr; }
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
              <a class="side-logo" href="/links">K</a>
              <a class="side-btn active" href="/links">≡</a>
              <a class="side-btn" href="/">⌂</a>
              <a class="side-btn" href="/links/json">J</a>
              <a class="side-btn" href="/links/export/csv">C</a>
              <a class="side-btn" href="/logout">↦</a>
            </div>

            <div class="content">
              <div class="main">
                <div class="topbar">
                  <div>
                    <div class="brand-title">HasanD Link Detector</div>
                    <div class="brand-sub">Gerçek Zamanlı Link Paneli</div>
                  </div>

                  <div class="top-actions">
                    <div class="stat-pill">
                      <div class="stat-label">Toplam Aktif</div>
                      <div class="stat-value">${totalCount}</div>
                    </div>
                    <div class="stat-pill">
                      <div class="stat-label">Bugün</div>
                      <div class="stat-value">${todayCount}</div>
                    </div>
                    <div class="stat-pill">
                      <div class="stat-label">Çöp</div>
                      <div class="stat-value">${deletedCount}</div>
                    </div>
                    <a class="top-btn green" href="/health">Bağlı</a>
                    <a class="top-btn" href="/links">Yenile</a>
                    <a class="top-btn" href="/logout">Çıkış</a>
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
                        placeholder="Link, mesaj, domain veya not ara..."
                        value="${escapeHtml(search)}"
                      />
                    </div>
                    <select class="select" name="status">
                      <option value="">Tüm Durumlar</option>
                      <option value="Beklemede" ${statusFilter === "Beklemede" ? "selected" : ""}>Beklemede</option>
                      <option value="Onaylandı" ${statusFilter === "Onaylandı" ? "selected" : ""}>Onaylandı</option>
                      <option value="Reddedildi" ${statusFilter === "Reddedildi" ? "selected" : ""}>Reddedildi</option>
                    </select>
                    <select class="select" name="risk">
                      <option value="">Tüm Riskler</option>
                      <option value="Normal" ${riskFilter === "Normal" ? "selected" : ""}>Normal</option>
                      <option value="Şüpheli" ${riskFilter === "Şüpheli" ? "selected" : ""}>Şüpheli</option>
                      <option value="Davet Linki" ${riskFilter === "Davet Linki" ? "selected" : ""}>Davet Linki</option>
                      <option value="Yüksek Risk" ${riskFilter === "Yüksek Risk" ? "selected" : ""}>Yüksek Risk</option>
                    </select>
                    <button class="search-btn" type="submit">Ara</button>
                    <a class="clear-btn" href="/links">Temizle</a>
                    <a class="clear-btn" href="/links?deleted=1">Çöpü Gör</a>
                  </form>
                </div>

                <div class="filter-panel">
                  <div class="chip-row">
                    <a class="chip" href="/links">Tüm Linkler</a>
                    <a class="chip blue" href="/links?search=fenerbahçe">#fenerbahçe</a>
                    <a class="chip green" href="/links?search=futbol">#futbol</a>
                    <a class="chip blue" href="/links?search=haber">#haber</a>
                    <a class="chip orange" href="/links?search=yemek">#yemek</a>
                    <a class="chip pink" href="/links?risk=Şüpheli">#şüpheli</a>
                  </div>
                </div>

                ${
                  rows.length > 0
                    ? `<div class="feed-list">${cards}</div>`
                    : `<div class="empty-box">Bu filtreye uyan kayıt yok.</div>`
                }
              </div>

              <div class="right">
                <div class="right-card">
                  <div class="right-title">Hızlı Erişim</div>
                  <div class="panel-buttons">
                    <a class="mini-panel-btn" href="/links">Liste</a>
                    <a class="mini-panel-btn" href="/links/json">JSON</a>
                    <a class="mini-panel-btn" href="/links/export/csv">CSV</a>
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

                <div class="right-card">
                  <div class="right-title">Özet</div>
                  <div class="chip-row">
                    <div class="chip blue">En Çok Domain: ${escapeHtml(topDomain)}</div>
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
  console.log(`Server ${PORT} portunda çalışıyor`);

  try {
    await ensureTables();
    console.log("Tablolar hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
