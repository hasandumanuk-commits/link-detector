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

function csvEscape(value) {
  const s = String(value ?? "");
  return `"${s.replace(/"/g, '""')}"`;
}

function getDomain(link) {
  try {
    const url = new URL(link);
    return url.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS whitelist_domains (
      id SERIAL PRIMARY KEY,
      domain TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blacklist_domains (
      id SERIAL PRIMARY KEY,
      domain TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      action_type TEXT NOT NULL,
      target_id INTEGER,
      details TEXT,
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
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
}

async function logAudit(actionType, targetId = null, details = "") {
  try {
    await pool.query(
      `INSERT INTO audit_logs (action_type, target_id, details) VALUES ($1, $2, $3)`,
      [actionType, targetId, details]
    );
  } catch (error) {
    console.error("AUDIT LOG ERROR:", error);
  }
}

async function getWhitelistDomains() {
  const result = await pool.query(`SELECT domain FROM whitelist_domains ORDER BY domain ASC`);
  return result.rows.map((r) => String(r.domain).toLowerCase());
}

async function getBlacklistDomains() {
  const result = await pool.query(`SELECT domain FROM blacklist_domains ORDER BY domain ASC`);
  return result.rows.map((r) => String(r.domain).toLowerCase());
}

function detectRisk(links, messageText = "", whitelist = [], blacklist = []) {
  const domains = (Array.isArray(links) ? links : []).map(getDomain).filter(Boolean);
  const text = `${messageText} ${(Array.isArray(links) ? links.join(" ") : "")}`.toLowerCase();

  if (domains.some((d) => blacklist.includes(d))) return "Yüksek Risk";
  if (domains.some((d) => whitelist.includes(d))) return "Whitelist";

  const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly", "shorturl"];
  const invites = ["discord.gg", "discord.com", "t.me", "telegram.me", "wa.me"];
  const adultish = ["onlyfans", "porn", "xxx", "escort", "nsfw", "18+"];
  const suspicious = ["free skin", "nitro", "gift", "airdrop", "casino", "bet", "hack", "crack"];

  if (adultish.some((k) => text.includes(k))) return "Yüksek Risk";
  if (domains.some((d) => shorteners.some((s) => d.includes(s)))) return "Şüpheli";
  if (suspicious.some((k) => text.includes(k))) return "Şüpheli";
  if (domains.some((d) => invites.some((s) => d.includes(s)))) return "Davet Linki";

  return "Normal";
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
app.get("/logo.png", (req, res) => {
  res.sendFile(__dirname + "/logo.png");
});

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
              radial-gradient(circle at 10% 10%, rgba(255, 221, 87, 0.12), transparent 22%),
              radial-gradient(circle at 90% 0%, rgba(37, 99, 235, 0.16), transparent 26%),
              radial-gradient(circle at 50% 100%, rgba(255, 221, 87, 0.06), transparent 20%),
              linear-gradient(180deg, #07122a 0%, #041126 45%, #020814 100%);
            color: white;
          }
          .card {
            width: 100%;
            max-width: 430px;
            background: linear-gradient(180deg, rgba(10, 20, 36, 0.92), rgba(6, 14, 26, 0.88));
            border: 1px solid rgba(102, 126, 173, 0.22);
            border-radius: 26px;
            padding: 30px;
            box-shadow:
              0 18px 40px rgba(0, 0, 0, 0.32),
              inset 0 1px 0 rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
          }
          .logo-wrap {
            display: flex;
            justify-content: center;
            margin-bottom: 18px;
          }
          .logo {
            width: 86px;
            height: 86px;
            border-radius: 50%;
            object-fit: cover;
            box-shadow:
              0 0 24px rgba(255, 216, 77, 0.18),
              inset 0 1px 0 rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.08);
            background: #111;
          }
          h1 { margin: 0 0 8px 0; font-size: 30px; text-align: center; }
          .sub { color: #b7c5e0; margin-bottom: 22px; text-align: center; }
          .input {
            width: 100%;
            background: linear-gradient(180deg, #0a1524, #07111c);
            border: 1px solid rgba(96, 120, 168, 0.22);
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
            background: linear-gradient(135deg, #ffe37a, #facc15);
            color: #0b1b44;
            box-shadow:
              0 0 18px rgba(250, 204, 21, 0.18),
              inset 0 1px 0 rgba(255,255,255,0.20);
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
          <div class="logo-wrap">
            <img class="logo" src="/logo.png" alt="Logo" />
          </div>
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

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAuthenticated = true;
    await logAudit("LOGIN_SUCCESS", null, `username=${username}`);
    return res.redirect("/links");
  }

  await logAudit("LOGIN_FAIL", null, `username=${username || ""}`);
  return res.redirect("/login?error=1");
});

app.get("/logout", requireAuth, async (req, res) => {
  await logAudit("LOGOUT", null, "logout");
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/", requireAuth, (req, res) => {
  res.redirect("/links");
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

    await logAudit("KICK_CALLBACK", null, "token kaydedildi");

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

    await ensureTables();

    const whitelist = await getWhitelistDomains();
    const blacklist = await getBlacklistDomains();
    const riskLevel = detectRisk(links, possibleText, whitelist, blacklist);

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
        is_deleted,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
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

    await logAudit("WEBHOOK_INSERT", null, `domain=${firstDomain || ""} risk=${riskLevel}`);

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
    await pool.query(
      `UPDATE links SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [id]
    );
    await logAudit("SOFT_DELETE", Number(id), "çöpe taşındı");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Silme hatası: " + error.message);
  }
});

app.post("/links/restore/:id", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const id = req.params.id;
    await pool.query(
      `UPDATE links SET is_deleted = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [id]
    );
    await logAudit("RESTORE", Number(id), "geri alındı");
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

    await pool.query(
      `UPDATE links SET review_status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [status, id]
    );

    await logAudit("STATUS_UPDATE", Number(id), `status=${status}`);
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

    await pool.query(
      `UPDATE links SET moderator_note = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [note || null, id]
    );

    await logAudit("NOTE_UPDATE", Number(id), note || "");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Not kaydetme hatası: " + error.message);
  }
});

app.post("/links/bulk-action", requireAuth, async (req, res) => {
  try {
    await ensureTables();

    const ids = Array.isArray(req.body.ids)
      ? req.body.ids
      : req.body.ids
      ? [req.body.ids]
      : [];

    const action = req.body.action;

    if (!ids.length) {
      return res.redirect("/links");
    }

    const numericIds = ids.map((id) => Number(id)).filter((id) => Number.isFinite(id));

    if (!numericIds.length) {
      return res.redirect("/links");
    }

    if (action === "approve") {
      await pool.query(
        `UPDATE links SET review_status = 'Onaylandı', updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`,
        [numericIds]
      );
      await logAudit("BULK_APPROVE", null, `ids=${numericIds.join(",")}`);
    } else if (action === "reject") {
      await pool.query(
        `UPDATE links SET review_status = 'Reddedildi', updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`,
        [numericIds]
      );
      await logAudit("BULK_REJECT", null, `ids=${numericIds.join(",")}`);
    } else if (action === "delete") {
      await pool.query(
        `UPDATE links SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`,
        [numericIds]
      );
      await logAudit("BULK_DELETE", null, `ids=${numericIds.join(",")}`);
    }

    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Toplu işlem hatası: " + error.message);
  }
});

app.post("/domains/whitelist", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const domain = String(req.body.domain || "").trim().toLowerCase().replace(/^www\./, "");
    if (!domain) return res.redirect("/links");

    await pool.query(
      `INSERT INTO whitelist_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING`,
      [domain]
    );

    await logAudit("WHITELIST_ADD", null, domain);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Whitelist ekleme hatası: " + error.message);
  }
});

app.post("/domains/blacklist", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const domain = String(req.body.domain || "").trim().toLowerCase().replace(/^www\./, "");
    if (!domain) return res.redirect("/links");

    await pool.query(
      `INSERT INTO blacklist_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING`,
      [domain]
    );

    await logAudit("BLACKLIST_ADD", null, domain);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Blacklist ekleme hatası: " + error.message);
  }
});

app.post("/domains/whitelist/delete/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query(`DELETE FROM whitelist_domains WHERE id = $1`, [id]);
    await logAudit("WHITELIST_DELETE", Number(id), "silindi");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Whitelist silme hatası: " + error.message);
  }
});

app.post("/domains/blacklist/delete/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query(`DELETE FROM blacklist_domains WHERE id = $1`, [id]);
    await logAudit("BLACKLIST_DELETE", Number(id), "silindi");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Blacklist silme hatası: " + error.message);
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
      SELECT id, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, moderator_note, is_deleted, created_at, updated_at
      FROM links
      ORDER BY id DESC
      LIMIT 500
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
      SELECT id, message_text, extracted_links, link_domain, risk_level, review_status, moderator_note, is_deleted, created_at, updated_at
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
      "updated_at",
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
        csvEscape(row.updated_at),
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
    const domainFilter = typeof req.query.domain === "string" ? req.query.domain.trim().toLowerCase() : "";
    const deletedFilter = req.query.deleted === "1";
    const dateFrom = typeof req.query.date_from === "string" ? req.query.date_from.trim() : "";
    const dateTo = typeof req.query.date_to === "string" ? req.query.date_to.trim() : "";
    const autoRefresh = typeof req.query.auto_refresh === "string" ? req.query.auto_refresh.trim() : "0";

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

    if (domainFilter) {
      whereParts.push(`COALESCE(link_domain, '') ILIKE $${idx}`);
      values.push(`%${domainFilter}%`);
      idx++;
    }

    if (dateFrom) {
      whereParts.push(`created_at::date >= $${idx}`);
      values.push(dateFrom);
      idx++;
    }

    if (dateTo) {
      whereParts.push(`created_at::date <= $${idx}`);
      values.push(dateTo);
      idx++;
    }

    whereParts.push(`COALESCE(is_deleted, FALSE) = $${idx}`);
    values.push(deletedFilter);

    const whereSql = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

    const result = await pool.query(
      `
      SELECT id, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, moderator_note, is_deleted, created_at, updated_at
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
    const suspiciousCountResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND COALESCE(risk_level, 'Normal') IN ('Şüpheli', 'Yüksek Risk', 'Davet Linki')
    `);
    const approvedCountResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND COALESCE(review_status, 'Beklemede') = 'Onaylandı'
    `);
    const domainStatResult = await pool.query(`
      SELECT COALESCE(link_domain, '') AS link_domain, COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      GROUP BY link_domain
      ORDER BY total DESC, link_domain ASC
      LIMIT 1
    `);
    const recentAuditResult = await pool.query(`
      SELECT id, action_type, target_id, details, created_at
      FROM audit_logs
      ORDER BY id DESC
      LIMIT 8
    `);
    const whitelistResult = await pool.query(`
      SELECT id, domain
      FROM whitelist_domains
      ORDER BY domain ASC
      LIMIT 20
    `);
    const blacklistResult = await pool.query(`
      SELECT id, domain
      FROM blacklist_domains
      ORDER BY domain ASC
      LIMIT 20
    `);

    const totalCount = totalCountResult.rows[0]?.total || 0;
    const deletedCount = deletedCountResult.rows[0]?.total || 0;
    const todayCount = todayCountResult.rows[0]?.total || 0;
    const suspiciousCount = suspiciousCountResult.rows[0]?.total || 0;
    const approvedCount = approvedCountResult.rows[0]?.total || 0;
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
            : riskLevel === "Whitelist"
            ? "risk-whitelist"
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
              <input class="bulk-checkbox" type="checkbox" name="ids" value="${row.id}" form="bulkForm" />
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

    const auditHtml = recentAuditResult.rows
      .map((row) => {
        return `
          <div class="audit-item">
            <div class="audit-top">
              <strong>${escapeHtml(row.action_type)}</strong>
              <span>${new Date(row.created_at).toLocaleString("tr-TR")}</span>
            </div>
            <div class="audit-bottom">${escapeHtml(row.details || "")}</div>
          </div>
        `;
      })
      .join("");

    const whitelistHtml = whitelistResult.rows
      .map(
        (row) => `
        <div class="domain-item">
          <span>${escapeHtml(row.domain)}</span>
          <form method="POST" action="/domains/whitelist/delete/${row.id}">
            <button type="submit" class="domain-del">Sil</button>
          </form>
        </div>
      `
      )
      .join("");

    const blacklistHtml = blacklistResult.rows
      .map(
        (row) => `
        <div class="domain-item">
          <span>${escapeHtml(row.domain)}</span>
          <form method="POST" action="/domains/blacklist/delete/${row.id}">
            <button type="submit" class="domain-del">Sil</button>
          </form>
        </div>
      `
      )
      .join("");

    const autoRefreshMeta =
      autoRefresh === "30" || autoRefresh === "60"
        ? `<meta http-equiv="refresh" content="${autoRefresh}">`
        : "";

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          ${autoRefreshMeta}
          <title>HasanD Link Detector</title>
          <style>
            * { box-sizing: border-box; }
            body {
              margin: 0;
              font-family: Arial, sans-serif;
              color: #f5f7fb;
              background:
                radial-gradient(circle at 10% 10%, rgba(255, 221, 87, 0.12), transparent 22%),
                radial-gradient(circle at 90% 0%, rgba(37, 99, 235, 0.16), transparent 26%),
                radial-gradient(circle at 50% 100%, rgba(255, 221, 87, 0.06), transparent 20%),
                linear-gradient(180deg, #07122a 0%, #041126 45%, #020814 100%);
            }
            a { color: inherit; text-decoration: none; }

            .app-shell {
              display: flex;
              min-height: 100vh;
              gap: 14px;
              padding: 14px;
            }

            .sidebar {
              width: 76px;
              background: linear-gradient(180deg, rgba(9, 18, 33, 0.95), rgba(6, 12, 24, 0.92));
              border: 1px solid rgba(102, 126, 173, 0.20);
              border-radius: 24px;
              padding: 16px 10px;
              display: flex;
              flex-direction: column;
              align-items: center;
              gap: 12px;
              box-shadow:
                0 18px 40px rgba(0,0,0,0.34),
                inset 0 1px 0 rgba(255,255,255,0.03);
            }

            .side-logo {
              width: 48px;
              height: 48px;
              border-radius: 50%;
              object-fit: cover;
              box-shadow:
                0 0 22px rgba(255, 216, 77, 0.26),
                inset 0 1px 0 rgba(255,255,255,0.25);
              border: 1px solid rgba(255,255,255,0.08);
              background: #111;
            }

            .side-btn {
              width: 44px;
              height: 44px;
              border-radius: 16px;
              border: 1px solid rgba(92, 117, 164, 0.26);
              background: linear-gradient(180deg, #0c1728, #08111e);
              color: #d3def5;
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 15px;
              transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
            }

            .side-btn:hover {
              transform: translateY(-2px);
              border-color: rgba(255, 221, 87, 0.30);
              box-shadow: 0 8px 18px rgba(0,0,0,0.28);
            }

            .side-btn.active {
              background: linear-gradient(135deg, #ffe37a, #facc15);
              color: #0b1b44;
              font-weight: bold;
              box-shadow:
                0 0 18px rgba(250, 204, 21, 0.24),
                inset 0 1px 0 rgba(255,255,255,0.25);
            }

            .content {
              flex: 1;
              display: grid;
              grid-template-columns: 1fr 320px;
              gap: 14px;
            }

            .topbar, .search-panel, .filter-panel, .bulk-panel, .feed-card, .right-card {
              background: linear-gradient(180deg, rgba(10, 20, 36, 0.92), rgba(6, 14, 26, 0.88));
              border: 1px solid rgba(102, 126, 173, 0.22);
              box-shadow:
                0 18px 40px rgba(0, 0, 0, 0.32),
                inset 0 1px 0 rgba(255, 255, 255, 0.03);
              backdrop-filter: blur(10px);
            }

            .topbar {
              border-radius: 24px;
              padding: 18px 22px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 16px;
              margin-bottom: 16px;
              position: relative;
              overflow: hidden;
            }

            .topbar::before {
              content: "";
              position: absolute;
              inset: 0;
              background: linear-gradient(90deg, rgba(255, 221, 87, 0.04), transparent 35%, rgba(59, 130, 246, 0.05));
              pointer-events: none;
            }

            .brand-title {
              font-size: 18px;
              font-weight: 700;
              margin-bottom: 3px;
              text-shadow: 0 0 16px rgba(255, 221, 87, 0.08);
            }

            .brand-sub {
              color: #c8d4ef;
              font-size: 12px;
              letter-spacing: 0.2px;
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
              background: linear-gradient(180deg, #0e1828, #091321);
              border: 1px solid rgba(96, 120, 168, 0.24);
              border-radius: 18px;
              padding: 11px 15px;
              text-align: center;
              box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
            }

            .stat-label {
              color: #7b8aa8;
              font-size: 11px;
              margin-bottom: 3px;
              letter-spacing: 0.2px;
            }

            .stat-value {
              font-size: 22px;
              font-weight: 800;
              letter-spacing: 0.2px;
            }

            .top-btn {
              background: linear-gradient(180deg, #101b2b, #0a1320);
              border: 1px solid rgba(92, 117, 164, 0.24);
              color: white;
              border-radius: 14px;
              padding: 10px 15px;
              font-weight: 700;
              transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
            }

            .top-btn:hover {
              transform: translateY(-2px);
              box-shadow: 0 10px 20px rgba(0,0,0,0.24);
              border-color: rgba(255, 221, 87, 0.24);
            }

            .top-btn.green {
              background: linear-gradient(135deg, #ffe37a, #facc15);
              color: #0b1b44;
              border: none;
              box-shadow:
                0 0 18px rgba(250, 204, 21, 0.18),
                inset 0 1px 0 rgba(255,255,255,0.20);
            }

            .search-panel, .filter-panel, .bulk-panel, .right-card {
              border-radius: 22px;
              padding: 18px;
              margin-bottom: 12px;
              position: relative;
              overflow: hidden;
            }

            .right-card::before {
              content: "";
              position: absolute;
              inset: 0;
              background: linear-gradient(90deg, rgba(255,255,255,0.015), transparent 45%, rgba(255,221,87,0.02));
              pointer-events: none;
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
              background: linear-gradient(180deg, #0a1524, #07111c);
              border: 1px solid rgba(96, 120, 168, 0.22);
              border-radius: 16px;
              padding: 12px 14px;
              box-shadow: inset 0 1px 0 rgba(255,255,255,0.02);
            }

            .search-input, .select, .note-input {
              background: linear-gradient(180deg, #0a1524, #07111c);
              border: 1px solid rgba(96, 120, 168, 0.22);
              outline: none;
              color: white;
              font-size: 14px;
              border-radius: 14px;
              padding: 10px 12px;
              box-shadow: inset 0 1px 0 rgba(255,255,255,0.02);
            }

            .search-input {
              flex: 1;
              background: transparent;
              border: none;
              padding: 0;
              box-shadow: none;
            }

            .select:focus, .note-input:focus {
              border-color: rgba(255, 221, 87, 0.28);
              box-shadow: 0 0 0 3px rgba(255, 221, 87, 0.08);
            }

            .search-btn, .clear-btn, .mini-btn, .bulk-btn, .domain-btn, .domain-del {
              border: none;
              cursor: pointer;
              border-radius: 12px;
              padding: 10px 12px;
              font-weight: 700;
            }

            .search-btn, .mini-btn, .bulk-btn, .domain-btn {
              background: linear-gradient(135deg, #ffe37a, #facc15);
              color: #0b1b44;
              border: 1px solid rgba(255, 216, 77, 0.35);
              transition: transform 0.18s ease, box-shadow 0.18s ease, filter 0.18s ease;
            }

            .search-btn:hover, .mini-btn:hover, .bulk-btn:hover, .domain-btn:hover {
              transform: translateY(-2px);
              box-shadow: 0 10px 20px rgba(0,0,0,0.22);
              filter: brightness(1.04);
            }

            .clear-btn {
              background: #141f2f;
              color: #dce8ff;
              border: 1px solid rgba(73, 95, 130, 0.35);
            }

            .domain-del {
              background: rgba(220, 38, 38, 0.16);
              color: #ffb4b4;
            }

            .chip {
              padding: 9px 13px;
              border-radius: 999px;
              background: linear-gradient(180deg, #0f1b2d, #091321);
              border: 1px solid rgba(92, 117, 164, 0.22);
              font-size: 12px;
              color: #b6c4df;
              box-shadow: inset 0 1px 0 rgba(255,255,255,0.02);
            }
            .chip.green { color: #79f0b6; border-color: rgba(13, 207, 131, 0.35); }
            .chip.pink { color: #f4a5d6; border-color: rgba(255, 95, 162, 0.35); }
            .chip.orange { color: #ffc078; border-color: rgba(255, 160, 60, 0.35); }
            .chip.blue { color: #88c7ff; border-color: rgba(72, 163, 255, 0.35); }

            .bulk-panel form {
              display: flex;
              gap: 10px;
              flex-wrap: wrap;
              align-items: center;
            }

            .feed-list {
              display: flex;
              flex-direction: column;
              gap: 12px;
            }

            .feed-card {
              border-radius: 22px;
              padding: 18px;
              display: grid;
              grid-template-columns: 190px 1fr 70px;
              gap: 18px;
              align-items: start;
              transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
            }

            .feed-card:hover {
              transform: translateY(-2px);
              border-color: rgba(255, 221, 87, 0.18);
              box-shadow:
                0 20px 40px rgba(0,0,0,0.30),
                inset 0 1px 0 rgba(255,255,255,0.03);
            }

            .feed-left {
              display: flex;
              gap: 10px;
              align-items: center;
            }

            .bulk-checkbox {
              width: 18px;
              height: 18px;
              accent-color: #facc15;
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
            .risk-whitelist { background: rgba(16, 185, 129, 0.12); color: #6ee7b7; border-color: rgba(16, 185, 129, 0.25); }

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

            .empty-box {
              background: linear-gradient(180deg, rgba(10, 20, 36, 0.92), rgba(6, 14, 26, 0.88));
              border: 1px solid rgba(102, 126, 173, 0.20);
              border-radius: 22px;
              padding: 34px 26px;
              color: #a8b7d2;
              text-align: center;
              box-shadow:
                0 18px 40px rgba(0,0,0,0.24),
                inset 0 1px 0 rgba(255,255,255,0.03);
            }

            .right {
              display: flex;
              flex-direction: column;
              gap: 14px;
            }

            .right-card {
              border-radius: 22px;
              padding: 18px;
            }

            .right-title {
              font-size: 13px;
              color: #8fa0bf;
              margin-bottom: 12px;
              letter-spacing: 0.2px;
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

            .domain-list, .audit-list {
              display: flex;
              flex-direction: column;
              gap: 8px;
              margin-top: 12px;
            }

            .domain-item, .audit-item {
              background: #0b1421;
              border: 1px solid rgba(73, 95, 130, 0.35);
              border-radius: 12px;
              padding: 10px;
              transition: transform 0.16s ease, border-color 0.16s ease;
            }

            .audit-item:hover, .domain-item:hover {
              transform: translateY(-1px);
              border-color: rgba(255, 221, 87, 0.16);
            }

            .domain-item {
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 8px;
            }

            .audit-top {
              display: flex;
              justify-content: space-between;
              gap: 8px;
              font-size: 12px;
              margin-bottom: 6px;
            }

            .audit-bottom {
              color: #c9d7ef;
              font-size: 12px;
              word-break: break-word;
            }

            @media (max-width: 1250px) {
              .content { grid-template-columns: 1fr; }
              .right { order: -1; }
            }

            @media (max-width: 900px) {
              .feed-card { grid-template-columns: 1fr; }
              .feed-actions {
                flex-direction: row;
                justify-content: flex-start;
              }
            }

            @media (max-width: 800px) {
              .app-shell { display: block; padding: 10px; }
              .sidebar {
                width: 100%;
                flex-direction: row;
                justify-content: center;
                margin-bottom: 10px;
              }
            }
          </style>
        </head>
        <body>
          <div class="app-shell">
            <div class="sidebar">
              <a href="/links"><img class="side-logo" src="/logo.png" alt="Logo" /></a>
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
                      <div class="stat-label">Şüpheli</div>
                      <div class="stat-value">${suspiciousCount}</div>
                    </div>
                    <div class="stat-pill">
                      <div class="stat-label">Onaylı</div>
                      <div class="stat-value">${approvedCount}</div>
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
                    <input class="select" type="text" name="domain" placeholder="domain filtrele" value="${escapeHtml(domainFilter)}" />
                    <select class="select" name="status">
                      <option value="">Tüm Durumlar</option>
                      <option value="Beklemede" ${statusFilter === "Beklemede" ? "selected" : ""}>Beklemede</option>
                      <option value="Onaylandı" ${statusFilter === "Onaylandı" ? "selected" : ""}>Onaylandı</option>
                      <option value="Reddedildi" ${statusFilter === "Reddedildi" ? "selected" : ""}>Reddedildi</option>
                    </select>
                    <select class="select" name="risk">
                      <option value="">Tüm Riskler</option>
                      <option value="Normal" ${riskFilter === "Normal" ? "selected" : ""}>Normal</option>
                      <option value="Whitelist" ${riskFilter === "Whitelist" ? "selected" : ""}>Whitelist</option>
                      <option value="Şüpheli" ${riskFilter === "Şüpheli" ? "selected" : ""}>Şüpheli</option>
                      <option value="Davet Linki" ${riskFilter === "Davet Linki" ? "selected" : ""}>Davet Linki</option>
                      <option value="Yüksek Risk" ${riskFilter === "Yüksek Risk" ? "selected" : ""}>Yüksek Risk</option>
                    </select>
                    <input class="select" type="date" name="date_from" value="${escapeHtml(dateFrom)}" />
                    <input class="select" type="date" name="date_to" value="${escapeHtml(dateTo)}" />
                    <select class="select" name="auto_refresh">
                      <option value="0" ${autoRefresh === "0" ? "selected" : ""}>Oto yenileme kapalı</option>
                      <option value="30" ${autoRefresh === "30" ? "selected" : ""}>30 sn yenile</option>
                      <option value="60" ${autoRefresh === "60" ? "selected" : ""}>60 sn yenile</option>
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
                    <a class="chip pink" href="/links?risk=Yüksek%20Risk">#yüksek-risk</a>
                  </div>
                </div>

                <div class="bulk-panel">
                  <form id="bulkForm" method="POST" action="/links/bulk-action">
                    <button class="bulk-btn" type="submit" name="action" value="approve">Seçilileri Onayla</button>
                    <button class="bulk-btn" type="submit" name="action" value="reject">Seçilileri Reddet</button>
                    <button class="bulk-btn" type="submit" name="action" value="delete">Seçilileri Çöpe Taşı</button>
                  </form>
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
                    <a class="chip pink" href="/subscribe/chat">Webhook Bekliyor</a>
                    <div class="chip orange">Çöp: ${deletedCount}</div>
                  </div>
                </div>

                <div class="right-card">
                  <div class="right-title">Özet</div>
                  <div class="chip-row">
                    <div class="chip blue">En Çok Domain: ${escapeHtml(topDomain)}</div>
                  </div>
                </div>

                <div class="right-card">
                  <div class="right-title">Whitelist Domain</div>
                  <form class="inline-form" method="POST" action="/domains/whitelist">
                    <input class="note-input" type="text" name="domain" placeholder="ör: youtube.com" />
                    <button class="domain-btn" type="submit">Ekle</button>
                  </form>
                  <div class="domain-list">
                    ${whitelistHtml || `<div class="audit-item">Henüz whitelist domain yok.</div>`}
                  </div>
                </div>

                <div class="right-card">
                  <div class="right-title">Blacklist Domain</div>
                  <form class="inline-form" method="POST" action="/domains/blacklist">
                    <input class="note-input" type="text" name="domain" placeholder="ör: spam-site.com" />
                    <button class="domain-btn" type="submit">Ekle</button>
                  </form>
                  <div class="domain-list">
                    ${blacklistHtml || `<div class="audit-item">Henüz blacklist domain yok.</div>`}
                  </div>
                </div>

                <div class="right-card">
                  <div class="right-title">Son İşlemler</div>
                  <div class="audit-list">
                    ${auditHtml || `<div class="audit-item">Henüz işlem yok.</div>`}
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
