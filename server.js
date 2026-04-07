require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();

const APP_URL = process.env.APP_URL;
const DATABASE_URL = process.env.DATABASE_URL;
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID;
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;
const KICK_CHANNEL_SLUG = process.env.KICK_CHANNEL_SLUG;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

const BLOCKED_BOT_USERNAMES = ["botrix"];

app.use(bodyParser.json({ limit: "2mb" }));
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
      maxAge: 1000 * 60 * 60 * 12,
    },
  })
);

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

let pkceVerifier = null;

function requireAuth(req, res, next) {
  if (req.session && req.session.isAuthenticated) return next();
  return res.redirect("/login");
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
  const matches = text.match(/https?:\/\/[^\s<>"'`]+/gi);
  return matches || [];
}

function getDomain(link) {
  try {
    const url = new URL(link);
    return url.hostname.replace(/^www\./i, "").toLowerCase();
  } catch {
    return "";
  }
}

function isShortLinkDomain(domain) {
  const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "short.io",
  ];
  return shorteners.some((s) => domain === s || domain.endsWith("." + s));
}

function detectRisk(links, messageText = "", whitelist = [], blacklist = []) {
  const domains = (Array.isArray(links) ? links : []).map(getDomain).filter(Boolean);
  const text = `${messageText} ${Array.isArray(links) ? links.join(" ") : ""}`.toLowerCase();

  if (domains.some((d) => blacklist.includes(d))) return "Yüksek Risk";
  if (domains.some((d) => whitelist.includes(d))) return "Whitelist";
  if (domains.some((d) => isShortLinkDomain(d))) return "Kısa Link";

  const suspiciousWords = [
    "free",
    "gift",
    "nitro",
    "airdrop",
    "bonus",
    "bedava",
    "promo",
    "çekiliş",
    "claim",
    "drop",
    "casino",
    "bet",
    "katıl",
    "join now",
    "ücretsiz",
  ];
  const inviteDomains = ["discord.gg", "discord.com", "t.me", "telegram.me", "wa.me"];

  if (domains.some((d) => inviteDomains.some((s) => d.includes(s)))) return "Davet Linki";
  if (suspiciousWords.some((w) => text.includes(w))) return "Şüpheli";

  return "Normal";
}

function statusColorClass(status) {
  if (status === "Onaylandı") return "status-approved";
  if (status === "Reddedildi") return "status-rejected";
  if (status === "İnceleniyor") return "status-review";
  return "status-pending";
}

function riskColorClass(risk) {
  if (risk === "Yüksek Risk") return "risk-high";
  if (risk === "Şüpheli") return "risk-mid";
  if (risk === "Davet Linki") return "risk-invite";
  if (risk === "Whitelist") return "risk-whitelist";
  if (risk === "Kısa Link") return "risk-short";
  return "risk-normal";
}

function buildQuery(baseQuery, overrides = {}) {
  const params = new URLSearchParams();
  const merged = { ...baseQuery, ...overrides };
  for (const [key, value] of Object.entries(merged)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
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
      sender_username TEXT,
      message_text TEXT,
      extracted_links TEXT,
      raw_data TEXT NOT NULL,
      link_domain TEXT,
      risk_level TEXT DEFAULT 'Normal',
      review_status TEXT DEFAULT 'Beklemede',
      is_deleted BOOLEAN DEFAULT FALSE,
      is_opened BOOLEAN DEFAULT FALSE,
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
    CREATE TABLE IF NOT EXISTS blocked_usernames (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
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

  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS sender_username TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS message_text TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS extracted_links TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS link_domain TEXT`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS risk_level TEXT DEFAULT 'Normal'`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'Beklemede'`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS is_opened BOOLEAN DEFAULT FALSE`);
  await pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
}

async function getWhitelistDomains() {
  const result = await pool.query(`SELECT domain FROM whitelist_domains ORDER BY domain ASC`);
  return result.rows.map((r) => String(r.domain).toLowerCase());
}

async function getBlacklistDomains() {
  const result = await pool.query(`SELECT domain FROM blacklist_domains ORDER BY domain ASC`);
  return result.rows.map((r) => String(r.domain).toLowerCase());
}

async function getBlockedUsernames() {
  const result = await pool.query(`SELECT username FROM blocked_usernames ORDER BY username ASC`);
  return result.rows.map((r) => String(r.username).toLowerCase());
}

async function getAppAccessToken() {
  const tokenRes = await fetch("https://id.kick.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
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

function baseLayoutStyles() {
  return `
    * { box-sizing: border-box; }
    :root {
      --bg-0: #030814;
      --bg-1: #07122a;
      --bg-2: #0b1730;
      --panel: rgba(8, 18, 36, 0.92);
      --panel-2: rgba(10, 22, 42, 0.88);
      --line: rgba(116, 144, 196, 0.16);
      --line-2: rgba(116, 144, 196, 0.24);
      --text: #eef4ff;
      --muted: #8ea0c4;
      --blue: #3b82f6;
      --cyan: #22d3ee;
      --green: #22c55e;
      --yellow: #facc15;
      --orange: #f59e0b;
      --red: #ef4444;
      --purple: #8b5cf6;
      --shadow: 0 18px 40px rgba(0,0,0,0.32);
    }

    html, body {
      margin: 0;
      min-height: 100%;
      background:
        radial-gradient(circle at 10% 10%, rgba(250, 204, 21, 0.10), transparent 22%),
        radial-gradient(circle at 90% 5%, rgba(59, 130, 246, 0.16), transparent 24%),
        radial-gradient(circle at 50% 100%, rgba(34, 211, 238, 0.06), transparent 20%),
        linear-gradient(180deg, var(--bg-1) 0%, #041126 42%, var(--bg-0) 100%);
      color: var(--text);
      font-family: Arial, sans-serif;
    }

    a { color: inherit; text-decoration: none; }

    .glass {
      background: linear-gradient(180deg, var(--panel), var(--panel-2));
      border: 1px solid rgba(94, 117, 163, 0.20);
      box-shadow: var(--shadow), inset 0 1px 0 rgba(255,255,255,0.03);
      backdrop-filter: blur(12px);
    }

    .page-shell {
      display: flex;
      gap: 16px;
      min-height: 100vh;
      padding: 16px;
    }

    .sidebar {
      width: 78px;
      border-radius: 26px;
      padding: 14px 10px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
      position: sticky;
      top: 16px;
      height: calc(100vh - 32px);
    }

    .side-logo {
      width: 48px;
      height: 48px;
      object-fit: cover;
      border-radius: 50%;
      background: #0f172a;
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 0 24px rgba(250,204,21,0.18);
    }

    .nav-btn {
      width: 44px;
      height: 44px;
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(180deg, #0f1b31, #091321);
      border: 1px solid var(--line-2);
      color: #dbeafe;
      font-size: 15px;
      font-weight: 700;
      transition: transform 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
    }

    .nav-btn:hover {
      transform: translateY(-1px);
      border-color: rgba(250, 204, 21, 0.24);
      box-shadow: 0 8px 20px rgba(0,0,0,0.20);
    }

    .nav-btn.active {
      background: linear-gradient(135deg, #ffe37a, #facc15);
      color: #0b1b44;
      border: none;
      box-shadow: 0 0 18px rgba(250, 204, 21, 0.20);
    }

    .content-grid {
      flex: 1;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 330px;
      gap: 16px;
    }

    .topbar {
      border-radius: 26px;
      padding: 18px 22px;
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: center;
      margin-bottom: 16px;
      position: relative;
      overflow: hidden;
    }

    .topbar::before {
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(90deg, rgba(250,204,21,0.04), transparent 35%, rgba(59,130,246,0.06));
      pointer-events: none;
    }

    .brand-title {
      font-size: 19px;
      font-weight: 800;
      margin-bottom: 4px;
      letter-spacing: 0.1px;
    }

    .brand-sub {
      color: #c9d6ef;
      font-size: 12px;
    }

    .top-actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: center;
    }

    .stat-card {
      min-width: 106px;
      border-radius: 20px;
      padding: 10px 14px;
      background: linear-gradient(180deg, rgba(12, 24, 45, 0.94), rgba(8, 17, 32, 0.90));
      border: 1px solid var(--line);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
      text-align: center;
    }

    .stat-label {
      color: #8ea2ca;
      font-size: 11px;
      margin-bottom: 4px;
    }

    .stat-value {
      font-size: 21px;
      font-weight: 800;
      margin-bottom: 2px;
    }

    .stat-sub {
      font-size: 11px;
      color: #56f0a3;
      font-weight: 700;
    }

    .btn, .top-btn, .quick-btn, .mini-btn, .side-mini-btn {
      border: none;
      cursor: pointer;
      border-radius: 14px;
      padding: 10px 14px;
      font-weight: 700;
      transition: transform 0.16s ease, box-shadow 0.16s ease, filter 0.16s ease;
    }

    .btn:hover, .top-btn:hover, .quick-btn:hover, .mini-btn:hover, .side-mini-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 22px rgba(0,0,0,0.20);
      filter: brightness(1.02);
    }

    .btn-primary, .mini-btn, .quick-btn.primary {
      background: linear-gradient(135deg, #ffe37a, #facc15);
      color: #0b1b44;
      border: 1px solid rgba(255, 216, 77, 0.35);
    }

    .btn-ghost, .top-btn, .side-mini-btn {
      background: linear-gradient(180deg, #101b2b, #0a1320);
      color: #f3f7ff;
      border: 1px solid rgba(92, 117, 164, 0.24);
    }

    .btn-danger, .quick-btn.reject, .danger-bulk, .small-del {
      background: rgba(239, 68, 68, 0.12);
      color: #ffb8b8;
      border: 1px solid rgba(239, 68, 68, 0.24);
    }

    .btn-success, .quick-btn.approve {
      background: rgba(34, 197, 94, 0.12);
      color: #9ef2b4;
      border: 1px solid rgba(34, 197, 94, 0.24);
    }

    .btn-info, .quick-btn.review {
      background: rgba(59, 130, 246, 0.12);
      color: #9bc7ff;
      border: 1px solid rgba(59, 130, 246, 0.24);
    }

    .btn-warn, .quick-btn.delete, .trash-accent {
      background: rgba(245, 158, 11, 0.12);
      color: #ffd08a;
      border: 1px solid rgba(245, 158, 11, 0.24);
    }

    .search-panel, .bulk-panel, .feed-card, .right-card, .sidebar, .empty-state, .notif-bar {
      border-radius: 24px;
      background: linear-gradient(180deg, var(--panel), var(--panel-2));
      border: 1px solid rgba(94, 117, 163, 0.20);
      box-shadow: var(--shadow), inset 0 1px 0 rgba(255,255,255,0.03);
      backdrop-filter: blur(12px);
    }

    .search-panel, .bulk-panel, .right-card {
      padding: 18px;
      margin-bottom: 14px;
    }

    .search-row, .bulk-row {
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
      background: linear-gradient(180deg, #0b1628, #07111d);
      border: 1px solid rgba(96, 120, 168, 0.22);
      border-radius: 16px;
      padding: 12px 14px;
    }

    .search-input, .select, .side-input {
      background: linear-gradient(180deg, #0b1628, #07111d);
      border: 1px solid rgba(96, 120, 168, 0.22);
      outline: none;
      color: white;
      font-size: 14px;
      border-radius: 14px;
      padding: 10px 12px;
      min-height: 42px;
    }

    .search-input {
      flex: 1;
      background: transparent;
      border: none;
      padding: 0;
      min-height: auto;
    }

    .select option {
      color: black;
      background: white;
    }

    .feed-list {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .feed-card {
      padding: 18px;
      display: grid;
      grid-template-columns: 170px minmax(0, 1fr) 240px;
      gap: 18px;
      align-items: start;
      overflow: hidden;
      position: relative;
    }

    .feed-card::before {
      content: "";
      position: absolute;
      left: 0;
      top: 14px;
      bottom: 14px;
      width: 4px;
      border-radius: 999px;
      background: linear-gradient(180deg, #22d3ee, #3b82f6);
      opacity: 0.55;
    }

    .feed-card.risk-border-high::before { background: linear-gradient(180deg, #fb7185, #ef4444); }
    .feed-card.risk-border-mid::before { background: linear-gradient(180deg, #f59e0b, #f97316); }
    .feed-card.risk-border-short::before { background: linear-gradient(180deg, #facc15, #f59e0b); }
    .feed-card.risk-border-whitelist::before { background: linear-gradient(180deg, #22c55e, #10b981); }
    .feed-card.risk-border-invite::before { background: linear-gradient(180deg, #60a5fa, #2563eb); }

    .feed-left {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      min-width: 0;
      padding-left: 10px;
    }

    .feed-main {
      min-width: 0;
    }

    .feed-side {
      display: flex;
      flex-direction: column;
      gap: 10px;
      align-items: stretch;
      justify-content: flex-start;
    }

    .bulk-checkbox {
      width: 18px;
      height: 18px;
      accent-color: #facc15;
      margin-top: 4px;
    }

    .dot {
      width: 12px;
      height: 12px;
      border-radius: 999px;
      margin-top: 3px;
      box-shadow: 0 0 16px currentColor;
    }

    .dot-0 { color: #8b5cf6; background: #8b5cf6; }
    .dot-1 { color: #22d3ee; background: #22d3ee; }
    .dot-2 { color: #22c55e; background: #22c55e; }
    .dot-3 { color: #f97316; background: #f97316; }
    .dot-4 { color: #ec4899; background: #ec4899; }

    .time {
      font-size: 12px;
      color: #d6e2f8;
      font-weight: 700;
      line-height: 1.45;
    }

    .subtime {
      font-size: 11px;
      color: #7383a6;
    }

    .user-row {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }

    .user-name {
      font-weight: 800;
      font-size: 18px;
      letter-spacing: 0.1px;
    }

    .badge-lite, .meta-chip, .notif-pill {
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      border: 1px solid transparent;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .meta-chip {
      background: #0c1624;
      border-color: rgba(73,95,130,0.35);
      color: #bdd0ef;
    }

    .status-approved { background: rgba(34,197,94,0.12); color: #8df3ab; border-color: rgba(34,197,94,0.26); }
    .status-rejected { background: rgba(239,68,68,0.12); color: #ffb1b1; border-color: rgba(239,68,68,0.26); }
    .status-pending { background: rgba(250,204,21,0.12); color: #ffe48b; border-color: rgba(250,204,21,0.26); }
    .status-review { background: rgba(59,130,246,0.12); color: #9bc7ff; border-color: rgba(59,130,246,0.26); }

    .risk-normal { background: rgba(34,197,94,0.10); color: #86efac; border-color: rgba(34,197,94,0.20); }
    .risk-mid { background: rgba(249,115,22,0.10); color: #fdba74; border-color: rgba(249,115,22,0.20); }
    .risk-high { background: rgba(239,68,68,0.10); color: #fda4af; border-color: rgba(239,68,68,0.20); }
    .risk-short { background: rgba(250,204,21,0.10); color: #fde68a; border-color: rgba(250,204,21,0.20); }
    .risk-whitelist { background: rgba(34,197,94,0.10); color: #6ee7b7; border-color: rgba(34,197,94,0.20); }
    .risk-invite { background: rgba(59,130,246,0.10); color: #93c5fd; border-color: rgba(59,130,246,0.20); }

    .opened-badge {
      background: rgba(239,68,68,0.10);
      color: #ffb1b1;
      border-color: rgba(239,68,68,0.20);
    }

    .message-line {
      color: #dce8ff;
      font-size: 14px;
      line-height: 1.55;
      margin-bottom: 10px;
      word-break: break-word;
    }

    .link-line {
      min-width: 0;
      margin-bottom: 14px;
    }

    .link-line a {
      color: #7dd3fc;
      font-size: 15px;
      font-weight: 700;
      line-height: 1.6;
      word-break: break-word;
      overflow-wrap: anywhere;
    }

    .link-line a:hover {
      text-decoration: underline;
    }

    .quick-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }

    .quick-btn {
      padding: 8px 10px;
      font-size: 12px;
      border-radius: 12px;
      border: 1px solid transparent;
    }

    .side-top {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
    }

    .select-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }

    .right {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .right-title {
      font-size: 13px;
      color: #8ea2ca;
      margin-bottom: 12px;
      font-weight: 700;
    }

    .panel-buttons {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
    }

    details.compact-box {
      border-radius: 16px;
      background: rgba(7, 18, 35, 0.68);
      border: 1px solid rgba(94,117,163,0.18);
      overflow: hidden;
      margin-top: 10px;
    }

    details.compact-box summary {
      list-style: none;
      cursor: pointer;
      padding: 14px 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-weight: 800;
    }

    details.compact-box summary::-webkit-details-marker { display: none; }

    .compact-content {
      padding: 0 14px 14px 14px;
    }

    .list-item, .audit-item, .notif-item {
      background: #0b1421;
      border: 1px solid rgba(73,95,130,0.35);
      border-radius: 12px;
      padding: 10px;
      margin-top: 8px;
    }

    .list-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }

    .small-del {
      cursor: pointer;
      border-radius: 10px;
      padding: 8px 10px;
    }

    .notif-bar {
      padding: 14px 16px;
      margin-bottom: 14px;
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
    }

    .notif-box {
      border-radius: 16px;
      padding: 14px 16px;
      border: 1px solid rgba(94,117,163,0.18);
      min-height: 88px;
    }

    .notif-box.red { background: rgba(239,68,68,0.10); }
    .notif-box.green { background: rgba(34,197,94,0.10); }
    .notif-box.blue { background: rgba(59,130,246,0.10); }

    .notif-head {
      font-weight: 800;
      margin-bottom: 8px;
    }

    .notif-sub {
      color: #bfd1ef;
      font-size: 13px;
      line-height: 1.45;
    }

    .empty-state {
      padding: 42px 24px;
      text-align: center;
      border-radius: 28px;
      position: relative;
      overflow: hidden;
    }

    .empty-state::before {
      content: "";
      position: absolute;
      inset: 0;
      background:
        radial-gradient(circle at 50% 50%, rgba(59,130,246,0.12), transparent 26%),
        radial-gradient(circle at 20% 20%, rgba(250,204,21,0.08), transparent 16%),
        radial-gradient(circle at 80% 80%, rgba(34,211,238,0.08), transparent 18%);
      pointer-events: none;
    }

    .empty-icon {
      font-size: 70px;
      margin-bottom: 12px;
      opacity: 0.96;
    }

    .empty-title {
      font-size: 32px;
      font-weight: 800;
      margin-bottom: 10px;
    }

    .empty-sub {
      font-size: 18px;
      color: #c2d3ef;
      margin-bottom: 10px;
    }

    .empty-note {
      font-size: 14px;
      color: #90a4ca;
      margin-bottom: 18px;
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
      line-height: 1.45;
      word-break: break-word;
    }

    .bottom-row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 16px;
    }

    .muted {
      color: var(--muted);
    }

    @media (max-width: 1400px) {
      .feed-card {
        grid-template-columns: 160px minmax(0, 1fr) 220px;
      }
    }

    @media (max-width: 1250px) {
      .content-grid {
        grid-template-columns: 1fr;
      }
      .right {
        order: -1;
      }
    }

    @media (max-width: 1120px) {
      .feed-card {
        grid-template-columns: 1fr;
      }
      .feed-side {
        flex-direction: row;
        flex-wrap: wrap;
      }
      .notif-bar {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 820px) {
      .page-shell {
        display: block;
        padding: 10px;
      }
      .sidebar {
        width: 100%;
        height: auto;
        position: static;
        flex-direction: row;
        justify-content: center;
        margin-bottom: 10px;
      }
      .topbar {
        display: block;
      }
      .top-actions {
        margin-top: 14px;
        justify-content: flex-start;
      }
    }
  `;
}

app.get("/logo.png", (req, res) => {
  res.sendFile(path.join(__dirname, "logo.png"));
});

app.get("/login", (req, res) => {
  if (req.session && req.session.isAuthenticated) return res.redirect("/links");
  const error = req.query.error ? "Kullanıcı adı veya şifre yanlış." : "";

  res.send(`
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Giriş Yap</title>
        <style>
          ${baseLayoutStyles()}
          body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .card {
            width: 100%;
            max-width: 430px;
            border-radius: 28px;
            padding: 30px;
          }
          .logo-wrap {
            display: flex;
            justify-content: center;
            margin-bottom: 18px;
          }
          .logo {
            width: 92px;
            height: 92px;
            border-radius: 50%;
            object-fit: cover;
            background: #111;
            border: 1px solid rgba(255,255,255,0.08);
            box-shadow: 0 0 24px rgba(250,204,21,0.18);
          }
          .title {
            font-size: 30px;
            font-weight: 800;
            text-align: center;
            margin-bottom: 8px;
          }
          .sub {
            color: #b7c5e0;
            text-align: center;
            margin-bottom: 22px;
          }
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
          .error {
            background: rgba(239,68,68,0.12);
            border: 1px solid rgba(239,68,68,0.24);
            color: #ffb4b4;
            padding: 12px;
            border-radius: 12px;
            margin-bottom: 14px;
          }
        </style>
      </head>
      <body>
        <form class="card glass" method="POST" action="/login">
          <div class="logo-wrap">
            <img class="logo" src="/logo.png" alt="Logo" />
          </div>
          <div class="title">HasanD Link Detector</div>
          <div class="sub">Panele girmek için giriş yap.</div>
          ${error ? `<div class="error">${error}</div>` : ""}
          <input class="input" type="text" name="username" placeholder="Kullanıcı adı" required />
          <input class="input" type="password" name="password" placeholder="Şifre" required />
          <button class="btn btn-primary" type="submit" style="width:100%;">Giriş Yap</button>
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
  req.session.destroy(() => res.redirect("/login"));
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
    if (!code) return res.status(400).send("Code yok");
    if (!pkceVerifier) return res.status(400).send("PKCE verifier yok");

    const redirectUri = `${APP_URL}/callback`;

    const tokenRes = await fetch("https://id.kick.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: KICK_CLIENT_ID,
        client_secret: KICK_CLIENT_SECRET,
        redirect_uri: redirectUri,
        code_verifier: pkceVerifier,
        code,
      }),
    });

    const tokenData = await tokenRes.json();
    await ensureTables();
    await pool.query(`INSERT INTO oauth_tokens (raw_data) VALUES ($1)`, [JSON.stringify(tokenData)]);
    await logAudit("KICK_CALLBACK", null, "token kaydedildi");
    res.send("Kick yetkilendirme tamamlandı. Token kaydedildi.");
  } catch (error) {
    console.error("CALLBACK ERROR:", error);
    res.status(500).send("Callback hatası: " + error.message);
  }
});

app.get("/find/broadcaster", requireAuth, async (req, res) => {
  try {
    if (!KICK_CHANNEL_SLUG) return res.status(400).send("KICK_CHANNEL_SLUG env değişkeni yok");
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
    await ensureTables();
    const tokenResult = await pool.query(
      `SELECT id, raw_data, created_at FROM oauth_tokens ORDER BY id DESC LIMIT 1`
    );

    if (!tokenResult.rows.length) {
      return res.status(400).send("Kayıtlı user token yok. Önce /auth/kick ile giriş yap.");
    }

    const tokenRow = tokenResult.rows[0];
    const tokenData = JSON.parse(tokenRow.raw_data || "{}");
    const accessToken = tokenData.access_token;
    if (!accessToken) return res.status(400).send("Access token bulunamadı.");

    const payload = {
      method: "webhook",
      broadcaster_user_id: 93350154,
      events: [{ name: "chat.message.sent", version: 1 }],
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
      "TOKEN_CREATED_AT=" + tokenRow.created_at +
      " | STATUS=" + subRes.status +
      " | BODY=" + bodyText +
      " | PAYLOAD=" + JSON.stringify(payload)
    );
  } catch (error) {
    console.error("SUBSCRIBE CHAT ERROR:", error);
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

    const senderUsername =
      payload?.sender?.username ||
      payload?.user?.username ||
      payload?.message?.sender?.username ||
      payload?.message?.user?.username ||
      payload?.data?.sender?.username ||
      payload?.data?.user?.username ||
      payload?.data?.message?.sender?.username ||
      payload?.data?.message?.user?.username ||
      "";

    const links = extractLinks(possibleText);
    if (!links.length) {
      return res.status(200).json({ success: true, skipped: true, reason: "no_link_in_message" });
    }

    await ensureTables();

    const blockedUsernames = await getBlockedUsernames();
    if (blockedUsernames.includes(String(senderUsername).toLowerCase())) {
      return res.status(200).json({
        success: true,
        skipped: true,
        reason: "blocked_username",
        username: senderUsername,
      });
    }

    if (BLOCKED_BOT_USERNAMES.includes(String(senderUsername).toLowerCase())) {
      return res.status(200).json({
        success: true,
        skipped: true,
        reason: "blocked_bot_link",
        username: senderUsername,
      });
    }

    const firstDomain = links.length ? getDomain(links[0]) : "";
    const whitelist = await getWhitelistDomains();
    const blacklist = await getBlacklistDomains();
    const riskLevel = detectRisk(links, possibleText, whitelist, blacklist);

    await pool.query(
      `
      INSERT INTO links (
        sender_username,
        message_text,
        extracted_links,
        raw_data,
        link_domain,
        risk_level,
        review_status,
        is_deleted,
        is_opened,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, 'Beklemede', FALSE, FALSE, CURRENT_TIMESTAMP)
      `,
      [
        senderUsername || null,
        possibleText || null,
        JSON.stringify(links),
        JSON.stringify(payload),
        firstDomain || null,
        riskLevel,
      ]
    );

    await logAudit("WEBHOOK_INSERT", null, `user=${senderUsername || ""} domain=${firstDomain || ""} risk=${riskLevel}`);

    res.status(200).json({ success: true, found_links: links, username: senderUsername });
  } catch (error) {
    console.error("WEBHOOK ERROR:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/links/open/:id", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const id = Number(req.params.id);

    const result = await pool.query(
      `SELECT id, extracted_links FROM links WHERE id = $1 LIMIT 1`,
      [id]
    );

    if (!result.rows.length) return res.status(404).send("Kayıt bulunamadı");

    let parsedLinks = [];
    try {
      parsedLinks = JSON.parse(result.rows[0].extracted_links || "[]");
    } catch {
      parsedLinks = [];
    }

    const firstLink = parsedLinks[0];
    if (!firstLink) return res.status(404).send("Açılacak link bulunamadı");

    await pool.query(
      `UPDATE links SET is_opened = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [id]
    );
    await logAudit("LINK_OPENED", id, firstLink);

    return res.redirect(firstLink);
  } catch (error) {
    console.error("LINK OPEN ERROR:", error);
    res.status(500).send("Link açma hatası: " + error.message);
  }
});

app.get("/links/live", requireAuth, async (req, res) => {
  try {
    await ensureTables();
    const lastId = Number(req.query.last_id || 0);

    const result = await pool.query(
      `
      SELECT id, sender_username, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, is_deleted, is_opened, created_at, updated_at
      FROM links
      WHERE id > $1 AND COALESCE(is_deleted, FALSE) = FALSE
      ORDER BY id ASC
      LIMIT 20
      `,
      [lastId]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/links/status/:id", requireAuth, async (req, res) => {
  try {
    const allowed = ["Onaylandı", "Reddedildi", "Beklemede", "İnceleniyor"];
    const status = allowed.includes(req.body.status) ? req.body.status : "Beklemede";
    await pool.query(
      `UPDATE links SET review_status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [status, req.params.id]
    );
    await logAudit("STATUS_UPDATE", Number(req.params.id), `status=${status}`);
    return res.redirect("/links" + (req.body.deleted === "1" ? "?deleted=1" : ""));
  } catch (error) {
    res.status(500).send("Durum güncelleme hatası: " + error.message);
  }
});

app.post("/links/quick/:id/:action", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const action = String(req.params.action || "");
    const deleted = req.body.deleted === "1";

    if (action === "approve") {
      await pool.query(`UPDATE links SET review_status = 'Onaylandı', updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [id]);
      await logAudit("QUICK_APPROVE", id, "kart hızlı onay");
    } else if (action === "review") {
      await pool.query(`UPDATE links SET review_status = 'İnceleniyor', updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [id]);
      await logAudit("QUICK_REVIEW", id, "kart hızlı incele");
    } else if (action === "reject") {
      await pool.query(`UPDATE links SET review_status = 'Reddedildi', updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [id]);
      await logAudit("QUICK_REJECT", id, "kart hızlı red");
    } else if (action === "delete") {
      await pool.query(`UPDATE links SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [id]);
      await logAudit("QUICK_DELETE", id, "kart hızlı çöp");
    } else if (action === "restore") {
      await pool.query(`UPDATE links SET is_deleted = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [id]);
      await logAudit("QUICK_RESTORE", id, "kart hızlı geri al");
    } else if (action === "destroy") {
      await pool.query(`DELETE FROM links WHERE id = $1`, [id]);
      await logAudit("QUICK_DESTROY", id, "kart hızlı kalıcı sil");
    }

    return res.redirect("/links" + (deleted ? "?deleted=1" : ""));
  } catch (error) {
    res.status(500).send("Hızlı aksiyon hatası: " + error.message);
  }
});

app.post("/links/delete/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE links SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [req.params.id]
    );
    await logAudit("SOFT_DELETE", Number(req.params.id), "çöpe taşındı");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Silme hatası: " + error.message);
  }
});

app.post("/links/restore/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE links SET is_deleted = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [req.params.id]
    );
    await logAudit("RESTORE", Number(req.params.id), "geri alındı");
    res.redirect("/links?deleted=1");
  } catch (error) {
    res.status(500).send("Geri alma hatası: " + error.message);
  }
});

app.post("/links/destroy/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM links WHERE id = $1`, [req.params.id]);
    await logAudit("DELETE_FOREVER", Number(req.params.id), "kalıcı silindi");
    res.redirect("/links?deleted=1");
  } catch (error) {
    res.status(500).send("Kalıcı silme hatası: " + error.message);
  }
});

app.post("/trash/empty", requireAuth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM links WHERE COALESCE(is_deleted, FALSE) = TRUE`);
    await logAudit("TRASH_EMPTY", null, "çöp tamamen boşaltıldı");
    res.redirect("/links?deleted=1");
  } catch (error) {
    res.status(500).send("Çöp boşaltma hatası: " + error.message);
  }
});

app.post("/links/bulk-action", requireAuth, async (req, res) => {
  try {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : req.body.ids ? [req.body.ids] : [];
    if (!ids.length) return res.redirect("/links" + (req.body.deleted === "1" ? "?deleted=1" : ""));

    const numericIds = ids.map((id) => Number(id)).filter((id) => Number.isFinite(id));
    if (!numericIds.length) return res.redirect("/links" + (req.body.deleted === "1" ? "?deleted=1" : ""));

    const action = req.body.action;

    if (action === "approve") {
      await pool.query(`UPDATE links SET review_status = 'Onaylandı', updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`, [numericIds]);
      await logAudit("BULK_APPROVE", null, `ids=${numericIds.join(",")}`);
    } else if (action === "review") {
      await pool.query(`UPDATE links SET review_status = 'İnceleniyor', updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`, [numericIds]);
      await logAudit("BULK_REVIEW", null, `ids=${numericIds.join(",")}`);
    } else if (action === "reject") {
      await pool.query(`UPDATE links SET review_status = 'Reddedildi', updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`, [numericIds]);
      await logAudit("BULK_REJECT", null, `ids=${numericIds.join(",")}`);
    } else if (action === "delete") {
      await pool.query(`UPDATE links SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`, [numericIds]);
      await logAudit("BULK_SOFT_DELETE", null, `ids=${numericIds.join(",")}`);
    } else if (action === "restore") {
      await pool.query(`UPDATE links SET is_deleted = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = ANY($1::int[])`, [numericIds]);
      await logAudit("BULK_RESTORE", null, `ids=${numericIds.join(",")}`);
    } else if (action === "destroy") {
      await pool.query(`DELETE FROM links WHERE id = ANY($1::int[])`, [numericIds]);
      await logAudit("BULK_DESTROY", null, `ids=${numericIds.join(",")}`);
    }

    return res.redirect("/links" + (req.body.deleted === "1" ? "?deleted=1" : ""));
  } catch (error) {
    res.status(500).send("Toplu işlem hatası: " + error.message);
  }
});

app.post("/domains/whitelist", requireAuth, async (req, res) => {
  try {
    const domain = String(req.body.domain || "").trim().toLowerCase().replace(/^www\./, "");
    if (!domain) return res.redirect("/links");
    await pool.query(`INSERT INTO whitelist_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING`, [domain]);
    await logAudit("WHITELIST_ADD", null, domain);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Whitelist ekleme hatası: " + error.message);
  }
});

app.post("/domains/blacklist", requireAuth, async (req, res) => {
  try {
    const domain = String(req.body.domain || "").trim().toLowerCase().replace(/^www\./, "");
    if (!domain) return res.redirect("/links");
    await pool.query(`INSERT INTO blacklist_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING`, [domain]);
    await logAudit("BLACKLIST_ADD", null, domain);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Blacklist ekleme hatası: " + error.message);
  }
});

app.post("/domains/whitelist/delete/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM whitelist_domains WHERE id = $1`, [req.params.id]);
    await logAudit("WHITELIST_DELETE", Number(req.params.id), "silindi");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Whitelist silme hatası: " + error.message);
  }
});

app.post("/domains/blacklist/delete/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM blacklist_domains WHERE id = $1`, [req.params.id]);
    await logAudit("BLACKLIST_DELETE", Number(req.params.id), "silindi");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Blacklist silme hatası: " + error.message);
  }
});

app.post("/users/block", requireAuth, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    if (!username) return res.redirect("/links");
    await pool.query(`INSERT INTO blocked_usernames (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, [username]);
    await logAudit("BLOCK_USERNAME_ADD", null, username);
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Kullanıcı engelleme hatası: " + error.message);
  }
});

app.post("/users/block/delete/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM blocked_usernames WHERE id = $1`, [req.params.id]);
    await logAudit("BLOCK_USERNAME_DELETE", Number(req.params.id), "silindi");
    res.redirect("/links");
  } catch (error) {
    res.status(500).send("Engelli kullanıcı silme hatası: " + error.message);
  }
});

app.get("/links/raw/:id", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, sender_username, raw_data, created_at, updated_at FROM links WHERE id = $1 LIMIT 1`,
      [req.params.id]
    );

    if (!result.rows.length) return res.status(404).send("Kayıt bulunamadı");

    const row = result.rows[0];

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>Ham Veri #${row.id}</title>
          <style>
            ${baseLayoutStyles()}
            body { padding: 24px; }
            .wrap { max-width: 1000px; margin: 0 auto; }
            .card { border-radius: 20px; padding: 18px; margin-top: 18px; }
            pre {
              white-space: pre-wrap;
              word-break: break-word;
              background: #11151b;
              border: 1px solid #232935;
              border-radius: 10px;
              padding: 14px;
              line-height: 1.6;
            }
          </style>
        </head>
        <body>
          <div class="wrap">
            <a class="btn btn-primary" href="/links">Panele Dön</a>
            <div class="card glass">
              <h2>Kayıt #${row.id}</h2>
              <p>Kullanıcı: ${escapeHtml(row.sender_username || "-")}</p>
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

function buildLinksWhere(reqQuery) {
  const search = typeof reqQuery.search === "string" ? reqQuery.search.trim() : "";
  const statusFilter = typeof reqQuery.status === "string" ? reqQuery.status.trim() : "";
  const riskFilter = typeof reqQuery.risk === "string" ? reqQuery.risk.trim() : "";
  const domainFilter = typeof reqQuery.domain === "string" ? reqQuery.domain.trim().toLowerCase() : "";
  const deletedFilter = reqQuery.deleted === "1";
  const perPage = Math.min(Math.max(Number(reqQuery.per_page || 20), 5), 100);
  const page = Math.max(Number(reqQuery.page || 1), 1);
  const sort = typeof reqQuery.sort === "string" ? reqQuery.sort.trim() : "newest";

  const whereParts = [];
  const values = [];
  let idx = 1;

  if (search) {
    whereParts.push(`
      (
        CAST(id AS TEXT) ILIKE $${idx}
        OR COALESCE(sender_username, '') ILIKE $${idx}
        OR COALESCE(message_text, '') ILIKE $${idx}
        OR COALESCE(extracted_links, '') ILIKE $${idx}
        OR COALESCE(raw_data, '') ILIKE $${idx}
        OR COALESCE(link_domain, '') ILIKE $${idx}
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

  whereParts.push(`COALESCE(is_deleted, FALSE) = $${idx}`);
  values.push(deletedFilter);

  const whereSql = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

  let orderSql = `ORDER BY id DESC`;
  if (sort === "oldest") orderSql = `ORDER BY id ASC`;
  if (sort === "domain") orderSql = `ORDER BY COALESCE(link_domain, '') ASC, id DESC`;
  if (sort === "status") orderSql = `ORDER BY COALESCE(review_status, 'Beklemede') ASC, id DESC`;

  return {
    search,
    statusFilter,
    riskFilter,
    domainFilter,
    deletedFilter,
    perPage,
    page,
    sort,
    whereSql,
    values,
    nextIdx: idx,
    orderSql,
  };
}

app.get("/links/json", requireAuth, async (req, res) => {
  try {
    const built = buildLinksWhere(req.query);

    const result = await pool.query(
      `
      SELECT id, sender_username, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, is_deleted, is_opened, created_at, updated_at
      FROM links
      ${built.whereSql}
      ${built.orderSql}
      LIMIT 1000
      `,
      built.values
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).send("Links json hatası: " + error.message);
  }
});

app.get("/links/export/csv", requireAuth, async (req, res) => {
  try {
    const built = buildLinksWhere(req.query);

    const result = await pool.query(
      `
      SELECT id, sender_username, message_text, extracted_links, link_domain, risk_level, review_status, is_deleted, is_opened, created_at, updated_at
      FROM links
      ${built.whereSql}
      ${built.orderSql}
      LIMIT 5000
      `,
      built.values
    );

    const header = [
      "id",
      "sender_username",
      "message_text",
      "extracted_links",
      "link_domain",
      "risk_level",
      "review_status",
      "is_deleted",
      "is_opened",
      "created_at",
      "updated_at",
    ].join(",");

    const rows = result.rows.map((row) =>
      [
        csvEscape(row.id),
        csvEscape(row.sender_username),
        csvEscape(row.message_text),
        csvEscape(row.extracted_links),
        csvEscape(row.link_domain),
        csvEscape(row.risk_level),
        csvEscape(row.review_status),
        csvEscape(row.is_deleted),
        csvEscape(row.is_opened),
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

app.get("/audit", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, action_type, target_id, details, created_at
      FROM audit_logs
      ORDER BY id DESC
      LIMIT 100
    `);

    const rowsHtml = result.rows
      .map(
        (row) => `
          <tr>
            <td>${row.id}</td>
            <td>${escapeHtml(row.action_type)}</td>
            <td>${row.target_id ?? "-"}</td>
            <td>${escapeHtml(row.details || "")}</td>
            <td>${new Date(row.created_at).toLocaleString("tr-TR")}</td>
          </tr>
        `
      )
      .join("");

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>Audit Log</title>
          <style>
            ${baseLayoutStyles()}
            body { padding: 24px; }
            .wrap { max-width: 1300px; margin: 0 auto; }
            .card { border-radius: 24px; padding: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td {
              border-bottom: 1px solid rgba(102,126,173,0.16);
              padding: 12px;
              text-align: left;
              vertical-align: top;
              font-size: 14px;
            }
            th { color: #ffe37a; }
          </style>
        </head>
        <body>
          <div class="wrap">
            <a class="btn btn-primary" href="/links">Panele Dön</a>
            <div class="card glass" style="margin-top:18px;">
              <h2>Audit Log</h2>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>İşlem</th>
                    <th>Target</th>
                    <th>Detay</th>
                    <th>Tarih</th>
                  </tr>
                </thead>
                <tbody>
                  ${rowsHtml || `<tr><td colspan="5">Kayıt yok.</td></tr>`}
                </tbody>
              </table>
            </div>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send("Audit sayfası hatası: " + error.message);
  }
});

app.get("/links", requireAuth, async (req, res) => {
  try {
    await ensureTables();

    const built = buildLinksWhere(req.query);
    const countResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links ${built.whereSql}`, built.values);
    const totalFiltered = countResult.rows[0]?.total || 0;
    const totalPages = Math.max(Math.ceil(totalFiltered / built.perPage), 1);
    const safePage = Math.min(built.page, totalPages);
    const safeOffset = (safePage - 1) * built.perPage;

    const result = await pool.query(
      `
      SELECT id, sender_username, message_text, extracted_links, raw_data, link_domain, risk_level, review_status, is_deleted, is_opened, created_at, updated_at
      FROM links
      ${built.whereSql}
      ${built.orderSql}
      LIMIT $${built.nextIdx + 1} OFFSET $${built.nextIdx + 2}
      `,
      [...built.values, built.perPage, safeOffset]
    );

    const totalCountResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links WHERE COALESCE(is_deleted, FALSE) = FALSE`);
    const deletedCountResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links WHERE COALESCE(is_deleted, FALSE) = TRUE`);
    const todayCountResult = await pool.query(`SELECT COUNT(*)::int AS total FROM links WHERE created_at::date = CURRENT_DATE AND COALESCE(is_deleted, FALSE) = FALSE`);
    const suspiciousCountResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND COALESCE(risk_level, 'Normal') IN ('Şüpheli', 'Yüksek Risk', 'Davet Linki', 'Kısa Link')
    `);
    const approvedCountResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND COALESCE(review_status, 'Beklemede') = 'Onaylandı'
    `);

    const shortLinkCountResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND COALESCE(risk_level, 'Normal') = 'Kısa Link'
    `);

    const recentAuditResult = await pool.query(`
      SELECT id, action_type, details, created_at
      FROM audit_logs
      ORDER BY id DESC
      LIMIT 8
    `);

    const recentNotificationsResult = await pool.query(`
      SELECT id, action_type, details, created_at
      FROM audit_logs
      WHERE action_type IN ('WEBHOOK_INSERT', 'LINK_OPENED', 'STATUS_UPDATE', 'SOFT_DELETE', 'TRASH_EMPTY', 'DELETE_FOREVER', 'QUICK_DELETE', 'BULK_SOFT_DELETE')
      ORDER BY id DESC
      LIMIT 6
    `);

    const latestHighRiskResult = await pool.query(`
      SELECT id, link_domain, risk_level, created_at
      FROM links
      WHERE COALESCE(is_deleted, FALSE) = FALSE
      AND COALESCE(risk_level, 'Normal') IN ('Yüksek Risk', 'Şüpheli', 'Kısa Link')
      ORDER BY id DESC
      LIMIT 1
    `);

    const whitelistResult = await pool.query(`SELECT id, domain FROM whitelist_domains ORDER BY domain ASC LIMIT 20`);
    const blacklistResult = await pool.query(`SELECT id, domain FROM blacklist_domains ORDER BY domain ASC LIMIT 20`);
    const blockedUsersResult = await pool.query(`SELECT id, username FROM blocked_usernames ORDER BY username ASC LIMIT 20`);

    const rows = result.rows;
    const totalCount = totalCountResult.rows[0]?.total || 0;
    const deletedCount = deletedCountResult.rows[0]?.total || 0;
    const todayCount = todayCountResult.rows[0]?.total || 0;
    const suspiciousCount = suspiciousCountResult.rows[0]?.total || 0;
    const approvedCount = approvedCountResult.rows[0]?.total || 0;
    const shortLinkCount = shortLinkCountResult.rows[0]?.total || 0;

    const currentQuery = {
      search: built.search,
      status: built.statusFilter,
      risk: built.riskFilter,
      domain: built.domainFilter,
      deleted: built.deletedFilter ? "1" : "",
      per_page: built.perPage,
      sort: built.sort,
    };

    const whitelistHtml = whitelistResult.rows
      .map(
        (row) => `
          <div class="list-item">
            <span>${escapeHtml(row.domain)}</span>
            <form method="POST" action="/domains/whitelist/delete/${row.id}">
              <button type="submit" class="small-del">Sil</button>
            </form>
          </div>
        `
      )
      .join("");

    const blacklistHtml = blacklistResult.rows
      .map(
        (row) => `
          <div class="list-item">
            <span>${escapeHtml(row.domain)}</span>
            <form method="POST" action="/domains/blacklist/delete/${row.id}">
              <button type="submit" class="small-del">Sil</button>
            </form>
          </div>
        `
      )
      .join("");

    const blockedUsersHtml = blockedUsersResult.rows
      .map(
        (row) => `
          <div class="list-item">
            <span>${escapeHtml(row.username)}</span>
            <form method="POST" action="/users/block/delete/${row.id}">
              <button type="submit" class="small-del">Sil</button>
            </form>
          </div>
        `
      )
      .join("");

    const auditHtml = recentAuditResult.rows
      .map(
        (row) => `
          <div class="audit-item">
            <div class="audit-top">
              <strong>${escapeHtml(row.action_type)}</strong>
              <span>${new Date(row.created_at).toLocaleString("tr-TR")}</span>
            </div>
            <div class="audit-bottom">${escapeHtml(row.details || "")}</div>
          </div>
        `
      )
      .join("");

    const notifHtml = recentNotificationsResult.rows
      .map(
        (row) => `
          <div class="notif-item">
            <div class="audit-top">
              <strong>${escapeHtml(row.action_type)}</strong>
              <span>${new Date(row.created_at).toLocaleString("tr-TR")}</span>
            </div>
            <div class="audit-bottom">${escapeHtml(row.details || "")}</div>
          </div>
        `
      )
      .join("");

    const latestRiskText = latestHighRiskResult.rows.length
      ? `${escapeHtml(latestHighRiskResult.rows[0].link_domain || "-")} • ${escapeHtml(latestHighRiskResult.rows[0].risk_level || "-")}`
      : "Son risk kaydı yok";

    const cards = rows
      .map((row, index) => {
        let parsedLinks = [];
        try {
          parsedLinks = JSON.parse(row.extracted_links || "[]");
        } catch {
          parsedLinks = [];
        }

        const firstLink = parsedLinks[0] || "";
        const timeText = new Date(row.created_at).toLocaleString("tr-TR");
        const senderText = row.sender_username || "-";
        const domainText = row.link_domain || (firstLink ? getDomain(firstLink) : "-");
        const reviewStatus = row.review_status || "Beklemede";
        const riskLevel = row.risk_level || "Normal";
        const statusClass = statusColorClass(reviewStatus);
        const riskClass = riskColorClass(riskLevel);
        const openedBadge = row.is_opened
          ? `<div class="badge-lite opened-badge">Açıldı</div>`
          : `<div class="badge-lite meta-chip" style="color:#94a3b8;">Açılmadı</div>`;

        let borderClass = "risk-border-normal";
        if (riskLevel === "Yüksek Risk") borderClass = "risk-border-high";
        else if (riskLevel === "Şüpheli") borderClass = "risk-border-mid";
        else if (riskLevel === "Kısa Link") borderClass = "risk-border-short";
        else if (riskLevel === "Whitelist") borderClass = "risk-border-whitelist";
        else if (riskLevel === "Davet Linki") borderClass = "risk-border-invite";

        const quickActions = built.deletedFilter
          ? `
            <div class="quick-row">
              <form method="POST" action="/links/quick/${row.id}/restore">
                <input type="hidden" name="deleted" value="1" />
                <button type="submit" class="quick-btn primary">Geri Al</button>
              </form>
              <form method="POST" action="/links/quick/${row.id}/destroy" onsubmit="return confirm('Bu kaydı kalıcı olarak silmek istiyor musun?')">
                <input type="hidden" name="deleted" value="1" />
                <button type="submit" class="quick-btn reject">Kalıcı Sil</button>
              </form>
            </div>
          `
          : `
            <div class="quick-row">
              <form method="POST" action="/links/quick/${row.id}/approve">
                <button type="submit" class="quick-btn approve">Onayla</button>
              </form>
              <form method="POST" action="/links/quick/${row.id}/review">
                <button type="submit" class="quick-btn review">İncele</button>
              </form>
              <form method="POST" action="/links/quick/${row.id}/reject">
                <button type="submit" class="quick-btn reject">Reddet</button>
              </form>
              <form method="POST" action="/links/quick/${row.id}/delete" onsubmit="return confirm('Bu kaydı çöpe taşımak istiyor musun?')">
                <button type="submit" class="quick-btn delete">Çöpe Taşı</button>
              </form>
            </div>
          `;

        const sideActions = built.deletedFilter
          ? `
            <div class="feed-side">
              <div class="badge-lite ${statusClass}">${escapeHtml(reviewStatus)}</div>
              ${openedBadge}
              <form method="POST" action="/links/quick/${row.id}/restore">
                <input type="hidden" name="deleted" value="1" />
                <button type="submit" class="side-mini-btn">Geri Al</button>
              </form>
              <form method="POST" action="/links/quick/${row.id}/destroy" onsubmit="return confirm('Bu kaydı kalıcı olarak silmek istiyor musun?')">
                <input type="hidden" name="deleted" value="1" />
                <button type="submit" class="side-mini-btn btn-danger">Kalıcı Sil</button>
              </form>
            </div>
          `
          : `
            <div class="feed-side">
              <div class="badge-lite ${statusClass}">${escapeHtml(reviewStatus)}</div>
              ${openedBadge}
              <div class="select-row">
                <form method="POST" action="/links/status/${row.id}" class="inline-form">
                  <input type="hidden" name="deleted" value="0" />
                  <select name="status" class="select">
                    <option ${reviewStatus === "Beklemede" ? "selected" : ""}>Beklemede</option>
                    <option ${reviewStatus === "İnceleniyor" ? "selected" : ""}>İnceleniyor</option>
                    <option ${reviewStatus === "Onaylandı" ? "selected" : ""}>Onaylandı</option>
                    <option ${reviewStatus === "Reddedildi" ? "selected" : ""}>Reddedildi</option>
                  </select>
                  <button type="submit" class="mini-btn">Kaydet</button>
                </form>
              </div>
            </div>
          `;

        return `
          <div class="feed-card ${borderClass}">
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
                <div class="user-name">${escapeHtml(senderText)}</div>
                <div class="badge-lite ${riskClass}">${escapeHtml(riskLevel)}</div>
                <div class="meta-chip">${escapeHtml(domainText || "-")}</div>
              </div>

              <div class="message-line">${escapeHtml(row.message_text || "Mesaj yok")}</div>

              <div class="link-line">
                ${
                  firstLink
                    ? `<a href="/links/open/${row.id}" target="_blank">${escapeHtml(firstLink)}</a>`
                    : `<span class="muted">Link bulunamadı</span>`
                }
              </div>

              ${quickActions}
            </div>

            ${sideActions}
          </div>
        `;
      })
      .join("");

    const bulkButtons = built.deletedFilter
      ? `
        <button class="quick-btn primary" type="submit" name="action" value="restore">Seçilileri Geri Al</button>
        <button class="danger-bulk" type="submit" name="action" value="destroy">Seçilileri Kalıcı Sil</button>
        <button class="danger-bulk" type="submit" formaction="/trash/empty" formmethod="POST" onclick="return confirm('Çöpü tamamen boşaltmak istiyor musun?')">Çöpü Tamamen Boşalt</button>
      `
      : `
        <button class="quick-btn approve" type="submit" name="action" value="approve">Seçilileri Onayla</button>
        <button class="quick-btn review" type="submit" name="action" value="review">Seçilileri İncele</button>
        <button class="quick-btn reject" type="submit" name="action" value="reject">Seçilileri Reddet</button>
        <button class="quick-btn delete" type="submit" name="action" value="delete">Seçilileri Çöpe Taşı</button>
      `;

    const emptyStateHtml = `
      <div class="empty-state">
        <div class="empty-icon">👻</div>
        <div class="empty-title">Kayıt Bulunamadı</div>
        <div class="empty-sub">Bu filtreye uyan kayıt yok.</div>
        <div class="empty-note">Yeni link geldiğinde burada görünecek.</div>
        <a class="btn btn-ghost" href="/links">Filtreleri Temizle</a>
      </div>
    `;

    const notifBarHtml = `
      <div class="notif-bar">
        <div class="notif-box red">
          <div class="notif-head">Risk Özeti</div>
          <div class="notif-sub">${latestRiskText}</div>
        </div>
        <div class="notif-box green">
          <div class="notif-head">Sistem Aktif</div>
          <div class="notif-sub">Webhook bağlantısı çalışıyor. Yeni linkler panele otomatik eklenir.</div>
        </div>
        <div class="notif-box blue">
          <div class="notif-head">Kısa Link Tespiti</div>
          <div class="notif-sub">Toplam kısa link kaydı: <strong>${shortLinkCount}</strong></div>
        </div>
      </div>
    `;

    res.send(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>HasanD Link Detector</title>
          <style>${baseLayoutStyles()}</style>
        </head>
        <body>
          <div class="page-shell">
            <div class="sidebar glass">
              <a href="/links"><img class="side-logo" src="/logo.png" alt="Logo" /></a>
              <a class="nav-btn active" href="/links">≡</a>
              <a class="nav-btn" href="/links/json${buildQuery(currentQuery)}">J</a>
              <a class="nav-btn" href="/links/export/csv${buildQuery(currentQuery)}">C</a>
              <a class="nav-btn" href="/audit">A</a>
              <a class="nav-btn" href="/logout">↦</a>
            </div>

            <div class="content-grid">
              <div class="main">
                <div class="topbar glass">
                  <div>
                    <div class="brand-title">HasanD Link Detector</div>
                    <div class="brand-sub">Gerçek Zamanlı Link Paneli • 10 sn canlı kontrol aktif</div>
                  </div>

                  <div class="top-actions">
                    <div class="stat-card">
                      <div class="stat-label">Toplam Aktif</div>
                      <div class="stat-value">${totalCount}</div>
                      <div class="stat-sub">canlı</div>
                    </div>
                    <div class="stat-card">
                      <div class="stat-label">Bugün</div>
                      <div class="stat-value">${todayCount}</div>
                      <div class="stat-sub">günlük</div>
                    </div>
                    <div class="stat-card">
                      <div class="stat-label">Şüpheli</div>
                      <div class="stat-value">${suspiciousCount}</div>
                      <div class="stat-sub">izle</div>
                    </div>
                    <div class="stat-card">
                      <div class="stat-label">Onaylı</div>
                      <div class="stat-value">${approvedCount}</div>
                      <div class="stat-sub">temiz</div>
                    </div>
                    <a class="top-btn btn-primary" href="/health">Bağlı</a>
                    <a class="top-btn btn-ghost" href="/links${buildQuery(currentQuery)}">Yenile</a>
                    <a class="top-btn btn-ghost" href="/logout">Çıkış</a>
                  </div>
                </div>

                <div class="search-panel glass">
                  <form class="search-row" method="GET" action="/links">
                    <div class="search-box">
                      <span>⌕</span>
                      <input class="search-input" type="text" name="search" placeholder="Link, mesaj, kullanıcı adı veya domain ara..." value="${escapeHtml(built.search)}" />
                    </div>

                    <input class="side-input" type="text" name="domain" placeholder="domain filtrele" value="${escapeHtml(built.domainFilter)}" />

                    <select class="select" name="status">
                      <option value="">Tüm Durumlar</option>
                      <option value="Beklemede" ${built.statusFilter === "Beklemede" ? "selected" : ""}>Beklemede</option>
                      <option value="İnceleniyor" ${built.statusFilter === "İnceleniyor" ? "selected" : ""}>İnceleniyor</option>
                      <option value="Onaylandı" ${built.statusFilter === "Onaylandı" ? "selected" : ""}>Onaylandı</option>
                      <option value="Reddedildi" ${built.statusFilter === "Reddedildi" ? "selected" : ""}>Reddedildi</option>
                    </select>

                    <select class="select" name="risk">
                      <option value="">Tüm Riskler</option>
                      <option value="Normal" ${built.riskFilter === "Normal" ? "selected" : ""}>Normal</option>
                      <option value="Whitelist" ${built.riskFilter === "Whitelist" ? "selected" : ""}>Whitelist</option>
                      <option value="Şüpheli" ${built.riskFilter === "Şüpheli" ? "selected" : ""}>Şüpheli</option>
                      <option value="Kısa Link" ${built.riskFilter === "Kısa Link" ? "selected" : ""}>Kısa Link</option>
                      <option value="Davet Linki" ${built.riskFilter === "Davet Linki" ? "selected" : ""}>Davet Linki</option>
                      <option value="Yüksek Risk" ${built.riskFilter === "Yüksek Risk" ? "selected" : ""}>Yüksek Risk</option>
                    </select>

                    <select class="select" name="per_page">
                      <option value="20" ${built.perPage === 20 ? "selected" : ""}>20 kayıt</option>
                      <option value="50" ${built.perPage === 50 ? "selected" : ""}>50 kayıt</option>
                      <option value="100" ${built.perPage === 100 ? "selected" : ""}>100 kayıt</option>
                    </select>

                    <select class="select" name="sort">
                      <option value="newest" ${built.sort === "newest" ? "selected" : ""}>En yeni</option>
                      <option value="oldest" ${built.sort === "oldest" ? "selected" : ""}>En eski</option>
                      <option value="domain" ${built.sort === "domain" ? "selected" : ""}>Domain</option>
                      <option value="status" ${built.sort === "status" ? "selected" : ""}>Durum</option>
                    </select>

                    <button class="btn btn-primary" type="submit">Ara</button>
                    <a class="btn btn-ghost" href="/links">Temizle</a>
                    <a class="btn btn-ghost ${built.deletedFilter ? "trash-accent" : ""}" href="/links?deleted=1">Çöpü Gör</a>
                  </form>
                </div>

                ${notifBarHtml}

                <div class="bulk-panel glass">
                  <form id="bulkForm" class="bulk-row" method="POST" action="/links/bulk-action">
                    <input type="hidden" name="deleted" value="${built.deletedFilter ? "1" : "0"}" />
                    <label class="notif-pill" style="background:#0b1624;border:1px solid rgba(73,95,130,0.35);"><input id="selectAll" type="checkbox" style="accent-color:#facc15;" /> Tümünü Seç</label>
                    ${bulkButtons}
                  </form>
                </div>

                ${
                  rows.length > 0
                    ? `<div class="feed-list">${cards}</div>`
                    : emptyStateHtml
                }

                <div class="bottom-row">
                  <a class="btn btn-ghost" href="/links${buildQuery(currentQuery, { page: Math.max(safePage - 1, 1) })}">Önceki</a>
                  <span class="notif-pill" style="background:#0b1624;border:1px solid rgba(73,95,130,0.35);">Sayfa ${safePage} / ${totalPages}</span>
                  <a class="btn btn-ghost" href="/links${buildQuery(currentQuery, { page: Math.min(safePage + 1, totalPages) })}">Sonraki</a>
                  <a class="btn btn-ghost" href="/links/json${buildQuery(currentQuery)}">Filtreli JSON</a>
                  <a class="btn btn-ghost" href="/links/export/csv${buildQuery(currentQuery)}">Filtreli CSV</a>
                </div>
              </div>

              <div class="right">
                <div class="right-card glass">
                  <div class="right-title">Hızlı Erişim</div>
                  <div class="panel-buttons">
                    <a class="side-mini-btn" href="/links">Liste</a>
                    <a class="side-mini-btn" href="/links?status=Reddedildi">Redler</a>
                    <a class="side-mini-btn" href="/links/json${buildQuery(currentQuery)}">JSON</a>
                    <a class="side-mini-btn" href="/links/export/csv${buildQuery(currentQuery)}">CSV</a>
                    <a class="side-mini-btn" href="/audit">Audit</a>
                    <a class="side-mini-btn" href="/subscribe/chat">Sub</a>
                  </div>
                </div>

                <div class="right-card glass">
                  <div class="right-title">Kompakt Paneller</div>

                  <details class="compact-box" open>
                    <summary>
                      <span>Whitelist (${whitelistResult.rows.length})</span>
                      <span>▾</span>
                    </summary>
                    <div class="compact-content">
                      <form class="search-row" method="POST" action="/domains/whitelist">
                        <input class="side-input" type="text" name="domain" placeholder="ör: youtube.com" />
                        <button class="domain-btn btn btn-primary" type="submit">Ekle</button>
                      </form>
                      ${whitelistHtml || `<div class="list-item"><span>Henüz whitelist yok.</span></div>`}
                    </div>
                  </details>

                  <details class="compact-box">
                    <summary>
                      <span>Blacklist (${blacklistResult.rows.length})</span>
                      <span>▾</span>
                    </summary>
                    <div class="compact-content">
                      <form class="search-row" method="POST" action="/domains/blacklist">
                        <input class="side-input" type="text" name="domain" placeholder="ör: spam-site.com" />
                        <button class="domain-btn btn btn-primary" type="submit">Ekle</button>
                      </form>
                      ${blacklistHtml || `<div class="list-item"><span>Henüz blacklist yok.</span></div>`}
                    </div>
                  </details>

                  <details class="compact-box">
                    <summary>
                      <span>Engelli Kullanıcılar (${blockedUsersResult.rows.length})</span>
                      <span>▾</span>
                    </summary>
                    <div class="compact-content">
                      <form class="search-row" method="POST" action="/users/block">
                        <input class="side-input" type="text" name="username" placeholder="ör: botrix" />
                        <button class="domain-btn btn btn-primary" type="submit">Ekle</button>
                      </form>
                      ${blockedUsersHtml || `<div class="list-item"><span>Henüz engelli kullanıcı yok.</span></div>`}
                    </div>
                  </details>

                  <details class="compact-box" ${built.deletedFilter ? "open" : ""}>
                    <summary>
                      <span>Çöp Kutusu (${deletedCount})</span>
                      <span>▾</span>
                    </summary>
                    <div class="compact-content">
                      <div class="list-item">
                        <span>Silinmiş kayıtlar: ${deletedCount}</span>
                        <a class="btn btn-ghost" href="/links?deleted=1">Aç</a>
                      </div>
                      <form method="POST" action="/trash/empty" onsubmit="return confirm('Çöpü tamamen boşaltmak istiyor musun?')">
                        <button class="danger-bulk" type="submit" style="margin-top:10px;">Çöpü Tamamen Boşalt</button>
                      </form>
                    </div>
                  </details>
                </div>

                <div class="right-card glass">
                  <div class="right-title">Bildirimler</div>
                  ${notifHtml || `<div class="list-item"><span>Henüz bildirim yok.</span></div>`}
                </div>

                <div class="right-card glass">
                  <div class="right-title">Son İşlemler</div>
                  ${auditHtml || `<div class="list-item"><span>Henüz işlem yok.</span></div>`}
                </div>
              </div>
            </div>
          </div>

          <script>
            const selectAll = document.getElementById("selectAll");
            if (selectAll) {
              selectAll.addEventListener("change", function () {
                document.querySelectorAll('input.bulk-checkbox').forEach((el) => {
                  el.checked = selectAll.checked;
                });
              });
            }

            let latestKnownId = 0;
            const idMatches = [...document.querySelectorAll(".subtime")]
              .map((el) => {
                const match = (el.textContent || "").match(/#(\\d+)/);
                return match ? Number(match[1]) : 0;
              })
              .filter(Boolean);

            if (idMatches.length) latestKnownId = Math.max(...idMatches);

            let beepEnabled = true;

            function playNotificationBeep() {
              if (!beepEnabled) return;
              try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();

                oscillator.type = "sine";
                oscillator.frequency.value = 880;
                gainNode.gain.value = 0.03;

                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);

                oscillator.start();
                oscillator.stop(audioContext.currentTime + 0.12);
              } catch (e) {
                console.error("BEEP ERROR:", e);
              }
            }

            async function notifyNewLink(count) {
              try {
                if ("Notification" in window) {
                  if (Notification.permission === "granted") {
                    new Notification("HasanD Link Detector", {
                      body: count + " yeni kayıt geldi.",
                      icon: "/logo.png"
                    });
                  } else if (Notification.permission !== "denied") {
                    await Notification.requestPermission();
                  }
                }
              } catch (e) {
                console.error("NOTIFY ERROR:", e);
              }
            }

            async function checkLiveUpdates() {
              try {
                const res = await fetch("/links/live?last_id=" + latestKnownId, {
                  credentials: "same-origin"
                });

                if (!res.ok) return;
                const rows = await res.json();

                if (Array.isArray(rows) && rows.length > 0) {
                  const newestId = Math.max(...rows.map((r) => Number(r.id || 0)));
                  if (newestId > latestKnownId) {
                    latestKnownId = newestId;
                    playNotificationBeep();
                    notifyNewLink(rows.length);
                    window.location.reload();
                  }
                }
              } catch (err) {
                console.error("LIVE UPDATE ERROR:", err);
              }
            }

            setInterval(checkLiveUpdates, 10000);
          </script>
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
  console.log("Server " + PORT + " portunda çalışıyor");
  try {
    await ensureTables();
    console.log("Tablolar hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
