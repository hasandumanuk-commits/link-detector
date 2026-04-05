require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");

const app = express();

app.use(bodyParser.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.get("/", (req, res) => {
  res.send("Link Detector çalışıyor");
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/webhook/kick", async (req, res) => {
  try {
    const payload = req.body || {};
    const message = JSON.stringify(payload);

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
    console.log("links tablosu hazır");
  } catch (err) {
    console.error("DB tablo oluşturma hatası:", err);
  }
});
