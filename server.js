// server.js
// Replaces Railway's zero-config static hosting with a minimal Node service
// that serves the exact same files (index.html, projects/*.html) but adds
// visitor IP logging + basic abuse rate-limiting.

const express = require("express");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();

// Railway sits behind a proxy — without this, req.ip returns Railway's
// internal proxy IP instead of the real visitor IP.
app.set("trust proxy", true);

const LOG_DIR = path.join(__dirname, "logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
const LOG_FILE = path.join(LOG_DIR, "visitors.log");

// --- Visitor logging middleware ---
// Logs to stdout (visible in Railway's dashboard logs in real time) AND to
// a local file (logs/visitors.log) for anything you want to grep/export later.
app.use((req, res, next) => {
  const entry = {
    time: new Date().toISOString(),
    ip: req.ip, // real visitor IP, thanks to trust proxy above
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    referer: req.headers["referer"] || null,
  };
  const line = JSON.stringify(entry);
  console.log(line); // shows up live in Railway logs
  fs.appendFile(LOG_FILE, line + "\n", (err) => {
    if (err) console.error("Failed to write visitor log:", err);
  });
  next();
});

// --- Basic abuse / rate-limit protection ---
// Flags & blocks any single IP making more than 100 requests in 5 minutes.
// Tune these numbers to your real traffic pattern once you have a baseline.
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(
      `[ABUSE FLAG] ${new Date().toISOString()} IP ${req.ip} exceeded rate limit on ${req.path}`
    );
    res.status(429).send("Too many requests — please slow down.");
  },
});
app.use(limiter);

// --- Serve the existing static site unchanged ---
// Drop this file next to your current index.html and projects/ folder.
app.use(express.static(path.join(__dirname)));

// --- Simple endpoint to review recent visitor log entries without SSH ---
// Protect this in production (see note below) — for now it's a quick way
// to eyeball recent traffic from a browser.
app.get("/admin/recent-visits", (req, res) => {
  const key = req.query.key;
  if (key !== process.env.ADMIN_KEY) {
    return res.status(403).send("Forbidden");
  }
  fs.readFile(LOG_FILE, "utf8", (err, data) => {
    if (err) return res.status(200).send("[]");
    const lines = data.trim().split("\n").filter(Boolean).slice(-200);
    res.type("text/plain").send(lines.reverse().join("\n"));
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CipherGuard Labs server running on port ${PORT}`);
});
