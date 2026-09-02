// ============================================================
//  KeyPanel — APK License Key Authentication Server
// ============================================================
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const DB_FILE = path.join(__dirname, "db.json");
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
// Default password: admin123  (change via ADMIN_PASS_HASH env var in production)
const ADMIN_PASS_HASH =
  process.env.ADMIN_PASS_HASH ||
  bcrypt.hashSync(process.env.ADMIN_PASS || "admin123", 10);

// ---------- tiny JSON "database" helpers ----------
function readDB() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ keys: [], logs: [] }, null, 2));
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
function log(db, line) {
  db.logs.unshift({ time: new Date().toISOString(), line });
  db.logs = db.logs.slice(0, 500); // keep last 500 lines
}
function genKey() {
  const chunk = () => Math.random().toString(36).substring(2, 6).toUpperCase();
  return `FP-${chunk()}-${chunk()}-${chunk()}`;
}

// ---------- auth middleware (protects admin dashboard APIs) ----------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ status: "failed", message: "No token provided" });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ status: "failed", message: "Invalid or expired token" });
  }
}

// ============================================================
//  ADMIN AUTH
// ============================================================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || !bcrypt.compareSync(password || "", ADMIN_PASS_HASH)) {
    return res.status(401).json({ status: "failed", message: "Invalid username or password" });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "12h" });
  res.json({ status: "success", token });
});

// ============================================================
//  KEY MANAGEMENT (admin dashboard — requires token)
// ============================================================

// list all keys
app.get("/api/keys", requireAuth, (req, res) => {
  const db = readDB();
  res.json({ status: "success", keys: db.keys });
});

// generate a new key
app.post("/api/keys/generate", requireAuth, (req, res) => {
  const { days = 30, deviceLimit = 1, note = "", count = 1 } = req.body || {};
  const db = readDB();
  const created = [];
  for (let i = 0; i < Math.max(1, Math.min(count, 100)); i++) {
    const key = {
      key: genKey(),
      createdAt: new Date().toISOString(),
      expiresAt:
        Number(days) > 0
          ? new Date(Date.now() + Number(days) * 86400000).toISOString()
          : null, // null = never expires
      deviceLimit: Number(deviceLimit) || 1,
      devices: [],
      note,
      revoked: false,
      usageCount: 0,
      lastUsed: null,
    };
    db.keys.push(key);
    created.push(key);
  }
  log(db, `Generated ${created.length} key(s) by ${req.admin.username}`);
  writeDB(db);
  res.json({ status: "success", keys: created });
});

// revoke a key
app.post("/api/keys/:key/revoke", requireAuth, (req, res) => {
  const db = readDB();
  const k = db.keys.find((x) => x.key === req.params.key);
  if (!k) return res.status(404).json({ status: "failed", message: "Key not found" });
  k.revoked = true;
  log(db, `Revoked key ${k.key} by ${req.admin.username}`);
  writeDB(db);
  res.json({ status: "success", key: k });
});

// unrevoke / reactivate a key
app.post("/api/keys/:key/activate", requireAuth, (req, res) => {
  const db = readDB();
  const k = db.keys.find((x) => x.key === req.params.key);
  if (!k) return res.status(404).json({ status: "failed", message: "Key not found" });
  k.revoked = false;
  log(db, `Reactivated key ${k.key} by ${req.admin.username}`);
  writeDB(db);
  res.json({ status: "success", key: k });
});

// reset bound devices on a key (let it be used on a new phone)
app.post("/api/keys/:key/reset-device", requireAuth, (req, res) => {
  const db = readDB();
  const k = db.keys.find((x) => x.key === req.params.key);
  if (!k) return res.status(404).json({ status: "failed", message: "Key not found" });
  k.devices = [];
  log(db, `Reset devices for key ${k.key} by ${req.admin.username}`);
  writeDB(db);
  res.json({ status: "success", key: k });
});

// extend expiry
app.post("/api/keys/:key/extend", requireAuth, (req, res) => {
  const { days = 30 } = req.body || {};
  const db = readDB();
  const k = db.keys.find((x) => x.key === req.params.key);
  if (!k) return res.status(404).json({ status: "failed", message: "Key not found" });
  const base = k.expiresAt && new Date(k.expiresAt) > new Date() ? new Date(k.expiresAt) : new Date();
  k.expiresAt = new Date(base.getTime() + Number(days) * 86400000).toISOString();
  log(db, `Extended key ${k.key} by ${days} day(s) — ${req.admin.username}`);
  writeDB(db);
  res.json({ status: "success", key: k });
});

// delete a key permanently
app.delete("/api/keys/:key", requireAuth, (req, res) => {
  const db = readDB();
  const before = db.keys.length;
  db.keys = db.keys.filter((x) => x.key !== req.params.key);
  log(db, `Deleted key ${req.params.key} by ${req.admin.username}`);
  writeDB(db);
  res.json({ status: "success", deleted: before !== db.keys.length });
});

// recent activity logs
app.get("/api/logs", requireAuth, (req, res) => {
  const db = readDB();
  res.json({ status: "success", logs: db.logs });
});

// dashboard stats
app.get("/api/stats", requireAuth, (req, res) => {
  const db = readDB();
  const now = new Date();
  const total = db.keys.length;
  const active = db.keys.filter((k) => !k.revoked && (!k.expiresAt || new Date(k.expiresAt) > now)).length;
  const expired = db.keys.filter((k) => k.expiresAt && new Date(k.expiresAt) <= now).length;
  const revoked = db.keys.filter((k) => k.revoked).length;
  res.json({ status: "success", stats: { total, active, expired, revoked } });
});

// ============================================================
//  APK VERIFICATION ENDPOINTS (public — called from your app)
//  Multiple paths/aliases so you can point older/newer APK
//  builds at whichever URL they already expect.
// ============================================================
function verifyHandler(req, res) {
  const params = { ...req.query, ...req.body };
  const key = params.key || params.license || params.token;
  const deviceId = params.device_id || params.hwid || params.device || "unknown";
  const appVersion = params.app_version || params.version || null;

  if (!key) {
    return res.status(400).json({ status: "failed", message: "Missing key parameter" });
  }

  const db = readDB();
  const k = db.keys.find((x) => x.key === key);

  if (!k) {
    log(db, `FAILED verify (invalid key) — ${key} — device ${deviceId}`);
    writeDB(db);
    return res.status(404).json({ status: "failed", message: "Invalid key" });
  }
  if (k.revoked) {
    log(db, `FAILED verify (revoked) — ${key} — device ${deviceId}`);
    writeDB(db);
    return res.status(403).json({ status: "failed", message: "Key revoked" });
  }
  if (k.expiresAt && new Date(k.expiresAt) <= new Date()) {
    log(db, `FAILED verify (expired) — ${key} — device ${deviceId}`);
    writeDB(db);
    return res.status(403).json({ status: "failed", message: "Key expired" });
  }
  if (!k.devices.includes(deviceId)) {
    if (k.devices.length >= k.deviceLimit) {
      log(db, `FAILED verify (device limit) — ${key} — device ${deviceId}`);
      writeDB(db);
      return res.status(403).json({ status: "failed", message: "Device limit reached" });
    }
    k.devices.push(deviceId);
  }

  k.usageCount += 1;
  k.lastUsed = new Date().toISOString();
  log(db, `OK verify — ${key} — device ${deviceId}${appVersion ? " — v" + appVersion : ""}`);
  writeDB(db);

  const daysLeft = k.expiresAt
    ? Math.max(0, Math.ceil((new Date(k.expiresAt) - new Date()) / 86400000))
    : null;

  return res.json({
    status: "success",
    message: "Key verified",
    expires_in_days: daysLeft,
    device_limit: k.deviceLimit,
    devices_used: k.devices.length,
  });
}

// register the same handler under every alias, GET and POST
["/connect", "/connect.php", "/server", "/api/verify", "/verify", "/auth"].forEach((route) => {
  app.get(route, verifyHandler);
  app.post(route, verifyHandler);
});

// health check
app.get("/api/health", (req, res) => res.json({ status: "success", message: "Server running" }));

// fallback to login page
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`KeyPanel running on port ${PORT}`));
