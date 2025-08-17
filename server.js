/* Minimal shared warnings relay: Socket.IO + native WS + SQLite persistence */
const fs = require("fs");
const path = require("path");
const http = require("http");
const express = require("express");
const cors = require("cors");
const { Server: IOServer } = require("socket.io");
const { WebSocketServer } = require("ws");
const Database = require("better-sqlite3");

/* ---- Config ---- */
const PORT = process.env.PORT || 8080;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*"; // comma-separated list OK
const DB_FILE = process.env.DB_FILE || "./data/warnings.sqlite";
const WS_PATH = process.env.WS_PATH || "/warn"; // native WebSocket path
const IO_PATH = process.env.IO_PATH || "/socket.io"; // socket.io default

/* ---- App/Server ---- */
const app = express();
app.use(cors({ origin: (CORS_ORIGIN === "*") ? true : CORS_ORIGIN.split(",") }));
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_, res) => res.json({ ok: true, t: Date.now() }));

/* ensure db dir */
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS warnings (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  polygon TEXT NOT NULL,       -- JSON string [[lat,lng]... or multi-ring array
  issuedISO TEXT NOT NULL,
  minutes INTEGER NOT NULL,
  expiresISO TEXT NOT NULL,
  wind TEXT,
  hail TEXT,
  threat TEXT,
  author TEXT,
  info TEXT,
  possibleTag TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_warnings_date ON warnings (issuedISO);
CREATE INDEX IF NOT EXISTS idx_warnings_active ON warnings (active);
`);

const insertWarning = db.prepare(`
  INSERT OR REPLACE INTO warnings
  (id, type, polygon, issuedISO, minutes, expiresISO, wind, hail, threat, author, info, possibleTag, active)
  VALUES (@id, @type, @polygon, @issuedISO, @minutes, @expiresISO, @wind, @hail, @threat, @author, @info, @possibleTag, @active)
`);
const getActive = db.prepare(`SELECT * FROM warnings WHERE active = 1 AND datetime(expiresISO) > datetime('now')`);
const expireById = db.prepare(`UPDATE warnings SET active = 0 WHERE id = ?`);
const getByDate = db.prepare(`
  SELECT * FROM warnings
  WHERE substr(issuedISO,1,10) = ?
  ORDER BY issuedISO ASC
`);

/* REST history endpoint */
app.get("/warnings", (req, res) => {
  const date = (req.query.date || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: "Use ?date=YYYY-MM-DD" });
  const rows = getByDate.all(date).map(row => ({ ...row, polygon: JSON.parse(row.polygon) }));
  res.json({ date, count: rows.length, warnings: rows });
});

/* ---- HTTP server + transports ---- */
const server = http.createServer(app);

/* Socket.IO (clients connect to /socket.io by default) */
const io = new IOServer(server, {
  path: IO_PATH,
  cors: { origin: (CORS_ORIGIN === "*") ? true : CORS_ORIGIN.split(",") }
});

/* Native WebSocket on /warn to match your current frontend */
const wss = new WebSocketServer({ server, path: WS_PATH });

/* Connected client sets */
const wsClients = new Set(); // native WS
io.on("connection", socket => {
  // bootstrap active warnings
  const actives = getActive.all().map(r => ({ ...r, polygon: JSON.parse(r.polygon) }));
  socket.emit("bootstrap", actives);

  socket.on("issue", payload => handleIssue(payload, "io"));
  socket.on("expire", ({ id }) => handleExpire(id, "io"));
});

wss.on("connection", ws => {
  wsClients.add(ws);
  // bootstrap active warnings
  try {
    const actives = getActive.all().map(r => ({ ...r, polygon: JSON.parse(r.polygon) }));
    ws.send(JSON.stringify({ kind: "bootstrap", warnings: actives }));
  } catch {}

  ws.on("message", data => {
    let msg;
    try { msg = JSON.parse(String(data)); } catch { return; }
    if (!msg || !msg.kind) return;
    if (msg.kind === "issue" && msg.payload) handleIssue(msg.payload, "ws");
    if (msg.kind === "expire" && msg.id) handleExpire(msg.id, "ws");
  });

  ws.on("close", () => wsClients.delete(ws));
});

/* ---- Helpers ---- */
function broadcast(kind, obj) {
  // socket.io
  if (kind === "issue") io.emit("issue", obj);
  if (kind === "expire") io.emit("expire", obj);

  // native ws
  const json = JSON.stringify({ kind, ...(kind === "issue" ? { payload: obj } : obj) });
  for (const client of wsClients) {
    if (client.readyState === 1) client.send(json);
  }
}

function scheduleExpiry(id, expiresISO) {
  const ms = new Date(expiresISO).getTime() - Date.now();
  if (ms <= 0) return;
  setTimeout(() => {
    try {
      expireById.run(id);
      broadcast("expire", { id });
    } catch (e) {
      console.error("[expire timer]", e);
    }
  }, ms);
}

function validateIssue(p) {
  const required = ["id", "type", "polygon", "issuedISO", "minutes"];
  for (const k of required) if (p[k] == null) throw new Error(`Missing ${k}`);
  if (!Array.isArray(p.polygon)) throw new Error("polygon must be an array of rings/points");
  if (!/^\d{4}-\d{2}-\d{2}T/.test(p.issuedISO)) throw new Error("issuedISO must be ISO string");
  const m = Number(p.minutes);
  if (!Number.isFinite(m) || m < 1 || m > 1440) throw new Error("minutes out of range");
}

function handleIssue(payload, src) {
  try {
    validateIssue(payload);
    const expiresISO = new Date(new Date(payload.issuedISO).getTime() + payload.minutes * 60000).toISOString();
    const row = {
      id: payload.id,
      type: payload.type,
      polygon: JSON.stringify(payload.polygon),
      issuedISO: payload.issuedISO,
      minutes: payload.minutes,
      expiresISO,
      wind: payload.wind ?? null,
      hail: payload.hail ?? null,
      threat: payload.threat ?? null,
      author: payload.author ?? null,
      info: payload.info ?? null,
      possibleTag: payload.possibleTag ?? null,
      active: 1
    };
    insertWarning.run(row);
    scheduleExpiry(row.id, row.expiresISO);
    broadcast("issue", { ...payload, expiresISO });
    console.log(`[issue:${src}] ${row.type} ${row.id}`);
  } catch (e) {
    console.error("[issue error]", e.message);
  }
}

function handleExpire(id, src) {
  try {
    expireById.run(id);
    broadcast("expire", { id });
    console.log(`[expire:${src}] ${id}`);
  } catch (e) {
    console.error("[expire error]", e.message);
  }
}

/* Reschedule timers for already-active warnings on boot */
for (const row of getActive.all()) scheduleExpiry(row.id, row.expiresISO);

/* Go */
server.listen(PORT, () => {
  console.log(`WarnPing relay listening on :${PORT}`);
  console.log(`- Socket.IO: ws(s)://<host>${IO_PATH}`);
  console.log(`- Native WS: ws(s)://<host>${WS_PATH}`);
});
