const express = require("express");
const session = require("express-session");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Data storage (JSON files) ----------
const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "public", "uploads");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const TOURNAMENTS_FILE = path.join(DATA_DIR, "tournaments.json");

for (const dir of [DATA_DIR, UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
for (const file of [USERS_FILE, TOURNAMENTS_FILE]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]");
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- Password hashing (built-in crypto, no native deps) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const check = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(check, "hex"));
}

// ---------- Admin credentials (change these!) ----------
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

// ---------- Middleware ----------
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  }),
);

function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).json({ error: "Admin access required" });
  next();
}

// ---------- Photo upload ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${file.fieldname}_${Date.now()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    const ok = [".jpg", ".jpeg", ".png", ".gif", ".webp"].includes(path.extname(file.originalname).toLowerCase());
    cb(ok ? null : new Error("Only image files are allowed"), ok);
  },
});

// ================= USER AUTH =================

// Register
app.post("/api/register", (req, res) => {
  const { fullName, bgmiId, bgmiName, email, phone, password } = req.body || {};

  if (!fullName || !bgmiId || !bgmiName || !email || !phone || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }
  if (!/^\d{8,12}$/.test(String(bgmiId))) {
    return res.status(400).json({ error: "BGMI ID must be 8-12 digits" });
  }
  if (!/^\d{10}$/.test(String(phone))) {
    return res.status(400).json({ error: "Phone number must be 10 digits" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const users = readJson(USERS_FILE);
  if (users.some((u) => u.bgmiId === String(bgmiId))) {
    return res.status(409).json({ error: "This BGMI ID is already registered" });
  }
  if (users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "This email is already registered" });
  }

  const user = {
    id: crypto.randomUUID(),
    fullName,
    bgmiId: String(bgmiId),
    bgmiName,
    email,
    phone: String(phone),
    password: hashPassword(password),
    registeredAt: new Date().toISOString(),
  };
  users.push(user);
  writeJson(USERS_FILE, users);

  req.session.userId = user.id;
  res.json({ success: true, user: { id: user.id, fullName, bgmiId: user.bgmiId, bgmiName } });
});

// Login (by BGMI ID + password)
app.post("/api/login", (req, res) => {
  const { bgmiId, password } = req.body || {};
  if (!bgmiId || !password) return res.status(400).json({ error: "BGMI ID and password are required" });

  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.bgmiId === String(bgmiId));
  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ error: "Invalid BGMI ID or password" });
  }

  req.session.userId = user.id;
  res.json({
    success: true,
    user: { id: user.id, fullName: user.fullName, bgmiId: user.bgmiId, bgmiName: user.bgmiName },
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Current logged-in user
app.get("/api/me", requireUser, (req, res) => {
  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  const { password, ...safe } = user;
  res.json(safe);
});

app.put("/api/me", requireUser, upload.single("avatar"), (req, res) => {
  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: "Not logged in" });

  // Allow users to update: fullName, bgmiId, bgmiName, password, avatar
  // Do NOT allow editing email from the user side (admin can still change via admin API)
  const { fullName, bgmiId, bgmiName, password } = req.body || {};

  if (fullName !== undefined && fullName.trim() !== "") {
    user.fullName = fullName.trim();
  }

  // BGMI ID validation and uniqueness
  if (bgmiId !== undefined && String(bgmiId).trim() !== "") {
    if (!/^\d{8,12}$/.test(String(bgmiId))) {
      return res.status(400).json({ error: "BGMI ID must be 8-12 digits" });
    }
    if (users.some((u) => u.id !== user.id && u.bgmiId === String(bgmiId))) {
      return res.status(409).json({ error: "This BGMI ID is already registered" });
    }
    user.bgmiId = String(bgmiId);
  }

  if (bgmiName !== undefined && String(bgmiName).trim() !== "") {
    user.bgmiName = String(bgmiName).trim();
  }

  if (password !== undefined && password !== "") {
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    user.password = hashPassword(password);
  }

  if (req.file) {
    if (user.avatar) {
      const oldAvatar = path.join(__dirname, "public", user.avatar.replace(/^\//, ""));
      if (oldAvatar.startsWith(UPLOAD_DIR) && fs.existsSync(oldAvatar)) fs.unlinkSync(oldAvatar);
    }
    user.avatar = `/uploads/${req.file.filename}`;
  }

  writeJson(USERS_FILE, users);

  // Propagate bgmiId/bgmiName changes into tournaments (players/results)
  const tournaments = readJson(TOURNAMENTS_FILE);
  let changed = false;
  for (const t of tournaments) {
    for (const p of t.players || []) {
      if (p.userId === user.id) {
        p.bgmiId = user.bgmiId;
        p.bgmiName = user.bgmiName;
        changed = true;
      }
    }
    for (const r of t.results || []) {
      if (r.userId === user.id) {
        r.bgmiId = user.bgmiId;
        r.bgmiName = user.bgmiName;
        changed = true;
      }
    }
  }
  if (changed) writeJson(TOURNAMENTS_FILE, tournaments);

  const { password: _pw, ...safe } = user;
  res.json({ success: true, user: safe });
});

// ================= TOURNAMENTS (player side) =================

// Match status: 'upcoming' (joining open) -> 'live' (joining closed) -> 'completed' (results announced)
function getStatus(t) {
  return t.status || "upcoming";
}

app.get("/api/tournaments", requireUser, (req, res) => {
  const tournaments = readJson(TOURNAMENTS_FILE);
  const userId = req.session.userId;
  // Hide room ID/password from players who have not joined
  const result = tournaments.map((t) => {
    const joined = (t.players || []).some((p) => p.userId === userId);
    const status = getStatus(t);
    return {
      id: t.id,
      name: t.name,
      type: t.type,
      map: t.map,
      dateTime: t.dateTime,
      entryFee: t.entryFee,
      prizePool: t.prizePool,
      maxPlayers: t.maxPlayers,
      photo: t.photo,
      status,
      playersCount: (t.players || []).length,
      joined,
      roomId: joined ? t.roomId : undefined,
      roomPassword: joined ? t.roomPassword : undefined,
      // Results are public once the match is completed (winner announcement)
      results: status === "completed" ? t.results || [] : undefined,
    };
  });
  res.json(result);
});

// Match history of the logged-in player (tournaments they joined)
app.get("/api/history", requireUser, (req, res) => {
  const userId = req.session.userId;
  const tournaments = readJson(TOURNAMENTS_FILE);
  const history = tournaments
    .filter((t) => (t.players || []).some((p) => p.userId === userId))
    .map((t) => {
      const status = getStatus(t);
      const results = t.results || [];
      const myResult = results.find((r) => r.userId === userId) || null;
      const winner = results.find((r) => Number(r.position) === 1) || null;
      return {
        id: t.id,
        name: t.name,
        type: t.type,
        map: t.map,
        dateTime: t.dateTime,
        entryFee: t.entryFee,
        prizePool: t.prizePool,
        status,
        myResult,
        winner,
      };
    })
    .sort((a, b) => new Date(b.dateTime) - new Date(a.dateTime));
  res.json(history);
});

app.post("/api/tournaments/:id/join", requireUser, (req, res) => {
  const tournaments = readJson(TOURNAMENTS_FILE);
  const t = tournaments.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Tournament not found" });

  const status = getStatus(t);
  if (status !== "upcoming") {
    return res.status(409).json({
      error: status === "live" ? "Match is LIVE — joining is closed" : "This match is already completed",
    });
  }

  t.players = t.players || [];
  if (t.players.some((p) => p.userId === req.session.userId)) {
    return res.status(409).json({ error: "You have already joined this tournament" });
  }
  if (t.maxPlayers && t.players.length >= t.maxPlayers) {
    return res.status(409).json({ error: "Tournament is full" });
  }

  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.id === req.session.userId);
  t.players.push({
    userId: user.id,
    bgmiId: user.bgmiId,
    bgmiName: user.bgmiName,
    joinedAt: new Date().toISOString(),
  });
  writeJson(TOURNAMENTS_FILE, tournaments);
  res.json({ success: true, roomId: t.roomId, roomPassword: t.roomPassword });
});

// ================= ADMIN =================

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.json({ success: true });
  }
  res.status(401).json({ error: "Invalid admin credentials" });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/admin/check", (req, res) => {
  res.json({ isAdmin: !!req.session.isAdmin });
});

// All registered users
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = readJson(USERS_FILE).map(({ password, ...u }) => u);
  res.json(users);
});

// Edit a user's details
app.put("/api/admin/users/:id", requireAdmin, (req, res) => {
  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const { fullName, bgmiId, bgmiName, email, phone, password } = req.body || {};

  if (bgmiId !== undefined && String(bgmiId) !== "") {
    if (!/^\d{8,12}$/.test(String(bgmiId))) {
      return res.status(400).json({ error: "BGMI ID must be 8-12 digits" });
    }
    if (users.some((u) => u.id !== user.id && u.bgmiId === String(bgmiId))) {
      return res.status(409).json({ error: "Another user already has this BGMI ID" });
    }
    user.bgmiId = String(bgmiId);
  }
  if (email !== undefined && email !== "") {
    if (users.some((u) => u.id !== user.id && u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(409).json({ error: "Another user already has this email" });
    }
    user.email = email;
  }
  if (phone !== undefined && String(phone) !== "") {
    if (!/^\d{10}$/.test(String(phone))) {
      return res.status(400).json({ error: "Phone number must be 10 digits" });
    }
    user.phone = String(phone);
  }
  if (fullName !== undefined && fullName !== "") user.fullName = fullName;
  if (bgmiName !== undefined && bgmiName !== "") user.bgmiName = bgmiName;
  if (password !== undefined && password !== "") {
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    user.password = hashPassword(password);
  }
  writeJson(USERS_FILE, users);

  // Keep the copies stored inside tournaments (players/results) in sync
  const tournaments = readJson(TOURNAMENTS_FILE);
  let changed = false;
  for (const t of tournaments) {
    for (const p of t.players || []) {
      if (p.userId === user.id) {
        p.bgmiId = user.bgmiId;
        p.bgmiName = user.bgmiName;
        changed = true;
      }
    }
    for (const r of t.results || []) {
      if (r.userId === user.id) {
        r.bgmiId = user.bgmiId;
        r.bgmiName = user.bgmiName;
        changed = true;
      }
    }
  }
  if (changed) writeJson(TOURNAMENTS_FILE, tournaments);

  const { password: _pw, ...safe } = user;
  res.json({ success: true, user: safe });
});

// Change match status: upcoming | live | completed
app.post("/api/admin/tournaments/:id/status", requireAdmin, (req, res) => {
  const { status } = req.body || {};
  if (!["upcoming", "live", "completed"].includes(status)) {
    return res.status(400).json({ error: "Status must be upcoming, live or completed" });
  }
  const tournaments = readJson(TOURNAMENTS_FILE);
  const t = tournaments.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Tournament not found" });

  t.status = status;
  writeJson(TOURNAMENTS_FILE, tournaments);
  res.json({ success: true, tournament: t });
});

// Declare results (winner + leaderboard) — also marks the match completed
app.post("/api/admin/tournaments/:id/results", requireAdmin, (req, res) => {
  const { results } = req.body || {};
  if (!Array.isArray(results)) {
    return res.status(400).json({ error: "results must be an array" });
  }
  const tournaments = readJson(TOURNAMENTS_FILE);
  const t = tournaments.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Tournament not found" });

  const players = t.players || [];
  t.results = results
    .filter((r) => players.some((p) => p.userId === r.userId))
    .map((r) => {
      const p = players.find((x) => x.userId === r.userId);
      return {
        userId: p.userId,
        bgmiId: p.bgmiId,
        bgmiName: p.bgmiName,
        position: Number(r.position) || 0,
        kills: Number(r.kills) || 0,
        prizeWon: Number(r.prizeWon) || 0,
      };
    })
    .sort((a, b) => (a.position || 999) - (b.position || 999));
  t.status = "completed";

  writeJson(TOURNAMENTS_FILE, tournaments);
  res.json({ success: true, tournament: t });
});

// All tournaments (full details incl. room + players)
app.get("/api/admin/tournaments", requireAdmin, (req, res) => {
  res.json(readJson(TOURNAMENTS_FILE));
});

// Create tournament (with photo)
app.post("/api/admin/tournaments", requireAdmin, upload.single("photo"), (req, res) => {
  const { name, type, map, dateTime, entryFee, prizePool, maxPlayers, roomId, roomPassword } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "Tournament name is required" });
  }

  const tournaments = readJson(TOURNAMENTS_FILE);
  const tournament = {
    id: crypto.randomUUID(),
    name,
    type: (type || "Match").trim(), // free text: 1v1, 2v2, Squad, Erangel, anything
    map: (map || "").trim() || "TBD",
    dateTime: dateTime || "",
    entryFee: Number(entryFee) || 0,
    prizePool: Number(prizePool) || 0,
    maxPlayers: Number(maxPlayers) || 100,
    roomId: roomId || "",
    roomPassword: roomPassword || "",
    photo: req.file ? `/uploads/${req.file.filename}` : "",
    players: [],
    createdAt: new Date().toISOString(),
  };
  tournaments.push(tournament);
  writeJson(TOURNAMENTS_FILE, tournaments);
  res.json({ success: true, tournament });
});

// Edit tournament (room id, name, time, etc. — photo optional)
app.put("/api/admin/tournaments/:id", requireAdmin, upload.single("photo"), (req, res) => {
  const tournaments = readJson(TOURNAMENTS_FILE);
  const t = tournaments.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Tournament not found" });

  const fields = ["name", "type", "map", "dateTime", "roomId", "roomPassword"];
  for (const f of fields) {
    if (req.body[f] !== undefined && req.body[f] !== "") t[f] = req.body[f];
  }
  for (const f of ["entryFee", "prizePool", "maxPlayers"]) {
    if (req.body[f] !== undefined && req.body[f] !== "") t[f] = Number(req.body[f]);
  }
  if (req.file) {
    // remove old photo file if it exists
    if (t.photo) {
      const old = path.join(__dirname, "public", t.photo.replace(/^\//, ""));
      if (old.startsWith(UPLOAD_DIR) && fs.existsSync(old)) fs.unlinkSync(old);
    }
    t.photo = `/uploads/${req.file.filename}`;
  }

  writeJson(TOURNAMENTS_FILE, tournaments);
  res.json({ success: true, tournament: t });
});

// Delete tournament
app.delete("/api/admin/tournaments/:id", requireAdmin, (req, res) => {
  let tournaments = readJson(TOURNAMENTS_FILE);
  const t = tournaments.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Tournament not found" });

  if (t.photo) {
    const old = path.join(__dirname, "public", t.photo.replace(/^\//, ""));
    if (old.startsWith(UPLOAD_DIR) && fs.existsSync(old)) fs.unlinkSync(old);
  }
  tournaments = tournaments.filter((x) => x.id !== req.params.id);
  writeJson(TOURNAMENTS_FILE, tournaments);
  res.json({ success: true });
});

// ---------- Error handler (multer etc.) ----------
app.use((err, req, res, next) => {
  res.status(400).json({ error: err.message || "Something went wrong" });
});

app.listen(PORT, () => {
  console.log(`\n  BGMI Tournament server running:  http://localhost:${PORT}`);
  console.log(`  Admin portal:                    http://localhost:${PORT}/admin.html`);
  console.log(`  Admin login: ${ADMIN_USER} / ${ADMIN_PASS}\n`);
});
