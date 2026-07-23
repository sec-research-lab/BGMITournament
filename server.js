require("dotenv").config();
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "bgmi_tournament";

if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI environment variable. Set it in a local .env file (for dev) or your host's environment settings (for production).");
  process.exit(1);
}

let usersCol, tournamentsCol, reportsCol;

function clean(doc) {
  if (!doc) return doc;
  const { _id, ...rest } = doc;
  return rest;
}
function cleanAll(docs) {
  return docs.map(clean);
}

// Wrap async route handlers so thrown errors reach the error-handling middleware below
function ah(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
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

// Free starting credit balance for new players
const STARTING_CREDITS = 100;

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

// ---------- Photo upload (kept in-memory, stored as a data URL in MongoDB — no local disk involved) ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    const ok = [".jpg", ".jpeg", ".png", ".gif", ".webp"].includes(path.extname(file.originalname).toLowerCase());
    cb(ok ? null : new Error("Only image files are allowed"), ok);
  },
});
function fileToDataUrl(file) {
  return `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;
}

// ================= USER AUTH =================

// Register
app.post(
  "/api/register",
  ah(async (req, res) => {
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

    const users = await usersCol.find({}).toArray();
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
      credits: STARTING_CREDITS,
      registeredAt: new Date().toISOString(),
    };
    await usersCol.insertOne(user);

    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, fullName, bgmiId: user.bgmiId, bgmiName, credits: user.credits } });
  }),
);

// Login (by BGMI ID + password)
app.post(
  "/api/login",
  ah(async (req, res) => {
    const { bgmiId, password } = req.body || {};
    if (!bgmiId || !password) return res.status(400).json({ error: "BGMI ID and password are required" });

    const user = await usersCol.findOne({ bgmiId: String(bgmiId) });
    if (!user || !verifyPassword(password, user.password)) {
      return res.status(401).json({ error: "Invalid BGMI ID or password" });
    }

    req.session.userId = user.id;
    res.json({
      success: true,
      user: { id: user.id, fullName: user.fullName, bgmiId: user.bgmiId, bgmiName: user.bgmiName },
    });
  }),
);

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Current logged-in user
app.get(
  "/api/me",
  requireUser,
  ah(async (req, res) => {
    const user = await usersCol.findOne({ id: req.session.userId });
    if (!user) return res.status(401).json({ error: "Not logged in" });
    const { password, ...safe } = clean(user);
    res.json(safe);
  }),
);

app.put(
  "/api/me",
  requireUser,
  upload.single("avatar"),
  ah(async (req, res) => {
    const user = await usersCol.findOne({ id: req.session.userId });
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
      const clash = await usersCol.findOne({ id: { $ne: user.id }, bgmiId: String(bgmiId) });
      if (clash) {
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
      user.avatar = fileToDataUrl(req.file);
    }

    await usersCol.updateOne({ id: user.id }, { $set: clean(user) });

    // Propagate bgmiId/bgmiName changes into tournaments (players/results)
    const tournaments = await tournamentsCol.find({}).toArray();
    for (const t of tournaments) {
      let changed = false;
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
      if (changed) {
        await tournamentsCol.updateOne({ id: t.id }, { $set: { players: t.players, results: t.results } });
      }
    }

    const { password: _pw, ...safe } = clean(user);
    res.json({ success: true, user: safe });
  }),
);

// ================= TOURNAMENTS (player side) =================

// Match status: 'upcoming' (joining open) -> 'live' (joining closed) -> 'completed' (results announced)
function getStatus(t) {
  return t.status || "upcoming";
}

app.get(
  "/api/tournaments",
  requireUser,
  ah(async (req, res) => {
    const tournaments = await tournamentsCol.find({}).toArray();
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
  }),
);

// Match history of the logged-in player (tournaments they joined)
app.get(
  "/api/history",
  requireUser,
  ah(async (req, res) => {
    const userId = req.session.userId;
    const tournaments = await tournamentsCol.find({}).toArray();
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
  }),
);

app.post(
  "/api/tournaments/:id/join",
  requireUser,
  ah(async (req, res) => {
    const t = await tournamentsCol.findOne({ id: req.params.id });
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

    const user = await usersCol.findOne({ id: req.session.userId });
    const cost = Number(t.entryFee) || 0;
    const balance = Number(user.credits) || 0;
    if (cost > 0 && balance < cost) {
      return res.status(409).json({ error: `Not enough credits. You have ${balance}, joining costs ${cost}.` });
    }

    t.players.push({
      userId: user.id,
      bgmiId: user.bgmiId,
      bgmiName: user.bgmiName,
      joinedAt: new Date().toISOString(),
      creditsSpent: cost,
    });
    await tournamentsCol.updateOne({ id: t.id }, { $set: { players: t.players } });
    if (cost > 0) {
      await usersCol.updateOne({ id: user.id }, { $inc: { credits: -cost } });
    }
    res.json({ success: true, roomId: t.roomId, roomPassword: t.roomPassword, creditsSpent: cost });
  }),
);

// ================= REPORTS (cheating / server errors / other issues) =================

const REPORT_TYPES = ["cheating", "server_error", "other"];

// Submit a report about a tournament (e.g. another player cheating, or a server error that blocked play)
app.post(
  "/api/reports",
  requireUser,
  ah(async (req, res) => {
    const { tournamentId, type, reportedBgmiId, description } = req.body || {};
    if (!tournamentId || !REPORT_TYPES.includes(type) || !description || !description.trim()) {
      return res.status(400).json({ error: "tournamentId, a valid type, and a description are required" });
    }
    const t = await tournamentsCol.findOne({ id: tournamentId });
    if (!t) return res.status(404).json({ error: "Tournament not found" });

    const user = await usersCol.findOne({ id: req.session.userId });
    const report = {
      id: crypto.randomUUID(),
      tournamentId: t.id,
      tournamentName: t.name,
      userId: user.id,
      bgmiId: user.bgmiId,
      bgmiName: user.bgmiName,
      type,
      reportedBgmiId: reportedBgmiId ? String(reportedBgmiId).trim() : "",
      description: description.trim(),
      status: "pending",
      creditsRefunded: 0,
      createdAt: new Date().toISOString(),
      resolvedAt: null,
    };
    await reportsCol.insertOne(report);
    res.json({ success: true, report: clean(report) });
  }),
);

// The logged-in player's own reports
app.get(
  "/api/reports",
  requireUser,
  ah(async (req, res) => {
    const reports = await reportsCol.find({ userId: req.session.userId }).toArray();
    reports.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(cleanAll(reports));
  }),
);

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
app.get(
  "/api/admin/users",
  requireAdmin,
  ah(async (req, res) => {
    const users = cleanAll(await usersCol.find({}).toArray()).map(({ password, ...u }) => u);
    res.json(users);
  }),
);

// Edit a user's details
app.put(
  "/api/admin/users/:id",
  requireAdmin,
  ah(async (req, res) => {
    const user = await usersCol.findOne({ id: req.params.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    const { fullName, bgmiId, bgmiName, email, phone, password } = req.body || {};

    if (bgmiId !== undefined && String(bgmiId) !== "") {
      if (!/^\d{8,12}$/.test(String(bgmiId))) {
        return res.status(400).json({ error: "BGMI ID must be 8-12 digits" });
      }
      const clash = await usersCol.findOne({ id: { $ne: user.id }, bgmiId: String(bgmiId) });
      if (clash) {
        return res.status(409).json({ error: "Another user already has this BGMI ID" });
      }
      user.bgmiId = String(bgmiId);
    }
    if (email !== undefined && email !== "") {
      const allUsers = await usersCol.find({ id: { $ne: user.id } }).toArray();
      if (allUsers.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
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
    await usersCol.updateOne({ id: user.id }, { $set: clean(user) });

    // Keep the copies stored inside tournaments (players/results) in sync
    const tournaments = await tournamentsCol.find({}).toArray();
    for (const t of tournaments) {
      let changed = false;
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
      if (changed) {
        await tournamentsCol.updateOne({ id: t.id }, { $set: { players: t.players, results: t.results } });
      }
    }

    const { password: _pw, ...safe } = clean(user);
    res.json({ success: true, user: safe });
  }),
);

// Add (or remove, with a negative amount) credits for a user
app.post(
  "/api/admin/users/:id/credits",
  requireAdmin,
  ah(async (req, res) => {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount === 0) {
      return res.status(400).json({ error: "amount must be a non-zero number" });
    }
    const user = await usersCol.findOne({ id: req.params.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    await usersCol.updateOne({ id: user.id }, { $inc: { credits: amount } });
    const updated = await usersCol.findOne({ id: user.id });
    const { password: _pw, ...safe } = clean(updated);
    res.json({ success: true, user: safe });
  }),
);

// All reports, newest first
app.get(
  "/api/admin/reports",
  requireAdmin,
  ah(async (req, res) => {
    const reports = await reportsCol.find({}).toArray();
    reports.sort((a, b) => {
      if (a.status === "pending" && b.status !== "pending") return -1;
      if (a.status !== "pending" && b.status === "pending") return 1;
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
    res.json(cleanAll(reports));
  }),
);

// Approve a report: refunds the credits that player spent joining that tournament
app.post(
  "/api/admin/reports/:id/approve",
  requireAdmin,
  ah(async (req, res) => {
    const report = await reportsCol.findOne({ id: req.params.id });
    if (!report) return res.status(404).json({ error: "Report not found" });
    if (report.status !== "pending") return res.status(409).json({ error: "This report was already resolved" });

    const t = await tournamentsCol.findOne({ id: report.tournamentId });
    const playerEntry = t && (t.players || []).find((p) => p.userId === report.userId);
    const refund = Number(playerEntry?.creditsSpent) || 0;

    if (refund > 0) {
      await usersCol.updateOne({ id: report.userId }, { $inc: { credits: refund } });
    }
    await reportsCol.updateOne(
      { id: report.id },
      { $set: { status: "approved", creditsRefunded: refund, resolvedAt: new Date().toISOString() } },
    );
    res.json({ success: true, creditsRefunded: refund });
  }),
);

// Reject a report — no refund
app.post(
  "/api/admin/reports/:id/reject",
  requireAdmin,
  ah(async (req, res) => {
    const report = await reportsCol.findOne({ id: req.params.id });
    if (!report) return res.status(404).json({ error: "Report not found" });
    if (report.status !== "pending") return res.status(409).json({ error: "This report was already resolved" });

    await reportsCol.updateOne({ id: report.id }, { $set: { status: "rejected", resolvedAt: new Date().toISOString() } });
    res.json({ success: true });
  }),
);

// Change match status: upcoming | live | completed
app.post(
  "/api/admin/tournaments/:id/status",
  requireAdmin,
  ah(async (req, res) => {
    const { status } = req.body || {};
    if (!["upcoming", "live", "completed"].includes(status)) {
      return res.status(400).json({ error: "Status must be upcoming, live or completed" });
    }
    const t = await tournamentsCol.findOne({ id: req.params.id });
    if (!t) return res.status(404).json({ error: "Tournament not found" });

    t.status = status;
    await tournamentsCol.updateOne({ id: t.id }, { $set: { status } });
    res.json({ success: true, tournament: clean(t) });
  }),
);

// Declare results (winner + leaderboard) — also marks the match completed
app.post(
  "/api/admin/tournaments/:id/results",
  requireAdmin,
  ah(async (req, res) => {
    const { results } = req.body || {};
    if (!Array.isArray(results)) {
      return res.status(400).json({ error: "results must be an array" });
    }
    const t = await tournamentsCol.findOne({ id: req.params.id });
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

    await tournamentsCol.updateOne({ id: t.id }, { $set: { results: t.results, status: t.status } });
    res.json({ success: true, tournament: clean(t) });
  }),
);

// All tournaments (full details incl. room + players)
app.get(
  "/api/admin/tournaments",
  requireAdmin,
  ah(async (req, res) => {
    res.json(cleanAll(await tournamentsCol.find({}).toArray()));
  }),
);

// Create tournament (with photo)
app.post(
  "/api/admin/tournaments",
  requireAdmin,
  upload.single("photo"),
  ah(async (req, res) => {
    const { name, type, map, dateTime, entryFee, prizePool, maxPlayers, roomId, roomPassword } = req.body || {};
    if (!name) {
      return res.status(400).json({ error: "Tournament name is required" });
    }

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
      photo: req.file ? fileToDataUrl(req.file) : "",
      players: [],
      results: [],
      status: "upcoming",
      createdAt: new Date().toISOString(),
    };
    await tournamentsCol.insertOne(tournament);
    res.json({ success: true, tournament: clean(tournament) });
  }),
);

// Edit tournament (room id, name, time, etc. — photo optional)
app.put(
  "/api/admin/tournaments/:id",
  requireAdmin,
  upload.single("photo"),
  ah(async (req, res) => {
    const t = await tournamentsCol.findOne({ id: req.params.id });
    if (!t) return res.status(404).json({ error: "Tournament not found" });

    const fields = ["name", "type", "map", "dateTime", "roomId", "roomPassword"];
    for (const f of fields) {
      if (req.body[f] !== undefined && req.body[f] !== "") t[f] = req.body[f];
    }
    for (const f of ["entryFee", "prizePool", "maxPlayers"]) {
      if (req.body[f] !== undefined && req.body[f] !== "") t[f] = Number(req.body[f]);
    }
    if (req.file) {
      t.photo = fileToDataUrl(req.file);
    }

    await tournamentsCol.updateOne({ id: t.id }, { $set: clean(t) });
    res.json({ success: true, tournament: clean(t) });
  }),
);

// Delete tournament
app.delete(
  "/api/admin/tournaments/:id",
  requireAdmin,
  ah(async (req, res) => {
    const result = await tournamentsCol.deleteOne({ id: req.params.id });
    if (!result.deletedCount) return res.status(404).json({ error: "Tournament not found" });
    res.json({ success: true });
  }),
);

// ---------- Error handler (multer, mongo, etc.) ----------
app.use((err, req, res, next) => {
  console.error(err);
  res.status(400).json({ error: err.message || "Something went wrong" });
});

async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(MONGODB_DB);
  usersCol = db.collection("users");
  tournamentsCol = db.collection("tournaments");
  reportsCol = db.collection("reports");
  console.log("Connected to MongoDB");

  // Backfill: accounts registered before the credits system existed start with the same free balance
  await usersCol.updateMany({ credits: { $exists: false } }, { $set: { credits: STARTING_CREDITS } });

  app.listen(PORT, () => {
    console.log(`\n  BGMI Tournament server running:  http://localhost:${PORT}`);
    console.log(`  Admin portal:                    http://localhost:${PORT}/admin.html`);
    console.log(`  Admin login: ${ADMIN_USER} / ${ADMIN_PASS}\n`);
  });
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
