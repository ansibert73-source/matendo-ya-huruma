
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs/promises");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "donations.json");
const SESSION_DURATION = 2 * 60 * 60 * 1000;

if (!ADMIN_PASSWORD || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("Set ADMIN_PASSWORD and SESSION_SECRET (minimum 32 characters).");
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

let donations = [];
let writeQueue = Promise.resolve();
const loginAttempts = new Map();

async function loadDonations() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    const data = await fs.readFile(DATA_FILE, "utf8");
    donations = JSON.parse(data);
    if (!Array.isArray(donations)) throw new Error("Invalid donations data.");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    donations = [];
    await fs.writeFile(DATA_FILE, "[]", "utf8");
  }
}

function saveDonations() {
  writeQueue = writeQueue.then(async () => {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const temp = DATA_FILE + ".tmp";
    await fs.writeFile(temp, JSON.stringify(donations, null, 2), "utf8");
    await fs.rename(temp, DATA_FILE);
  });
  return writeQueue;
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function createSession() {
  const payload = Buffer.from(JSON.stringify({
    expires: Date.now() + SESSION_DURATION
  })).toString("base64url");
  return payload + "." + sign(payload);
}

function validSession(req) {
  const cookie = (req.headers.cookie || "").split("; ")
    .find((item) => item.startsWith("mh_admin="));
  if (!cookie) return false;

  const parts = cookie.slice("mh_admin=".length).split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;
  const expected = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    return Number(data.expires) > Date.now();
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  if (!validSession(req)) {
    return res.status(401).json({ error: "Admin login required." });
  }
  next();
}

function verifiedTotal() {
  return donations
    .filter((d) => d.status === "verified")
    .reduce((sum, d) => sum + d.amount, 0);
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.post("/api/donations", async (req, res, next) => {
  try {
    const { name, amount, paymentMethod, reference, publicConsent } = req.body || {};
    const value = Number(amount);

    if (
      typeof name !== "string" ||
      name.trim().length < 2 ||
      name.trim().length > 100 ||
      !Number.isFinite(value) ||
      value <= 0 ||
      value > 1000000000 ||
      typeof paymentMethod !== "string" ||
      paymentMethod.trim().length < 2 ||
      paymentMethod.length > 60 ||
      (reference !== undefined && typeof reference !== "string")
    ) {
      return res.status(400).json({ error: "Check your donation details." });
    }

    const donation = {
      id: crypto.randomUUID(),
      name: name.trim(),
      amount: value,
      paymentMethod: paymentMethod.trim(),
      reference: typeof reference === "string" ? reference.trim().slice(0, 100) : "",
      publicConsent: publicConsent === true,
      status: "pending",
      createdAt: new Date().toISOString(),
      verifiedAt: null
    };

    donations.push(donation);
    await saveDonations();

    res.status(201).json({
      message: "Donation submitted for review.",
      id: donation.id,
      status: donation.status
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/donations", (req, res) => {
  const publicDonations = donations
    .filter((d) => d.status === "verified" && d.publicConsent)
    .map((d) => ({
      name: d.name,
      amount: d.amount,
      verifiedAt: d.verifiedAt
    }));

  res.json({ total: verifiedTotal(), donations: publicDonations });
});

app.post("/api/admin/login", (req, res) => {
  const ip = req.ip;
  const attempt = loginAttempts.get(ip) || { count: 0, until: 0 };

  if (Date.now() < attempt.until) {
    return res.status(429).json({ error: "Too many attempts. Try again later." });
  }

  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  const matches = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!matches) {
    attempt.count++;
    if (attempt.count >= 5) {
      attempt.count = 0;
      attempt.until = Date.now() + 15 * 60 * 1000;
    }
    loginAttempts.set(ip, attempt);
    return res.status(401).json({ error: "Incorrect password." });
  }

  loginAttempts.delete(ip);
  res.setHeader(
    "Set-Cookie",
    `mh_admin=${createSession()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=7200`
  );
  res.json({ message: "Login successful." });
});

app.post("/api/admin/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "mh_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
  );
  res.json({ message: "Logged out." });
});

app.get("/api/admin/donations", requireAdmin, (req, res) => {
  res.json({ donations, totalVerified: verifiedTotal() });
});

app.post("/api/admin/donations/:id/verify", requireAdmin, async (req, res, next) => {
  try {
    const donation = donations.find((d) => d.id === req.params.id);
    if (!donation) return res.status(404).json({ error: "Donation not found." });
    if (donation.status !== "pending") {
      return res.status(409).json({ error: "Donation has already been reviewed." });
    }

    donation.status = "verified";
    donation.verifiedAt = new Date().toISOString();
    await saveDonations();

    res.json({
      message: "Donation verified.",
      donation,
      totalVerified: verifiedTotal()
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/donations/:id/reject", requireAdmin, async (req, res, next) => {
  try {
    const donation = donations.find((d) => d.id === req.params.id);
    if (!donation) return res.status(404).json({ error: "Donation not found." });
    if (donation.status !== "pending") {
      return res.status(409).json({ error: "Donation has already been reviewed." });
    }

    donation.status = "rejected";
    await saveDonations();
    res.json({ message: "Donation rejected." });
  } catch (error) {
    next(error);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Server error. Please try again." });
});

loadDonations()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Matendo ya Huruma running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Failed to load donations:", error);
    process.exit(1);
  });
