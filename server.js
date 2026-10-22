
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs/promises");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.SESSION_SECRET;
const DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DF = path.join(DIR, "donations.json");
const RF = path.join(DIR, "reports.json");

if (!ADMIN_PASSWORD || !SECRET || SECRET.length < 32) {
  throw new Error("Set ADMIN_PASSWORD and SESSION_SECRET (minimum 32 characters).");
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "30kb" }));
app.use(express.static(path.join(__dirname, "public")));

let donations = [];
let reports = [];
let queue = Promise.resolve();
const attempts = new Map();

async function readFileData(file) {
  try {
    const data = JSON.parse(await fs.readFile(file, "utf8"));
    if (!Array.isArray(data)) throw new Error("Invalid data");
    return data;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    await fs.writeFile(file, "[]");
    return [];
  }
}

async function loadData() {
  await fs.mkdir(DIR, { recursive: true });
  donations = await readFileData(DF);
  reports = await readFileData(RF);
}

function saveData(file, data) {
  queue = queue.then(async () => {
    await fs.mkdir(DIR, { recursive: true });
    const temp = file + ".tmp";
    await fs.writeFile(temp, JSON.stringify(data, null, 2));
    await fs.rename(temp, file);
  });
  return queue;
}

function totalVerified() {
  return donations
    .filter(d => d.status === "verified")
    .reduce((sum, d) => sum + d.amount, 0);
}

function sign(value) {
  return crypto.createHmac("sha256", SECRET)
    .update(value)
    .digest("hex");
}

function createSession() {
  const payload = Buffer.from(JSON.stringify({
    expires: Date.now() + 7200000
  })).toString("base64url");

  return payload + "." + sign(payload);
}

function isAdmin(req) {
  const cookie = (req.headers.cookie || "")
    .split("; ")
    .find(item => item.startsWith("mh_admin="));

  if (!cookie) return false;

  const parts = cookie.slice(9).split(".");
  if (parts.length !== 2) return false;

  const expected = Buffer.from(sign(parts[0]));
  const actual = Buffer.from(parts[1]);

  if (
    expected.length !== actual.length ||
    !crypto.timingSafeEqual(expected, actual)
  ) return false;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );
    return payload.expires > Date.now();
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) {
    return res.status(401).json({
      error: "Admin login required."
    });
  }
  next();
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

/* Fomu ya mchango */
app.post("/api/donations", async (req, res, next) => {
  try {
    const body = req.body || {};
    const amount = Number(body.amount);

    if (
      typeof body.name !== "string" ||
      body.name.trim().length < 2 ||
      body.name.length > 100 ||
      !Number.isFinite(amount) ||
      amount < 100 ||
      amount > 1000000000 ||
      typeof body.paymentMethod !== "string" ||
      body.paymentMethod.trim().length < 2 ||
      body.paymentMethod.length > 60 ||
      typeof (body.reference || "") !== "string"
    ) {
      return res.status(400).json({
        error: "Tafadhali hakiki jina, kiasi na njia ya malipo."
      });
    }

    const donation = {
      id: crypto.randomUUID(),
      name: body.name.trim(),
      amount,
      paymentMethod: body.paymentMethod.trim(),
      reference: (body.reference || "").trim().slice(0, 100),
      publicConsent: body.showName === true || body.publicConsent === true,
      status: "pending",
      createdAt: new Date().toISOString(),
      verifiedAt: null
    };

    donations.push(donation);

    try {
      await saveData(DF, donations);
    } catch (error) {
      donations = donations.filter(d => d.id !== donation.id);
      throw error;
    }

    res.status(201).json({
      message: "Taarifa zimepokelewa na zinasubiri uhakiki."
    });
  } catch (error) {
    next(error);
  }
});

/* Jumla ya michango iliyothibitishwa pekee */
app.get("/api/donations", (req, res) => {
  const verified = donations.filter(d => d.status === "verified");

  res.set("Cache-Control", "no-store");
  res.json({
    total: totalVerified(),
    totalAmount: totalVerified(),
    donationCount: verified.length,
    donations: verified.map(d => ({
      name: d.publicConsent ? d.name : "",
      showName: d.publicConsent,
      amount: d.amount,
      createdAt: d.createdAt
    }))
  });
});

/* Fomu ya kuripoti watu au maeneo yenye uhitaji */
app.post("/api/reports", async (req, res, next) => {
  try {
    const body = req.body || {};
    const fields = [
      ["reporterName", 2, 100],
      ["contact", 5, 100],
      ["location", 2, 150],
      ["needType", 2, 80],
      ["details", 10, 1500]
    ];

    for (const [key, min, max] of fields) {
      if (
        typeof body[key] !== "string" ||
        body[key].trim().length < min ||
        body[key].length > max
      ) {
        return res.status(400).json({
          error: "Jaza taarifa zote zinazohitajika kwa usahihi."
        });
      }
    }

    const report = {
      id: crypto.randomUUID(),
      reporterName: body.reporterName.trim(),
      contact: body.contact.trim(),
      location: body.location.trim(),
      needType: body.needType.trim(),
      details: body.details.trim(),
      consentContact: body.consentContact === true,
      status: "new",
      createdAt: new Date().toISOString()
    };

    reports.push(report);

    try {
      await saveData(RF, reports);
    } catch (error) {
      reports = reports.filter(r => r.id !== report.id);
      throw error;
    }

    res.status(201).json({
      message: "Taarifa imepokelewa na itapitiwa."
    });
  } catch (error) {
    next(error);
  }
});

/* Kuingia kwa msimamizi */
app.post("/api/admin/login", (req, res) => {
  const ip = req.ip;
  const record = attempts.get(ip) || { count: 0, until: 0 };

  if (Date.now() < record.until) {
    return res.status(429).json({
      error: "Majaribio mengi. Jaribu tena baadaye."
    });
  }

  const password = typeof req.body?.password === "string"
    ? req.body.password
    : "";

  const actual = Buffer.from(password);
  const expected = Buffer.from(ADMIN_PASSWORD);

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    record.count++;

    if (record.count >= 5) {
      record.count = 0;
      record.until = Date.now() + 900000;
    }

    attempts.set(ip, record);

    return res.status(401).json({
      error: "Nenosiri si sahihi."
    });
  }

  attempts.delete(ip);

  res.setHeader(
    "Set-Cookie",
    `mh_admin=${createSession()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=7200`
  );

  res.json({ message: "Umeingia." });
});

app.post("/api/admin/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "mh_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
  );
  res.json({ message: "Umetoka." });
});

/* Msimamizi anaona michango yote */
app.get("/api/admin/donations", requireAdmin, (req, res) => {
  res.json({
    donations,
    totalVerified: totalVerified()
  });
});

/* Kuthibitisha au kukataa mchango */
app.post(
  "/api/admin/donations/:id/:action",
  requireAdmin,
  async (req, res, next) => {
    try {
      const donation = donations.find(d => d.id === req.params.id);

      if (!donation) {
        return res.status(404).json({
          error: "Mchango haujapatikana."
        });
      }

      if (donation.status !== "pending") {
        return res.status(409).json({
          error: "Tayari umekaguliwa."
        });
      }

      if (!["verify", "reject"].includes(req.params.action)) {
        return res.status(400).json({
          error: "Kitendo si sahihi."
        });
      }

      const oldStatus = donation.status;
      const oldDate = donation.verifiedAt;

      donation.status = req.params.action === "verify"
        ? "verified"
        : "rejected";

      donation.verifiedAt = donation.status === "verified"
        ? new Date().toISOString()
        : null;

      try {
        await saveData(DF, donations);
      } catch (error) {
        donation.status = oldStatus;
        donation.verifiedAt = oldDate;
        throw error;
      }

      res.json({
        message: "Hali ya mchango imesasishwa.",
        totalVerified: totalVerified()
      });
    } catch (error) {
      next(error);
    }
  }
);

/* Msimamizi anaona taarifa za uhitaji */
app.get("/api/admin/reports", requireAdmin, (req, res) => {
  res.json({ reports });
});

/* Kubadilisha hali ya taarifa ya uhitaji */
app.post(
  "/api/admin/reports/:id/review",
  requireAdmin,
  async (req, res, next) => {
    try {
      const report = reports.find(r => r.id === req.params.id);
      const status = req.body?.status;

      if (!report) {
        return res.status(404).json({
          error: "Taarifa haijapatikana."
        });
      }

      if (!["new", "reviewing", "resolved", "closed"].includes(status)) {
        return res.status(400).json({
          error: "Hali si sahihi."
        });
      }

      const oldStatus = report.status;
      report.status = status;
      report.updatedAt = new Date().toISOString();

      try {
        await saveData(RF, reports);
      } catch (error) {
        report.status = oldStatus;
        throw error;
      }

      res.json({ message: "Hali imesasishwa." });
    } catch (error) {
      next(error);
    }
  }
);

app.use((error, req, res, next) => {
  console.error(error);
  if (!res.headersSent) {
    res.status(500).json({
      error: "Hitilafu ya seva. Jaribu tena baadaye."
    });
  }
});

loadData()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("Matendo ya Huruma running on port " + PORT);
    });
  })
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
