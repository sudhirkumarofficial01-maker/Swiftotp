require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(__dirname));

app.use(
  "/api",
  rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false
  })
);

/* ---------- Session helpers ---------- */

const sessions = new Map();

function createSession(user) {
  const id = crypto.randomBytes(32).toString("hex");

  sessions.set(id, {
    ...user,
    createdAt: Date.now()
  });

  return id;
}

function getSession(req) {
  const id = req.headers["x-session-id"];

  if (!id) return null;

  const session = sessions.get(id);

  if (!session) return null;

  // 24 hour session
  if (Date.now() - session.createdAt > 86400000) {
    sessions.delete(id);
    return null;
  }

  return session;
}

/* ---------- Health ---------- */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "SwiftOTP"
  });
});

/* ---------- MSG91 access-token verification ---------- */

app.post("/api/auth/verify", async (req, res) => {
  try {
    const accessToken = String(req.body?.accessToken || "");

    if (!accessToken) {
      return res.status(400).json({
        ok: false,
        error: "Missing access token."
      });
    }

    if (!process.env.MSG91_AUTHKEY) {
      return res.status(500).json({
        ok: false,
        error: "MSG91_AUTHKEY is not configured."
      });
    }

    const response = await fetch(
      "https://control.msg91.com/api/v5/widget/verifyAccessToken",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          authkey: process.env.MSG91_AUTHKEY,
          "access-token": accessToken
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(401).json({
        ok: false,
        error: "MSG91 token verification failed."
      });
    }

    /*
      MSG91 response structure can vary.
      Keep the verified response server-side.
    */

    const user = {
      verified: true,
      provider: "MSG91",
      verifiedAt: new Date().toISOString(),
      data
    };

    const sessionId = createSession(user);

    return res.json({
      ok: true,
      sessionId,
      user: {
        verified: true,
        provider: "MSG91",
        verifiedAt: user.verifiedAt
      }
    });

  } catch (error) {
    console.error("MSG91 verification error:", error);

    return res.status(500).json({
      ok: false,
      error: "Authentication service error."
    });
  }
});

/* ---------- Current user ---------- */

app.get("/api/me", (req, res) => {
  const session = getSession(req);

  if (!session) {
    return res.status(401).json({
      ok: false,
      error: "Not authenticated."
    });
  }

  res.json({
    ok: true,
    user: {
      verified: session.verified,
      provider: session.provider,
      verifiedAt: session.verifiedAt
    }
  });
});

/* ---------- Logout ---------- */

app.post("/api/logout", (req, res) => {
  const id = req.headers["x-session-id"];

  if (id) {
    sessions.delete(id);
  }

  res.json({
    ok: true
  });
});

/* ---------- Website ---------- */

app.get(/.*/, (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`SwiftOTP running on port ${PORT}`);
});
