require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));

app.use(express.static(__dirname));

app.use(
  "/api",
  rateLimit({
    windowMs: 60 * 1000,
    max: 30
  })
);

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "SwiftOTP"
  });
});

app.post("/api/otp/request", (req, res) => {
  const phone = String(req.body?.phone || "");

  if (!/^\+91\d{10}$/.test(phone)) {
    return res.status(400).json({
      ok: false,
      error: "Use +91XXXXXXXXXX format."
    });
  }

  return res.status(501).json({
    ok: false,
    error: "SMS provider is not connected yet."
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`SwiftOTP running on port ${PORT}`);
});
