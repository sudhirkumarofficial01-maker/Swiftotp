require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;

/* ================================
   SECURITY
================================ */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: "20kb"
  })
);

app.use(express.static(__dirname));


/* ================================
   API RATE LIMIT
================================ */

app.use(
  "/api",
  rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false
  })
);


/* ================================
   SESSION STORAGE
================================ */

const sessions = new Map();

function createSession(user) {

  const sessionId =
    crypto.randomBytes(32).toString("hex");

  sessions.set(sessionId, {
    ...user,
    createdAt: Date.now()
  });

  return sessionId;
}


function getSession(req) {

  const sessionId =
    req.headers["x-session-id"];

  if (!sessionId) {
    return null;
  }

  const session =
    sessions.get(sessionId);

  if (!session) {
    return null;
  }

  /* 24 hour session */

  if (
    Date.now() - session.createdAt >
    24 * 60 * 60 * 1000
  ) {

    sessions.delete(sessionId);

    return null;
  }

  return session;
}


/* ================================
   HEALTH
================================ */

app.get(
  "/api/health",
  (_req, res) => {

    res.json({
      ok: true,
      service: "SwiftOTP"
    });

  }
);


/* ================================
   MSG91 ACCESS TOKEN VERIFY
================================ */

app.post(
  "/api/auth/verify",
  async (req, res) => {

    try {

      const accessToken =
        String(
          req.body?.accessToken || ""
        ).trim();


      if (!accessToken) {

        return res.status(400).json({
          ok: false,
          error:
            "Access token missing."
        });

      }


      const authKey =
        process.env.MSG91_AUTHKEY;


      if (!authKey) {

        console.error(
          "MSG91_AUTHKEY missing"
        );

        return res.status(500).json({
          ok: false,
          error:
            "MSG91_AUTHKEY is not configured."
        });

      }


      /*
       * MSG91 Access Token Verification
       */

      const response =
        await fetch(
          "https://control.msg91.com/api/v5/widget/verifyAccessToken",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              "authkey":
                authKey
            },

            body: JSON.stringify({
              "access-token":
                accessToken
            })
          }
        );


      const data =
        await response.json()
          .catch(() => ({}));


      console.log(
        "MSG91 verify status:",
        response.status
      );


      if (!response.ok) {

        console.error(
          "MSG91 verify response:",
          data
        );

        return res.status(401).json({

          ok: false,

          error:
            "MSG91 access token verification failed."

        });

      }


      /*
       * Create application session
       */

      const user = {

        verified: true,

        provider: "MSG91",

        verifiedAt:
          new Date().toISOString(),

        msg91: data

      };


      const sessionId =
        createSession(user);


      return res.json({

        ok: true,

        sessionId,

        user: {

          verified: true,

          provider: "MSG91",

          verifiedAt:
            user.verifiedAt

        }

      });

    }

    catch (error) {

      console.error(
        "Authentication error:",
        error
      );

      return res.status(500).json({

        ok: false,

        error:
          "Authentication service error."

      });

    }

  }
);


/* ================================
   CURRENT USER
================================ */

app.get(
  "/api/me",
  (req, res) => {

    const session =
      getSession(req);


    if (!session) {

      return res.status(401).json({

        ok: false,

        error:
          "Not authenticated."

      });

    }


    return res.json({

      ok: true,

      user: {

        verified:
          session.verified,

        provider:
          session.provider,

        verifiedAt:
          session.verifiedAt

      }

    });

  }
);


/* ================================
   LOGOUT
================================ */

app.post(
  "/api/logout",
  (req, res) => {

    const sessionId =
      req.headers["x-session-id"];


    if (sessionId) {

      sessions.delete(
        sessionId
      );

    }


    return res.json({
      ok: true
    });

  }
);


/* ================================
   DASHBOARD
================================ */

app.get(
  "/dashboard.html",
  (_req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "dashboard.html"
      )
    );

  }
);


/* ================================
   WEBSITE
================================ */

app.get(
  /.*/,
  (_req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );

  }
);


/* ================================
   START
================================ */

app.listen(
  PORT,
  () => {

    console.log(
      `SwiftOTP running on port ${PORT}`
    );

  }
);
