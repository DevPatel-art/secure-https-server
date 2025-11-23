require("dotenv").config();

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const session = require("express-session");
const passport = require("./auth/passport.cjs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const profileRoutes = require("./routes/profile");
const authRouter = require("./routes/authroutes.js");

const HTTP_PORT = 3000;
const HTTPS_PORT = 3001;

const keyPath = path.join(__dirname, "cert", "private-key.pem");
const crtPath = path.join(__dirname, "cert", "certificate.pem");
if (!fs.existsSync(keyPath) || !fs.existsSync(crtPath)) {
  console.error("❌ Missing SSL files.\nExpected:\n -", keyPath, "\n -", crtPath);
  process.exit(1);
}
const httpsOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(crtPath),
};

const app = express();

app.use(helmet());
app.use(helmet.frameguard({ action: "deny" }));
app.use(
  helmet.hsts({ maxAge: 15552000, includeSubDomains: true, preload: false })
);
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
    },
  })
);

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

app.use(compression());
app.use(express.json({ limit: "100kb" }));
app.use(morgan("tiny"));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const csrfProtection = csrf({ cookie: true });
app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/auth", authLimiter);

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, 
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(authRouter);
app.use(profileRoutes);


const cacheFor =
  (seconds, { swr = 0, privacy = "public" } = {}) =>
  (req, res, next) => {
    const parts = [`${privacy}`, `max-age=${seconds}`];
    if (swr > 0) parts.push(`stale-while-revalidate=${swr}`);
    res.setHeader("Cache-Control", parts.join(", "));
    next();
  };

const posts = [
  { id: "b1", title: "Security-first backend", public: true },
  { id: "b2", title: "Cache-Control strategies", public: true },
];
const users = [{ id: "u1", name: "Dev Patel", email: "dev.patel@edu.sait.ca" }];

app.get("/", (req, res) => {
  res.setHeader(
    "Cache-Control",
    "public, max-age=60, stale-while-revalidate=30"
  );
  res.send("<h1>Secure HTTPS Server</h1><h2>Phase-2 Auth Server Running ✅</h2>");
});

app.get(
  "/posts",
  cacheFor(300, { swr: 60, privacy: "public" }),
  (req, res) => res.json(posts)
);

app.get("/posts/:id", (req, res) => {
  const p = posts.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "Not found" });
  res.setHeader(
    "Cache-Control",
    "public, max-age=300, stale-while-revalidate=60"
  );
  res.json(p);
});

app.get("/profile", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(users[0]);
});

app.get("/healthz", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get(
  "/docs/security",
  cacheFor(120, { swr: 30, privacy: "public" }),
  (req, res) =>
    res.json({
      https: true,
      headers: [
        "CSP",
        "HSTS",
        "X-Frame-Options",
        "X-Content-Type-Options",
      ],
      caching: "Public endpoints short cache; sensitive endpoints no-store",
    })
);

https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
  console.log(`🔐 HTTPS server on https://localhost:${HTTPS_PORT}`);
});

const redirectApp = express();
redirectApp.use((req, res) => {
  const host = (req.headers.host || "localhost").split(":")[0];
  res.redirect(301, `https://${host}:${HTTPS_PORT}${req.originalUrl}`);
});
http.createServer(redirectApp).listen(HTTP_PORT, () => {
  console.log(`➡️  HTTP redirector on http://localhost:${HTTP_PORT}`);
});

app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect("/"); 
  }

  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});
