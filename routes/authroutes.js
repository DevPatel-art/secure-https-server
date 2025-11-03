
const express = require("express");
const passport = require("../auth/passport.cjs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Users, UsersByEmail, RefreshTokens } = require("../db/DBManager.js");

const router = express.Router();


router.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/login-failed",
    successRedirect: "/auth/login-success",
  })
);

router.get("/auth/login-success", (req, res) => {
  res.json({ message: "Login successful!", user: req.user });
});

router.get("/auth/login-failed", (req, res) => {
  res.status(401).json({ message: "Login failed" });
});

router.get("/auth/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.json({ message: "Logged out" });
  });
});

router.get("/auth/me", (req, res) => {
  if (!req.user) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: req.user });
});


router.post("/auth/local/signup", async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email & password required" });

  if (UsersByEmail[email])
    return res.status(409).json({ error: "Email already registered" });

  const id = "local_" + Date.now();
  const passwordHash = await bcrypt.hash(password, 12);

  const user = {
    id,
    name: name || email.split("@")[0],
    email,
    passwordHash,
    role: "User",
    provider: "local",
  };

  Users[id] = user;
  UsersByEmail[email] = id;

  res.status(201).json({
    message: "User created",
    user: { id: user.id, email: user.email, name: user.name },
  });
});

router.post("/auth/local/login", async (req, res, next) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email & password required" });

  const userId = UsersByEmail[email];
  if (!userId) return res.status(401).json({ error: "Invalid credentials" });

  const user = Users[userId];
  const ok = await bcrypt.compare(password, user.passwordHash || "");
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  req.session.regenerate(err => {
    if (err) return next(err);
    req.login(user, err2 => {
      if (err2) return next(err2);
      res.json({
        message: "Logged in (session)",
        user: { id: user.id, email: user.email, role: user.role },
      });
    });
  });
});


const JWT_ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET || "dev_access_secret_change_me";
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || "dev_refresh_secret_change_me";

function signAccessToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_ACCESS_SECRET, {
    expiresIn: "15m",
  });
}
function signRefreshToken(user) {
  return jwt.sign({ sub: user.id }, JWT_REFRESH_SECRET, { expiresIn: "7d" });
}

function jwtRequired(req, res, next) {
  const token =
    req.cookies.access_token ||
    (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Missing access token" });
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    const user = Users[payload.sub];
    if (!user) return res.status(401).json({ error: "Unknown user" });
    req.jwtUser = user;
    return next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }
}

router.post("/auth/jwt/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email & password required" });

  const userId = UsersByEmail[email];
  if (!userId) return res.status(401).json({ error: "Invalid credentials" });

  const user = Users[userId];
  const ok = await bcrypt.compare(password, user.passwordHash || "");
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  RefreshTokens[refreshToken] = {
    userId: user.id,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };

  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });
  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({ message: "JWT issued" });
});

router.post("/auth/jwt/refresh", (req, res) => {
  const rt = req.cookies.refresh_token;
  if (!rt) return res.status(401).json({ error: "Missing refresh token" });

  try {
    const payload = jwt.verify(rt, JWT_REFRESH_SECRET);
    const record = RefreshTokens[rt];
    if (!record || record.userId !== payload.sub)
      return res.status(401).json({ error: "Invalid refresh token" });

    const user = Users[payload.sub];
    if (!user) return res.status(401).json({ error: "Unknown user" });

    const newAccess = signAccessToken(user);
    res.cookie("access_token", newAccess, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });
    res.json({ message: "Access token refreshed" });
  } catch (e) {
    return res.status(401).json({ error: "Expired/invalid refresh token" });
  }
});

router.post("/auth/jwt/logout", (req, res) => {
  const rt = req.cookies.refresh_token;
  if (rt) delete RefreshTokens[rt];
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.json({ message: "JWT logout complete" });
});

router.get("/api/secret", jwtRequired, (req, res) => {
  res.json({
    ok: true,
    user: { id: req.jwtUser.id, role: req.jwtUser.role },
    secret: "JWT-only data",
  });
});


router.post("/auth/make-admin", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not authenticated" });
  Users[req.user.id].role = "Admin";
  return res.json({
    message: "Promoted to Admin",
    user: Users[req.user.id],
  });
});

module.exports = router;
