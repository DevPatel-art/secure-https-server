
const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const { Users } = require("../db/DBManager.js");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL || "https://localhost:3001/auth/google/callback";

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn("⚠️ Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in .env file.");
}
if (!process.env.GOOGLE_CALLBACK_URL) {
  console.warn(`ℹ️ Using default callback URL: ${GOOGLE_CALLBACK_URL}`);
}

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      try {
        const user = {
          id: profile?.id,
          name: profile?.displayName || "Unknown",
          email: profile?.emails?.[0]?.value,
          profile_photo: profile?.photos?.[0]?.value,
          role: "User",
          provider: "google",
        };

        if (!user.id) return done(new Error("No profile.id from Google"), null);

        Users[user.id] = { ...(Users[user.id] || {}), ...user };

        return done(null, Users[user.id]);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  try {
    if (!user || typeof user.id !== "string") {
      return done(new Error("serializeUser: user.id is missing or invalid"));
    }
    done(null, user.id);
  } catch (err) {
    done(err);
  }
});

passport.deserializeUser((id, done) => {
  try {
    if (!id || typeof id !== "string") {
      return done(new Error("deserializeUser: invalid id"));
    }
    const user = Users[id] || null;
    done(null, user);
  } catch (err) {
    done(err);
  }
});

module.exports = passport;
