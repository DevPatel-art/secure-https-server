
const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const { Users } = require("../db/DBManager.js");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URL =
  process.env.GOOGLE_REDIRECT_URL || "https://localhost:3001/auth/google/callback";

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn(
    "⚠️ Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in .env file."
  );
}

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_REDIRECT_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      try {

        const user = {
          id: profile.id,
          name: profile.displayName,
          email:
            profile.emails && profile.emails[0]
              ? profile.emails[0].value
              : undefined,
          profile_photo:
            profile.photos && profile.photos[0]
              ? profile.photos[0].value
              : undefined,
          role: "User",
          provider: "google",
        };

        Users[user.id] = user;

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  try {
    if (!user || !user.id || typeof user.id !== "string") {
      return done(new Error("serializeUser: user.id is missing or invalid"));
    }
    done(null, user.id);
  } catch (error) {
    done(error);
  }
});

passport.deserializeUser((id, done) => {
  try {
    if (!id || typeof id !== "string") {
      return done(new Error("deserializeUser: invalid id"));
    }
    const user = Users[id];
    done(null, user || null);
  } catch (error) {
    done(error);
  }
});

module.exports = passport;
