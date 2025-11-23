export const PORT = process.env.PORT || 3001;
export const SESSION_SECRET = process.env.SESSION_SECRET || "dev_session_secret_change_me";
export const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "<YOUR_GOOGLE_CLIENT_ID>";
export const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "<YOUR_GOOGLE_CLIENT_SECRET>";
export const GOOGLE_REDIRECT_URL = process.env.GOOGLE_REDIRECT_URL || "https://localhost:3001/auth/google/callback";
