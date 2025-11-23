const crypto = require("crypto");
const ENC_KEY = process.env.PROFILE_ENC_KEY; 
const ALGO = "aes-256-gcm";

if (!ENC_KEY || ENC_KEY.length !== 32) {
  console.warn("WARNING: PROFILE_ENC_KEY must be 32 characters long");
}

function encrypt(text) {
  if (!text) return null;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, Buffer.from(ENC_KEY), iv);

  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");
  const tag = cipher.getAuthTag().toString("base64");

  // store as iv:tag:data
  return `${iv.toString("base64")}:${tag}:${encrypted}`;
}

function decrypt(payload) {
  if (!payload) return null;

  const [ivB64, tagB64, dataB64] = payload.split(":");
  if (!ivB64 || !tagB64 || !dataB64) return null;

  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");

  const decipher = crypto.createDecipheriv(ALGO, Buffer.from(ENC_KEY), iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(dataB64, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

module.exports = { encrypt, decrypt };
