const express = require("express");
const { body, validationResult } = require("express-validator");
const escapeHtml = require("escape-html");

const { Users } = require("../db/DBManager.js");
const { encrypt, decrypt } = require("../security/encryption");
const { ensureAuthenticated } = require("../middleware/auth");

const router = express.Router();

router.get("/api/profile", ensureAuthenticated, (req, res) => {
  const userId = req.user && req.user.id;
  const user = userId && Users[userId];

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const decryptedEmail = user.encrypted_email
    ? decrypt(user.encrypted_email)
    : user.email;

  const decryptedBio = user.encrypted_bio ? decrypt(user.encrypted_bio) : "";

  const safeName = escapeHtml(user.name || "");
  const safeEmail = escapeHtml(decryptedEmail || "");
  const safeBio = escapeHtml(decryptedBio || "");

  return res.json({
    id: user.id,
    name: safeName,
    email: safeEmail,
    bio: safeBio,
  });
});

router.post(
  "/api/profile",
  ensureAuthenticated,
  [
    body("name")
      .trim()
      .isLength({ min: 3, max: 50 })
      .withMessage("Name must be 3–50 characters")
      .matches(/^[A-Za-z\s]+$/)
      .withMessage("Name must contain only letters and spaces")
      .escape(),

    body("email")
      .trim()
      .isEmail()
      .withMessage("Invalid email format")
      .normalizeEmail(),

    body("bio")
      .trim()
      .isLength({ max: 500 })
      .withMessage("Bio must be 500 characters or less")
      .matches(/^[A-Za-z0-9 .,!?'"-]*$/)
      .withMessage("Bio contains invalid characters")
      .escape(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: "Validation failed",
        errors: errors.array(),
      });
    }

    const userId = req.user && req.user.id;
    const user = userId && Users[userId];
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { name, email, bio } = req.body;

    const encryptedEmail = encrypt(email);
    const encryptedBio = encrypt(bio || "");

    user.name = name;
    user.encrypted_email = encryptedEmail;
    user.encrypted_bio = encryptedBio;

    user.email = email;

    return res.json({
      message: "Profile updated successfully",
      user: {
        id: user.id,
        name: escapeHtml(user.name || ""),
        email: escapeHtml(decrypt(user.encrypted_email) || ""),
        bio: escapeHtml(decrypt(user.encrypted_bio) || ""),
      },
    });
  }
);

module.exports = router;
