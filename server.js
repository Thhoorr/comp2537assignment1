require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database connection ──────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ── User model ───────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// ── Joi validation schema ────────────────────────────────────────────────────
// Joi strips unknown keys by default, preventing NoSQL injection via extra fields.
const signupSchema = Joi.object({
  name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z\s'\-]+$/) // letters, spaces, apostrophes, hyphens only
    .required()
    .messages({
      "string.pattern.base":
        "Name may only contain letters, spaces, apostrophes, and hyphens.",
      "string.min": "Name must not be empty.",
      "string.max": "Name must be 100 characters or fewer.",
      "any.required": "Name is required.",
    }),

  email: Joi.string()
    .email({ tlds: { allow: false } })
    .max(254)
    .required()
    .messages({
      "string.email": "Please enter a valid email address.",
      "string.max": "Email must be 254 characters or fewer.",
      "any.required": "Email is required.",
    }),

  password: Joi.string().min(8).max(128).required().messages({
    "string.min": "Password must be at least 8 characters.",
    "string.max": "Password must be 128 characters or fewer.",
    "any.required": "Password is required.",
  }),
});

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: false })); // parse form POST bodies
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me-in-production",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 60 * 60 * 24, // sessions expire after 24 hours
    }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24,
    },
  }),
);

// ── Middleware: require login ────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/signup");
  }
  next();
}

// ── Routes ───────────────────────────────────────────────────────────────────

// GET /signup  — show the signup form
app.get("/signup", (req, res) => {
  // If already logged in, skip to /loggedin
  if (req.session.userId) return res.redirect("/loggedin");
  res.send(renderSignupPage());
});

// POST /signup  — process the form
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // ── 1. Basic empty-field check (catches missing keys too) ─────────────────
  const emptyFields = [];
  if (!name || String(name).trim() === "") emptyFields.push("Name");
  if (!email || String(email).trim() === "") emptyFields.push("Email");
  if (!password || String(password).trim() === "") emptyFields.push("Password");

  if (emptyFields.length > 0) {
    const msg = `The following field${emptyFields.length > 1 ? "s are" : " is"} required: ${emptyFields.join(", ")}.`;
    return res.status(400).send(renderSignupPage({ error: msg, name, email }));
  }

  // ── 2. Joi validation (type safety + NoSQL injection prevention) ───────────
  const { error: joiError, value: safeData } = signupSchema.validate(
    { name, email, password },
    { abortEarly: false, stripUnknown: true },
  );

  if (joiError) {
    const messages = joiError.details.map((d) => d.message).join(" ");
    return res
      .status(400)
      .send(renderSignupPage({ error: messages, name, email }));
  }

  try {
    // ── 3. Check for duplicate email ─────────────────────────────────────────
    const existing = await User.findOne({ email: safeData.email }).lean();
    if (existing) {
      return res
        .status(409)
        .send(
          renderSignupPage({
            error: "An account with that email already exists.",
            name,
          }),
        );
    }

    // ── 4. Hash password with bcrypt (cost factor 12) ─────────────────────────
    const hashedPassword = await bcrypt.hash(safeData.password, 12);

    // ── 5. Save user to MongoDB ───────────────────────────────────────────────
    const user = await User.create({
      name: safeData.name,
      email: safeData.email,
      password: hashedPassword,
    });

    // ── 6. Create session and redirect ────────────────────────────────────────
    req.session.userId = user._id.toString();
    req.session.userName = user.name;

    return res.redirect("/loggedin");
  } catch (err) {
    console.error("Signup error:", err);
    return res
      .status(500)
      .send(
        renderSignupPage({ error: "Something went wrong. Please try again." }),
      );
  }
});

// GET /loggedin  — protected page shown after signup
app.get("/loggedin", requireLogin, async (req, res) => {
  res.send(renderLoggedInPage(req.session.userName));
});

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/signup"));
});

// ── HTML templates (zero CSS) ─────────────────────────────────────────────────

function renderSignupPage({ error, name = "", email = "" } = {}) {
  const errorHtml = error
    ? `<p><strong>Error:</strong> ${escapeHtml(error)}</p><hr>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sign Up</title>
</head>
<body>
  <h1>Create an Account</h1>
  <p>Fill in the details below to get started.</p>
  <hr>

  ${errorHtml}

  <form method="post" action="/signup">
    <p>
      <label for="name">Full Name:</label><br>
      <input type="text" id="name" name="name" value="${escapeHtml(name)}" autocomplete="name" required>
    </p>
    <p>
      <label for="email">Email Address:</label><br>
      <input type="email" id="email" name="email" value="${escapeHtml(email)}" autocomplete="email" required>
    </p>
    <p>
      <label for="password">Password:</label><br>
      <input type="password" id="password" name="password" autocomplete="new-password" required>
    </p>
    <p>
      <input type="submit" value="Create Account">
    </p>
  </form>

  <hr>
  <p>Already have an account? <a href="/login">Log in</a></p>
</body>
</html>`;
}

function renderLoggedInPage(name) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Welcome!</title>
</head>
<body>
  <h1>You're in, ${escapeHtml(name)}!</h1>
  <p>Your account has been created and you are now logged in.</p>
  <hr>
  <p><a href="/logout">Log out</a></p>
</body>
</html>`;
}

// ── XSS helper ────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}/signup`),
);
