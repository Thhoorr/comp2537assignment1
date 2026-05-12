require("dotenv").config();
const express = require("express");
const Joi = require("joi");
const app = express();
const port = process.env.PORT || 3000;
const session = require("cookie-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const SALT_ROUNDS = 12;

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    name: "session",
    username: null,
    authenticated: false,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 },
  }),
);
app.set("view engine", "ejs");

mongoose.connect(process.env.MONGODB_URI || process.env.LOCAL_DB_URI);

const signUpSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(1)
    .max(20)
    .pattern(/^[a-zA-Z0-9 .,'_-]+$/)
    .required(),
  email: Joi.string()
    .trim()
    .email({ tlds: { allow: false } })
    .required(),
  password: Joi.string().min(8).max(100).required(),
});

const loginSchema = Joi.object({
  email: Joi.string()
    .trim()
    .email({ tlds: { allow: false } })
    .required(),
  password: Joi.string().min(8).max(100).required(),
});

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
  user_type: { type: String, default: "user" },
});

const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => {
  res.render("signuplogin");
});

app.get("/signup", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/loggedIn");
    return;
  }
  res.render("signup");
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/loggedIn");
    return;
  }
  res.render("login");
});

app.post("/signingup", async (req, res) => {
  const { name, email, password } = req.body;

  const { error, value } = signUpSchema.validate(
    { name, email, password },
    { abortEarly: false, stripUnknown: true },
  );

  if (error) {
    const messages = error.details.map((detail) => detail.message).join("\n");

    res.render("tryagain", { message: messages, action: "/signup" });
    return;
  }

  try {
    const hashedPassword = await bcrypt.hash(value.password, SALT_ROUNDS);

    const newUser = new User({
      name: value.name,
      email: value.email,
      password: hashedPassword,
    });

    await newUser.save();

    req.session.username = newUser.name;
    req.session.authenticated = true;

    res.redirect("/loggedIn");
  } catch (err) {
    if (err.code === 11000) {
      res.render("tryagain", {
        message: "Email already registered.",
        action: "/signup",
      });
      return;
    }
    next(err);
  }
});

app.post("/loggingin", async (req, res, next) => {
  const { email, password } = req.body;

  const { error, value } = loginSchema.validate(
    { email, password },
    { abortEarly: false, stripUnknown: true },
  );

  if (error) {
    const messages = error.details.map((detail) => detail.message).join("\n");
    res.render("tryagain", { message: messages, action: "/login" });
    return;
  }

  const user = await User.findOne({ email: email.trim().toLowerCase() });
  if (!user) {
    res.render("tryagain", {
      message: "Invalid email or password.",
      action: "/login",
    });
    return;
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    res.render("tryagain", {
      message: "Invalid email or password.",
      action: "/login",
    });
    return;
  }

  req.session.authenticated = true;
  req.session.username = user.name;

  res.redirect("/loggedIn");
});

app.get("/loggedIn", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  res.render("loggedIn", {
    username: req.session.username,
  });
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  res.render("members", {
    username: req.session.username,
  });
});

async function isAdmin(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  const user = await User.findOne({ name: req.session.username });
  if (!user) {
    res.render("tryagain", {
      message: "Could not find user with your name.",
      action: "/login",
    });
    return;
  }
  if (user.user_type !== "admin") {
    res.status(403);
    res.render("tryagain", {
      message: "You do not have permission to access this page.",
      action: "/loggedIn",
    });
    return;
  }
  next();
}

app.get("/admin", isAdmin, async (req, res) => {
  const users = await User.find({}, "name email user_type").lean();
  res.render("users", { users: users });
});

app.post("/admin/:action/:email", isAdmin, async (req, res) => {
  const email = req.params.email;
  const user = await User.findOne({ email: email.trim().toLowerCase() });
  if (!user) {
    res.render("tryagain", {
      message: "Could not find user with that email.",
      action: "/admin",
    });
    return;
  }
  user.user_type =
    req.params.action === "promote"
      ? "admin"
      : req.params.action === "demote"
        ? "user"
        : user.user_type;
  await user.save();
  res.redirect("/admin");
});

app.post("/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

// 404 handler
app.use((req, res) => {
  res.status(404).send("Not Found");
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Server Error");
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
