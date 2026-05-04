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
});

const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => {
  res.send(`
    <form action="/signup" method="get">
      <button>sign up</button>
    </form>
    <form action="/login" method="get">
      <button>log in</button>
    </form>
    `);
});

app.get("/signup", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/loggedIn");
  }
  res.send(`
    <form action="/signingup" method="post">
      <input name="name" type="text" placeholder="Name"/><br/>
      <input name="email" type="email" placeholder="Email"/><br/>
      <input name="password" type="password" placeholder="Password"/><br/>
      <button type="submit">Sign Up</button>
    </form>
    `);
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/loggedIn");
  }
  res.send(`
    <form action="/loggingin" method="post">
      <input name="email" type="email" placeholder="Email"/><br/>
      <input name="password" type="password" placeholder="Password"/><br/>
      <button type="submit">Log In</button>
    </form>
    `);
});

app.post("/signingup", async (req, res) => {
  const { name, email, password } = req.body;

  const { error, value } = signUpSchema.validate(
    { name, email, password },
    { abortEarly: false, stripUnknown: true },
  );

  if (error) {
    const messages = error.details.map((detail) => detail.message).join("\n");

    res.send(
      `${messages}
    <form action="/signup" method="get">
      <button>Try Again</button>
    </form>
    `,
    );
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
      res.send('Email already registered. <a href="/signup">Try again</a>.');
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

    res.send(
      `${messages}
    <form action="/login" method="get">
      <button>Try Again</button>
    </form>
    `,
    );
    return;
  }

  const user = await User.findOne({ email: email.trim().toLowerCase() });
  if (!user) {
    return res.send(
      'Invalid email or password. <a href="/login">Try again</a>.',
    );
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.send(
      'Invalid email or password. <a href="/login">Try again</a>.',
    );
  }

  req.session.authenticated = true;
  req.session.username = user.name;

  res.redirect("/loggedIn");
});

app.get("/loggedIn", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  res.send(`Hello, ${req.session.username}! <br/>
    <form action="/members" method="get">
      <button>Go to Members Area</button>
    </form>
    <form action="/logout" method="post">
      <button>Log Out</button>
    </form>
    `);
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  var randomImg = Math.floor(Math.random() * 3) + 1;
  res.send(`
    <h2>Hello, ${req.session.username}.</h2>
    <figure>
      <img src="${randomImg}.gif" alt="A cute kitten"/>
      <figcaption>A gif from my computer.</figcaption>
    </figure>
    <form action="/loggedIn" method="get">
      <button>Back to Home</button>
    </form>
    <form action="/logout" method="post">
      <button>Log Out</button>
    </form>
      `);
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    res.redirect("/");
  });
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
