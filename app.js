require("dotenv").config();
const express = require("express");
const Joi = require("joi");
const app = express();
const port = process.env.PORT || 3000;
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "some random whatver",
    name: null,
    authenticated: false,
    resave: false,
    saveUninitialized: false,
  }),
);

mongoose.connect(
  process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/comp2537assignment1",
);

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

const signupSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9 .,'_-]+$/)
    .required(),
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

app.post("/signingup", async (req, res) => {
  const { name, email, password } = req.body;

  const { error, value } = signupSchema.validate(
    { name, email, password },
    { abortEarly: false, stripUnknown: true },
  );

  if (error) {
    const messages = error.details.map((detail) => detail.message).join(" ");
    res.send(
      `Validation error: ${messages}
      <form action="/signup" method="get">
        <button>Try Again</button>
      </form>
      `,
    );
    return;
  }

  const emptyFields = [];
  if (!value.name) emptyFields.push("Name");
  if (!value.email) emptyFields.push("Email");
  if (!value.password) emptyFields.push("Password");

  if (emptyFields.length > 0) {
    const msg = `The following field${emptyFields.length > 1 ? "s are" : " is"} required: ${emptyFields.join(", ")}.`;
    res.send(
      msg +
        `
      <form action="/signup" method="get">
        <button>Try Again</button>
      </form>
      `,
    );
    return;
  }

  try {
    const hashedPassword = await bcrypt.hash(value.password, 10);

    const newUser = new User({
      name: value.name,
      email: value.email,
      password: hashedPassword,
    });

    await newUser.save();

    req.session.name = newUser.name;
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

app.get("/login", (req, res) => {});

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
