const express = require("express");
const path = require("path");
const morgan = require("morgan");

const app = express();
const port = process.env.PORT || 3000;

// Routes
app.get("/", (req, res) => {
  res.send("Hello from Express!");
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
