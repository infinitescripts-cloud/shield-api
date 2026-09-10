const express = require("express");

const {
  testDatabase,
  initializeDatabase
} = require("./database");

const keysRouter = require("./routes/keys");
const scriptsRouter = require("./routes/scripts");
const logsRouter = require("./routes/logs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

/*
 * Root
 */
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "Shield API",
    version: "1.0.0",
    status: "online"
  });
});

/*
 * Health check
 */
app.get("/v1/health", async (req, res) => {
  try {
    const databaseTime = await testDatabase();

    return res.json({
      success: true,
      service: "Shield API",
      version: "1.0.0",
      database: "connected",
      databaseTime
    });
  } catch (error) {
    console.error(
      "Health check error:",
      error.message
    );

    return res.status(503).json({
      success: false,
      service: "Shield API",
      database: "disconnected"
    });
  }
});

/*
 * Key routes
 */
app.use("/v1/keys", keysRouter);

/*
 * Script routes
 */
app.use("/v1/scripts", scriptsRouter);

/*
 * Admin authentication logs
 */
app.use("/v1/admin/logs", logsRouter);

/*
 * Unknown route handler
 */
app.use((req, res) => {
  return res.status(404).json({
    success: false,
    error: "NOT_FOUND"
  });
});

/*
 * Error handler
 */
app.use((error, req, res, next) => {
  console.error(
    "Unhandled server error:",
    error.message
  );

  return res.status(500).json({
    success: false,
    error: "INTERNAL_ERROR"
  });
});

/*
 * Start Shield API
 */
async function start() {
  try {
    console.log("Starting Shield API...");

    await initializeDatabase();

    console.log("PostgreSQL connected.");
    console.log("Database tables initialized.");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Shield API listening on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Failed to start Shield API:",
      error.message
    );

    process.exit(1);
  }
}

start();