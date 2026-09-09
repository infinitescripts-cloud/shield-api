const express = require("express");
const {
  testDatabase,
  initializeDatabase
} = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/v1/health", async (req, res) => {
  try {
    const databaseTime = await testDatabase();

    res.json({
      success: true,
      service: "Shield API",
      version: "1.0.0",
      database: "connected",
      databaseTime
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      service: "Shield API",
      database: "disconnected"
    });
  }
});

async function start() {
  try {
    console.log("Starting Shield API...");

    await initializeDatabase();

    console.log("PostgreSQL connected.");
    console.log("Database tables initialized.");

    app.listen(PORT, () => {
      console.log(`Shield API listening on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start Shield API:", error.message);
    process.exit(1);
  }
}

start();