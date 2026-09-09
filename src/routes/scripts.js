const express = require("express");
const router = express.Router();

const { pool } = require("../database");

// Get all scripts
router.get("/", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, created_at
      FROM scripts
      ORDER BY id DESC
    `);

    res.json({
      success: true,
      scripts: result.rows
    });
  } catch (error) {
    console.error("Scripts GET error:", error.message);

    res.status(500).json({
      success: false,
      error: "Failed to fetch scripts"
    });
  }
});

// Get one script
router.get("/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, created_at FROM scripts WHERE id = $1",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Script not found"
      });
    }

    res.json({
      success: true,
      script: result.rows[0]
    });
  } catch (error) {
    console.error("Script GET error:", error.message);

    res.status(500).json({
      success: false,
      error: "Failed to fetch script"
    });
  }
});

// Create a script
router.post("/", async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({
        success: false,
        error: "Script name is required"
      });
    }

    const result = await pool.query(
      "INSERT INTO scripts (name) VALUES ($1) RETURNING id, name, created_at",
      [name]
    );

    res.status(201).json({
      success: true,
      script: result.rows[0]
    });
  } catch (error) {
    console.error("Script POST error:", error.message);

    res.status(500).json({
      success: false,
      error: "Failed to create script"
    });
  }
});

module.exports = router;