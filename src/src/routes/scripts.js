const express = require("express");
const { pool } = require("../database");
const adminAuth = require("../middleware/adminAuth");

const router = express.Router();

// Create a protected script
router.post("/", adminAuth, async (req, res) => {
  try {
    const {
      name,
      identifier,
      version = "1.0.0"
    } = req.body;

    if (!name || !identifier) {
      return res.status(400).json({
        success: false,
        error: "NAME_AND_IDENTIFIER_REQUIRED"
      });
    }

    const result = await pool.query(
      `
        INSERT INTO scripts (name, identifier, version)
        VALUES ($1, $2, $3)
        RETURNING id, name, identifier, version, status, created_at
      `,
      [name, identifier, version]
    );

    return res.status(201).json({
      success: true,
      script: result.rows[0]
    });
  } catch (error) {
    console.error("Create script error:", error.message);

    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "SCRIPT_IDENTIFIER_ALREADY_EXISTS"
      });
    }

    return res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

// List scripts
router.get("/", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, identifier, version, status, created_at, updated_at
      FROM scripts
      ORDER BY id ASC
    `);

    return res.json({
      success: true,
      scripts: result.rows
    });
  } catch (error) {
    console.error("List scripts error:", error.message);

    return res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

module.exports = router;