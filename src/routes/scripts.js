const express = require("express");
const router = express.Router();

const { pool } = require("../database");

function adminAuth(req, res, next) {
  const token = req.query.token;

  if (!process.env.SHIELD_ADMIN_TOKEN) {
    return res.status(500).json({
      success: false,
      error: "ADMIN_TOKEN_NOT_CONFIGURED"
    });
  }

  if (!token || token !== process.env.SHIELD_ADMIN_TOKEN) {
    return res.status(401).json({
      success: false,
      error: "UNAUTHORIZED"
    });
  }

  next();
}

// Browser-friendly admin script creation
router.get("/create", adminAuth, async (req, res) => {
  try {
    const name = req.query.name || "Reboot";

    const result = await pool.query(
      `INSERT INTO scripts (name)
       VALUES ($1)
       RETURNING id, name, created_at`,
      [name]
    );

    res.status(201).json({
      success: true,
      message: "Script created",
      script: result.rows[0]
    });
  } catch (error) {
    console.error("Create script error:", error.message);

    res.status(500).json({
      success: false,
      error: "FAILED_TO_CREATE_SCRIPT"
    });
  }
});

// List scripts
router.get("/", adminAuth, async (req, res) => {
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
      error: "FAILED_TO_FETCH_SCRIPTS"
    });
  }
});

module.exports = router;