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

/*
 * Create script from mobile browser
 * TEMPORARY diagnostic version
 */
router.get("/create", adminAuth, async (req, res) => {
  try {
    const name = req.query.name || "Reboot";
    const identifier = req.query.identifier || "reboot";
    const version = req.query.version || "1.0.0";

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
      message: "Script created",
      script: result.rows[0]
    });
  } catch (error) {
    console.error("Create script error:", error);

    return res.status(500).json({
      success: false,
      error: "FAILED_TO_CREATE_SCRIPT",
      details: error.message,
      code: error.code
    });
  }
});

/*
 * List scripts
 */
router.get("/", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        name,
        identifier,
        version,
        status,
        created_at,
        updated_at
      FROM scripts
      ORDER BY id DESC
    `);

    return res.json({
      success: true,
      scripts: result.rows
    });
  } catch (error) {
    console.error("Scripts GET error:", error);

    return res.status(500).json({
      success: false,
      error: "FAILED_TO_FETCH_SCRIPTS",
      details: error.message,
      code: error.code
    });
  }
});

/*
 * Get one script
 */
router.get("/:id", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        identifier,
        version,
        status,
        created_at,
        updated_at
      FROM scripts
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "SCRIPT_NOT_FOUND"
      });
    }

    return res.json({
      success: true,
      script: result.rows[0]
    });
  } catch (error) {
    console.error("Script GET error:", error);

    return res.status(500).json({
      success: false,
      error: "FAILED_TO_FETCH_SCRIPT",
      details: error.message,
      code: error.code
    });
  }
});

module.exports = router;