const express = require("express");
const {
  createKey,
  getKeyByPlaintext,
  revokeKey,
  resetHwid
} = require("../services/keyService");

const router = express.Router();

// Create a key
router.post("/create", async (req, res) => {
  try {
    const { scriptId, expiresAt } = req.body;

    if (!scriptId) {
      return res.status(400).json({
        success: false,
        error: "SCRIPT_ID_REQUIRED"
      });
    }

    const result = await createKey({
      scriptId,
      expiresAt: expiresAt || null
    });

    res.status(201).json({
      success: true,
      key: result.key,
      id: result.id,
      scriptId: result.script_id,
      status: result.status,
      expiresAt: result.expires_at
    });
  } catch (error) {
    console.error("Create key error:", error.message);

    res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

// Look up a key
router.post("/validate", async (req, res) => {
  try {
    const { key } = req.body;

    if (!key) {
      return res.status(400).json({
        success: false,
        error: "KEY_REQUIRED"
      });
    }

    const result = await getKeyByPlaintext(key);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "KEY_NOT_FOUND"
      });
    }

    res.json({
      success: true,
      key: {
        id: result.id,
        scriptId: result.script_id,
        status: result.status,
        expiresAt: result.expires_at
      }
    });
  } catch (error) {
    console.error("Validate key error:", error.message);

    res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

// Revoke a key
router.post("/:id/revoke", async (req, res) => {
  try {
    const result = await revokeKey(req.params.id);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "KEY_NOT_FOUND"
      });
    }

    res.json({
      success: true,
      id: result.id,
      status: result.status
    });
  } catch (error) {
    console.error("Revoke key error:", error.message);

    res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

// Reset HWID
router.post("/:id/reset-hwid", async (req, res) => {
  try {
    const result = await resetHwid(req.params.id);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "KEY_NOT_FOUND"
      });
    }

    res.json({
      success: true,
      id: result.id,
      hwidReset: true
    });
  } catch (error) {
    console.error("Reset HWID error:", error.message);

    res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

module.exports = router;