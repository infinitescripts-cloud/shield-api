const express = require("express");

const {
  createKey,
  getKeyByPlaintext,
  revokeKey,
  resetHwid
} = require("../services/keyService");

const adminAuth = require("../middleware/adminAuth");

const router = express.Router();

/*
 * GET /v1/keys/create
 * Admin only
 *
 * Browser testing:
 * /v1/keys/create?scriptId=3&token=YOUR_ADMIN_TOKEN
 */
router.get("/create", adminAuth, async (req, res) => {
  try {
    const scriptId = Number(req.query.scriptId);
    const expiresAt = req.query.expiresAt || null;

    if (!Number.isInteger(scriptId) || scriptId <= 0) {
      return res.status(400).json({
        success: false,
        error: "INVALID_SCRIPT_ID"
      });
    }

    const result = await createKey({
      scriptId,
      expiresAt
    });

    return res.status(201).json({
      success: true,
      message: "Key created",
      key: result.key,
      id: result.id,
      scriptId: result.script_id,
      status: result.status,
      expiresAt: result.expires_at
    });
  } catch (error) {
    console.error("Create key error:", error.message);

    if (error.code === "23503") {
      return res.status(404).json({
        success: false,
        error: "SCRIPT_NOT_FOUND"
      });
    }

    return res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

/*
 * POST /v1/keys/create
 * Admin only
 */
router.post("/create", adminAuth, async (req, res) => {
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

    return res.status(201).json({
      success: true,
      message: "Key created",
      key: result.key,
      id: result.id,
      scriptId: result.script_id,
      status: result.status,
      expiresAt: result.expires_at
    });
  } catch (error) {
    console.error("Create key error:", error.message);

    if (error.code === "23503") {
      return res.status(404).json({
        success: false,
        error: "SCRIPT_NOT_FOUND"
      });
    }

    return res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

/*
 * GET /v1/keys/validate
 * Browser testing only
 *
 * Example:
 * /v1/keys/validate?key=SHIELD-XXXXX-XXXXX-XXXXX
 */
router.get("/validate", async (req, res) => {
  try {
    const key = req.query.key;

    if (!key) {
      return res.status(400).json({
        success: false,
        valid: false,
        error: "KEY_REQUIRED"
      });
    }

    const result = await getKeyByPlaintext(key);

    if (!result) {
      return res.status(404).json({
        success: false,
        valid: false,
        error: "KEY_NOT_FOUND"
      });
    }

    if (result.status !== "active") {
      return res.status(403).json({
        success: false,
        valid: false,
        error: "KEY_INACTIVE"
      });
    }

    if (
      result.expires_at &&
      new Date(result.expires_at).getTime() <= Date.now()
    ) {
      return res.status(403).json({
        success: false,
        valid: false,
        error: "KEY_EXPIRED"
      });
    }

    return res.json({
      success: true,
      valid: true,
      key: {
        id: result.id,
        scriptId: result.script_id,
        status: result.status,
        expiresAt: result.expires_at
      }
    });
  } catch (error) {
    console.error("Validate key error:", error.message);

    return res.status(500).json({
      success: false,
      valid: false,
      error: "INTERNAL_ERROR"
    });
  }
});

/*
 * POST /v1/keys/validate
 * Public client endpoint
 */
router.post("/validate", async (req, res) => {
  try {
    const { key } = req.body;

    if (!key) {
      return res.status(400).json({
        success: false,
        valid: false,
        error: "KEY_REQUIRED"
      });
    }

    const result = await getKeyByPlaintext(key);

    if (!result) {
      return res.status(404).json({
        success: false,
        valid: false,
        error: "KEY_NOT_FOUND"
      });
    }

    if (result.status !== "active") {
      return res.status(403).json({
        success: false,
        valid: false,
        error: "KEY_INACTIVE"
      });
    }

    if (
      result.expires_at &&
      new Date(result.expires_at).getTime() <= Date.now()
    ) {
      return res.status(403).json({
        success: false,
        valid: false,
        error: "KEY_EXPIRED"
      });
    }

    return res.json({
      success: true,
      valid: true,
      key: {
        id: result.id,
        scriptId: result.script_id,
        status: result.status,
        expiresAt: result.expires_at
      }
    });
  } catch (error) {
    console.error("Validate key error:", error.message);

    return res.status(500).json({
      success: false,
      valid: false,
      error: "INTERNAL_ERROR"
    });
  }
});

/*
 * POST /v1/keys/:id/revoke
 * Admin only
 */
router.post("/:id/revoke", adminAuth, async (req, res) => {
  try {
    const result = await revokeKey(req.params.id);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "KEY_NOT_FOUND"
      });
    }

    return res.json({
      success: true,
      message: "Key revoked",
      id: result.id,
      status: result.status
    });
  } catch (error) {
    console.error("Revoke key error:", error.message);

    return res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

/*
 * POST /v1/keys/:id/reset-hwid
 * Admin only
 */
router.post("/:id/reset-hwid", adminAuth, async (req, res) => {
  try {
    const result = await resetHwid(req.params.id);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "KEY_NOT_FOUND"
      });
    }

    return res.json({
      success: true,
      message: "HWID reset",
      id: result.id,
      hwidReset: true
    });
  } catch (error) {
    console.error("Reset HWID error:", error.message);

    return res.status(500).json({
      success: false,
      error: "INTERNAL_ERROR"
    });
  }
});

module.exports = router;