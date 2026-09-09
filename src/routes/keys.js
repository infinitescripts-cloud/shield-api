const express = require("express");

const {
  createKey,
  validateKey,
  revokeKey,
  resetHwid
} = require("../services/keyService");

const adminAuth = require("../middleware/adminAuth");

const router = express.Router();

/*
 * GET /v1/keys/create
 *
 * Admin/browser testing.
 *
 * Example:
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
 *
 * Admin API.
 *
 * Body:
 * {
 *   "scriptId": 3,
 *   "expiresAt": null
 * }
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
      scriptId: Number(scriptId),
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
 *
 * Browser testing.
 *
 * Example:
 * /v1/keys/validate?key=SHIELD-XXXXX-XXXXX-XXXXX&hwid=test-device-001
 */
router.get("/validate", async (req, res) => {
  try {
    const { key, hwid } = req.query;

    if (!key) {
      return res.status(400).json({
        success: false,
        valid: false,
        error: "KEY_REQUIRED"
      });
    }

    const result = await validateKey(
      key,
      hwid || null,
      req.ip
    );

    if (!result.valid) {
      return res.status(403).json({
        success: false,
        valid: false,
        error: result.error
      });
    }

    return res.json({
      success: true,
      valid: true,
      bound: result.bound,
      key: {
        id: result.key.id,
        scriptId: result.key.script_id,
        status: result.key.status,
        expiresAt: result.key.expires_at,
        hwidBound: Boolean(result.key.hwid_hash),
        lastUsedAt: result.key.last_used_at
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
 *
 * Public client endpoint.
 *
 * Body:
 * {
 *   "key": "SHIELD-XXXXX-XXXXX-XXXXX",
 *   "hwid": "device-001"
 * }
 */
router.post("/validate", async (req, res) => {
  try {
    const { key, hwid } = req.body;

    if (!key) {
      return res.status(400).json({
        success: false,
        valid: false,
        error: "KEY_REQUIRED"
      });
    }

    const result = await validateKey(
      key,
      hwid || null,
      req.ip
    );

    if (!result.valid) {
      return res.status(403).json({
        success: false,
        valid: false,
        error: result.error
      });
    }

    return res.json({
      success: true,
      valid: true,
      bound: result.bound,
      key: {
        id: result.key.id,
        scriptId: result.key.script_id,
        status: result.key.status,
        expiresAt: result.key.expires_at,
        hwidBound: Boolean(result.key.hwid_hash),
        lastUsedAt: result.key.last_used_at
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
 *
 * Admin only.
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
 *
 * Admin only.
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