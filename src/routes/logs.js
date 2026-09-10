const express = require("express");

const {
  getAuthLogs,
  getAuthLogCount
} = require("../services/logService");

const adminAuth = require("../middleware/adminAuth");

const router = express.Router();

/*
 * GET /v1/admin/logs
 *
 * Admin only.
 *
 * Optional:
 * ?limit=100&offset=0
 */
router.get("/", adminAuth, async (req, res) => {
  try {
    const requestedLimit = Number(req.query.limit) || 100;
    const requestedOffset = Number(req.query.offset) || 0;

    const limit = Math.min(
      Math.max(requestedLimit, 1),
      500
    );

    const offset = Math.max(
      requestedOffset,
      0
    );

    const [logs, total] = await Promise.all([
      getAuthLogs({
        limit,
        offset
      }),
      getAuthLogCount()
    ]);

    return res.json({
      success: true,
      total,
      limit,
      offset,
      logs
    });
  } catch (error) {
    console.error(
      "Fetch auth logs error:",
      error.message
    );

    return res.status(500).json({
      success: false,
      error: "FAILED_TO_FETCH_LOGS"
    });
  }
});

module.exports = router;