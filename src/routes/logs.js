const express = require("express");

const {
  getAuthLogs,
  getAuthLogCount
} = require("../services/logService");

const adminAuth = require("../middleware/adminAuth");

const router = express.Router();

/*
 * GET /v1/admin/logs
 * Admin only
 *
 * Optional:
 * ?limit=100&offset=0
 */
router.get("/", adminAuth, async (req, res) => {
  try {
    const limit = req.query.limit || 100;
    const offset = req.query.offset || 0;

    const [logs, total] = await Promise.all([
      getAuthLogs({ limit, offset }),
      getAuthLogCount()
    ]);

    return res.json({
      success: true,
      total,
      limit: Math.min(Math.max(Number(limit) || 100, 1), 500),
      offset: Math.max(Number(offset) || 0, 0),
      logs
    });
  } catch (error) {
    console.error("Fetch auth logs error:", error.message);

    return res.status(500).json({
      success: false,
      error: "FAILED_TO_FETCH_LOGS"
    });
  }
});

module.exports = router;