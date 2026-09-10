const { pool } = require("../database");

async function createAuthLog({
  keyId = null,
  scriptId = null,
  success = false,
  reason = null,
  ipAddress = null
}) {
  const result = await pool.query(
    `
      INSERT INTO auth_logs (
        key_id,
        script_id,
        success,
        reason,
        ip_address
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING
        id,
        key_id,
        script_id,
        success,
        reason,
        ip_address,
        created_at
    `,
    [
      keyId,
      scriptId,
      success,
      reason,
      ipAddress
    ]
  );

  return result.rows[0];
}

async function getAuthLogs({
  limit = 100,
  offset = 0
} = {}) {
  const safeLimit = Math.min(
    Math.max(Number(limit) || 100, 1),
    500
  );

  const safeOffset = Math.max(
    Number(offset) || 0,
    0
  );

  const result = await pool.query(
    `
      SELECT
        id,
        key_id,
        script_id,
        success,
        reason,
        ip_address,
        created_at
      FROM auth_logs
      ORDER BY id DESC
      LIMIT $1 OFFSET $2
    `,
    [safeLimit, safeOffset]
  );

  return result.rows;
}

async function getAuthLogCount() {
  const result = await pool.query(
    `
      SELECT COUNT(*)::INTEGER AS count
      FROM auth_logs
    `
  );

  return result.rows[0].count;
}

module.exports = {
  createAuthLog,
  getAuthLogs,
  getAuthLogCount
};