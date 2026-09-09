const crypto = require("crypto");
const { pool } = require("../database");

function generateKey() {
  const bytes = crypto.randomBytes(15).toString("hex").toUpperCase();

  return `SHIELD-${bytes.slice(0, 5)}-${bytes.slice(5, 10)}-${bytes.slice(10, 15)}`;
}

function hashValue(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

async function logAuth({
  keyId = null,
  scriptId = null,
  success,
  reason,
  ipAddress = null
}) {
  try {
    await pool.query(
      `
        INSERT INTO auth_logs (
          key_id,
          script_id,
          success,
          reason,
          ip_address
        )
        VALUES ($1, $2, $3, $4, $5)
      `,
      [
        keyId,
        scriptId,
        success,
        reason,
        ipAddress
      ]
    );
  } catch (error) {
    // Logging failure must never break authentication.
    console.error("Auth log error:", error.message);
  }
}

async function createKey({ scriptId, expiresAt = null }) {
  const key = generateKey();
  const keyHash = hashValue(key);

  const result = await pool.query(
    `
      INSERT INTO keys (
        key_hash,
        script_id,
        expires_at
      )
      VALUES ($1, $2, $3)
      RETURNING id, script_id, status, expires_at, created_at
    `,
    [keyHash, scriptId, expiresAt]
  );

  return {
    ...result.rows[0],
    key
  };
}

async function getKeyByPlaintext(key) {
  const keyHash = hashValue(key);

  const result = await pool.query(
    `
      SELECT
        id,
        script_id,
        status,
        hwid_hash,
        expires_at,
        created_at,
        last_used_at
      FROM keys
      WHERE key_hash = $1
      LIMIT 1
    `,
    [keyHash]
  );

  return result.rows[0] || null;
}

/*
 * Validate key + optional HWID.
 *
 * First HWID use:
 *   binds the key.
 *
 * Existing HWID:
 *   must match.
 */
async function validateKey(key, hwid = null, ipAddress = null) {
  const keyHash = hashValue(key);

  const result = await pool.query(
    `
      SELECT
        id,
        script_id,
        status,
        hwid_hash,
        expires_at,
        created_at,
        last_used_at
      FROM keys
      WHERE key_hash = $1
      LIMIT 1
    `,
    [keyHash]
  );

  const record = result.rows[0];

  if (!record) {
    await logAuth({
      success: false,
      reason: "KEY_NOT_FOUND",
      ipAddress
    });

    return {
      valid: false,
      error: "KEY_NOT_FOUND"
    };
  }

  if (record.status !== "active") {
    await logAuth({
      keyId: record.id,
      scriptId: record.script_id,
      success: false,
      reason: "KEY_INACTIVE",
      ipAddress
    });

    return {
      valid: false,
      error: "KEY_INACTIVE",
      key: record
    };
  }

  if (
    record.expires_at &&
    new Date(record.expires_at).getTime() <= Date.now()
  ) {
    await logAuth({
      keyId: record.id,
      scriptId: record.script_id,
      success: false,
      reason: "KEY_EXPIRED",
      ipAddress
    });

    return {
      valid: false,
      error: "KEY_EXPIRED",
      key: record
    };
  }

  /*
   * HWID protection.
   */
  if (hwid) {
    const incomingHwidHash = hashValue(hwid);

    /*
     * First use: bind HWID.
     */
    if (!record.hwid_hash) {
      const bindResult = await pool.query(
        `
          UPDATE keys
          SET
            hwid_hash = $1,
            last_used_at = NOW()
          WHERE id = $2
          RETURNING
            id,
            script_id,
            status,
            hwid_hash,
            expires_at,
            created_at,
            last_used_at
        `,
        [incomingHwidHash, record.id]
      );

      await logAuth({
        keyId: record.id,
        scriptId: record.script_id,
        success: true,
        reason: "HWID_BOUND",
        ipAddress
      });

      return {
        valid: true,
        bound: true,
        key: bindResult.rows[0]
      };
    }

    /*
     * Existing HWID must match.
     */
    if (record.hwid_hash !== incomingHwidHash) {
      await logAuth({
        keyId: record.id,
        scriptId: record.script_id,
        success: false,
        reason: "HWID_MISMATCH",
        ipAddress
      });

      return {
        valid: false,
        error: "HWID_MISMATCH",
        key: record
      };
    }

    /*
     * Correct HWID.
     */
    const updateResult = await pool.query(
      `
        UPDATE keys
        SET last_used_at = NOW()
        WHERE id = $1
        RETURNING
          id,
          script_id,
          status,
          hwid_hash,
          expires_at,
          created_at,
          last_used_at
      `,
      [record.id]
    );

    await logAuth({
      keyId: record.id,
      scriptId: record.script_id,
      success: true,
      reason: "VALID",
      ipAddress
    });

    return {
      valid: true,
      bound: true,
      key: updateResult.rows[0]
    };
  }

  /*
   * No HWID supplied.
   */
  await logAuth({
    keyId: record.id,
    scriptId: record.script_id,
    success: true,
    reason: "VALID_NO_HWID",
    ipAddress
  });

  return {
    valid: true,
    bound: Boolean(record.hwid_hash),
    key: record
  };
}

async function revokeKey(id) {
  const result = await pool.query(
    `
      UPDATE keys
      SET status = 'revoked'
      WHERE id = $1
      RETURNING id, status
    `,
    [id]
  );

  return result.rows[0] || null;
}

async function resetHwid(id) {
  const result = await pool.query(
    `
      UPDATE keys
      SET hwid_hash = NULL
      WHERE id = $1
      RETURNING id, hwid_hash
    `,
    [id]
  );

  return result.rows[0] || null;
}

module.exports = {
  generateKey,
  hashValue,
  createKey,
  getKeyByPlaintext,
  validateKey,
  revokeKey,
  resetHwid,
  logAuth
};