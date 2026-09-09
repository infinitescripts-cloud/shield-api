const crypto = require("crypto");
const { pool } = require("../database");

function generateKey() {
  const bytes = crypto.randomBytes(15).toString("hex").toUpperCase();

  return `SHIELD-${bytes.slice(0, 5)}-${bytes.slice(5, 10)}-${bytes.slice(10, 15)}`;
}

function hashValue(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
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
  revokeKey,
  resetHwid
};