const crypto = require("crypto");
const { pool } = require("../database");

function generateSessionToken() {
  return `SHIELD-SESSION-${crypto.randomBytes(32).toString("hex")}`;
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(String(token))
    .digest("hex");
}

async function createSession({
  keyId,
  hwid = null,
  expiresInSeconds = 3600
}) {
  if (!keyId) {
    throw new Error("KEY_ID_REQUIRED");
  }

  const token = generateSessionToken();
  const tokenHash = hashToken(token);

  const expiresAt = new Date(
    Date.now() + expiresInSeconds * 1000
  );

  const hwidHash = hwid ? hashToken(hwid) : null;

  const result = await pool.query(
    `
      INSERT INTO sessions (
        token_hash,
        key_id,
        hwid_hash,
        expires_at
      )
      VALUES ($1, $2, $3, $4)
      RETURNING
        id,
        key_id,
        hwid_hash,
        expires_at,
        created_at
    `,
    [
      tokenHash,
      keyId,
      hwidHash,
      expiresAt
    ]
  );

  return {
    ...result.rows[0],
    token
  };
}

async function getSession(token) {
  if (!token) {
    return null;
  }

  const tokenHash = hashToken(token);

  const result = await pool.query(
    `
      SELECT
        id,
        key_id,
        hwid_hash,
        expires_at,
        created_at
      FROM sessions
      WHERE token_hash = $1
      LIMIT 1
    `,
    [tokenHash]
  );

  return result.rows[0] || null;
}

async function validateSession(token, hwid = null) {
  const session = await getSession(token);

  if (!session) {
    return {
      valid: false,
      error: "SESSION_NOT_FOUND"
    };
  }

  if (
    !session.expires_at ||
    new Date(session.expires_at).getTime() <= Date.now()
  ) {
    return {
      valid: false,
      error: "SESSION_EXPIRED",
      session
    };
  }

  if (hwid && session.hwid_hash) {
    const incomingHwidHash = hashToken(hwid);

    if (incomingHwidHash !== session.hwid_hash) {
      return {
        valid: false,
        error: "HWID_MISMATCH",
        session
      };
    }
  }

  return {
    valid: true,
    session
  };
}

async function revokeSession(token) {
  if (!token) {
    return false;
  }

  const tokenHash = hashToken(token);

  const result = await pool.query(
    `
      DELETE FROM sessions
      WHERE token_hash = $1
      RETURNING id
    `,
    [tokenHash]
  );

  return result.rowCount > 0;
}

async function revokeSessionsForKey(keyId) {
  const result = await pool.query(
    `
      DELETE FROM sessions
      WHERE key_id = $1
    `,
    [keyId]
  );

  return result.rowCount;
}

module.exports = {
  generateSessionToken,
  hashToken,
  createSession,
  getSession,
  validateSession,
  revokeSession,
  revokeSessionsForKey
};