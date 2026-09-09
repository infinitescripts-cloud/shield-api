const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is not set");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", (error) => {
  console.error("PostgreSQL pool error:", error.message);
});

async function testDatabase() {
  const result = await pool.query("SELECT NOW() AS time");
  return result.rows[0].time;
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(64) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE,
      password_hash TEXT,
      role VARCHAR(32) NOT NULL DEFAULT 'developer',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scripts (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(128) NOT NULL,
      identifier VARCHAR(128) UNIQUE NOT NULL,
      version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS keys (
      id BIGSERIAL PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      script_id BIGINT REFERENCES scripts(id) ON DELETE CASCADE,
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      hwid_hash TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      key_id BIGINT REFERENCES keys(id) ON DELETE CASCADE,
      hwid_hash TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS auth_logs (
      id BIGSERIAL PRIMARY KEY,
      key_id BIGINT REFERENCES keys(id) ON DELETE SET NULL,
      script_id BIGINT REFERENCES scripts(id) ON DELETE SET NULL,
      success BOOLEAN NOT NULL,
      reason VARCHAR(128),
      ip_address INET,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_keys_script_id
      ON keys(script_id);

    CREATE INDEX IF NOT EXISTS idx_keys_status
      ON keys(status);

    CREATE INDEX IF NOT EXISTS idx_sessions_key_id
      ON sessions(key_id);

    CREATE INDEX IF NOT EXISTS idx_auth_logs_created_at
      ON auth_logs(created_at);
  `);
}

module.exports = {
  pool,
  testDatabase,
  initializeDatabase
};