const crypto = require("crypto");

function safeEqual(a, b) {
  const first = Buffer.from(a || "");
  const second = Buffer.from(b || "");

  if (first.length !== second.length) {
    return false;
  }

  return crypto.timingSafeEqual(first, second);
}

function adminAuth(req, res, next) {
  const expected = process.env.SHIELD_ADMIN_TOKEN;
  const provided = req.get("Authorization");

  if (!expected) {
    return res.status(503).json({
      success: false,
      error: "ADMIN_AUTH_NOT_CONFIGURED"
    });
  }

  if (!provided || !provided.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      error: "AUTH_REQUIRED"
    });
  }

  const token = provided.slice(7);

  if (!safeEqual(token, expected)) {
    return res.status(403).json({
      success: false,
      error: "INVALID_ADMIN_TOKEN"
    });
  }

  next();
}

module.exports = adminAuth;