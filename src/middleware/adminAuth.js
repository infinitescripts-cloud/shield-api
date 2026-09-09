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

  if (!expected) {
    return res.status(503).json({
      success: false,
      error: "ADMIN_AUTH_NOT_CONFIGURED"
    });
  }

  // Normal method: Authorization: Bearer TOKEN
  const authorization = req.get("Authorization");

  // Temporary browser testing method
  const queryToken = req.query.token;

  let token = null;

  if (authorization && authorization.startsWith("Bearer ")) {
    token = authorization.slice(7);
  } else if (queryToken) {
    token = queryToken;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: "AUTH_REQUIRED"
    });
  }

  if (!safeEqual(token, expected)) {
    return res.status(403).json({
      success: false,
      error: "INVALID_ADMIN_TOKEN"
    });
  }

  next();
}

module.exports = adminAuth;