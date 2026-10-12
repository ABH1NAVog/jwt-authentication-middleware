
const jwt = require('jsonwebtoken');

module.exports = function requireAuth(req, res, next) {
  // 1. Read the Authorization header
  const authHeader = req.headers.authorization ?? '';

  // 2. Extract the Bearer token using a strict regex
  const match = /^Bearer ([^\s]+)$/i.exec(authHeader);
  const token = match ? match[1] : null;

  // 3. Return 401 if the token is missing or the scheme is invalid
  if (!token) {
    return res.status(401).json({
      error: {
        code: 'AUTH_REQUIRED',
        message: 'Authentication required'
      }
    });
  }

  // 4. Verify the token
  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET,
      { algorithms: ['HS256'] }
    );

    // 5. Attach the verified payload to the request
    req.user = payload;

    // 6. Pass control to the next middleware or route handler
    return next();

  } catch (_error) {
    // 7. Return the same generic response for every verification failure
    return res.status(401).json({
      error: {
        code: 'AUTH_REQUIRED',
        message: 'Authentication required'
      }
    });
  }
};
