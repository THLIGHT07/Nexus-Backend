/**
 * middleware/auth.js
 * -----------------------------------------------------------------------------
 * JWT authentication middleware.
 *
 * Expects the header:   Authorization: Bearer <token>
 * On success, attaches the user record (without password) to `req.user`.
 */

const jwt = require('jsonwebtoken');
const db = require('../db');

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res
      .status(401)
      .json({ error: 'Authentication required. Send "Authorization: Bearer <token>".' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    const message =
      err.name === 'TokenExpiredError' ? 'Token has expired.' : 'Invalid token.';
    return res.status(401).json({ error: message });
  }

  try {
    // Make sure the user still exists (e.g. wasn't deleted after the token was issued).
    const user = db.get(
      'SELECT id, username, status, created_at FROM users WHERE id = ?',
      [payload.id]
    );
    if (!user) {
      return res.status(401).json({ error: 'User no longer exists.' });
    }
    if (user.status === 'blocked') {
      return res
        .status(403)
        .json({ error: 'Your account is blocked. Please contact admin.' });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = authenticate;
