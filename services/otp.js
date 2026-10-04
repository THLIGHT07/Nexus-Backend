/**
 * services/otp.js
 * -----------------------------------------------------------------------------
 * One-time codes for password reset, password change and email verification.
 *
 *  - 6 random digits from crypto.randomInt (cryptographically secure).
 *  - Only an HMAC-SHA256 of the code is stored (keyed with OTP_SECRET, or JWT_SECRET if unset),
 *    bound to the user and the purpose — a database leak does not reveal live codes, and a code
 *    for one purpose can't be replayed for another. A 6-digit code is small, so the real
 *    protection is the short life (10 min), the 5-guess limit per code and the request limiters.
 *  - Asking for a new code of the same purpose replaces the old one.
 *  - A code dies on first successful use, after 5 wrong guesses, or when it expires.
 *
 * Everything here is synchronous (sql.js), so two requests can never both "win" the same code.
 */

const crypto = require('crypto');
const db = require('../db');

function intFromEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const TTL_MINUTES = intFromEnv('OTP_TTL_MINUTES', 10);
const TTL_MS = TTL_MINUTES * 60 * 1000;
const MAX_ATTEMPTS = 5;
const PURPOSES = ['reset', 'change', 'verify_email'];

function hashCode(userId, purpose, code) {
  const key = process.env.OTP_SECRET || process.env.JWT_SECRET;
  return crypto.createHmac('sha256', key).update(`${purpose}:${userId}:${code}`).digest('hex');
}

function safeEqualHex(a, b) {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** Creates a fresh code (replacing any earlier one for this user + purpose). Returns the PLAIN code once, to be emailed. */
function issue({ userId, purpose, email = null }) {
  if (!PURPOSES.includes(purpose)) throw new Error(`Unknown OTP purpose: ${purpose}`);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.run('DELETE FROM otp_codes WHERE user_id = ? AND purpose = ?', [userId, purpose]);
  db.run(
    'INSERT INTO otp_codes (user_id, purpose, code_hash, email, attempts, expires_at, created_at) VALUES (?, ?, ?, ?, 0, ?, ?)',
    [userId, purpose, hashCode(userId, purpose, code), email, Date.now() + TTL_MS, Date.now()]
  );
  return { code, expiresMinutes: TTL_MINUTES };
}

/**
 * Checks a code. consume=true deletes it on success (single use).
 * Returns { ok: true, email } or { ok: false } — callers show ONE generic message for every failure.
 */
function check({ userId, purpose, code, consume }) {
  const row = db.get(
    'SELECT * FROM otp_codes WHERE user_id = ? AND purpose = ? ORDER BY id DESC LIMIT 1',
    [userId, purpose]
  );
  if (!row) return { ok: false };
  if (row.expires_at <= Date.now()) {
    db.run('DELETE FROM otp_codes WHERE id = ?', [row.id]);
    return { ok: false };
  }
  if (typeof code !== 'string' || !/^\d{6}$/.test(code) || !safeEqualHex(row.code_hash, hashCode(userId, purpose, code))) {
    if (row.attempts + 1 >= MAX_ATTEMPTS) db.run('DELETE FROM otp_codes WHERE id = ?', [row.id]);
    else db.run('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?', [row.id]);
    return { ok: false };
  }
  if (consume) db.run('DELETE FROM otp_codes WHERE id = ?', [row.id]);
  return { ok: true, email: row.email };
}

/** Removes a user's outstanding codes (all purposes, or just the listed ones). */
function clearForUser(userId, purposes) {
  if (!purposes) return db.run('DELETE FROM otp_codes WHERE user_id = ?', [userId]);
  for (const p of purposes) db.run('DELETE FROM otp_codes WHERE user_id = ? AND purpose = ?', [userId, p]);
}

/** Housekeeping: drops expired codes and codes of deleted accounts. */
function sweep() {
  try {
    db.run('DELETE FROM otp_codes WHERE expires_at <= ?', [Date.now()]);
    db.run('DELETE FROM otp_codes WHERE user_id NOT IN (SELECT id FROM users)');
  } catch (e) { /* db may be closing */ }
}
setInterval(sweep, 10 * 60 * 1000).unref();

module.exports = { issue, check, clearForUser, sweep, TTL_MINUTES, MAX_ATTEMPTS };
