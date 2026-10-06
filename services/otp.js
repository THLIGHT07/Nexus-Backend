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
 * Every function is async (PostgreSQL); single use and the guess limit are enforced with atomic SQL — see check().
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
async function issue({ userId, purpose, email = null }) {
  if (!PURPOSES.includes(purpose)) throw new Error(`Unknown OTP purpose: ${purpose}`);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const now = Date.now();
  // One atomic upsert: (user_id, purpose) is unique, so a new request replaces the old code and resets its guesses.
  await db.run(
    `INSERT INTO otp_codes (user_id, purpose, code_hash, email, attempts, expires_at, created_at)
     VALUES ($1, $2, $3, $4, 0, $5, $6)
     ON CONFLICT (user_id, purpose) DO UPDATE
       SET code_hash = EXCLUDED.code_hash, email = EXCLUDED.email, attempts = 0,
           expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at`,
    [userId, purpose, hashCode(userId, purpose, code), email, now + TTL_MS, now]
  );
  return { code, expiresMinutes: TTL_MINUTES };
}

/**
 * Checks a code. consume=true deletes it on success (single use).
 * Returns { ok: true, email } or { ok: false } — callers show ONE generic message for every failure.
 *
 * The database is shared by concurrent requests, so this is built from atomic statements:
 *  1. the guess is COUNTED first (UPDATE ... attempts + 1 ... RETURNING) — parallel guesses cannot exceed MAX_ATTEMPTS;
 *  2. a correct code is consumed with DELETE ... RETURNING — of two parallel requests with the right code, only one wins.
 */
async function check({ userId, purpose, code, consume }) {
  const now = Date.now();
  const row = await db.get(
    `UPDATE otp_codes SET attempts = attempts + 1
      WHERE user_id = $1 AND purpose = $2 AND expires_at > $3 AND attempts < $4
      RETURNING id, code_hash, email, attempts`,
    [userId, purpose, now, MAX_ATTEMPTS]
  );
  if (!row) {
    await db.run('DELETE FROM otp_codes WHERE user_id = $1 AND purpose = $2 AND expires_at <= $3', [userId, purpose, now]);
    return { ok: false };
  }
  const good = typeof code === 'string' && /^\d{6}$/.test(code) && safeEqualHex(row.code_hash, hashCode(userId, purpose, code));
  if (!good) {
    if (row.attempts >= MAX_ATTEMPTS) await db.run('DELETE FROM otp_codes WHERE id = $1', [row.id]);
    return { ok: false };
  }
  if (consume) {
    const del = await db.run('DELETE FROM otp_codes WHERE id = $1 RETURNING id', [row.id]);
    return del.changes === 1 ? { ok: true, email: row.email } : { ok: false };
  }
  await db.run('UPDATE otp_codes SET attempts = attempts - 1 WHERE id = $1', [row.id]); // a correct code is not a failed guess
  return { ok: true, email: row.email };
}

/** Removes a user's outstanding codes (all purposes, or just the listed ones). */
async function clearForUser(userId, purposes) {
  if (!purposes) return db.run('DELETE FROM otp_codes WHERE user_id = $1', [userId]);
  for (const p of purposes) await db.run('DELETE FROM otp_codes WHERE user_id = $1 AND purpose = $2', [userId, p]);
}

/** Housekeeping: drops expired codes (codes of deleted accounts go via ON DELETE CASCADE). */
async function sweep() {
  try {
    await db.run('DELETE FROM otp_codes WHERE expires_at <= $1', [Date.now()]);
  } catch (e) { /* database may be restarting or closing; try again next time */ }
}
setInterval(sweep, 10 * 60 * 1000).unref();

module.exports = { issue, check, clearForUser, sweep, TTL_MINUTES, MAX_ATTEMPTS };
