/**
 * middleware/otpLimiter.js
 * -----------------------------------------------------------------------------
 * Rate limits for the email-code endpoints (in-memory, same style as rateLimiter.js).
 *
 *  Asking for a code (forgot password, change password, link email):
 *    - 1 request / 60 s            per account-or-identifier  (OTP_COOLDOWN_SECONDS)
 *    - 5 requests / hour           per account-or-identifier  (OTP_MAX_PER_HOUR)
 *    - 5 requests / hour           per IP                     (OTP_MAX_PER_HOUR)
 *  Guessing a code (verify-otp / reset-password / change-password / verify-email):
 *    - 20 tries / 15 min per IP, 10 tries / 15 min per account-or-identifier
 *    (on top of the 5-wrong-guesses-per-code limit in services/otp.js)
 *
 * "Account-or-identifier" is whatever string the caller typed (username or email) for the public
 * routes, so an unknown name is limited exactly like a real one — the 429s never reveal if it exists.
 * Counters reset on restart; use a shared store (Redis) if you run several processes.
 */

const { createLimiter, normalizeIp } = require('./rateLimiter');

function intFromEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const COOLDOWN_MS = intFromEnv('OTP_COOLDOWN_SECONDS', 60) * 1000;
const HOURLY_MAX = intFromEnv('OTP_MAX_PER_HOUR', 5);
const HOUR_MS = 60 * 60 * 1000;
const TRY_WINDOW_MS = 15 * 60 * 1000;

const cooldownBySubject = createLimiter({ max: 1, windowMs: COOLDOWN_MS });
const hourlyBySubject = createLimiter({ max: HOURLY_MAX, windowMs: HOUR_MS });
const hourlyByIp = createLimiter({ max: HOURLY_MAX, windowMs: HOUR_MS });
const triesByIp = createLimiter({ max: 20, windowMs: TRY_WINDOW_MS });
const triesBySubject = createLimiter({ max: 10, windowMs: TRY_WINDOW_MS });

const all = [cooldownBySubject, hourlyBySubject, hourlyByIp, triesByIp, triesBySubject];
setInterval(() => all.forEach((l) => l.sweep()), 5 * 60 * 1000).unref();

const ipOf = (req) => normalizeIp(req.ip || (req.socket && req.socket.remoteAddress));
const subjectKey = (purpose, subject) => `${purpose}|${String(subject).trim().toLowerCase().slice(0, 254)}`;

function sendLimited(res, waitMs, message) {
  const seconds = Math.max(1, Math.ceil(waitMs / 1000));
  res.set('Retry-After', String(seconds));
  res.status(429).json({ error: message, retryAfterSeconds: seconds });
  return false;
}

/** Call before sending a code. Returns true if allowed (and counts it); otherwise answers 429 and returns false. */
function allowCodeRequest(req, res, purpose, subject) {
  const key = subjectKey(purpose, subject);
  const ip = ipOf(req);
  const cool = cooldownBySubject.retryAfterMs(key);
  if (cool > 0) {
    return sendLimited(res, cool, `Please wait ${Math.ceil(cool / 1000)}s before requesting another code.`);
  }
  const hourly = Math.max(hourlyBySubject.retryAfterMs(key), hourlyByIp.retryAfterMs(ip));
  if (hourly > 0) {
    const mins = Math.max(1, Math.ceil(hourly / 60000));
    return sendLimited(res, hourly, `Too many code requests. Please try again in ${mins} minute${mins === 1 ? '' : 's'}.`);
  }
  cooldownBySubject.hit(key);
  hourlyBySubject.hit(key);
  hourlyByIp.hit(ip);
  return true;
}

/** Call before checking a submitted code. Returns true if allowed (and counts it); otherwise answers 429. */
function allowCodeTry(req, res, purpose, subject) {
  const key = subjectKey(purpose, subject);
  const ip = ipOf(req);
  const wait = Math.max(triesByIp.retryAfterMs(ip), triesBySubject.retryAfterMs(key));
  if (wait > 0) {
    const mins = Math.max(1, Math.ceil(wait / 60000));
    return sendLimited(res, wait, `Too many attempts. Please try again in ${mins} minute${mins === 1 ? '' : 's'}.`);
  }
  triesByIp.hit(ip);
  triesBySubject.hit(key);
  return true;
}

module.exports = { allowCodeRequest, allowCodeTry };
