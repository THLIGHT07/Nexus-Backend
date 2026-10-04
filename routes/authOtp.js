/**
 * routes/authOtp.js
 * -----------------------------------------------------------------------------
 * Email one-time-code flows, mounted at /api/auth (next to routes/auth.js)
 *
 *  Forgot password (public)
 *    POST /forgot-password   { username }                  -> emails a code IF the account has a verified email
 *    POST /verify-otp        { username, otp, purpose:'reset' }  -> is the code right? (does NOT use it up)
 *    POST /reset-password    { username, otp, newPassword } -> sets the new password, code is used up
 *      `username` may be the login username OR the verified email address.
 *
 *  Change password (JWT required; the account needs a verified email)
 *    POST /change-password/send-otp   {}                    -> emails a code to the verified email
 *    POST /verify-otp        { otp, purpose:'change' }      -> (optional pre-check, same route as above)
 *    POST /change-password   { otp, newPassword }           -> sets the password, returns a fresh token
 *
 *  Link / change the account's email (JWT required)
 *    POST /link-email        { email, password }            -> emails a code to the NEW address
 *    POST /verify-email      { otp }                        -> stores it as the verified email
 *
 * Security notes
 *  - The public routes answer identically whether or not the account/email exists; mail is sent in
 *    the background so response time doesn't leak it either. Limits are keyed on what was typed.
 *  - Codes: services/otp.js (hashed, 10 min, 5 guesses, single use). Limits: middleware/otpLimiter.js.
 *  - A password reset/change stamps users.password_changed_at; middleware/auth.js then rejects every
 *    token issued before that moment, so a stolen session dies when the password changes.
 *  - Password rules are the same constants as /register (min 8, max 72).
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const authenticate = require('../middleware/auth');
const otp = require('../services/otp');
const { sendOtpEmail } = require('../services/mailer');
const { allowCodeRequest, allowCodeTry } = require('../middleware/otpLimiter');
const authRouter = require('./auth');

const {
  signToken, normalizeUsernameBody, PASSWORD_MIN, PASSWORD_MAX, SALT_ROUNDS, TOKEN_EXPIRY,
  reauthLockedSeconds, reauthFailed, reauthOk,
} = authRouter.helpers;

const router = express.Router();

const INVALID_CODE = 'Invalid or expired code.';
const COOLDOWN_SECONDS = parseInt(process.env.OTP_COOLDOWN_SECONDS, 10) > 0 ? parseInt(process.env.OTP_COOLDOWN_SECONDS, 10) : 60;
const FORGOT_REPLY = {
  message: "If that account has a verified email, we've sent a 6-digit code to it. It can take a minute to arrive — check spam too.",
  cooldownSeconds: COOLDOWN_SECONDS,
};

// ── helpers ──────────────────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function cleanEmail(v) {
  if (typeof v !== 'string') return null;
  const e = v.trim().toLowerCase();
  return e.length <= 254 && EMAIL_RE.test(e) ? e : null;
}

/** j***@gmail.com — shown to the account's own owner, never to an anonymous caller. */
function maskEmail(email) {
  const [local, domain] = String(email).split('@');
  return `${local.slice(0, 1)}${'*'.repeat(Math.max(2, Math.min(6, local.length - 1)))}@${domain}`;
}

function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < PASSWORD_MIN || pw.length > PASSWORD_MAX) {
    return `Password must be between ${PASSWORD_MIN} and ${PASSWORD_MAX} characters.`;
  }
  return null;
}

/** Account for a typed username or email (email only matches VERIFIED addresses). Blocked accounts are ignored. */
function findByIdentifier(ident) {
  if (typeof ident !== 'string') return undefined;
  const v = ident.trim().toLowerCase();
  if (!v || v.length > 254) return undefined;
  const user = v.includes('@')
    ? db.get('SELECT * FROM users WHERE email = ? AND email_verified = 1', [v])
    : db.get('SELECT * FROM users WHERE lower(username) = ?', [v]);
  return user && user.status !== 'blocked' ? user : undefined;
}
const hasVerifiedEmail = (u) => Boolean(u && u.email && u.email_verified === 1);

/** Sets the password and kills older sessions + outstanding codes. */
async function setPassword(userId, newPassword) {
  const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  db.run('UPDATE users SET password = ?, password_changed_at = ? WHERE id = ?', [hash, Math.floor(Date.now() / 1000), userId]);
  otp.clearForUser(userId, ['reset', 'change']);
}

/** Only authenticate when the caller is doing the logged-in 'change' flow. */
function authIfChange(req, res, next) {
  if (req.body && req.body.purpose === 'change') return authenticate(req, res, next);
  next();
}

const asString = (v, max = 254) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

// ── POST /forgot-password ────────────────────────────────────────────────────
router.post('/forgot-password', normalizeUsernameBody, (req, res, next) => {
  try {
    const ident = asString(req.body && req.body.username);
    if (!ident) return res.status(400).json({ error: 'Enter your username or email.' });
    if (!allowCodeRequest(req, res, 'reset', ident)) return; // 429 already sent

    const user = findByIdentifier(ident);
    if (hasVerifiedEmail(user)) {
      const { code, expiresMinutes } = otp.issue({ userId: user.id, purpose: 'reset' });
      // Not awaited on purpose: the reply must not be slower for real accounts than for unknown ones.
      sendOtpEmail({ to: user.email, code, purpose: 'reset', expiresMinutes })
        .catch((err) => console.error(`[otp] reset email for user #${user.id} failed: ${err.message}`));
    }
    return res.json(FORGOT_REPLY); // same reply for every case
  } catch (err) {
    next(err);
  }
});

// ── POST /verify-otp ─────────────────────────────────────────────────────────
router.post('/verify-otp', authIfChange, normalizeUsernameBody, (req, res, next) => {
  try {
    const { purpose, otp: code } = req.body || {};
    if (purpose !== 'reset' && purpose !== 'change') return res.status(400).json({ error: 'Invalid request.' });

    const subject = purpose === 'change' ? `user:${req.user.id}` : asString(req.body.username);
    if (!subject) return res.status(400).json({ error: 'Invalid request.' });
    if (!allowCodeTry(req, res, purpose, subject)) return;

    const userId = purpose === 'change' ? req.user.id : (findByIdentifier(subject) || {}).id;
    const result = userId ? otp.check({ userId, purpose, code: asString(code, 12), consume: false }) : { ok: false };
    if (!result.ok) return res.status(400).json({ error: INVALID_CODE });
    return res.json({ valid: true });
  } catch (err) {
    next(err);
  }
});

// ── POST /reset-password ─────────────────────────────────────────────────────
router.post('/reset-password', normalizeUsernameBody, async (req, res, next) => {
  try {
    const { otp: code, newPassword } = req.body || {};
    const ident = asString(req.body && req.body.username);
    const pwProblem = passwordProblem(newPassword);
    if (pwProblem) return res.status(400).json({ error: pwProblem });
    if (!ident) return res.status(400).json({ error: INVALID_CODE });
    if (!allowCodeTry(req, res, 'reset', ident)) return;

    const user = findByIdentifier(ident);
    const result = user ? otp.check({ userId: user.id, purpose: 'reset', code: asString(code, 12), consume: true }) : { ok: false };
    if (!result.ok) return res.status(400).json({ error: INVALID_CODE });

    await setPassword(user.id, newPassword);
    console.log(`[auth] user #${user.id} reset their password via email code`);
    return res.json({ message: 'Password updated. You can now sign in with your new password.' });
  } catch (err) {
    next(err);
  }
});

// ── POST /change-password/send-otp  (JWT) ────────────────────────────────────
router.post('/change-password/send-otp', authenticate, async (req, res, next) => {
  try {
    const user = db.get('SELECT id, email, email_verified FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'Account not found.' });
    if (!hasVerifiedEmail(user)) {
      return res.status(400).json({ error: 'Add and verify an email address first.', code: 'EMAIL_REQUIRED' });
    }
    if (!allowCodeRequest(req, res, 'change', `user:${user.id}`)) return;

    const { code, expiresMinutes } = otp.issue({ userId: user.id, purpose: 'change' });
    try {
      await sendOtpEmail({ to: user.email, code, purpose: 'change', expiresMinutes });
    } catch (err) {
      console.error(`[otp] change email for user #${user.id} failed: ${err.message}`);
      otp.clearForUser(user.id, ['change']);
      return res.status(502).json({ error: "We couldn't send the email right now. Please try again in a moment." });
    }
    return res.json({ message: `We sent a 6-digit code to ${maskEmail(user.email)}.`, maskedEmail: maskEmail(user.email), cooldownSeconds: COOLDOWN_SECONDS });
  } catch (err) {
    next(err);
  }
});

// ── POST /change-password  (JWT) ─────────────────────────────────────────────
router.post('/change-password', authenticate, async (req, res, next) => {
  try {
    const { otp: code, newPassword } = req.body || {};
    const pwProblem = passwordProblem(newPassword);
    if (pwProblem) return res.status(400).json({ error: pwProblem });
    if (!allowCodeTry(req, res, 'change', `user:${req.user.id}`)) return;

    const user = db.get('SELECT id, username, password FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'Account not found.' });

    const result = otp.check({ userId: user.id, purpose: 'change', code: asString(code, 12), consume: true });
    if (!result.ok) return res.status(400).json({ error: INVALID_CODE });

    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({ error: 'Choose a password different from your current one. (Request a new code to try again.)' });
    }

    await setPassword(user.id, newPassword);
    console.log(`[auth] user #${user.id} changed their password via email code`);
    return res.json({
      message: 'Password changed. Other devices have been signed out.',
      token: signToken({ id: user.id, username: user.username }), // issued after password_changed_at, so it stays valid
      expiresIn: TOKEN_EXPIRY,
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /link-email  (JWT) ──────────────────────────────────────────────────
// Needs the current password: a left-open session alone must not be able to attach an attacker's inbox.
router.post('/link-email', authenticate, async (req, res, next) => {
  try {
    const { password } = req.body || {};
    const email = cleanEmail(req.body && req.body.email);
    if (!email) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (typeof password !== 'string' || !password) return res.status(400).json({ error: 'Enter your current password.' });

    const locked = reauthLockedSeconds(req.user.id);
    if (locked) {
      res.set('Retry-After', String(locked));
      return res.status(429).json({ error: 'Too many wrong passwords. Try again in a few minutes.' });
    }
    const user = db.get('SELECT id, password, email, email_verified FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'Account not found.' });
    if (!(await bcrypt.compare(password, user.password))) {
      reauthFailed(user.id);
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    reauthOk(user.id);

    if (hasVerifiedEmail(user) && user.email === email) {
      return res.status(400).json({ error: 'That is already your verified email.' });
    }
    if (!allowCodeRequest(req, res, 'verify_email', `user:${user.id}`)) return;

    const reply = {
      message: `If ${maskEmail(email)} can be used, a 6-digit code is on its way.`,
      maskedEmail: maskEmail(email),
      cooldownSeconds: COOLDOWN_SECONDS,
    };
    // Address already belongs to someone else: say nothing different (no email enumeration), send nothing.
    if (db.get('SELECT id FROM users WHERE email = ? AND id <> ?', [email, user.id])) return res.json(reply);

    const { code, expiresMinutes } = otp.issue({ userId: user.id, purpose: 'verify_email', email });
    try {
      await sendOtpEmail({ to: email, code, purpose: 'verify_email', expiresMinutes });
    } catch (err) {
      console.error(`[otp] verify-email mail for user #${user.id} failed: ${err.message}`);
      otp.clearForUser(user.id, ['verify_email']);
      return res.status(502).json({ error: "We couldn't send the email right now. Please try again in a moment." });
    }
    return res.json(reply);
  } catch (err) {
    next(err);
  }
});

// ── POST /verify-email  (JWT) ────────────────────────────────────────────────
router.post('/verify-email', authenticate, (req, res, next) => {
  try {
    if (!allowCodeTry(req, res, 'verify_email', `user:${req.user.id}`)) return;
    const result = otp.check({ userId: req.user.id, purpose: 'verify_email', code: asString(req.body && req.body.otp, 12), consume: true });
    if (!result.ok || !result.email) return res.status(400).json({ error: INVALID_CODE });

    try {
      db.run('UPDATE users SET email = ?, email_verified = 1 WHERE id = ?', [result.email, req.user.id]);
    } catch (err) {
      if (db.isUniqueViolation(err)) return res.status(400).json({ error: "This email address can't be used." });
      throw err;
    }
    otp.clearForUser(req.user.id, ['reset', 'change']); // codes sent to the previous address are void
    console.log(`[auth] user #${req.user.id} verified an email address`);
    return res.json({ message: 'Email verified.', email: result.email, emailVerified: true, maskedEmail: maskEmail(result.email) });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
