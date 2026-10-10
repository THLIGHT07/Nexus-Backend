/**
 * routes/auth.js
 * -----------------------------------------------------------------------------
 * Authentication routes, mounted at /api/auth
 *
 *   POST /register  -> create a new account          (rate-limited, see middleware/rateLimiter.js)
 *   POST /login     -> verify credentials, return a JWT (rate-limited, see middleware/rateLimiter.js)
 *   GET  /me        -> return the current user (protected)
 *   PATCH /me/username -> change your login username (protected, needs your current password)
 *   DELETE /me      -> delete your own account (protected, needs your current password)
 *
 * Password reset / change / email linking live in routes/authOtp.js (same /api/auth prefix).
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const authenticate = require('../middleware/auth');
const {
  loginGuard,
  registerGuard,
  clearLoginFailures,
  getLoginFailureState,
  sendTooManyAttempts,
} = require('../middleware/rateLimiter');

const router = express.Router();

const SALT_ROUNDS = 12;
const TOKEN_EXPIRY = '7d';

// Version of the Terms of Use / Privacy Policy pages (their "Last updated" date). Stored next to the acceptance
// timestamp for your records. Override with TERMS_VERSION in .env when you publish new wording.
const TERMS_VERSION = process.env.TERMS_VERSION || '2026-10-08';

// bcrypt silently ignores anything past 72 bytes, so we cap the length.
// Usernames: only a-z, 0-9 and hyphen (-); at least 5 letters and at least 1 digit; no spaces; always stored
// lowercase; 30 characters at most; unique (case-insensitive).
//   valid:   nexus-nexi1088   lord12345   sainath9
//   invalid: nexus (no digit)   12345678 (no 5 letters)   "nexus nexi1088" (space)
// Input is trimmed + lowercased by normalizeUsernameBody() before anything else sees it. These rules apply to NEW
// registrations and username changes only — login never validates the format, so existing accounts keep working.
const USERNAME_MIN_LETTERS = 5;
const USERNAME_MIN_DIGITS = 1;
const USERNAME_MAX = 30;
const USERNAME_MSG = {
  empty: 'Choose a username.',
  space: "Spaces aren't allowed — use a hyphen (-) instead.",
  chars: 'Only letters a–z, numbers 0–9 and hyphens (-) are allowed.',
  letters: `Needs at least ${USERNAME_MIN_LETTERS} letters (a–z).`,
  digit: `Needs at least ${USERNAME_MIN_DIGITS} number (0–9).`,
  max: `Can be at most ${USERNAME_MAX} characters.`,
};
const USERNAME_TAKEN = 'Username already exists';
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 72;

// A throwaway hash used to keep login timing similar whether or not the
// username exists (helps prevent username enumeration via response time).
const DUMMY_HASH = bcrypt.hashSync('dummy-password', SALT_ROUNDS);

/** Signs a JWT that expires in 7 days. */
function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

/** Extracts string credentials from the request body, or null if invalid. */
function getCredentials(body) {
  const { username, password } = body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return null;
  }
  return { username: username.trim(), password };
}

/** Trims + lowercases body.username so the rate limiter, lookups and storage all see ONE spelling. */
function normalizeUsernameBody(req, res, next) {
  if (req.body && typeof req.body.username === 'string') {
    req.body.username = req.body.username.trim().toLowerCase();
  }
  next();
}

/** Every rule a (normalized) username breaks, as messages — [] if it is acceptable. */
function usernameProblems(name) {
  if (typeof name !== 'string' || !name) return [USERNAME_MSG.empty];
  const out = [];
  if (/\s/.test(name)) out.push(USERNAME_MSG.space);
  const rest = name.replace(/\s/g, '');
  if (/[^a-z0-9-]/.test(rest)) out.push(USERNAME_MSG.chars);
  if ((rest.match(/[a-z]/g) || []).length < USERNAME_MIN_LETTERS) out.push(USERNAME_MSG.letters);
  if ((rest.match(/[0-9]/g) || []).length < USERNAME_MIN_DIGITS) out.push(USERNAME_MSG.digit);
  if (name.length > USERNAME_MAX) out.push(USERNAME_MSG.max);
  return out;
}
/** 400 body for a rejected username: `error` (all messages in one line) + `errors` (the list). */
function usernameRejection(problems) {
  return { error: problems.join(' '), errors: problems };
}

/** True if another account (not `exceptId`) already uses this name, ignoring case. */
async function usernameTaken(name, exceptId) {
  return !!(await db.get('SELECT id FROM users WHERE lower(username) = $1 AND id <> $2', [name, exceptId || 0]));
}

// Wrong-password limiter for actions that re-ask for the password (delete account, change username):
// 5 failures in a row -> locked for 15 minutes, per user.
const REAUTH_MAX_FAILS = 5;
const REAUTH_LOCK_MS = 15 * 60 * 1000;
const reauthFailures = new Map(); // userId -> { count, lockedUntil }
function reauthLockedSeconds(userId) {
  const st = reauthFailures.get(userId);
  return st && st.lockedUntil > Date.now() ? Math.ceil((st.lockedUntil - Date.now()) / 1000) : 0;
}
function reauthFailed(userId) {
  const st = reauthFailures.get(userId) || { count: 0, lockedUntil: 0 };
  st.count += 1;
  if (st.count >= REAUTH_MAX_FAILS) { st.lockedUntil = Date.now() + REAUTH_LOCK_MS; st.count = 0; }
  reauthFailures.set(userId, st);
}
function reauthOk(userId) { reauthFailures.delete(userId); }

// -----------------------------------------------------------------------------
// POST /api/auth/register
// -----------------------------------------------------------------------------
router.post('/register', normalizeUsernameBody, registerGuard, async (req, res, next) => {
  try {
    const creds = getCredentials(req.body);
    if (!creds) {
      return res
        .status(400)
        .json({ error: 'Username and password are required.' });
    }

    const { username, password } = creds;

    const problems = usernameProblems(username);
    if (problems.length) {
      return res.status(400).json(usernameRejection(problems));
    }
    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
      return res.status(400).json({
        error: `Password must be between ${PASSWORD_MIN} and ${PASSWORD_MAX} characters.`,
      });
    }

    // Friendly duplicate check (the UNIQUE constraint below is the real guard).
    if (await usernameTaken(username)) {
      return res.status(409).json({ error: USERNAME_TAKEN });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    let user;
    try {
      user = await db.get(
        'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at',
        [username, hashedPassword]
      );
    } catch (err) {
      // Handles a race where two requests register the same name at once.
      if (db.isUniqueViolation(err)) {
        return res.status(409).json({ error: USERNAME_TAKEN });
      }
      throw err;
    }

    return res.status(201).json({
      message: 'User registered successfully.',
      user,
    });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// POST /api/auth/login
// -----------------------------------------------------------------------------
router.post('/login', normalizeUsernameBody, loginGuard, async (req, res, next) => {
  try {
    const creds = getCredentials(req.body);
    if (!creds || !creds.username || !creds.password) {
      return res
        .status(400)
        .json({ error: 'Username and password are required.' });
    }

    const { username, password } = creds;
    // Case-insensitive (the database enforces one account per lower-cased name), so accounts created
    // before the lowercase rule still log in.
    const user = await db.get(
      'SELECT id, username, password_hash, status, created_at, terms_accepted_at, terms_version FROM users WHERE lower(username) = $1',
      [username]
    );

    // Always run a bcrypt comparison, even for unknown users.
    const hashToCheck = user ? user.password_hash : DUMMY_HASH;
    const passwordMatches = await bcrypt.compare(password, hashToCheck);

    if (!user || !passwordMatches) {
      // Same message for both cases so attackers can't tell which was wrong.
      // The last allowed attempt answers 429 (the page then shows its lock countdown);
      // earlier ones answer 401 + how many attempts are left.
      const limit = getLoginFailureState(req);
      if (limit.locked) return sendTooManyAttempts(res, limit.retryAfterMs);
      return res.status(401).json({
        error: 'Invalid username or password.',
        attemptsLeft: limit.attemptsLeft,
        maxAttempts: limit.maxAttempts,
      });
    }

    // Correct credentials: forget this IP's / username's earlier failed attempts.
    clearLoginFailures(req);

    if (user.status === 'blocked') {
      return res
        .status(403)
        .json({ error: 'Your account is blocked. Please contact admin.' });
    }

    const token = signToken(user);

    return res.json({
      message: 'Login successful.',
      token,
      expiresIn: TOKEN_EXPIRY,
      user: {
        id: user.id,
        username: user.username,
        created_at: user.created_at,
        terms_accepted_at: user.terms_accepted_at, // null until the user accepts the Terms + Privacy Policy gate
        terms_version: user.terms_version,
      },
    });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// POST /api/auth/accept-terms  (protected) — record that THIS account accepted the Terms of Use + Privacy Policy
// -----------------------------------------------------------------------------
// No body needed. Idempotent: the first acceptance time/version is kept (COALESCE), so repeating the call, or
// accepting from a second device, changes nothing. Once set, the app never shows the acceptance gate again.
router.post('/accept-terms', authenticate, async (req, res, next) => {
  try {
    const row = await db.get(
      `UPDATE users
          SET terms_accepted_at = COALESCE(terms_accepted_at, now()),
              terms_version     = COALESCE(terms_version, $2)
        WHERE id = $1
    RETURNING terms_accepted_at, terms_version`,
      [req.user.id, TERMS_VERSION]
    );
    if (!row) return res.status(401).json({ error: 'User no longer exists.' });
    return res.json({ message: 'Terms accepted.', terms_accepted_at: row.terms_accepted_at, terms_version: row.terms_version });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// GET /api/auth/me  (protected)
// -----------------------------------------------------------------------------
router.get('/me', authenticate, (req, res) => {
  res.json({ user: req.user });
});

// -----------------------------------------------------------------------------
// PATCH /api/auth/me/username  (protected) — change your own login username
// -----------------------------------------------------------------------------
// Body: { username, password }.  The new name must follow the username rules above; the current password is required. Order matters:
// format check -> lock check -> password -> "already exists", so nobody can probe which
// usernames exist without knowing the password. The reply carries a fresh JWT (the old
// token still names the old username).
router.patch('/me/username', authenticate, normalizeUsernameBody, async (req, res, next) => {
  try {
    const userId = req.user && req.user.id;
    if (!userId) return res.status(401).json({ error: 'Not authenticated.' });

    const username = req.body && req.body.username;
    const password = req.body && req.body.password;
    if (typeof password !== 'string' || !password) {
      return res.status(400).json({ error: 'Enter your current password to change your username.' });
    }
    const problems = usernameProblems(username);
    if (problems.length) return res.status(400).json(usernameRejection(problems));

    const locked = reauthLockedSeconds(userId);
    if (locked) {
      res.set('Retry-After', String(locked));
      return res.status(429).json({ error: 'Too many wrong passwords. Try again in a few minutes.' });
    }

    const user = await db.get('SELECT id, username, password_hash FROM users WHERE id = $1', [userId]);
    if (!user) return res.status(404).json({ error: 'Account not found.' });

    if (!(await bcrypt.compare(password, user.password_hash))) {
      reauthFailed(userId);
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    reauthOk(userId);

    if (user.username === username) {
      return res.status(400).json({ error: 'That is already your username.' });
    }
    if (await usernameTaken(username, userId)) {
      return res.status(409).json({ error: USERNAME_TAKEN });
    }

    try {
      await db.run('UPDATE users SET username = $1 WHERE id = $2', [username, userId]);
    } catch (err) {
      if (db.isUniqueViolation(err)) return res.status(409).json({ error: USERNAME_TAKEN });
      throw err;
    }

    console.log(`[auth] user #${userId} changed username ${user.username} -> ${username}`);
    return res.json({
      message: 'Username updated.',
      username,
      token: signToken({ id: userId, username }),
      expiresIn: TOKEN_EXPIRY,
    });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// DELETE /api/auth/me  (protected) — a user deletes their OWN account
// -----------------------------------------------------------------------------
// The caller must send their current password again (a stolen/left-open session
// alone can't delete the account). Wrong passwords share the limiter above.
router.delete('/me', authenticate, async (req, res, next) => {
  try {
    const userId = req.user && req.user.id;
    const password = req.body && req.body.password;
    if (!userId) return res.status(401).json({ error: 'Not authenticated.' });
    if (typeof password !== 'string' || !password) {
      return res.status(400).json({ error: 'Password is required to delete your account.' });
    }

    const locked = reauthLockedSeconds(userId);
    if (locked) {
      res.set('Retry-After', String(locked));
      return res.status(429).json({ error: 'Too many wrong passwords. Try again in a few minutes.' });
    }

    const user = await db.get('SELECT id, username, password_hash FROM users WHERE id = $1', [userId]);
    if (!user) return res.status(404).json({ error: 'Account not found.' });

    if (!(await bcrypt.compare(password, user.password_hash))) {
      reauthFailed(userId);
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    reauthOk(userId);
    await db.run('DELETE FROM users WHERE id = $1', [user.id]); // profile, settings, apps, notes and codes go with it (ON DELETE CASCADE)
    console.log(`[auth] user #${user.id} (${user.username}) deleted their account`);
    return res.json({ message: 'Account deleted.' });
  } catch (err) {
    next(err);
  }
});

// Shared with routes/authOtp.js (email-code flows) so both use the same rules, hashing cost and token format.
router.helpers = {
  signToken,
  normalizeUsernameBody,
  PASSWORD_MIN,
  PASSWORD_MAX,
  SALT_ROUNDS,
  TOKEN_EXPIRY,
  reauthLockedSeconds,
  reauthFailed,
  reauthOk,
};

module.exports = router;
