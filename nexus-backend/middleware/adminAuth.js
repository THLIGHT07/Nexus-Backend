/**
 * middleware/adminAuth.js
 * -----------------------------------------------------------------------------
 * Single-admin protection for everything under /api/admin/*.
 *
 *   POST /api/admin/login   { password }  ->  { token, expiresAt }   (public, rate-limited)
 *   every other /api/admin/* route        ->  needs  Authorization: Bearer <admin token>
 *
 * HOW THE PASSWORD IS STORED (in .env, never in code, never sent to the browser)
 *   ADMIN_PASSWORD_HASH  bcrypt hash — preferred. Create it with:  npm run set-admin-password
 *   ADMIN_PASSWORD       plain text — accepted for convenience; hashed in memory on
 *                        startup, and a warning is printed. Prefer the hash.
 *   If neither is set (or the value is unusable) the admin API stays DISABLED and
 *   answers 503. It never falls back to "open" or to a built-in default password.
 *
 * HOW THE TOKEN WORKS
 *   A short-lived JWT (ADMIN_TOKEN_TTL, default 2h) signed with a key that is
 *   DERIVED from JWT_SECRET *and* the admin password. That means:
 *     - a normal user's login token can never be used as an admin token (different key),
 *     - changing the admin password instantly invalidates every existing admin token,
 *     - "Log out" revokes the token on the server (until it would have expired anyway).
 *
 * BRUTE-FORCE PROTECTION
 *   5 wrong passwords from one IP  ->  that IP is locked out of /login for 15 minutes
 *   (HTTP 429 + Retry-After), even if it then sends the right password.
 *   Behind a reverse proxy set TRUST_PROXY (see server.js) so each visitor has their
 *   own IP — otherwise they all look like the proxy and would share one lockout.
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const ISSUER = 'nexus-admin';
const MIN_PASSWORD_LENGTH = 8;
const BCRYPT_ROUNDS = 12;
const BCRYPT_HASH_RE = /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/;

const MAX_FAILED_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // failures older than this are forgotten
const LOCKOUT_MS = 15 * 60 * 1000; // how long an IP is locked after too many failures
const FAILURE_DELAY_MS = 300; // small fixed delay on every wrong password

/** Filled in by initAdminAuth(). */
const state = {
  enabled: false,
  hash: null,
  signingKey: null,
  ttl: '2h',
  reason: 'Admin authentication has not been initialised.',
};

const failures = new Map(); // ip -> { count, first, lockedUntil }
const revoked = new Map(); // token id (jti) -> expiry in ms

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

// -----------------------------------------------------------------------------
// Startup configuration
// -----------------------------------------------------------------------------

function disable(reason) {
  state.enabled = false;
  state.hash = null;
  state.signingKey = null;
  state.reason = reason;
  console.error(`[admin] ADMIN API DISABLED: ${reason}`);
  console.error('[admin] Every /api/admin/* request will be refused until this is fixed.');
  console.error('[admin] Fix: run  npm run set-admin-password  and restart the server.');
}

/** Reads the admin settings from process.env. Call once at startup (after dotenv). */
function initAdminAuth() {
  const rawHash = (process.env.ADMIN_PASSWORD_HASH || '').trim();
  const rawPlain = process.env.ADMIN_PASSWORD || '';

  let hash;
  let fingerprint;

  if (rawHash) {
    if (!BCRYPT_HASH_RE.test(rawHash)) {
      return disable('ADMIN_PASSWORD_HASH in .env is not a valid bcrypt hash (re-create it with: npm run set-admin-password).');
    }
    hash = rawHash;
    fingerprint = `hash:${rawHash}`;
  } else if (rawPlain) {
    if (rawPlain.length < MIN_PASSWORD_LENGTH) {
      return disable(`ADMIN_PASSWORD in .env is shorter than ${MIN_PASSWORD_LENGTH} characters.`);
    }
    hash = bcrypt.hashSync(rawPlain, BCRYPT_ROUNDS); // compare against a bcrypt hash even in plain mode
    fingerprint = `plain:${sha256(rawPlain)}`;
    console.warn('[admin] ADMIN_PASSWORD is stored in plain text in .env. Safer: run  npm run set-admin-password  (stores only a bcrypt hash).');
  } else {
    return disable('No admin password is configured (set ADMIN_PASSWORD_HASH or ADMIN_PASSWORD in .env).');
  }

  // Token lifetime: validate it now so a typo can't turn into a 500 at login time.
  let ttl = (process.env.ADMIN_TOKEN_TTL || '2h').trim();
  const signingKey = crypto
    .createHmac('sha256', process.env.JWT_SECRET)
    .update(`nexus-admin-token-v1|${fingerprint}`)
    .digest('hex');
  try {
    jwt.sign({ scope: 'admin' }, signingKey, { expiresIn: ttl });
  } catch (err) {
    console.warn(`[admin] ADMIN_TOKEN_TTL "${ttl}" is not valid (examples: 30m, 2h, 1d) — using 2h.`);
    ttl = '2h';
  }

  state.enabled = true;
  state.hash = hash;
  state.signingKey = signingKey;
  state.ttl = ttl;
  state.reason = '';
  console.log(`[admin] Admin protection is ON (sessions last ${ttl}; ${MAX_FAILED_ATTEMPTS} wrong passwords = ${LOCKOUT_MS / 60000} min lockout).`);
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function sendDisabled(res) {
  return res.status(503).json({
    error: 'Admin access is not configured on the server. Set ADMIN_PASSWORD_HASH in .env (run: npm run set-admin-password) and restart.',
    code: 'ADMIN_DISABLED',
  });
}

function clientIp(req) {
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

/** Seconds left on this IP's lockout, or 0 if it is not locked. */
function lockoutSecondsLeft(ip) {
  const rec = failures.get(ip);
  if (!rec || !rec.lockedUntil) return 0;
  const left = rec.lockedUntil - Date.now();
  return left > 0 ? Math.ceil(left / 1000) : 0;
}

/** Records a wrong password; returns how many attempts remain before lockout. */
function recordFailure(ip) {
  const now = Date.now();
  let rec = failures.get(ip);
  if (!rec || now - rec.first > WINDOW_MS) {
    rec = { count: 0, first: now, lockedUntil: 0 };
    failures.set(ip, rec);
  }
  rec.count += 1;
  if (rec.count >= MAX_FAILED_ATTEMPTS) {
    rec.lockedUntil = now + LOCKOUT_MS;
    console.warn(`[admin] ${ip} locked out for ${LOCKOUT_MS / 60000} min after ${rec.count} failed logins.`);
  }
  return Math.max(0, MAX_FAILED_ATTEMPTS - rec.count);
}

// Forget old failures / expired revocations so these maps can't grow forever.
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of failures) {
    if (now - rec.first > WINDOW_MS && rec.lockedUntil < now) failures.delete(ip);
  }
  for (const [jti, expiresAt] of revoked) {
    if (expiresAt < now) revoked.delete(jti);
  }
}, 60 * 1000).unref();

// -----------------------------------------------------------------------------
// Route handlers / middleware
// -----------------------------------------------------------------------------

/** Adds headers that stop browsers/proxies from caching admin responses. */
function noStore(req, res, next) {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  });
  next();
}

/** POST /api/admin/login */
async function adminLogin(req, res, next) {
  try {
    if (!state.enabled) return sendDisabled(res);

    const ip = clientIp(req);
    const locked = lockoutSecondsLeft(ip);
    if (locked > 0) {
      res.set('Retry-After', String(locked));
      return res.status(429).json({
        error: `Too many failed attempts. Try again in ${Math.ceil(locked / 60)} minute(s).`,
        retryAfterSeconds: locked,
      });
    }

    const password = req.body && req.body.password;
    if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
      return res.status(400).json({ error: 'Password is required.' });
    }

    const ok = await bcrypt.compare(password, state.hash);
    if (!ok) {
      const attemptsLeft = recordFailure(ip);
      console.warn(`[admin] failed login from ${ip} (${attemptsLeft} attempt(s) left)`);
      await sleep(FAILURE_DELAY_MS);
      const nowLocked = lockoutSecondsLeft(ip);
      if (nowLocked > 0) res.set('Retry-After', String(nowLocked));
      return res.status(nowLocked > 0 ? 429 : 401).json(
        nowLocked > 0
          ? { error: `Too many failed attempts. Try again in ${Math.ceil(nowLocked / 60)} minute(s).`, retryAfterSeconds: nowLocked }
          : { error: 'Incorrect admin password.', attemptsLeft }
      );
    }

    failures.delete(ip);
    const token = jwt.sign({ scope: 'admin' }, state.signingKey, {
      algorithm: 'HS256',
      expiresIn: state.ttl,
      issuer: ISSUER,
      subject: 'admin',
      jwtid: crypto.randomUUID(),
    });
    const { exp } = jwt.decode(token);
    console.log(`[admin] login ok from ${ip}`);
    return res.json({ token, expiresAt: new Date(exp * 1000).toISOString() });
  } catch (err) {
    return next(err);
  }
}

/** Guards every admin route: requires a valid, unexpired, unrevoked admin token. */
function requireAdmin(req, res, next) {
  if (!state.enabled) return sendDisabled(res);

  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Admin authentication required.' });
  }

  let payload;
  try {
    payload = jwt.verify(token, state.signingKey, { algorithms: ['HS256'], issuer: ISSUER });
  } catch (err) {
    return res.status(401).json({
      error: err.name === 'TokenExpiredError' ? 'Admin session expired. Please sign in again.' : 'Invalid admin token.',
    });
  }

  if (payload.scope !== 'admin' || !payload.jti || revoked.has(payload.jti)) {
    return res.status(401).json({ error: 'Invalid admin token.' });
  }

  req.admin = { jti: payload.jti, exp: payload.exp, ip: clientIp(req) };
  return next();
}

/** GET /api/admin/verify — lets the page check a stored token without loading any data. */
function adminVerify(req, res) {
  res.json({ ok: true, expiresAt: new Date(req.admin.exp * 1000).toISOString() });
}

/** POST /api/admin/logout — revokes the presented token on the server. */
function adminLogout(req, res) {
  revoked.set(req.admin.jti, req.admin.exp * 1000);
  console.log(`[admin] logout from ${req.admin.ip}`);
  res.json({ message: 'Signed out.' });
}

module.exports = { initAdminAuth, noStore, adminLogin, requireAdmin, adminVerify, adminLogout };
