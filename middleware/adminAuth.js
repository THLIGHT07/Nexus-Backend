/**
 * middleware/adminAuth.js
 * -----------------------------------------------------------------------------
 * Single-admin protection for everything under /api/admin/*.
 *
 *   POST /api/admin/login   { password }  ->  { token, expiresAt }   (public, rate-limited)
 *   every other /api/admin/* route        ->  needs  Authorization: Bearer <admin token>
 *
 * HOW THE PASSWORD IS STORED (environment variables — Railway: Variables; never in code, never sent to the browser)
 *   ADMIN_PASSWORD_HASH  RECOMMENDED. A bcrypt hash. Generate it on your own computer with
 *                        `npm run set-admin-password` (it only prints the hash) and paste it into the variable.
 *                        Sign-in uses bcrypt.compare(typedPassword, hash). You always TYPE the real password.
 *   ADMIN_PASSWORD       simple setups only: the plain password, compared in constant time. A warning is printed.
 *                        (If this variable holds a bcrypt hash by mistake it is treated as ADMIN_PASSWORD_HASH,
 *                        so the real password still works — and a warning tells you to rename the variable.)
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
 *   Every attempt from an IP is counted BEFORE the password is checked (so a burst of parallel requests can't
 *   get more than 5 tries). Wrong passwords answer 401 with attemptsLeft 4, 3, 2, 1; the 5th wrong one locks
 *   that IP out of /login for 15 minutes (HTTP 429 + Retry-After + retryAfterSeconds), even if it then sends
 *   the right password. A correct password clears that IP's counter.
 *
 * WHICH IP IS "THE CLIENT"
 *   Behind Railway the TCP peer and the number of X-Forwarded-For hops change from request to request, so
 *   Express's req.ip can be a different proxy every time — every attempt then looks like a new visitor and the
 *   counter never moves. Railway's edge proxy sets X-Real-IP to the real client address, so on Railway
 *   (detected from RAILWAY_* variables) that header is used. Override with CLIENT_IP_HEADER:
 *     CLIENT_IP_HEADER=x-real-ip   use that header      CLIENT_IP_HEADER=none   always use req.ip (TRUST_PROXY)
 *   Only point this at a header your own proxy overwrites. IPv6 addresses are counted per /64.
 */

const crypto = require('crypto');
const net = require('net');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { normalizeIp } = require('./rateLimiter');

const ISSUER = 'nexus-admin';
const MIN_PASSWORD_LENGTH = 8;
const BCRYPT_ROUNDS = 12;
const BCRYPT_HASH_RE = /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/;

const MAX_FAILED_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // failures older than this are forgotten
const LOCKOUT_MS = 15 * 60 * 1000; // how long an IP is locked after too many failures
const FAILURE_DELAY_MS = 300; // small fixed delay on every wrong password

/** Filled in by initAdminAuth(). `verify(plain)` resolves true/false and is the ONLY place a password is checked. */
const state = {
  enabled: false,
  verify: null,
  signingKey: null,
  ttl: '2h',
  reason: 'Admin authentication has not been initialised.',
};

const failures = new Map(); // client key (see clientKey) -> { count, first, lockedUntil }
const revoked = new Map(); // token id (jti) -> expiry in ms

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const sha256Buf = (value) => crypto.createHash('sha256').update(value).digest();
/** Env values are sometimes pasted together with their quotes (e.g. a whole `NAME='value'` line copied into Railway). */
const stripQuotes = (value) => value.replace(/^(['"])(.*)\1$/s, '$2');

// -----------------------------------------------------------------------------
// Startup configuration
// -----------------------------------------------------------------------------

function disable(reason) {
  state.enabled = false;
  state.verify = null;
  state.signingKey = null;
  state.reason = reason;
  console.error(`[admin] ADMIN API DISABLED: ${reason}`);
  console.error('[admin] Every /api/admin/* request will be refused until this is fixed.');
  console.error('[admin] Fix: run  npm run set-admin-password  on your computer, set ADMIN_PASSWORD_HASH to the hash it prints (Railway: Variables), and redeploy.');
}

/** Reads the admin settings from process.env. Call once at startup (after dotenv). */
function initAdminAuth() {
  let rawHash = stripQuotes((process.env.ADMIN_PASSWORD_HASH || '').trim());
  let rawPlain = process.env.ADMIN_PASSWORD || '';

  // Common mistake: the hash was pasted into ADMIN_PASSWORD. Used as a plain password it would only ever
  // match when someone TYPES the hash. Treat it as the hash it is, so the real password is what works.
  const plainAsHash = stripQuotes(rawPlain.trim());
  if (!rawHash && plainAsHash && BCRYPT_HASH_RE.test(plainAsHash)) {
    console.warn('[admin] ADMIN_PASSWORD contains a bcrypt hash. Treating it as ADMIN_PASSWORD_HASH — sign in with the real password, never the hash. Please rename the variable to ADMIN_PASSWORD_HASH.');
    rawHash = plainAsHash;
    rawPlain = '';
  }

  let verify;
  let fingerprint;

  if (rawHash) {
    if (!BCRYPT_HASH_RE.test(rawHash)) {
      return disable('ADMIN_PASSWORD_HASH is not a valid bcrypt hash (re-create it with: npm run set-admin-password).');
    }
    if (rawPlain) console.warn('[admin] ADMIN_PASSWORD is ignored because ADMIN_PASSWORD_HASH is set. You can remove ADMIN_PASSWORD.');
    verify = (plain) => bcrypt.compare(plain, rawHash);
    fingerprint = `hash:${rawHash}`;
  } else if (rawPlain) {
    if (rawPlain.length < MIN_PASSWORD_LENGTH) {
      return disable(`ADMIN_PASSWORD is shorter than ${MIN_PASSWORD_LENGTH} characters.`);
    }
    // Constant-time comparison of fixed-length digests (no early exit that leaks how much matched).
    const expected = sha256Buf(rawPlain);
    verify = async (plain) => crypto.timingSafeEqual(sha256Buf(plain), expected);
    fingerprint = `plain:${sha256(rawPlain)}`;
    console.warn('[admin] ADMIN_PASSWORD is a plain-text password in your environment. Safer: run  npm run set-admin-password  and set ADMIN_PASSWORD_HASH instead.');
  } else {
    return disable('No admin password is configured (set ADMIN_PASSWORD_HASH — or, for simple setups, ADMIN_PASSWORD).');
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
  state.verify = verify;
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
    error: 'Admin access is not configured on the server. Set ADMIN_PASSWORD_HASH (generate it with: npm run set-admin-password) in the server environment variables and redeploy.',
    code: 'ADMIN_DISABLED',
  });
}

// Header that carries the real client IP: CLIENT_IP_HEADER, or X-Real-IP automatically when running on Railway.
const ON_RAILWAY = Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID || process.env.RAILWAY_PUBLIC_DOMAIN);
function clientIpHeader() {
  const configured = (process.env.CLIENT_IP_HEADER || '').trim().toLowerCase();
  if (configured === 'none' || configured === 'off') return '';
  return configured || (ON_RAILWAY ? 'x-real-ip' : '');
}

/** The visitor's address and where it came from. Falls back to Express's req.ip (honours TRUST_PROXY). */
function resolveClient(req) {
  const header = clientIpHeader();
  if (header) {
    const raw = req.headers[header];
    const value = Array.isArray(raw) ? raw[raw.length - 1] : raw;
    // If a list slipped through ("a, b"), the entry added closest to us (the last) is the trustworthy one.
    const candidate = typeof value === 'string' ? value.split(',').pop().trim() : '';
    if (candidate && net.isIP(candidate)) return { ip: candidate, via: header };
  }
  return { ip: req.ip || (req.socket && req.socket.remoteAddress) || 'unknown', via: 'req.ip' };
}

const clientIp = (req) => resolveClient(req).ip;
/** Counter key: IPv4 as is, IPv6 collapsed to its /64 (one connection controls billions of addresses). */
const clientKey = (req) => normalizeIp(clientIp(req));

/**
 * Counts this attempt BEFORE the (slow) password check, so parallel requests can't slip past the limit.
 * Returns { locked: secondsLeft } when the client may not try, otherwise { attempt: 1..5 }.
 */
function startAttempt(key) {
  const now = Date.now();
  let rec = failures.get(key);
  if (rec && rec.lockedUntil > now) return { locked: Math.ceil((rec.lockedUntil - now) / 1000) };
  if (!rec || now - rec.first > WINDOW_MS) {
    rec = { count: 0, first: now, lockedUntil: 0 };
    failures.set(key, rec);
  }
  // All tries are already taken (the last may still be in flight): refuse without starting another check.
  if (rec.count >= MAX_FAILED_ATTEMPTS) return { locked: Math.ceil(LOCKOUT_MS / 1000) };
  rec.count += 1;
  return { attempt: rec.count };
}

/** A wrong password: locks the client when this was the last allowed try. Returns the lock length in seconds, or 0. */
function failAttempt(key, attempt) {
  if (attempt < MAX_FAILED_ATTEMPTS) return 0;
  const rec = failures.get(key);
  if (rec) rec.lockedUntil = Date.now() + LOCKOUT_MS;
  return Math.ceil(LOCKOUT_MS / 1000);
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

const tooManyAttempts = (res, seconds) => {
  res.set('Retry-After', String(seconds));
  return res.status(429).json({
    error: `Too many failed attempts. Try again in ${Math.ceil(seconds / 60)} minute(s).`,
    retryAfterSeconds: seconds,
  });
};

/** POST /api/admin/login */
async function adminLogin(req, res, next) {
  try {
    if (!state.enabled) return sendDisabled(res);

    const password = req.body && req.body.password;
    if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
      return res.status(400).json({ error: 'Password is required.' });
    }

    const { ip, via } = resolveClient(req);
    const key = normalizeIp(ip);
    const turn = startAttempt(key);
    if (turn.locked) return tooManyAttempts(res, turn.locked);

    if (!(await state.verify(password))) {
      const lockedFor = failAttempt(key, turn.attempt);
      const attemptsLeft = Math.max(0, MAX_FAILED_ATTEMPTS - turn.attempt);
      // The header values are logged (quoted) so you can confirm in the Railway logs that every try maps to ONE address.
      const xff = JSON.stringify(String(req.headers['x-forwarded-for'] || '').slice(0, 200));
      console.warn(`[admin] failed login from ${key} (via ${via}, x-forwarded-for=${xff}) — ${attemptsLeft} attempt(s) left${lockedFor ? `; LOCKED for ${lockedFor / 60} min` : ''}`);
      await sleep(FAILURE_DELAY_MS);
      return lockedFor
        ? tooManyAttempts(res, lockedFor)
        : res.status(401).json({ error: 'Incorrect admin password.', attemptsLeft });
    }

    failures.delete(key); // a correct password clears this client's counter
    const token = jwt.sign({ scope: 'admin' }, state.signingKey, {
      algorithm: 'HS256',
      expiresIn: state.ttl,
      issuer: ISSUER,
      subject: 'admin',
      jwtid: crypto.randomUUID(),
    });
    const { exp } = jwt.decode(token);
    console.log(`[admin] login ok from ${key}`);
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
