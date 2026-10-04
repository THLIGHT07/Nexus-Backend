/**
 * middleware/rateLimiter.js
 * -----------------------------------------------------------------------------
 * Brute-force protection for the public auth endpoints. Simple, in-memory, no
 * extra dependencies and no database.
 *
 *   POST /api/auth/login     loginGuard     -> blocks guessing passwords
 *   POST /api/auth/register  registerGuard  -> blocks account-creation spam
 *
 * LOGIN — three counters are checked on every attempt:
 *   1. per IP        7 failed attempts / 15 min   (any username)
 *   2. per username  7 failed attempts / 15 min   (any IP -> stops distributed guessing)
 *   3. per IP total  50 attempts / 15 min, successful or not (safety net, see below)
 *   A correct login clears counters 1 and 2 for that IP and username.
 *   The 401 for a wrong password says how many attempts are left; the 7th wrong
 *   attempt already answers 429 (+ retryAfterSeconds) so the page can show its lock
 *   countdown straight away — same flow as the admin panel.
 *   Counter 3 is never cleared: without it an attacker who owns one valid account
 *   could log in to it between guesses and keep resetting counter 1 forever.
 *
 * REGISTER — 5 attempts / 15 min per IP, whatever the outcome. Successful sign-ups
 *   count too, because mass-creating accounts is the abuse we are stopping.
 *
 * When any limit is hit that request and the following ones get HTTP 429 + a Retry-After header until
 * the 15 minutes are over. Blocked requests return immediately, before any bcrypt work.
 *
 * Attempts are counted BEFORE the password is checked (and given back on success), not
 * after. Counting afterwards would let someone fire 100 requests at once and have them
 * all slip through before the first failure was recorded.
 *
 * BEHIND A REVERSE PROXY (nginx, Cloudflare, ...) set TRUST_PROXY in .env (see
 * server.js). Otherwise every visitor looks like the proxy's IP and they all share
 * one set of counters.
 *
 * Optional .env overrides (defaults in brackets):
 *   AUTH_MAX_FAILED_LOGINS [7]   AUTH_MAX_REGISTRATIONS [5]   AUTH_WINDOW_MINUTES [15]
 *
 * NOTE: counters live in memory, so they reset when the server restarts and are not
 * shared between several server processes. Fine for one instance; use a shared store
 * (e.g. Redis) if you ever scale out.
 */

const net = require('net');

function intFromEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const MAX_FAILED_LOGINS = intFromEnv('AUTH_MAX_FAILED_LOGINS', 7);
const MAX_REGISTRATIONS = intFromEnv('AUTH_MAX_REGISTRATIONS', 5);
const WINDOW_MS = intFromEnv('AUTH_WINDOW_MINUTES', 15) * 60 * 1000;
const MAX_LOGIN_ATTEMPTS_PER_IP = 50; // all outcomes; see header comment
const MAX_TRACKED_KEYS = 50000; // memory cap, so random usernames can't grow the maps forever
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

// -----------------------------------------------------------------------------
// Counter store
// -----------------------------------------------------------------------------

/**
 * Counts hits per key. Failures are remembered for `windowMs`; once a key reaches
 * `max` hits it is locked for `lockMs`. `now` can be replaced to test with a fake clock.
 */
function createLimiter({ max, windowMs, lockMs = windowMs, maxKeys = MAX_TRACKED_KEYS, now = Date.now }) {
  const store = new Map(); // key -> { count, windowStart, lockedUntil }

  /** Returns the entry if still relevant; forgets (and returns null for) expired ones. */
  function live(key, t) {
    const e = store.get(key);
    if (!e) return null;
    const expired = e.lockedUntil ? e.lockedUntil <= t : t - e.windowStart >= windowMs;
    if (expired) {
      store.delete(key);
      return null;
    }
    return e;
  }

  return {
    /** Milliseconds until `key` may try again (0 = not locked). */
    retryAfterMs(key) {
      const t = now();
      const e = live(key, t);
      return e && e.lockedUntil ? e.lockedUntil - t : 0;
    },
    /** Attempts recorded for `key` in the current window. */
    count(key) {
      const e = live(key, now());
      return e ? e.count : 0;
    },
    /** Records one attempt; locks the key when it reaches `max`. */
    hit(key) {
      const t = now();
      let e = live(key, t);
      if (!e) {
        if (store.size >= maxKeys) store.delete(store.keys().next().value); // drop the oldest
        e = { count: 0, windowStart: t, lockedUntil: 0 };
        store.set(key, e);
      }
      e.count += 1;
      if (e.count >= max) e.lockedUntil = t + lockMs;
      return e;
    },
    reset(key) {
      store.delete(key);
    },
    sweep() {
      const t = now();
      for (const key of [...store.keys()]) live(key, t);
    },
    size: () => store.size,
  };
}

// -----------------------------------------------------------------------------
// Keys
// -----------------------------------------------------------------------------

/**
 * Normalises an IP so one client can't dodge the limit by changing form:
 *   ::ffff:1.2.3.4 (IPv4 over a dual-stack socket) -> 1.2.3.4
 *   IPv6 -> its /64 prefix, because a single home connection controls billions of addresses in it
 */
function normalizeIp(ip) {
  if (!ip) return 'unknown';
  const s = String(ip).toLowerCase().split('%')[0]; // drop any zone id (fe80::1%eth0)
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return mapped[1];
  if (!net.isIPv6(s) || s.includes('.')) return s; // IPv4, or an odd form we leave untouched
  const [left, right] = s.split('::');
  const head = left ? left.split(':') : [];
  const tail = right === undefined ? [] : right ? right.split(':') : [];
  const groups = [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return groups.slice(0, 4).map((g) => g.padStart(4, '0')).join(':') + '::/64';
}

const clientKey = (req) => normalizeIp(req.ip || (req.socket && req.socket.remoteAddress));

// The users table is COLLATE NOCASE, so "Alice" and "alice" are the same account.
const userKey = (username) => username.trim().toLowerCase().slice(0, 64);

// -----------------------------------------------------------------------------
// Limiters
// -----------------------------------------------------------------------------

const loginByIp = createLimiter({ max: MAX_FAILED_LOGINS, windowMs: WINDOW_MS });
const loginByUser = createLimiter({ max: MAX_FAILED_LOGINS, windowMs: WINDOW_MS });
const loginAttemptsByIp = createLimiter({ max: MAX_LOGIN_ATTEMPTS_PER_IP, windowMs: WINDOW_MS });
const registerByIp = createLimiter({ max: MAX_REGISTRATIONS, windowMs: WINDOW_MS });

const all = [loginByIp, loginByUser, loginAttemptsByIp, registerByIp];
setInterval(() => all.forEach((l) => l.sweep()), SWEEP_INTERVAL_MS).unref(); // .unref(): never keeps the process alive

/** Sends the 429. The wording is the same for every limit, so it reveals nothing about accounts. */
function tooManyAttempts(res, waitMs) {
  const seconds = Math.max(1, Math.ceil(waitMs / 1000));
  const minutes = Math.max(1, Math.ceil(waitMs / 60000));
  res.set('Retry-After', String(seconds));
  return res.status(429).json({
    error: `Too many attempts. Please try again after ${minutes} minute${minutes === 1 ? '' : 's'}.`,
    retryAfterSeconds: seconds,
  });
}

// -----------------------------------------------------------------------------
// Middleware
// -----------------------------------------------------------------------------

/** Put before the login handler; call clearLoginFailures(req) there once the password is right. */
function loginGuard(req, res, next) {
  const { username, password } = req.body || {};
  // Malformed requests aren't password guesses (the handler answers them with 400), so they aren't counted.
  if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password) {
    return next();
  }

  const ip = clientKey(req);
  const user = userKey(username);

  const wait = Math.max(
    loginByIp.retryAfterMs(ip),
    loginByUser.retryAfterMs(user),
    loginAttemptsByIp.retryAfterMs(ip)
  );
  if (wait > 0) return tooManyAttempts(res, wait);

  // Count the attempt now; a correct login hands it back (clearLoginFailures).
  // Remember THIS request's own attempt number: when many requests arrive at once, each one must
  // report its own position (attempt 3 -> "4 left"), not whatever the shared counter says by the time it finishes.
  const attempt = Math.max(loginByIp.hit(ip).count, loginByUser.hit(user).count);
  const totalAttempts = loginAttemptsByIp.hit(ip).count;
  req.loginLimitKeys = { ip, user, attempt, totalAttempts };
  next();
}

/**
 * Call when the password was WRONG, to build the response: tells the route whether this
 * attempt used up the allowance (-> answer 429) or how many attempts remain (-> 401).
 * Works for unknown usernames identically, so it reveals nothing about which accounts exist.
 */
function getLoginFailureState(req) {
  const keys = req.loginLimitKeys;
  if (!keys) return { locked: false, retryAfterMs: 0, attemptsLeft: undefined, maxAttempts: MAX_FAILED_LOGINS };
  // This very attempt used up an allowance -> the lock starts now.
  const exhausted = keys.attempt >= MAX_FAILED_LOGINS || keys.totalAttempts >= MAX_LOGIN_ATTEMPTS_PER_IP;
  const remaining = Math.max(
    loginByIp.retryAfterMs(keys.ip),
    loginByUser.retryAfterMs(keys.user),
    loginAttemptsByIp.retryAfterMs(keys.ip)
  );
  // `locked` depends only on this request's own attempt (not on what other simultaneous requests did).
  return {
    locked: exhausted,
    retryAfterMs: exhausted ? remaining || WINDOW_MS : 0,
    attemptsLeft: Math.max(0, MAX_FAILED_LOGINS - keys.attempt),
    maxAttempts: MAX_FAILED_LOGINS,
  };
}

/** Call after the credentials were verified: clears the failure counters for this IP and username. */
function clearLoginFailures(req) {
  const keys = req.loginLimitKeys;
  if (!keys) return;
  loginByIp.reset(keys.ip);
  loginByUser.reset(keys.user);
}

/** Put before the register handler. */
function registerGuard(req, res, next) {
  const ip = clientKey(req);
  const wait = registerByIp.retryAfterMs(ip);
  if (wait > 0) return tooManyAttempts(res, wait);
  registerByIp.hit(ip);
  next();
}

module.exports = {
  loginGuard,
  registerGuard,
  clearLoginFailures,
  getLoginFailureState,
  sendTooManyAttempts: tooManyAttempts,
  createLimiter,
  normalizeIp,
};
