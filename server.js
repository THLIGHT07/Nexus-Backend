/**
 * server.js
 * -----------------------------------------------------------------------------
 * Application entry point: loads config, connects to PostgreSQL (DATABASE_URL) and runs migrations,
 * wires middleware and routes, and starts the HTTP server.
 */

// Load environment variables first, before anything reads process.env.
require('dotenv').config();

const express = require('express');
const cors = require('cors');

// Fail fast if required settings are missing.
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not defined in your .env file.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not defined (your PostgreSQL connection string; Railway: Variables -> DATABASE_URL).');
  process.exit(1);
}

const { initAdminAuth } = require('./middleware/adminAuth');
const db = require('./db');
const authRoutes = require('./routes/auth');
const authOtpRoutes = require('./routes/authOtp');
const meRoutes = require('./routes/me');
const mailer = require('./services/mailer');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 5000;

app.disable('x-powered-by');
// Behind nginx/Cloudflare/etc.? Set TRUST_PROXY (e.g. 1) so req.ip is the real visitor,
// which the admin login lockout relies on. Leave unset when clients connect directly.
if (process.env.TRUST_PROXY) {
  const tp = process.env.TRUST_PROXY.trim();
  app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : tp === 'true' ? true : tp);
}

// Read ADMIN_PASSWORD_HASH / ADMIN_PASSWORD. If missing/invalid the admin API stays
// disabled (it never runs open) — see middleware/adminAuth.js.
initAdminAuth();

// --- Global middleware -------------------------------------------------------
// CORS: by default any origin (same as before). In production set CORS_ORIGIN to your frontend, e.g.
//   CORS_ORIGIN=https://nexus.example.com            (several: comma-separated)
const corsOrigins = (process.env.CORS_ORIGIN || '').split(',').map((o) => o.trim()).filter(Boolean);
app.use(corsOrigins.length && !corsOrigins.includes('*') ? cors({ origin: corsOrigins }) : cors());
// Body size limits are per area: credentials are tiny, the per-user data (apps, notes) is not.
const smallJson = express.json({ limit: '10kb' });
const userDataJson = express.json({ limit: '2mb' });

// --- Routes ------------------------------------------------------------------
// Health check (Railway etc.): 200 only while the database answers.
app.get('/api/health', async (req, res) => {
  try {
    await db.ping();
    res.json({ status: 'ok', db: 'up' });
  } catch (err) {
    res.status(503).json({ status: 'degraded', db: 'down' });
  }
});
app.use('/api/auth', smallJson, authRoutes);
app.use('/api/auth', smallJson, authOtpRoutes); // forgot / change password + email linking (email codes via Brevo)
app.use('/api/me', userDataJson, meRoutes);     // the signed-in user's profile, settings, apps, notes (PostgreSQL)
// Protected: only POST /api/admin/login is public; the rest needs an admin token.
app.use('/api/admin', smallJson, adminRoutes);

// --- 404 handler -------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// --- Centralised error handler ----------------------------------------------
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON in request body.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large.' });
  }

  // PostgreSQL errors, by SQLSTATE class — never echo database messages to the client.
  if (err && typeof err.code === 'string') {
    if (err.code === '23505') return res.status(409).json({ error: 'That already exists.' });
    if (err.code.startsWith('22')) return res.status(400).json({ error: 'Invalid data.' }); // e.g. unsupported characters
    if (err.code.startsWith('08') || err.code.startsWith('57') || ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND'].includes(err.code)) {
      console.error('[db] unavailable:', err.code, err.message);
      return res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    }
  }

  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

// --- Start: initialise the database first, then listen ----------------------
async function start() {
  await db.initDb();

  const server = app.listen(PORT, () => {
    console.log(`Nexus backend running on http://localhost:${PORT}`);
    if (!mailer.isConfigured()) {
      console.warn(
        process.env.NODE_ENV === 'production'
          ? '[mail] BREVO_API_KEY / BREVO_FROM_EMAIL not set — password reset & email verification will FAIL.'
          : '[mail] Brevo not configured — one-time codes will be printed here instead of emailed (dev mode).'
      );
    }
  });

  const shutdown = (signal) => {
    console.log(`${signal} received, shutting down...`);
    server.close(async () => {
      try { await db.close(); } catch (e) { /* exiting anyway */ }
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 10000).unref(); // don't hang on open keep-alive connections
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
