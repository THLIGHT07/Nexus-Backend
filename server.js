/**
 * server.js
 * -----------------------------------------------------------------------------
 * Application entry point: loads config, initialises the database, wires
 * middleware and routes, and starts the HTTP server.
 */

// Load environment variables first, before anything reads process.env.
require('dotenv').config();

const express = require('express');
const cors = require('cors');

// Fail fast if the JWT secret is missing.
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not defined in your .env file.');
  process.exit(1);
}

const { initAdminAuth } = require('./middleware/adminAuth');
const db = require('./db');
const authRoutes = require('./routes/auth');
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
app.use(cors());
app.use(express.json({ limit: '10kb' })); // small limit: only credentials expected

// --- Routes ------------------------------------------------------------------
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.use('/api/auth', authRoutes);
// Protected: only POST /api/admin/login is public; the rest needs an admin token.
app.use('/api/admin', adminRoutes);

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

  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

// --- Start: initialise the database first, then listen ----------------------
async function start() {
  await db.initDb();

  const server = app.listen(PORT, () => {
    console.log(`Nexus backend running on http://localhost:${PORT}`);
  });

  const shutdown = (signal) => {
    console.log(`${signal} received, shutting down...`);
    server.close(() => {
      db.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
