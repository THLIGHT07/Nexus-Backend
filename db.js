/**
 * db.js — PostgreSQL access (node-postgres). Replaces the old SQLite/sql.js file.
 * -----------------------------------------------------------------------------
 * Connection:   DATABASE_URL            e.g. postgresql://user:pass@host:5432/railway   (Railway sets it for you)
 *               DATABASE_SSL=true       force TLS (needed for Railway's PUBLIC proxy URL; the private
 *                                       *.railway.internal URL does not need it). Certificate is not verified,
 *                                       because the proxy uses a self-signed one.
 *               DATABASE_POOL_MAX=10    max connections
 *
 * Every query goes through parameters ($1, $2, ...) — never string-built SQL.
 *
 *   await db.initDb()                   connect (with retries) + run migrations/*.sql
 *   await db.get(sql, params)           first row or undefined
 *   await db.all(sql, params)           array of rows
 *   await db.run(sql, params)           -> { changes, rows }   (rows only for INSERT/UPDATE/DELETE ... RETURNING)
 *   await db.tx(async (t) => { ... })   BEGIN/COMMIT with ROLLBACK on throw; t has get / all / run
 *   db.isUniqueViolation(err)           true for a unique-constraint error (SQLSTATE 23505)
 *   await db.ping() / await db.close()
 */

const fs = require('fs');
const path = require('path');
const { Pool, types } = require('pg');

// int8 (BIGINT, COUNT(*)) comes back as a string by default — every int8 column here holds small numbers.
types.setTypeParser(20, (v) => Number(v));

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const MIGRATION_LOCK_ID = 727274; // arbitrary constant: stops two instances migrating at once

let pool = null;

function intFromEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function poolConfig() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error('DATABASE_URL is not set. Add your PostgreSQL connection string (Railway: Variables -> DATABASE_URL).');
  }
  const config = {
    connectionString: url,
    max: intFromEnv('DATABASE_POOL_MAX', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  };
  if (/^(1|true|require)$/i.test(process.env.DATABASE_SSL || '')) config.ssl = { rejectUnauthorized: false };
  return config;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function migrate() {
  const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => /^\d+.*\.sql$/.test(f)).sort();
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
    await client.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())'
    );
    const done = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map((r) => r.name));
    for (const file of files) {
      if (done.has(file)) continue;
      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
      try {
        await client.query('BEGIN');
        await client.query(sql); // no parameters => may contain several statements
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch (e) { broken = true; }
        err.message = `Migration ${file} failed: ${err.message}`;
        throw err;
      }
      console.log(`[db] applied migration ${file}`);
    }
  } finally {
    try { await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]); } catch (e) { broken = true; }
    client.release(broken ? new Error('discard') : undefined);
  }
}

/** Connects (retrying a while — on Railway the app can boot before the database accepts connections) and migrates. */
async function initDb({ retries = 10, delayMs = 2000 } = {}) {
  if (pool) return;
  const p = new Pool(poolConfig());
  p.on('error', (err) => console.error('[db] idle client error:', err.message)); // never crash on a dropped idle connection
  for (let attempt = 1; ; attempt++) {
    try {
      await p.query('SELECT 1');
      break;
    } catch (err) {
      if (attempt >= retries) {
        await p.end().catch(() => {});
        throw new Error(`Could not connect to PostgreSQL after ${attempt} attempts: ${err.message}`);
      }
      console.warn(`[db] not reachable yet (${err.code || err.message}); retry ${attempt}/${retries - 1} in ${delayMs / 1000}s`);
      await sleep(delayMs);
    }
  }
  pool = p;
  await migrate();
  console.log('[db] PostgreSQL ready');
}

function requirePool() {
  if (!pool) throw new Error('Database not initialised — call db.initDb() first.');
  return pool;
}

const makeHelpers = (executor) => ({
  query: (text, params) => executor.query(text, params),
  get: async (text, params) => (await executor.query(text, params)).rows[0],
  all: async (text, params) => (await executor.query(text, params)).rows,
  run: async (text, params) => {
    const r = await executor.query(text, params);
    return { changes: r.rowCount, rows: r.rows };
  },
});

const poolExec = { query: (text, params) => requirePool().query(text, params) };
const helpers = makeHelpers(poolExec);

/** Runs fn inside one transaction on a dedicated connection. */
async function tx(fn) {
  const client = await requirePool().connect();
  let broken = false;
  try {
    await client.query('BEGIN');
    const result = await fn(makeHelpers(client));
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (e) { broken = true; }
    throw err;
  } finally {
    client.release(broken ? new Error('discard') : undefined);
  }
}

const isUniqueViolation = (err) => Boolean(err) && err.code === '23505';
const ping = async () => { await requirePool().query('SELECT 1'); };
async function close() {
  if (!pool) return;
  const p = pool;
  pool = null;
  await p.end();
}

module.exports = { initDb, tx, ping, close, isUniqueViolation, ...helpers };
