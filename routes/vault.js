/**
 * routes/vault.js — API Vault (mounted at /api/me/vault)
 * -----------------------------------------------------------------------------
 * Stores a user's API keys as CIPHERTEXT. The browser encrypts (AES-256-GCM) before upload; this server never
 * sees a key, a passphrase or the vault key, and has no code path that could decrypt anything.
 *
 * Every route needs the owner's JWT and only touches rows WHERE user_id = <id from the token>. There is no
 * user id in any URL or body, and admin routes (routes/admin.js) never read these tables.
 *
 *   GET    /                    { meta|null, categories:[], entries:[] }   (one call after unlock)
 *   PUT    /meta                create the vault meta, or change the passphrase (needs expectedVersion)
 *   POST   /reset               { confirm:"RESET" }  deletes ALL vault data (for a forgotten passphrase)
 *   GET    /categories          POST /categories {id?, name}     PUT /categories/:id {name}     DELETE /categories/:id
 *   GET    /apis                POST /apis {id, categoryId, name, ciphertext, iv, defaultModel?, defaultUrl?}
 *   PUT    /apis/:id            {name?, categoryId?, ciphertext?+iv?, defaultModel?, defaultUrl?}
 *   DELETE /apis/:id
 *
 * LOGGING RULE: nothing in this file logs request bodies, params or database error details. Postgres error
 * DETAIL can contain the failing row (= ciphertext), so every error is replaced by a sanitized one (safeErr)
 * before it reaches the app's central error handler, which logs errors.
 */

const express = require('express');
const db = require('../db');
const authenticate = require('../middleware/auth');
const { createLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

const MAX_CATEGORIES = 50;
const MAX_ENTRIES = 500;
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const KDF_NAME = 'PBKDF2-SHA256';

// ── helpers ──────────────────────────────────────────────────────────────
class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra || {}; }
}
/** Replaces any thrown error with one that carries no row data (pg puts the failing row into err.detail). */
function safeErr(err) {
  if (err instanceof HttpError) return err;
  const e = new Error(`vault: ${err && typeof err.code === 'string' ? `database error (SQLSTATE ${err.code})` : 'internal error'}`);
  if (err && typeof err.code === 'string') e.code = err.code; // lets the central handler map 23505 / connection errors
  return e;
}
const ah = (fn) => async (req, res, next) => {
  try { await fn(req, res); }
  catch (err) {
    const e = safeErr(err);
    if (e instanceof HttpError) return res.status(e.status).json({ error: e.message, ...e.extra });
    return next(e);
  }
};

const clean = (s) => String(s).replace(/[\u0000-\u001f\u007f\ud800-\udfff]/g, '').trim();
function reqString(body, field, label, max) {
  const raw = body[field];
  if (typeof raw !== 'string') throw new HttpError(400, `${label} is required.`);
  const s = clean(raw);
  if (!s) throw new HttpError(400, `${label} is required.`);
  if (s.length > max) throw new HttpError(400, `${label} is too long (max ${max} characters).`);
  return s;
}
function optHint(body, field, label, max) {
  if (!(field in body) || body[field] === null || body[field] === '') return null;
  if (typeof body[field] !== 'string') throw new HttpError(400, `${label} must be text.`);
  const s = clean(body[field]);
  if (s.length > max) throw new HttpError(400, `${label} is too long (max ${max} characters).`);
  return s || null;
}
function optUrl(body) {
  const s = optHint(body, 'defaultUrl', 'Default URL', 300);
  if (s === null) return null;
  let u;
  try { u = new URL(s); } catch (e) { throw new HttpError(400, 'Default URL must be a full http(s) URL.'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new HttpError(400, 'Default URL must start with http:// or https://');
  if (u.username || u.password) throw new HttpError(400, 'Default URL must not contain a username or password — keep secrets in the key field.');
  return s;
}
function reqId(value, label) {
  if (typeof value !== 'string' || !ID_RE.test(value)) throw new HttpError(400, `${label} is invalid.`);
  return value;
}
function reqB64(body, field, label, { min, max, exactBytes }) {
  const s = body[field];
  if (typeof s !== 'string' || !s || s.length > max || s.length < min || s.length % 4 !== 0 || !B64_RE.test(s)) {
    throw new HttpError(400, `${label} is invalid.`);
  }
  if (exactBytes && Buffer.from(s, 'base64').length !== exactBytes) throw new HttpError(400, `${label} is invalid.`);
  return s;
}

const metaOut = (r) => r && ({
  kdf: r.kdf, kdfIterations: r.kdf_iterations, salt: r.salt, wrappedKey: r.wrapped_key, wrapIv: r.wrap_iv,
  version: r.version, createdAt: r.created_at, updatedAt: r.updated_at,
});
const catOut = (r) => ({ id: r.id, name: r.name, createdAt: r.created_at, updatedAt: r.updated_at });
const entryOut = (r) => ({
  id: r.id, categoryId: r.category_id, name: r.name, ciphertext: r.ciphertext, iv: r.iv, schemaVersion: r.schema_version,
  defaultModel: r.default_model, defaultUrl: r.default_url, createdAt: r.created_at, updatedAt: r.updated_at,
});
const ENTRY_COLS = 'id, category_id, name, ciphertext, iv, schema_version, default_model, default_url, created_at, updated_at';

// ── auth + per-user write limiter ────────────────────────────────────────
router.use(authenticate);
const writes = createLimiter({ max: 60, windowMs: 60 * 1000 });
setInterval(() => writes.sweep(), 5 * 60 * 1000).unref();
router.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const key = String(req.user.id);
  const wait = writes.retryAfterMs(key);
  if (wait > 0) {
    const seconds = Math.max(1, Math.ceil(wait / 1000));
    res.set('Retry-After', String(seconds));
    return res.status(429).json({ error: 'You are saving too fast. Please wait a moment.', retryAfterSeconds: seconds });
  }
  writes.hit(key);
  next();
});
router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }); // never let a proxy/browser cache ciphertext

// ── everything in one call ───────────────────────────────────────────────
router.get('/', ah(async (req, res) => {
  const uid = req.user.id;
  const [meta, cats, entries] = await Promise.all([
    db.get('SELECT kdf, kdf_iterations, salt, wrapped_key, wrap_iv, version, created_at, updated_at FROM vault_meta WHERE user_id = $1', [uid]),
    db.all('SELECT id, name, created_at, updated_at FROM vault_categories WHERE user_id = $1 ORDER BY lower(name)', [uid]),
    db.all(`SELECT ${ENTRY_COLS} FROM vault_entries WHERE user_id = $1 ORDER BY lower(name), created_at`, [uid]),
  ]);
  res.json({ meta: metaOut(meta) || null, categories: cats.map(catOut), entries: entries.map(entryOut) });
}));

// ── meta: create the vault, or change the passphrase ─────────────────────
router.put('/meta', ah(async (req, res) => {
  const b = req.body || {};
  if (b.kdf !== KDF_NAME) throw new HttpError(400, 'Unsupported key-derivation method.');
  const iterations = b.kdfIterations;
  if (!Number.isInteger(iterations) || iterations < 200000 || iterations > 5000000) throw new HttpError(400, 'Key-derivation strength is out of range.');
  const salt = reqB64(b, 'salt', 'Salt', { min: 16, max: 128, exactBytes: 16 });
  const wrapped = reqB64(b, 'wrappedKey', 'Wrapped key', { min: 16, max: 200, exactBytes: 48 }); // 32-byte key + 16-byte GCM tag
  const wrapIv = reqB64(b, 'wrapIv', 'IV', { min: 8, max: 32, exactBytes: 12 });
  const uid = req.user.id;

  const existing = await db.get('SELECT version FROM vault_meta WHERE user_id = $1', [uid]);
  if (!existing) {
    const r = await db.get(
      `INSERT INTO vault_meta (user_id, kdf, kdf_iterations, salt, wrapped_key, wrap_iv) VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (user_id) DO NOTHING RETURNING version, created_at, updated_at`,
      [uid, KDF_NAME, iterations, salt, wrapped, wrapIv]
    );
    if (!r) throw new HttpError(409, 'A vault already exists for this account. Reload and unlock it.');
    return res.status(201).json({ version: r.version, createdAt: r.created_at, updatedAt: r.updated_at });
  }
  if (!Number.isInteger(b.expectedVersion)) throw new HttpError(400, 'expectedVersion is required to change the passphrase.');
  const r = await db.get(
    `UPDATE vault_meta SET kdf=$2, kdf_iterations=$3, salt=$4, wrapped_key=$5, wrap_iv=$6, version=version+1, updated_at=now()
      WHERE user_id=$1 AND version=$7 RETURNING version, updated_at`,
    [uid, KDF_NAME, iterations, salt, wrapped, wrapIv, b.expectedVersion]
  );
  if (!r) throw new HttpError(409, 'Your vault changed on another device. Reload, unlock again, then retry.');
  res.json({ version: r.version, updatedAt: r.updated_at });
}));

// ── reset (forgotten passphrase): deletes the whole vault ─────────────────
router.post('/reset', ah(async (req, res) => {
  if (!req.body || req.body.confirm !== 'RESET') throw new HttpError(400, 'Send {"confirm":"RESET"} to delete the whole vault.');
  const uid = req.user.id;
  const n = await db.tx(async (t) => {
    const e = await t.run('DELETE FROM vault_entries WHERE user_id = $1', [uid]);
    await t.run('DELETE FROM vault_categories WHERE user_id = $1', [uid]);
    await t.run('DELETE FROM vault_meta WHERE user_id = $1', [uid]);
    return e.changes;
  });
  res.json({ message: 'Vault deleted.', deletedEntries: n });
}));

// ── categories ───────────────────────────────────────────────────────────
router.get('/categories', ah(async (req, res) => {
  const rows = await db.all('SELECT id, name, created_at, updated_at FROM vault_categories WHERE user_id = $1 ORDER BY lower(name)', [req.user.id]);
  res.json({ categories: rows.map(catOut) });
}));

router.post('/categories', ah(async (req, res) => {
  const b = req.body || {};
  const name = reqString(b, 'name', 'Category name', 60);
  const id = b.id === undefined ? require('crypto').randomUUID() : reqId(b.id, 'Category id');
  const uid = req.user.id;
  const count = await db.get('SELECT COUNT(*) AS n FROM vault_categories WHERE user_id = $1', [uid]);
  if (count.n >= MAX_CATEGORIES) throw new HttpError(400, `You can have at most ${MAX_CATEGORIES} categories.`);
  try {
    const r = await db.get('INSERT INTO vault_categories (user_id, id, name) VALUES ($1,$2,$3) RETURNING id, name, created_at, updated_at', [uid, id, name]);
    res.status(201).json({ category: catOut(r) });
  } catch (err) {
    if (err && err.code === '23505') throw new HttpError(409, 'You already have a category with that name.');
    throw err;
  }
}));

router.put('/categories/:id', ah(async (req, res) => {
  const id = reqId(req.params.id, 'Category id');
  const name = reqString(req.body || {}, 'name', 'Category name', 60);
  try {
    const r = await db.get('UPDATE vault_categories SET name=$3, updated_at=now() WHERE user_id=$1 AND id=$2 RETURNING id, name, created_at, updated_at', [req.user.id, id, name]);
    if (!r) throw new HttpError(404, 'Category not found.');
    res.json({ category: catOut(r) });
  } catch (err) {
    if (err && err.code === '23505') throw new HttpError(409, 'You already have a category with that name.');
    throw err;
  }
}));

router.delete('/categories/:id', ah(async (req, res) => {
  const id = reqId(req.params.id, 'Category id');
  const uid = req.user.id;
  const out = await db.tx(async (t) => {
    const n = await t.get('SELECT COUNT(*) AS n FROM vault_entries WHERE user_id=$1 AND category_id=$2', [uid, id]);
    const r = await t.run('DELETE FROM vault_categories WHERE user_id=$1 AND id=$2', [uid, id]); // entries cascade
    return { found: r.changes > 0, entries: n.n };
  });
  if (!out.found) throw new HttpError(404, 'Category not found.');
  res.json({ message: 'Category deleted.', deletedEntries: out.entries });
}));

// ── api entries ──────────────────────────────────────────────────────────
router.get('/apis', ah(async (req, res) => {
  const rows = await db.all(`SELECT ${ENTRY_COLS} FROM vault_entries WHERE user_id = $1 ORDER BY lower(name), created_at`, [req.user.id]);
  res.json({ apis: rows.map(entryOut) });
}));

router.post('/apis', ah(async (req, res) => {
  const b = req.body || {};
  const uid = req.user.id;
  const id = reqId(b.id, 'Entry id');
  const categoryId = reqId(b.categoryId, 'Category');
  const name = reqString(b, 'name', 'Name', 80);
  const ciphertext = reqB64(b, 'ciphertext', 'Ciphertext', { min: 32, max: 8000 });
  const iv = reqB64(b, 'iv', 'IV', { min: 8, max: 32, exactBytes: 12 });
  const defaultModel = optHint(b, 'defaultModel', 'Default model', 120);
  const defaultUrl = optUrl(b);

  const cat = await db.get('SELECT 1 AS ok FROM vault_categories WHERE user_id=$1 AND id=$2', [uid, categoryId]);
  if (!cat) throw new HttpError(400, 'That category does not exist.');
  const count = await db.get('SELECT COUNT(*) AS n FROM vault_entries WHERE user_id = $1', [uid]);
  if (count.n >= MAX_ENTRIES) throw new HttpError(400, `You can store at most ${MAX_ENTRIES} API keys.`);
  try {
    const r = await db.get(
      `INSERT INTO vault_entries (user_id, id, category_id, name, ciphertext, iv, default_model, default_url)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING ${ENTRY_COLS}`,
      [uid, id, categoryId, name, ciphertext, iv, defaultModel, defaultUrl]
    );
    res.status(201).json({ api: entryOut(r) });
  } catch (err) {
    if (err && err.code === '23505') throw new HttpError(409, 'That entry already exists.');
    throw err;
  }
}));

router.put('/apis/:id', ah(async (req, res) => {
  const b = req.body || {};
  const uid = req.user.id;
  const id = reqId(req.params.id, 'Entry id');
  const cur = await db.get('SELECT 1 AS ok FROM vault_entries WHERE user_id=$1 AND id=$2', [uid, id]);
  if (!cur) throw new HttpError(404, 'API entry not found.');

  const sets = [];
  const vals = [uid, id];
  const add = (col, val) => { vals.push(val); sets.push(`${col} = $${vals.length}`); };
  if ('name' in b) add('name', reqString(b, 'name', 'Name', 80));
  if ('categoryId' in b) {
    const categoryId = reqId(b.categoryId, 'Category');
    const cat = await db.get('SELECT 1 AS ok FROM vault_categories WHERE user_id=$1 AND id=$2', [uid, categoryId]);
    if (!cat) throw new HttpError(400, 'That category does not exist.');
    add('category_id', categoryId);
  }
  if ('ciphertext' in b || 'iv' in b) { // both or neither: a ciphertext is only valid with its own IV
    add('ciphertext', reqB64(b, 'ciphertext', 'Ciphertext', { min: 32, max: 8000 }));
    add('iv', reqB64(b, 'iv', 'IV', { min: 8, max: 32, exactBytes: 12 }));
  }
  if ('defaultModel' in b) add('default_model', optHint(b, 'defaultModel', 'Default model', 120));
  if ('defaultUrl' in b) add('default_url', optUrl(b));
  if (!sets.length) throw new HttpError(400, 'Nothing to update.');

  const r = await db.get(`UPDATE vault_entries SET ${sets.join(', ')}, updated_at = now() WHERE user_id=$1 AND id=$2 RETURNING ${ENTRY_COLS}`, vals);
  res.json({ api: entryOut(r) });
}));

router.delete('/apis/:id', ah(async (req, res) => {
  const id = reqId(req.params.id, 'Entry id');
  const r = await db.run('DELETE FROM vault_entries WHERE user_id=$1 AND id=$2', [req.user.id, id]);
  if (!r.changes) throw new HttpError(404, 'API entry not found.');
  res.json({ message: 'Deleted.' });
}));

module.exports = router;
