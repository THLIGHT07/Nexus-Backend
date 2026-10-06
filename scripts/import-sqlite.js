#!/usr/bin/env node
/**
 * scripts/import-sqlite.js — one-time import of the OLD SQLite accounts into PostgreSQL
 * -----------------------------------------------------------------------------
 *   DATABASE_URL=postgresql://... node scripts/import-sqlite.js [path/to/nexus.db]      (default: ./nexus.db)
 *   (add DATABASE_SSL=true when you use Railway's public URL from your own computer)
 *
 * Copies every user (id, username, bcrypt hash, status, email, email_verified, password_changed_at, created_at) so
 * existing logins keep working — passwords are NOT re-hashed. Safe to run twice: users that already exist
 * (same id, username or email) are skipped. Needs sql.js (a devDependency: run `npm install` locally first).
 *
 * What it does NOT move: apps, notes, profile and settings live in each person's browser (localStorage), so
 * the server can't read them. The frontend will upload them the first time each user signs in (Phase 2).
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');

async function main() {
  const file = path.resolve(process.argv[2] || path.join(__dirname, '..', 'nexus.db'));
  if (!fs.existsSync(file)) throw new Error(`SQLite file not found: ${file}`);
  let initSqlJs;
  try { initSqlJs = require('sql.js'); } catch (e) { throw new Error('sql.js is not installed — run "npm install" (it is a devDependency) and try again.'); }

  const db = require('../db');
  await db.initDb(); // connects + makes sure the tables exist

  const SQL = await initSqlJs();
  const lite = new SQL.Database(fs.readFileSync(file));
  const res = lite.exec('SELECT * FROM users ORDER BY id');
  if (!res.length) { console.log('No users in the SQLite file — nothing to import.'); return db.close(); }
  const cols = res[0].columns;
  const rows = res[0].values.map((vals) => Object.fromEntries(vals.map((x, i) => [cols[i], x])));
  // the old column was called "password"; the new one is "password_hash"
  const hashOf = (r) => r.password_hash || r.password;

  let imported = 0, skipped = 0, maxId = 0;
  for (const r of rows) {
    maxId = Math.max(maxId, Number(r.id));
    if (!hashOf(r)) { console.warn(`  skipped #${r.id} (${r.username}): no password hash`); skipped++; continue; }
    const created = r.created_at ? `${String(r.created_at).replace(' ', 'T')}Z` : new Date().toISOString(); // SQLite stored UTC
    const out = await db.run(
      `INSERT INTO users (id, username, password_hash, status, email, email_verified, password_changed_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT DO NOTHING`,
      [
        Number(r.id), String(r.username), String(hashOf(r)),
        r.status === 'blocked' ? 'blocked' : 'active',
        r.email ? String(r.email).toLowerCase() : null,
        Boolean(r.email && Number(r.email_verified) === 1),
        r.password_changed_at == null ? null : Number(r.password_changed_at),
        created,
      ]
    );
    if (out.changes === 1) imported++; else { skipped++; console.log(`  skipped #${r.id} (${r.username}): already exists`); }
  }
  // explicit ids don't advance the SERIAL counter — move it past the largest imported id
  await db.run("SELECT setval(pg_get_serial_sequence('users', 'id'), $1)", [Math.max(maxId, 1)]);
  const total = await db.get('SELECT COUNT(*) AS n FROM users');
  console.log(`Imported ${imported} user(s), skipped ${skipped}. PostgreSQL now has ${total.n} user(s).`);
  await db.close();
}

main().catch((err) => { console.error('Import failed:', err.message); process.exit(1); });
