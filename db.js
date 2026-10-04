/**
 * db.js
 * -----------------------------------------------------------------------------
 * SQLite via sql.js (SQLite compiled to WebAssembly, so no native build).
 *
 * sql.js keeps the whole database in memory. To make data survive restarts,
 * we load the database from `nexus.db` on startup and write the file back to
 * disk after every write operation (atomically: temp file + rename).
 *
 * Usage:
 *   await initDb();                       // once, before starting the server
 *   get(sql, params)  -> first row object or undefined
 *   all(sql, params)  -> array of row objects
 *   run(sql, params)  -> { lastInsertRowid, changes }
 */

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const DB_PATH = path.join(__dirname, 'nexus.db');

let db = null; // set by initDb()

/** Writes the in-memory database to disk atomically. */
function persist() {
  const data = Buffer.from(db.export());
  const tmpPath = `${DB_PATH}.tmp`;
  fs.writeFileSync(tmpPath, data);
  fs.renameSync(tmpPath, DB_PATH);
}

/** Loads (or creates) the database file and ensures the schema exists. */
async function initDb() {
  const SQL = await initSqlJs();

  db = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password   TEXT    NOT NULL,
      status     TEXT    NOT NULL DEFAULT 'active',
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Migration: add `status` to databases created before this column existed.
  const columns = db.exec('PRAGMA table_info(users);');
  const hasStatus = columns[0]?.values.some((row) => row[1] === 'status');
  if (!hasStatus) {
    db.run("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';");
  }

  persist(); // makes sure the file exists right away
}

function assertReady() {
  if (!db) throw new Error('Database not initialised. Call initDb() first.');
}

/** Runs a SELECT and returns the first row as an object (or undefined). */
function get(sql, params = []) {
  assertReady();
  const stmt = db.prepare(sql);
  try {
    stmt.bind(params);
    return stmt.step() ? stmt.getAsObject() : undefined;
  } finally {
    stmt.free();
  }
}

/** Runs a SELECT and returns every matching row as an array of objects. */
function all(sql, params = []) {
  assertReady();
  const stmt = db.prepare(sql);
  const rows = [];
  try {
    stmt.bind(params);
    while (stmt.step()) rows.push(stmt.getAsObject());
    return rows;
  } finally {
    stmt.free();
  }
}

/** Runs INSERT/UPDATE/DELETE, persists to disk, returns metadata. */
function run(sql, params = []) {
  assertReady();
  db.run(sql, params);
  const changes = db.getRowsModified();
  const lastInsertRowid = get('SELECT last_insert_rowid() AS id').id;
  persist();
  return { lastInsertRowid, changes };
}

/** True if the error is a UNIQUE constraint violation. */
function isUniqueViolation(err) {
  return Boolean(err && /UNIQUE constraint failed/i.test(err.message));
}

/** Saves and closes the database (used on shutdown). */
function close() {
  if (!db) return;
  persist();
  db.close();
  db = null;
}

module.exports = { initDb, get, all, run, isUniqueViolation, close };
