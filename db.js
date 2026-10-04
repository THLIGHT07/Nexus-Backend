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

  // Migrations: add columns to databases created before they existed. Safe to run on every start.
  const ensureColumn = (name, ddl) => {
    const cols = db.exec('PRAGMA table_info(users);');
    if (!cols[0]?.values.some((row) => row[1] === name)) db.run(`ALTER TABLE users ADD COLUMN ${ddl};`);
  };
  ensureColumn('status', "status TEXT NOT NULL DEFAULT 'active'");
  ensureColumn('email', 'email TEXT');                                      // only ever holds a VERIFIED address
  ensureColumn('email_verified', 'email_verified INTEGER NOT NULL DEFAULT 0'); // 0 / 1
  ensureColumn('password_changed_at', 'password_changed_at INTEGER');       // unix seconds; older sessions are rejected
  // SQLite can't add a UNIQUE column with ALTER TABLE, so uniqueness is a unique index (many NULLs are allowed).
  db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);');

  // One-time codes (password reset / password change / email verification).
  // Only a keyed hash of the code is stored, never the code itself. See services/otp.js.
  db.run(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      purpose    TEXT    NOT NULL,            -- 'reset' | 'change' | 'verify_email'
      code_hash  TEXT    NOT NULL,
      email      TEXT,                        -- the address a 'verify_email' code was sent to
      attempts   INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,            -- epoch milliseconds
      created_at INTEGER NOT NULL
    );
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_otp_user_purpose ON otp_codes(user_id, purpose);');

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
