-- 001_init.sql — Nexus Storage schema (PostgreSQL)
-- Applied automatically on startup by db.js (tracked in schema_migrations; each file runs once, in a transaction).
-- To change the schema later, ADD a new file (002_*.sql, ...) — never edit one that has already been deployed.

-- ── Accounts ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  SERIAL      PRIMARY KEY,
  username            TEXT        NOT NULL,
  password_hash       TEXT        NOT NULL,                       -- bcrypt
  status              TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked')),
  email               TEXT,                                       -- only ever a VERIFIED, lower-cased address
  email_verified      BOOLEAN     NOT NULL DEFAULT FALSE,
  password_changed_at BIGINT,                                     -- unix seconds; JWTs issued before this are rejected
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq ON users (lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq          ON users (email) WHERE email IS NOT NULL;

-- One-time codes (password reset / password change / email verification). Only a keyed hash is stored.
CREATE TABLE IF NOT EXISTS otp_codes (
  id         SERIAL      PRIMARY KEY,
  user_id    INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose    TEXT        NOT NULL,                                -- 'reset' | 'change' | 'verify_email'
  code_hash  TEXT        NOT NULL,
  email      TEXT,                                                -- the address a 'verify_email' code was sent to
  attempts   INTEGER     NOT NULL DEFAULT 0,
  expires_at BIGINT      NOT NULL,                                -- epoch milliseconds
  created_at BIGINT      NOT NULL,                                -- epoch milliseconds
  UNIQUE (user_id, purpose)                                       -- at most one live code per purpose
);

-- ── Per-user data (moved here from browser localStorage) ────────────────────
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id      INTEGER     PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  display_name TEXT        NOT NULL DEFAULT '',
  avatar       TEXT        NOT NULL DEFAULT '',
  bio          TEXT        NOT NULL DEFAULT '',
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Free-form UI settings (theme, wallpaper, clock, AI config, ...) + the "recently opened" list.
-- The *_saved_at columns say whether that part has EVER been saved to the server, so a client can tell
-- "never synced" (import from localStorage / seed defaults) apart from "user really has none".
CREATE TABLE IF NOT EXISTS user_settings (
  user_id           INTEGER     PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  settings_json     JSONB       NOT NULL DEFAULT '{}'::jsonb,
  recent_json       JSONB       NOT NULL DEFAULT '[]'::jsonb,     -- app ids, most recent first
  settings_saved_at TIMESTAMPTZ,
  apps_saved_at     TIMESTAMPTZ,
  notes_saved_at    TIMESTAMPTZ,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS apps (
  user_id    INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  id         TEXT        NOT NULL,                                -- client-side id, e.g. "chatgpt"
  name       TEXT        NOT NULL,
  url        TEXT        NOT NULL,                                -- http(s) only (checked in services/validate.js)
  icon       TEXT        NOT NULL DEFAULT 'globe',                -- Tabler icon name
  cat        TEXT        NOT NULL DEFAULT 'Other',
  bg         TEXT,                                                -- "#rrggbb" or NULL (client derives from category)
  color      TEXT,                                                -- the frontend's "c" field
  fav        BOOLEAN     NOT NULL DEFAULT FALSE,
  sort_order INTEGER     NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, id)
);
CREATE INDEX IF NOT EXISTS apps_user_sort_idx ON apps (user_id, sort_order);

CREATE TABLE IF NOT EXISTS notes (
  user_id    INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  id         TEXT        NOT NULL,
  title      TEXT        NOT NULL DEFAULT 'Untitled',
  body       TEXT        NOT NULL DEFAULT '',
  date_label TEXT        NOT NULL DEFAULT '',                     -- the short label the UI shows, e.g. "5/10 14:32"
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, id)
);
CREATE INDEX IF NOT EXISTS notes_user_created_idx ON notes (user_id, created_at DESC);
