-- 003_api_vault.sql — "API Vault": per-user, client-side-encrypted API keys.
-- Applied automatically on startup by db.js (each file runs once, in a transaction).
--
-- SECURITY MODEL (see routes/vault.js and README-API-VAULT.md)
--   • The browser encrypts every API key with AES-256-GCM BEFORE upload. This database only ever holds
--     ciphertext + IV + non-secret metadata. The decryption key never reaches the server.
--   • vault_meta.wrapped_key is the user's random 256-bit "vault key", itself AES-GCM-encrypted by a key
--     derived (PBKDF2-SHA256) from a vault passphrase that only the user knows. Server cannot unwrap it.
--   • No CHECK constraints on purpose: Postgres prints the whole failing row (including ciphertext) in
--     error DETAIL, which could land in logs. All validation happens in the route before any INSERT.

CREATE TABLE IF NOT EXISTS vault_meta (
  user_id        INTEGER     PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  kdf            TEXT        NOT NULL,                 -- 'PBKDF2-SHA256'
  kdf_iterations INTEGER     NOT NULL,
  salt           TEXT        NOT NULL,                 -- base64, random per vault
  wrapped_key    TEXT        NOT NULL,                 -- base64 AES-GCM(vault key) — useless without the passphrase
  wrap_iv        TEXT        NOT NULL,                 -- base64, 12 bytes
  version        INTEGER     NOT NULL DEFAULT 1,       -- bumped on passphrase change (optimistic concurrency)
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vault_categories (
  user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  id         TEXT        NOT NULL,                     -- client-generated id
  name       TEXT        NOT NULL,                     -- e.g. 'OpenRouter' (plaintext metadata)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS vault_categories_name_uq ON vault_categories (user_id, lower(name));

CREATE TABLE IF NOT EXISTS vault_entries (
  user_id        INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  id             TEXT        NOT NULL,                 -- client-generated; also bound into the ciphertext (AES-GCM AAD)
  category_id    TEXT        NOT NULL,
  name           TEXT        NOT NULL,                 -- e.g. 'openrouter 1' (plaintext metadata)
  ciphertext     TEXT        NOT NULL,                 -- base64 AES-256-GCM of {"key": "..."} — the ONLY place a key exists
  iv             TEXT        NOT NULL,                 -- base64, 12 bytes, fresh per write
  schema_version INTEGER     NOT NULL DEFAULT 1,
  default_model  TEXT,                                 -- optional non-secret hint
  default_url    TEXT,                                 -- optional non-secret hint
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, id),
  FOREIGN KEY (user_id, category_id) REFERENCES vault_categories (user_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS vault_entries_cat_idx ON vault_entries (user_id, category_id);
