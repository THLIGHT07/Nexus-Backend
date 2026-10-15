# API Vault — security & unlock model

**What the server stores:** per user, a `vault_meta` row (KDF settings, salt, and the *wrapped* vault key), `vault_categories`
(names) and `vault_entries` (name, category, **ciphertext + IV**, optional `default_model` / `default_url` hints, timestamps).
It never receives a plaintext API key, the vault passphrase, or the unwrapped vault key, and has no code that can decrypt.

**How it works (all in the browser, WebCrypto):**
1. First open → the user picks a **vault passphrase** (separate from the login password, 12+ chars).
2. PBKDF2-SHA256 (600 000 rounds, random 16-byte salt) turns it into a key-wrapping key.
3. A random 256-bit **vault key** is generated and AES-GCM-wrapped with that key; only the wrapped form is uploaded (`PUT /api/me/vault/meta`).
4. Each API key is AES-256-GCM encrypted with the vault key (fresh 12-byte IV; the user id + entry id are bound in as GCM
   additional data, so rows can't be swapped between entries/accounts) → `POST /api/me/vault/apis`.

**Unlock step:** after login, on every new session or device the user opens the Vault and types the passphrase once. The vault
key then lives only in memory as a non-extractable CryptoKey, and is dropped on Lock, sign-out, page reload, 15 min idle, or
5 min with the tab in the background. The passphrase is never stored.

**Forgot password vs. forgot passphrase:** because the vault passphrase is independent of the login password, a login password
reset / change does **not** affect the vault. A forgotten *vault passphrase* is **not recoverable** (by design — that is what
makes a DB breach harmless). The user can "Reset vault" (deletes all vault rows, `POST /api/me/vault/reset`) and re-add keys.

**Access control:** every `/api/me/vault/*` route requires the owner's JWT and only touches `WHERE user_id = <token user>`.
No user id appears in URLs or bodies. `routes/admin.js` never reads vault tables. Deleting an account cascades to all vault rows.

**Logging:** vault routes never log request bodies/params; database errors are replaced by a sanitized error before they reach
the central handler (Postgres error DETAIL can contain the failing row). Responses are `Cache-Control: no-store`.

**Playground / Test:** requests go straight from the browser to the URL the user types (their key is never sent through the
Nexus server). Some providers block browser calls (CORS) — the UI says so rather than failing silently.

**Deploy:** `003_api_vault.sql` is applied automatically at startup. Only `server.js` changes (mount `/api/me/vault` *before* `/api/me`).
