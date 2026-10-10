-- 002_terms_acceptance.sql — remember, per account, that the user accepted the Terms of Use + Privacy Policy.
-- Applied automatically on startup by db.js (each file runs once, in a transaction).
--
--   terms_accepted_at  NULL  = this account has not accepted yet  -> the app shows the acceptance gate after login
--                      set   = accepted (first acceptance is kept; the gate never shows again on any device)
--   terms_version      which version of the pages was accepted (the "Last updated" date), for your own records.
--
-- Existing accounts start as NULL, so each one sees the gate exactly once at its next login.
ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_version     TEXT;
