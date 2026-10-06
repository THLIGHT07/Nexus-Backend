/**
 * services/validate.js — server-side input rules for the per-user data API (routes/me.js).
 * -----------------------------------------------------------------------------
 * These mirror the frontend's own sanitizers (js/utils.js: safeUrl, safeId, safeHex, safeIconName,
 * sanitizeApp, sanitizeNote, sanitizeDisplayName, sanitizeBio). The server can't trust the browser, so the
 * same rules are enforced again here — most importantly "app links must be http(s)" (no javascript: URLs).
 *
 * PostgreSQL can't store NUL characters in TEXT/JSONB and rejects unpaired UTF-16 surrogates in JSONB; either
 * would turn into a 500, so every string is cleaned of both before it goes anywhere near the database.
 *
 * Functions return the cleaned value, or null when the input can't be made valid.
 */

const crypto = require('crypto');

const LIMITS = {
  DISPLAY_NAME: 40,
  BIO: 1000,
  AVATAR_CHARS: 8,
  APP_NAME: 120,
  APP_CAT: 60,
  URL: 2048,
  MAX_APPS: 500,
  MAX_RECENT: 20,
  NOTE_TITLE: 200,
  NOTE_BODY: 100000,
  NOTE_DATE: 40,
  MAX_NOTES: 1000,
  SETTINGS_BYTES: 128 * 1024,
};

const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const HEX6 = /^#[0-9a-fA-F]{6}$/;
const ICON = /^[a-z0-9]+(?:-[a-z0-9]+)*$/i;
// control + bidi-override characters (same set as the frontend's _TEXT_JUNK); \t \n \r are kept
const TEXT_JUNK = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/** Removes NUL and repairs unpaired surrogates. Applied to every stored string. */
const baseClean = (s) => s.replace(/\u0000/g, '').replace(LONE_SURROGATE, '\uFFFD');

/** Cuts to `max` characters without splitting an emoji / surrogate pair. */
function cutSafe(str, max) {
  const chars = Array.from(str);
  return chars.length <= max ? str : chars.slice(0, max).join('');
}

function line(v, max) {
  if (typeof v !== 'string') return '';
  return cutSafe(baseClean(v).replace(TEXT_JUNK, '').replace(/\s+/g, ' ').trim(), max);
}

function safeId(v) {
  return typeof v === 'string' && SAFE_ID.test(v) ? v : null;
}

/** Random id in the same style as the frontend's uid(). */
function newId() {
  return Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
}

/** Normalised absolute http(s) URL, or null. */
function safeUrl(u) {
  if (typeof u !== 'string') return null;
  const s = baseClean(u).trim();
  if (!s || s.length > LIMITS.URL) return null;
  let url;
  try { url = new URL(s); } catch (e) { return null; }
  return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
}

const safeHex = (v) => (typeof v === 'string' && HEX6.test(v.trim()) ? v.trim() : null);

function safeIcon(v) {
  const s = String(v == null ? '' : v).trim().replace(/^ti-/i, '');
  return s.length <= 40 && ICON.test(s) ? s.toLowerCase() : 'globe';
}

// ── profile ──────────────────────────────────────────────────────────────────
const displayName = (v) => line(v, LIMITS.DISPLAY_NAME);

function bio(v) {
  if (typeof v !== 'string') return '';
  return cutSafe(baseClean(v).replace(/\r\n?/g, '\n').replace(TEXT_JUNK, '').trim(), LIMITS.BIO);
}

/** "" (default), "initial", or a short emoji string. Returns null if it isn't a short plain string. */
function avatar(v) {
  if (typeof v !== 'string') return null;
  const s = baseClean(v).replace(TEXT_JUNK, '').trim();
  return Array.from(s).length <= LIMITS.AVATAR_CHARS ? s : null;
}

// ── apps ─────────────────────────────────────────────────────────────────────
/** One app record -> { id, name, url, icon, cat, bg, c } or null when unusable (bad name / non-http(s) URL / bad id). */
function app(raw) {
  if (!isPlainObject(raw)) return null;
  const url = safeUrl(raw.url);
  const name = line(raw.name, LIMITS.APP_NAME);
  if (!url || !name) return null;
  let id;
  if (raw.id == null || raw.id === '') id = newId();
  else { id = safeId(raw.id); if (!id) return null; }
  const cat = line(raw.cat, LIMITS.APP_CAT) || 'Other';
  const bg = safeHex(raw.bg), c = safeHex(raw.c);
  return { id, name, url, icon: safeIcon(raw.icon), cat, bg: bg && c ? bg : null, c: bg && c ? c : null };
}

// ── notes ────────────────────────────────────────────────────────────────────
/**
 * One note. With `existing`, omitted fields keep their current value (PUT /notes/:id).
 * -> { id, title, body, date } or null (needs a title or a body; id must be safe).
 */
function note(raw, existing) {
  if (!isPlainObject(raw)) return null;
  let id;
  if (raw.id == null || raw.id === '') id = existing ? existing.id : newId();
  else { id = safeId(raw.id); if (!id) return null; }
  const title = has(raw, 'title') ? line(raw.title, LIMITS.NOTE_TITLE) : (existing ? existing.title : '');
  const body = has(raw, 'body')
    ? (typeof raw.body === 'string' ? cutSafe(baseClean(raw.body), LIMITS.NOTE_BODY) : '')
    : (existing ? existing.body : '');
  const date = has(raw, 'date') ? line(raw.date, LIMITS.NOTE_DATE) : (existing ? existing.date : '');
  if (!title && !body) return null;
  return { id, title: title || 'Untitled', body, date };
}

// ── settings ─────────────────────────────────────────────────────────────────
/**
 * Free-form JSON object (theme, wallpaper, clock, AI config, ...). Checked for shape and size only —
 * what the keys mean is the frontend's business. Returns { value } or { error }.
 */
function settings(raw) {
  if (!isPlainObject(raw)) return { error: 'settings must be a JSON object.' };
  let nodes = 0;
  const walk = (v, depth) => {
    if (++nodes > 5000) throw new Error('settings has too many values.');
    if (depth > 8) throw new Error('settings is nested too deeply.');
    if (v === null || typeof v === 'boolean') return v;
    if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('settings contains a non-finite number.'); return v; }
    if (typeof v === 'string') return baseClean(v);
    if (Array.isArray(v)) {
      if (v.length > 500) throw new Error('settings contains an array that is too long.');
      return v.map((x) => walk(x, depth + 1));
    }
    if (isPlainObject(v)) {
      const keys = Object.keys(v);
      if (keys.length > 200) throw new Error('settings contains an object with too many keys.');
      const out = {};
      for (const k of keys) {
        const key = baseClean(k);
        if (DANGEROUS_KEYS.has(key)) throw new Error(`settings contains a forbidden key "${key}".`);
        out[key] = walk(v[k], depth + 1);
      }
      return out;
    }
    throw new Error('settings contains an unsupported value.');
  };
  try {
    const value = walk(raw, 0);
    if (Buffer.byteLength(JSON.stringify(value), 'utf8') > LIMITS.SETTINGS_BYTES) {
      return { error: `settings is too large (max ${LIMITS.SETTINGS_BYTES / 1024} KB).` };
    }
    return { value };
  } catch (err) {
    return { error: err.message };
  }
}

module.exports = { LIMITS, isPlainObject, has, safeId, newId, safeUrl, displayName, bio, avatar, app, note, settings };
