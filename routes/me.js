/**
 * routes/me.js — the signed-in user's own data, stored in PostgreSQL (mounted at /api/me)
 * -----------------------------------------------------------------------------
 * Every route needs a valid user JWT ("Authorization: Bearer <token>") and only ever touches the rows of the
 * user in that token — there is no user id in any URL or body. JSON fields are camelCase.
 *
 *   GET  /bootstrap          everything in one call (use this right after login)
 *   GET  /profile            PUT /profile    { displayName?, avatar?, bio? }   omitted fields stay as they are
 *   GET  /settings           PUT /settings   { settings: {...} }               replaces the whole settings object
 *   GET  /apps               PUT /apps       { apps: [...], favs?, recent? }   replaces the whole list (atomic)
 *   GET  /notes
 *   POST   /notes            { id?, title?, body?, date? }  -> 201, 409 if that id exists
 *   PUT    /notes/:id        create-or-update one note (omitted fields stay as they are)
 *   DELETE /notes/:id
 *   PUT    /notes            { notes: [...] }  replaces ALL notes (for importing localStorage; a stale tab could wipe notes)
 *
 * bootstrap -> {
 *   user:     { id, username, status, created_at, email, email_verified },
 *   profile:  { displayName, avatar, bio, updatedAt },        ("" / null when never saved)
 *   settings: { ... },  settingsUpdatedAt,
 *   apps:     [{ id, name, url, icon, cat, bg, c }],          (in saved order; same shape as the frontend's app objects)
 *   favs:     [appId, ...],   recent: [appId, ...],
 *   notes:    [{ id, title, body, date, updatedAt }],         (newest first)
 *   initialized: { profile, settings, apps, notes }           true once that part has EVER been saved. An empty list
 *                                                             with initialized=true means "the user really has none";
 *                                                             initialized=false means "never synced" (seed defaults or
 *                                                             import from localStorage).
 * }
 *
 * Input is validated by services/validate.js (http(s)-only links, size limits, NUL/surrogate cleanup). Bad input ->
 * 400 with { error }. Writes are limited to 120 per minute per user.
 */

const express = require('express');
const db = require('../db');
const authenticate = require('../middleware/auth');
const { createLimiter } = require('../middleware/rateLimiter');
const v = require('../services/validate');

const router = express.Router();
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); // async errors -> error handler

router.use(authenticate);

// ── write limiter (per user) ─────────────────────────────────────────────────
const writes = createLimiter({ max: 120, windowMs: 60 * 1000 });
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

const bad = (res, message, extra) => res.status(400).json({ error: message, ...(extra || {}) });

// ── row <-> API shape ────────────────────────────────────────────────────────
const toApp = (r) => ({ id: r.id, name: r.name, url: r.url, icon: r.icon, cat: r.cat, bg: r.bg, c: r.color });
const toNote = (r) => ({ id: r.id, title: r.title, body: r.body, date: r.date_label, updatedAt: r.updated_at });
const toProfile = (r) => (r
  ? { displayName: r.display_name, avatar: r.avatar, bio: r.bio, updatedAt: r.updated_at }
  : { displayName: '', avatar: '', bio: '', updatedAt: null });
const asArray = (x) => (Array.isArray(x) ? x : []); // JSONB comes back parsed; be defensive anyway

// ── loaders (shared by bootstrap and the single GETs) ────────────────────────
const loadProfile = async (uid) =>
  db.get('SELECT display_name, avatar, bio, updated_at FROM user_profiles WHERE user_id = $1', [uid]);
const loadState = async (uid) =>
  db.get('SELECT settings_json, recent_json, settings_saved_at, apps_saved_at, notes_saved_at FROM user_settings WHERE user_id = $1', [uid]);
const loadApps = async (uid) =>
  db.all('SELECT id, name, url, icon, cat, bg, color, fav FROM apps WHERE user_id = $1 ORDER BY sort_order ASC, id ASC', [uid]);
const loadNotes = async (uid) =>
  db.all('SELECT id, title, body, date_label, updated_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC, id DESC', [uid]);

function appsPayload(rows, state) {
  const ids = new Set(rows.map((r) => r.id));
  return {
    apps: rows.map(toApp),
    favs: rows.filter((r) => r.fav === true).map((r) => r.id),
    recent: asArray(state && state.recent_json).filter((id) => ids.has(id)),
  };
}

// ── "has this part ever been saved" markers (one fixed statement each) ───────
const MARK_SETTINGS = `INSERT INTO user_settings (user_id, settings_saved_at, updated_at) VALUES ($1, $2, $2)
  ON CONFLICT (user_id) DO UPDATE SET settings_saved_at = EXCLUDED.settings_saved_at, updated_at = EXCLUDED.updated_at`;
const MARK_NOTES = `INSERT INTO user_settings (user_id, notes_saved_at, updated_at) VALUES ($1, $2, $2)
  ON CONFLICT (user_id) DO UPDATE SET notes_saved_at = EXCLUDED.notes_saved_at, updated_at = EXCLUDED.updated_at`;

// ── GET /bootstrap ───────────────────────────────────────────────────────────
router.get('/bootstrap', ah(async (req, res) => {
  const uid = req.user.id;
  const [profile, state, appRows, noteRows] = await Promise.all([loadProfile(uid), loadState(uid), loadApps(uid), loadNotes(uid)]);
  res.json({
    user: req.user,
    profile: toProfile(profile),
    settings: (state && v.isPlainObject(state.settings_json)) ? state.settings_json : {},
    settingsUpdatedAt: (state && state.settings_saved_at) || null,
    ...appsPayload(appRows, state),
    notes: noteRows.map(toNote),
    initialized: {
      profile: Boolean(profile),
      settings: Boolean(state && state.settings_saved_at),
      apps: Boolean(state && state.apps_saved_at),
      notes: Boolean(state && state.notes_saved_at),
    },
  });
}));

// ── profile ──────────────────────────────────────────────────────────────────
router.get('/profile', ah(async (req, res) => {
  res.json({ profile: toProfile(await loadProfile(req.user.id)) });
}));

router.put('/profile', ah(async (req, res) => {
  const body = v.isPlainObject(req.body) ? req.body : {};
  if (!['displayName', 'avatar', 'bio'].some((k) => v.has(body, k))) return bad(res, 'Send displayName, avatar and/or bio.');
  for (const k of ['displayName', 'avatar', 'bio']) {
    if (v.has(body, k) && typeof body[k] !== 'string') return bad(res, `${k} must be a string.`);
  }
  let avatar;
  if (v.has(body, 'avatar')) {
    avatar = v.avatar(body.avatar);
    if (avatar === null) return bad(res, `avatar must be at most ${v.LIMITS.AVATAR_CHARS} characters.`);
  }
  const uid = req.user.id;
  const current = await loadProfile(uid);
  const next = {
    display_name: v.has(body, 'displayName') ? v.displayName(body.displayName) : (current ? current.display_name : ''),
    avatar: v.has(body, 'avatar') ? avatar : (current ? current.avatar : ''),
    bio: v.has(body, 'bio') ? v.bio(body.bio) : (current ? current.bio : ''),
  };
  const row = await db.get(
    `INSERT INTO user_profiles (user_id, display_name, avatar, bio, updated_at) VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id) DO UPDATE
       SET display_name = EXCLUDED.display_name, avatar = EXCLUDED.avatar, bio = EXCLUDED.bio, updated_at = EXCLUDED.updated_at
     RETURNING display_name, avatar, bio, updated_at`,
    [uid, next.display_name, next.avatar, next.bio, new Date()]
  );
  res.json({ profile: toProfile(row) });
}));

// ── settings ─────────────────────────────────────────────────────────────────
router.get('/settings', ah(async (req, res) => {
  const state = await loadState(req.user.id);
  res.json({
    settings: (state && v.isPlainObject(state.settings_json)) ? state.settings_json : {},
    updatedAt: (state && state.settings_saved_at) || null,
  });
}));

router.put('/settings', ah(async (req, res) => {
  const checked = v.settings(v.isPlainObject(req.body) ? req.body.settings : undefined);
  if (checked.error) return bad(res, checked.error);
  const now = new Date();
  const row = await db.get(
    `INSERT INTO user_settings (user_id, settings_json, settings_saved_at, updated_at) VALUES ($1, $2::jsonb, $3, $3)
     ON CONFLICT (user_id) DO UPDATE
       SET settings_json = EXCLUDED.settings_json, settings_saved_at = EXCLUDED.settings_saved_at, updated_at = EXCLUDED.updated_at
     RETURNING settings_json, settings_saved_at`,
    [req.user.id, JSON.stringify(checked.value), now]
  );
  res.json({ settings: row.settings_json, updatedAt: row.settings_saved_at });
}));

// ── apps (+ favourites, recent) ──────────────────────────────────────────────
router.get('/apps', ah(async (req, res) => {
  const [rows, state] = await Promise.all([loadApps(req.user.id), loadState(req.user.id)]);
  res.json(appsPayload(rows, state));
}));

router.put('/apps', ah(async (req, res) => {
  const body = v.isPlainObject(req.body) ? req.body : {};
  if (!Array.isArray(body.apps)) return bad(res, 'apps must be an array.');
  if (body.apps.length > v.LIMITS.MAX_APPS) return bad(res, `At most ${v.LIMITS.MAX_APPS} apps are allowed.`);
  for (const k of ['favs', 'recent']) {
    if (v.has(body, k) && !Array.isArray(body[k])) return bad(res, `${k} must be an array of app ids.`);
  }

  const apps = [];
  const seen = new Set();
  const invalid = [];
  const flagged = []; // ids of apps that carry fav: true
  body.apps.forEach((raw, i) => {
    const a = v.app(raw);
    if (!a) return invalid.push(i);
    if (seen.has(a.id)) return invalid.push(i);
    seen.add(a.id);
    apps.push(a);
    if (raw.fav === true) flagged.push(a.id);
  });
  if (invalid.length) {
    return bad(res, `Some apps are invalid (need a name, a unique id and an http(s) link). Positions: ${invalid.slice(0, 10).join(', ')}.`, { invalid: invalid.slice(0, 50) });
  }

  const uid = req.user.id;
  // favourites: the explicit list wins; otherwise each app's own `fav` flag (true) is used
  const favSet = new Set(v.has(body, 'favs') ? body.favs.filter((id) => typeof id === 'string' && seen.has(id)) : flagged);
  const now = new Date();

  const result = await db.tx(async (t) => {
    let recent;
    if (v.has(body, 'recent')) {
      recent = [...new Set(body.recent.filter((id) => typeof id === 'string' && seen.has(id)))].slice(0, v.LIMITS.MAX_RECENT);
    } else {
      const st = await t.get('SELECT recent_json FROM user_settings WHERE user_id = $1', [uid]);
      recent = asArray(st && st.recent_json).filter((id) => seen.has(id));
    }
    await t.run('DELETE FROM apps WHERE user_id = $1', [uid]);
    const CHUNK = 100; // 10 columns x 100 rows stays far below PostgreSQL's 65,535-parameter limit
    for (let i = 0; i < apps.length; i += CHUNK) {
      const part = apps.slice(i, i + CHUNK);
      const params = [];
      const tuples = part.map((a, j) => {
        const o = params.length;
        params.push(uid, a.id, a.name, a.url, a.icon, a.cat, a.bg, a.c, favSet.has(a.id), i + j);
        return `($${o + 1}, $${o + 2}, $${o + 3}, $${o + 4}, $${o + 5}, $${o + 6}, $${o + 7}, $${o + 8}, $${o + 9}, $${o + 10})`;
      });
      await t.run(`INSERT INTO apps (user_id, id, name, url, icon, cat, bg, color, fav, sort_order) VALUES ${tuples.join(', ')}`, params);
    }
    await t.run(
      `INSERT INTO user_settings (user_id, recent_json, apps_saved_at, updated_at) VALUES ($1, $2::jsonb, $3, $3)
       ON CONFLICT (user_id) DO UPDATE
         SET recent_json = EXCLUDED.recent_json, apps_saved_at = EXCLUDED.apps_saved_at, updated_at = EXCLUDED.updated_at`,
      [uid, JSON.stringify(recent), now]
    );
    return { apps: apps.map(({ id, name, url, icon, cat, bg, c }) => ({ id, name, url, icon, cat, bg, c })), favs: apps.filter((a) => favSet.has(a.id)).map((a) => a.id), recent };
  });
  res.json(result);
}));

// ── notes ────────────────────────────────────────────────────────────────────
const noteRow = (uid, id) =>
  db.get('SELECT id, title, body, date_label, updated_at FROM notes WHERE user_id = $1 AND id = $2', [uid, id]);

router.get('/notes', ah(async (req, res) => {
  res.json({ notes: (await loadNotes(req.user.id)).map(toNote) });
}));

/** Insert-or-update inside a transaction; keeps the "ever saved" marker current. Returns { created, note }. */
async function saveNote(uid, clean, { mustBeNew }) {
  return db.tx(async (t) => {
    const existing = await t.get('SELECT id FROM notes WHERE user_id = $1 AND id = $2', [uid, clean.id]);
    if (existing && mustBeNew) return { conflict: true };
    if (!existing) {
      const n = await t.get('SELECT COUNT(*) AS n FROM notes WHERE user_id = $1', [uid]);
      if (Number(n.n) >= v.LIMITS.MAX_NOTES) return { full: true };
    }
    const now = new Date();
    const row = await t.get(
      `INSERT INTO notes (user_id, id, title, body, date_label, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)
       ON CONFLICT (user_id, id) DO UPDATE
         SET title = EXCLUDED.title, body = EXCLUDED.body, date_label = EXCLUDED.date_label, updated_at = EXCLUDED.updated_at
       RETURNING id, title, body, date_label, updated_at`,
      [uid, clean.id, clean.title, clean.body, clean.date, now]
    );
    await t.run(MARK_NOTES, [uid, now]);
    return { created: !existing, note: toNote(row) };
  });
}
const noteProblem = (res, out) => {
  if (out.conflict) return res.status(409).json({ error: 'A note with that id already exists.' });
  if (out.full) return bad(res, `You have reached the limit of ${v.LIMITS.MAX_NOTES} notes.`);
  return null;
};

router.post('/notes', ah(async (req, res) => {
  const clean = v.note(req.body);
  if (!clean) return bad(res, 'A note needs a title or some text (and a valid id, if you send one).');
  const out = await saveNote(req.user.id, clean, { mustBeNew: true });
  if (noteProblem(res, out)) return;
  res.status(201).json({ note: out.note });
}));

router.put('/notes/:id', ah(async (req, res) => {
  const id = v.safeId(req.params.id);
  if (!id) return bad(res, 'Invalid note id.');
  const uid = req.user.id;
  const existing = await noteRow(uid, id);
  const clean = v.note({ ...(v.isPlainObject(req.body) ? req.body : {}), id },
    existing ? { id, title: existing.title, body: existing.body, date: existing.date_label } : undefined);
  if (!clean) return bad(res, 'A note needs a title or some text.');
  const out = await saveNote(uid, clean, { mustBeNew: false });
  if (noteProblem(res, out)) return;
  res.status(out.created ? 201 : 200).json({ note: out.note });
}));

router.delete('/notes/:id', ah(async (req, res) => {
  const id = v.safeId(req.params.id);
  if (!id) return bad(res, 'Invalid note id.');
  const uid = req.user.id;
  const out = await db.tx(async (t) => {
    const del = await t.run('DELETE FROM notes WHERE user_id = $1 AND id = $2 RETURNING id', [uid, id]);
    if (del.changes === 0) return false;
    await t.run(MARK_NOTES, [uid, new Date()]);
    return true;
  });
  if (!out) return res.status(404).json({ error: 'Note not found.' });
  res.json({ message: 'Note deleted.' });
}));

router.put('/notes', ah(async (req, res) => {
  const body = v.isPlainObject(req.body) ? req.body : {};
  if (!Array.isArray(body.notes)) return bad(res, 'notes must be an array.');
  if (body.notes.length > v.LIMITS.MAX_NOTES) return bad(res, `At most ${v.LIMITS.MAX_NOTES} notes are allowed.`);
  const notes = [];
  const seen = new Set();
  const invalid = [];
  body.notes.forEach((raw, i) => {
    const n = v.note(raw);
    if (!n || seen.has(n.id)) return invalid.push(i);
    seen.add(n.id);
    notes.push(n);
  });
  if (invalid.length) return bad(res, `Some notes are invalid. Positions: ${invalid.slice(0, 10).join(', ')}.`, { invalid: invalid.slice(0, 50) });

  const uid = req.user.id;
  const base = Date.now();
  const stamp = new Date(base);
  await db.tx(async (t) => {
    await t.run('DELETE FROM notes WHERE user_id = $1', [uid]);
    const CHUNK = 100;
    for (let i = 0; i < notes.length; i += CHUNK) {
      const part = notes.slice(i, i + CHUNK);
      const params = [];
      const tuples = part.map((n, j) => {
        const o = params.length;
        // the array is newest-first: give each note a created_at 1 ms older than the one before it, so order survives
        params.push(uid, n.id, n.title, n.body, n.date, new Date(base - (i + j)), stamp);
        return `($${o + 1}, $${o + 2}, $${o + 3}, $${o + 4}, $${o + 5}, $${o + 6}, $${o + 7})`;
      });
      await t.run(`INSERT INTO notes (user_id, id, title, body, date_label, created_at, updated_at) VALUES ${tuples.join(', ')}`, params);
    }
    await t.run(MARK_NOTES, [uid, stamp]);
  });
  res.json({ notes: (await loadNotes(uid)).map(toNote) });
}));

module.exports = router;
