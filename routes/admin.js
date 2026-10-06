/**
 * routes/admin.js
 * -----------------------------------------------------------------------------
 * Admin routes, mounted at /api/admin
 *
 *   POST   /login        -> exchange the admin password for a short-lived admin token (public)
 *   -------- everything below needs   Authorization: Bearer <admin token>   --------
 *   GET    /verify       -> check that the token is still valid
 *   POST   /logout       -> revoke the token
 *   GET    /users        -> list all users
 *   POST   /block/:id    -> set a user's status to 'blocked'
 *   POST   /unblock/:id  -> set a user's status to 'active'
 *   DELETE /users/:id    -> permanently delete a user
 *
 * The guard is applied with router.use(requireAdmin) BEFORE any of those routes,
 * so any path under /api/admin (even one that doesn't exist) is refused without a
 * valid token. See middleware/adminAuth.js for how the password and token work.
 */

const express = require('express');
const db = require('../db');

const { noStore, adminLogin, requireAdmin, adminVerify, adminLogout } = require('../middleware/adminAuth');

const router = express.Router();

router.use(noStore); // admin responses must never be cached
router.post('/login', adminLogin); // the ONLY public admin route (rate-limited inside adminLogin)
router.use(requireAdmin); // 🔒 everything below requires a valid admin token
router.get('/verify', adminVerify);
router.post('/logout', adminLogout);

/** Parses an `:id` route param into a positive integer, or null if invalid. */
function parseId(raw) {
  const id = Number(raw);
  return Number.isInteger(id) && id > 0 ? id : null;
}

// -----------------------------------------------------------------------------
// GET /api/admin/users
// -----------------------------------------------------------------------------
router.get('/users', async (req, res, next) => {
  try {
    const users = await db.all(
      'SELECT id, username, status, created_at FROM users ORDER BY id DESC'
    );
    res.json({ users });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// POST /api/admin/block/:id
// -----------------------------------------------------------------------------
router.post('/block/:id', async (req, res, next) => {
  try {
    const id = parseId(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid user id.' });

    const user = await db.get('SELECT id FROM users WHERE id = $1', [id]);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    await db.run("UPDATE users SET status = 'blocked' WHERE id = $1", [id]);
    console.log(`[admin] ${req.admin.ip} blocked user #${id}`);
    const updated = await db.get(
      'SELECT id, username, status, created_at FROM users WHERE id = $1',
      [id]
    );
    res.json({ message: 'User blocked.', user: updated });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// POST /api/admin/unblock/:id
// -----------------------------------------------------------------------------
router.post('/unblock/:id', async (req, res, next) => {
  try {
    const id = parseId(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid user id.' });

    const user = await db.get('SELECT id FROM users WHERE id = $1', [id]);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    await db.run("UPDATE users SET status = 'active' WHERE id = $1", [id]);
    console.log(`[admin] ${req.admin.ip} unblocked user #${id}`);
    const updated = await db.get(
      'SELECT id, username, status, created_at FROM users WHERE id = $1',
      [id]
    );
    res.json({ message: 'User unblocked.', user: updated });
  } catch (err) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// DELETE /api/admin/users/:id
// -----------------------------------------------------------------------------
router.delete('/users/:id', async (req, res, next) => {
  try {
    const id = parseId(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid user id.' });

    const user = await db.get('SELECT id FROM users WHERE id = $1', [id]);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    await db.run('DELETE FROM users WHERE id = $1', [id]); // their profile, settings, apps and notes are removed too (ON DELETE CASCADE)
    console.log(`[admin] ${req.admin.ip} deleted user #${id}`);
    res.json({ message: 'User deleted permanently.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

