/**
 * nexus-auth.js
 * -----------------------------------------------------------------------------
 * Tiny client for the Nexus auth backend. Works in any plain HTML page:
 *
 *   <script src="nexus-auth.js"></script>
 *
 * Then use:  NexusAuth.register(u, p) / login(u, p) / me() / logout() / isLoggedIn()
 */
const NexusAuth = (() => {
  // Deploy: change API_BASE to your live backend URL (e.g. https://your-api.railway.app)
  const API_BASE = 'http://localhost:5000'; // <- the ONE line to change for production (no trailing slash)
  const API_URL = API_BASE.replace(/\/+$/, '') + '/api/auth';
  const TOKEN_KEY = 'nexus_token';

  /** Shared fetch helper: sends JSON, throws Error(message) on failure. */
  async function request(path, { method = 'GET', body, auth = false } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers.Authorization = `Bearer ${getToken()}`;

    const res = await fetch(API_URL + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');
    return data;
  }

  const getToken = () => localStorage.getItem(TOKEN_KEY);
  const isLoggedIn = () => Boolean(getToken());

  /** Creates an account (does not log in). */
  const register = (username, password) =>
    request('/register', { method: 'POST', body: { username, password } });

  /** Logs in and stores the JWT in the browser. */
  async function login(username, password) {
    const data = await request('/login', { method: 'POST', body: { username, password } });
    localStorage.setItem(TOKEN_KEY, data.token);
    return data.user;
  }

  /** Returns the logged-in user, or null if not logged in / token expired. */
  async function me() {
    if (!isLoggedIn()) return null;
    try {
      return (await request('/me', { auth: true })).user;
    } catch {
      logout(); // token invalid or expired
      return null;
    }
  }

  const logout = () => localStorage.removeItem(TOKEN_KEY);

  return { register, login, me, logout, isLoggedIn, getToken };
})();
