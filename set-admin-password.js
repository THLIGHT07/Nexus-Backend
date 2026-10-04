/**
 * set-admin-password.js
 * -----------------------------------------------------------------------------
 * Sets the admin panel password WITHOUT ever writing it to disk in plain text.
 *
 *   npm run set-admin-password
 *
 * It asks for the new password twice (typing is hidden), hashes it with bcrypt,
 * and stores only the hash as ADMIN_PASSWORD_HASH in .env. Any old plain-text
 * ADMIN_PASSWORD line is removed. All your other .env lines are left untouched.
 * Restart the server afterwards. (This also logs out any open admin sessions.)
 *
 * For automation you can pipe two identical lines:  printf 'pw\npw\n' | node set-admin-password.js
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const bcrypt = require('bcryptjs');

const ENV_PATH = path.join(__dirname, '.env');
const MIN_LENGTH = 10;
const ROUNDS = 12;

/** Prompts on a TTY with the typed characters hidden. */
function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let muted = false;
    rl._writeToOutput = (text) => {
      if (muted) rl.output.write(text.includes('\n') || text.includes('\r') ? text : '*');
      else rl.output.write(text);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
    muted = true;
  });
}

async function readPasswords() {
  if (process.stdin.isTTY) {
    const first = await askHidden('New admin password: ');
    const second = await askHidden('Repeat password:    ');
    return [first, second];
  }
  const lines = fs.readFileSync(0, 'utf8').split(/\r?\n/);
  return [lines[0] || '', lines[1] || ''];
}

/** Returns .env text with ADMIN_PASSWORD / ADMIN_PASSWORD_HASH replaced by the new hash line. */
function withHash(envText, hash) {
  const kept = envText
    .split(/\r?\n/)
    .filter((line) => !/^\s*ADMIN_PASSWORD(_HASH)?\s*=/.test(line));
  while (kept.length && kept[kept.length - 1].trim() === '') kept.pop();
  kept.push(`ADMIN_PASSWORD_HASH='${hash}'`);
  return kept.join('\n') + '\n';
}

(async () => {
  const [first, second] = await readPasswords();

  if (first !== second) {
    console.error('The two passwords do not match. Nothing was changed.');
    process.exit(1);
  }
  if (first.length < MIN_LENGTH) {
    console.error(`Use at least ${MIN_LENGTH} characters. Nothing was changed.`);
    process.exit(1);
  }
  if (first.length > 72) {
    console.error('Use at most 72 characters (bcrypt limit). Nothing was changed.');
    process.exit(1);
  }

  const hash = await bcrypt.hash(first, ROUNDS);
  const existing = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';

  // Write atomically and keep the file private to the owner.
  const tmp = `${ENV_PATH}.tmp`;
  fs.writeFileSync(tmp, withHash(existing, hash), { mode: 0o600 });
  fs.renameSync(tmp, ENV_PATH);
  try { fs.chmodSync(ENV_PATH, 0o600); } catch (e) { /* not supported on this OS */ }

  console.log('✔ Admin password saved to .env as a bcrypt hash (the password itself is not stored).');
  console.log('  Restart the server for it to take effect.');
})().catch((err) => {
  console.error('Failed:', err.message);
  process.exit(1);
});
