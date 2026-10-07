/**
 * set-admin-password.js
 * -----------------------------------------------------------------------------
 * Creates the bcrypt hash for the admin panel password. It only PRINTS the hash —
 * it does not write .env or any other file (on Railway the filesystem is ephemeral,
 * so a file written on the server would vanish at the next deploy).
 *
 *   npm run set-admin-password          (run it on your own computer)
 *
 * Steps:
 *   1. Run the command and type the new password twice (typing is hidden).
 *   2. Copy the printed hash into  Railway -> your service -> Variables  as  ADMIN_PASSWORD_HASH
 *      (value = the hash only, no quotes). Remove any old ADMIN_PASSWORD variable. Redeploy.
 *   3. Sign in to the admin page with the PASSWORD you typed in step 1 — never the hash.
 *
 * Running locally? Put the line in your .env instead:  ADMIN_PASSWORD_HASH='<hash>'
 *
 * For automation you can pipe two identical lines:  printf 'pw\npw\n' | node set-admin-password.js
 * Changing the password also signs out any open admin sessions.
 */

const fs = require('fs');
const readline = require('readline');
const bcrypt = require('bcryptjs');

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

(async () => {
  const [first, second] = await readPasswords();

  if (first !== second) {
    console.error('The two passwords do not match. No hash was created.');
    process.exit(1);
  }
  if (first.length < MIN_LENGTH) {
    console.error(`Use at least ${MIN_LENGTH} characters. No hash was created.`);
    process.exit(1);
  }
  if (first.length > 72) {
    console.error('Use at most 72 characters (bcrypt limit). No hash was created.');
    process.exit(1);
  }

  const hash = await bcrypt.hash(first, ROUNDS);

  console.log('\nYour ADMIN_PASSWORD_HASH (nothing was written to disk):\n');
  console.log(hash);
  console.log('\nRailway: Variables -> New Variable');
  console.log('   name : ADMIN_PASSWORD_HASH');
  console.log('   value: the hash above, exactly as printed (no quotes)');
  console.log('   Then delete any ADMIN_PASSWORD variable and redeploy.');
  console.log('\nLocal .env file instead:');
  console.log(`   ADMIN_PASSWORD_HASH='${hash}'`);
  console.log('\nSign in to the admin page with the PASSWORD you just typed — never with the hash.');
})().catch((err) => {
  console.error('Failed:', err.message);
  process.exit(1);
});
