'use strict';
// Create or reset a staff account.
//   node scripts/create-admin.js you@example.com "Your Name"            (prints a random password once)
//   ADMIN_PASSWORD='...' node scripts/create-admin.js you@example.com "Your Name"
const crypto = require('crypto');
const { makePool } = require('../server');
const support = require('../lib/support');
const password = require('../lib/password');

(async () => {
  const email = String(process.argv[2] || '').toLowerCase().trim();
  const name = process.argv[3] || 'Administrator';
  if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,24}$/i.test(email)) {
    console.error('Usage: node scripts/create-admin.js you@example.com "Your Name"');
    process.exit(1);
  }
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, 'A') + '9';
  if (pw.length < 8) { console.error('Password must be at least 8 characters.'); process.exit(1); }
  const pool = makePool();
  await support.ensureSchema(pool);
  await pool.query(
    `INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?, 'super_admin')
     ON DUPLICATE KEY UPDATE name=VALUES(name), password_hash=VALUES(password_hash), role='super_admin', is_active=1`,
    [name, email, await password.hash(pw)]);
  console.log(`Admin ready: ${email}`);
  if (!process.env.ADMIN_PASSWORD) console.log(`Password (shown once, change it after logging in): ${pw}`);
  await pool.end();
})().catch((e) => { console.error('create-admin failed:', e.message); process.exit(1); });
