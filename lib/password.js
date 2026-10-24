// lib/password.js — password hashing with bcrypt.
//
// Backward-compatible with the legacy SHA-256 hashes that older accounts may
// still have: verify() accepts either, and reports `needsRehash` so the caller
// can transparently upgrade a legacy account to bcrypt on its next login.

const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ROUNDS = 12;

function sha256(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

function isBcrypt(hash) {
  return typeof hash === 'string' && /^\$2[aby]\$/.test(hash);
}

async function hash(plain) {
  return bcrypt.hash(String(plain), ROUNDS);
}

// Returns { ok, needsRehash }.
//   ok          – password matches the stored hash
//   needsRehash – true when it matched a legacy SHA-256 hash (re-store as bcrypt)
async function verify(plain, stored) {
  if (!stored) return { ok: false, needsRehash: false };
  if (isBcrypt(stored)) {
    const ok = await bcrypt.compare(String(plain), stored);
    return { ok, needsRehash: false };
  }
  const ok = sha256(plain) === stored; // legacy SHA-256 hex
  return { ok, needsRehash: ok };
}

module.exports = { hash, verify, isBcrypt, sha256, ROUNDS };
