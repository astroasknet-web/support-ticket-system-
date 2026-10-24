'use strict';
// Creates (or updates) every table the ticket system needs. Safe to run any number of times; the server also does this on start.
const { makePool } = require('../server');
const support = require('../lib/support');

(async () => {
  const pool = makePool();
  await support.ensureSchema(pool);
  console.log('Schema is ready.');
  await pool.end();
})().catch((e) => { console.error('migrate failed:', e.message); process.exit(1); });
