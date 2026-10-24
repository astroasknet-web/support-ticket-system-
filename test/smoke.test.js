'use strict';
// End-to-end test of the whole app against a real MySQL database. Skipped unless TEST_DB_NAME is set, e.g.
//   TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=3307 TEST_DB_USER=root TEST_DB_NAME=support_ticket_test npm test
// The database is created if missing and its tables are emptied first.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const mysql = require('mysql2/promise');

const DB = process.env.TEST_DB_NAME;
const skip = DB ? false : 'set TEST_DB_NAME to run the database tests';

let server, base, pool;
const jar = (name) => ({ name, cookie: '', csrf: '' });

async function req(who, method, url, { form, multipart, expect } = {}) {
  const headers = { cookie: who.cookie };
  let body;
  if (form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams({ _csrf: who.csrf, ...form }).toString(); }
  if (multipart) { multipart.set('_csrf', who.csrf); body = multipart; }
  const res = await fetch(base + url, { method, headers, body, redirect: 'manual' });
  const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of set) { const kv = c.split(';')[0]; const k = kv.split('=')[0]; who.cookie = who.cookie.split('; ').filter((x) => x && !x.startsWith(k + '=')).concat(kv).join('; '); }
  const text = await res.text();
  const m = /<meta name="csrf-token" content="([a-f0-9]+)"/.exec(text);
  if (m) who.csrf = m[1];
  if (expect !== undefined) assert.equal(res.status, expect, `${method} ${url} -> ${res.status}`);
  return { status: res.status, text, location: res.headers.get('location') };
}

async function fileTicket(who, over = {}) {
  const page = await req(who, 'GET', '/support', { expect: 200 });
  const q = /what is <strong>(\d+) \+ (\d+)<\/strong>/.exec(page.text);
  assert.ok(q, 'captcha question is on the form');
  const cat = /<option value="(\d+)"/.exec(page.text)[1];
  const form = { name: 'Test Customer', email: 'customer@example.invalid', phone: '', category_id: cat, subject: 'Cannot download my invoice', description: 'I tried to download the invoice three times and the page shows an error each time.', captcha: String(Number(q[1]) + Number(q[2])), form_ts: String(Date.now() - 20000), website: '', order_ref: '1001', ...over };
  return req(who, 'POST', '/support', { form });
}

before(async () => {
  if (skip) return;
  process.env.DB_NAME = DB;
  process.env.DB_HOST = process.env.TEST_DB_HOST || '127.0.0.1';
  process.env.DB_PORT = process.env.TEST_DB_PORT || '3306';
  process.env.DB_USER = process.env.TEST_DB_USER || 'root';
  process.env.DB_PASSWORD = process.env.TEST_DB_PASSWORD || '';
  process.env.SESSION_SECRET = 'test-secret';
  process.env.SUPPORT_CREATE_LIMIT = '1000';
  process.env.SUPPORT_REPLY_LIMIT = '1000';
  const root = await mysql.createConnection({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT), user: process.env.DB_USER, password: process.env.DB_PASSWORD });
  await root.query('CREATE DATABASE IF NOT EXISTS `' + DB + '` CHARACTER SET utf8mb4');
  await root.end();
  const { createApp, makePool } = require('../server');
  const support = require('../lib/support');
  const password = require('../lib/password');
  pool = makePool();
  await support.ensureSchema(pool);
  await pool.query('SET FOREIGN_KEY_CHECKS=0');
  for (const t of ['support_events', 'support_attachments', 'support_messages', 'support_tickets', 'support_blocklist', 'users']) await pool.query('DELETE FROM ' + t);
  await pool.query('SET FOREIGN_KEY_CHECKS=1');
  await pool.query("INSERT INTO users (name, email, password_hash, role) VALUES ('Admin One','admin@example.invalid',?, 'admin'), ('Plain User','user@example.invalid',?, 'user')", [await password.hash('correct-horse-1'), await password.hash('plain-user-pass-1')]);
  const session = require('express-session');
  const store = new session.MemoryStore();
  const app = createApp(pool, store);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  base = 'http://127.0.0.1:' + server.address().port;
});

after(async () => { if (server) server.close(); if (pool) await pool.end(); });

test('the public form works without an account and gives a private ticket link', { skip }, async () => {
  const guest = jar('guest');
  const res = await fileTicket(guest);
  assert.equal(res.status, 200);
  assert.match(res.text, /SUP-\d{4}-\d{6}/);
  const link = /href="(\/support\/ticket\/[a-f0-9]{48})"/.exec(res.text)[1];
  const page = await req(guest, 'GET', link, { expect: 200 });
  assert.match(page.text, /Cannot download my invoice/);
  const [[t]] = await pool.query("SELECT t.*, c.default_priority FROM support_tickets t JOIN support_categories c ON c.id=t.category_id ORDER BY t.id DESC LIMIT 1");
  assert.equal(t.status, 'open');
  assert.equal(t.priority, t.default_priority); // priority follows the category
  assert.equal((await req(guest, 'GET', '/support/ticket/' + 'a'.repeat(48))).status, 404);
  assert.equal((await req(guest, 'GET', '/support/ticket/not-a-token')).status, 404);
});

test('a wrong captcha, a filled honeypot and a missing security token are all refused', { skip }, async () => {
  const before = (await pool.query('SELECT COUNT(*) n FROM support_tickets'))[0][0].n;
  const g = jar('g');
  const wrong = await fileTicket(g, { captcha: '999', subject: 'Wrong captcha test' });
  assert.equal(wrong.status, 400);
  assert.match(wrong.text, /security answer/i);
  const bot = await fileTicket(g, { website: 'http://spam.example', subject: 'Honeypot test' });
  assert.equal(bot.status, 200); // pretends success so the bot learns nothing...
  assert.equal((await pool.query('SELECT COUNT(*) n FROM support_tickets'))[0][0].n, before); // ...but stores nothing
  const noCsrf = await fetch(base + '/support', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: g.cookie }, body: 'name=x' });
  assert.equal(noCsrf.status, 403);
});

test('the same email and subject within a day does not open a second ticket', { skip }, async () => {
  const g = jar('dup');
  const first = await fileTicket(g, { subject: 'Duplicate subject check', email: 'dup@example.invalid' });
  assert.equal(first.status, 200);
  const n1 = (await pool.query('SELECT COUNT(*) n FROM support_tickets'))[0][0].n;
  const second = await fileTicket(g, { subject: 'Duplicate subject check', email: 'dup@example.invalid' });
  assert.match(second.text, /did not create a second one/);
  assert.equal((await pool.query('SELECT COUNT(*) n FROM support_tickets'))[0][0].n, n1);
});

test('only an admin can reach the admin pages, and a plain user cannot', { skip }, async () => {
  const anon = jar('anon');
  await req(anon, 'GET', '/support', { expect: 200 });
  assert.equal((await req(anon, 'GET', '/admin/support')).status, 403);
  const user = jar('user');
  await req(user, 'GET', '/auth/login', { expect: 200 });
  const login = await req(user, 'POST', '/auth/login', { form: { email: 'user@example.invalid', password: 'plain-user-pass-1', next: '/dashboard/support' } });
  assert.equal(login.status, 302);
  assert.equal((await req(user, 'GET', '/admin/support')).status, 403);
  assert.equal((await req(user, 'GET', '/admin/support/export.csv')).status, 403);
  const bad = await req(user, 'POST', '/auth/login', { form: { email: 'user@example.invalid', password: 'wrong', next: '/' } });
  assert.match(bad.text, /Invalid email or password/);
});

test('staff can work a ticket from open to resolved, and the customer sees only public replies', { skip }, async () => {
  const cust = jar('cust');
  const made = await fileTicket(cust, { subject: 'Staff workflow ticket', email: 'flow@example.invalid' });
  const link = /href="(\/support\/ticket\/[a-f0-9]{48})"/.exec(made.text)[1];
  const [[t]] = await pool.query("SELECT id FROM support_tickets WHERE subject='Staff workflow ticket'");

  const admin = jar('admin');
  await req(admin, 'GET', '/auth/login', { expect: 200 });
  assert.equal((await req(admin, 'POST', '/auth/login', { form: { email: 'admin@example.invalid', password: 'correct-horse-1', next: '/admin/support' } })).status, 302);
  const list = await req(admin, 'GET', '/admin/support', { expect: 200 });
  assert.match(list.text, /Staff workflow ticket/);
  const detail = await req(admin, 'GET', '/admin/support/' + t.id, { expect: 200 });
  assert.match(detail.text, /Cannot download my invoice|I tried to download/);

  const fd = new FormData(); fd.set('message', 'Hello, we are looking into this now.');
  await req(admin, 'POST', `/admin/support/${t.id}/reply`, { multipart: fd, expect: 302 });
  const note = new FormData(); note.set('message', 'INTERNAL: customer has had three failed downloads'); note.set('is_internal', '1');
  await req(admin, 'POST', `/admin/support/${t.id}/reply`, { multipart: note, expect: 302 });

  const seen = await req(cust, 'GET', link, { expect: 200 });
  assert.match(seen.text, /looking into this now/);
  assert.doesNotMatch(seen.text, /INTERNAL: customer has had/); // staff-only notes never reach the customer
  const [[after1]] = await pool.query('SELECT status FROM support_tickets WHERE id=?', [t.id]);
  assert.equal(after1.status, 'waiting_customer');

  const reply = new FormData(); reply.set('message', 'Thanks, it works now.');
  await req(cust, 'POST', link + '/reply', { multipart: reply, expect: 302 });
  assert.equal((await pool.query('SELECT status FROM support_tickets WHERE id=?', [t.id]))[0][0].status, 'open'); // a customer reply reopens it

  await req(admin, 'POST', `/admin/support/${t.id}/status`, { form: { status: 'resolved' }, expect: 302 });
  await req(admin, 'POST', `/admin/support/${t.id}/priority`, { form: { priority: 'low' }, expect: 302 });
  const done = await req(cust, 'GET', link, { expect: 200 });
  assert.match(done.text, /Resolved/);
  await req(cust, 'POST', link + '/rating', { form: { rating: '5', rating_comment: 'Quick and friendly' }, expect: 302 });
  const [[rated]] = await pool.query('SELECT rating, priority, resolved_at FROM support_tickets WHERE id=?', [t.id]);
  assert.equal(rated.rating, 5);
  assert.equal(rated.priority, 'low');
  assert.ok(rated.resolved_at);
  const [events] = await pool.query('SELECT kind FROM support_events WHERE ticket_id=?', [t.id]);
  assert.ok(['created', 'reply', 'note', 'status', 'priority', 'rating'].every((k) => events.some((e) => e.kind === k)), 'every action is in the audit trail');

  // exports and print views are admin-only and work
  const csv = await req(admin, 'GET', '/admin/support/export.csv', { expect: 200 });
  assert.match(csv.text, /ticket_no/);
  assert.match(csv.text, /Staff workflow ticket/);
  assert.match((await req(admin, 'GET', `/admin/support/${t.id}/print`, { expect: 200 })).text, /Support Ticket SUP-/);
  assert.equal((await req(cust, 'GET', `/admin/support/${t.id}/print`)).status, 403);
});

test('attachments: a real PNG is kept and gated, a fake one is deleted', { skip }, async () => {
  const g = jar('att');
  const page = await req(g, 'GET', '/support', { expect: 200 });
  const q = /what is <strong>(\d+) \+ (\d+)<\/strong>/.exec(page.text);
  const cat = /<option value="(\d+)"/.exec(page.text)[1];
  const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082', 'hex');
  const fd = new FormData();
  for (const [k, v] of Object.entries({ name: 'Att Tester', email: 'att@example.invalid', category_id: cat, subject: 'Attachment test ticket', description: 'Please see the attached screenshot of the error.', captcha: String(Number(q[1]) + Number(q[2])), form_ts: String(Date.now() - 20000), website: '' })) fd.set(k, v);
  fd.append('attachments', new Blob([png], { type: 'image/png' }), 'shot.png');
  fd.append('attachments', new Blob([Buffer.from('MZ-not-a-png')], { type: 'image/png' }), 'fake.png');
  const res = await req(g, 'POST', '/support', { multipart: fd, expect: 200 });
  const link = /href="(\/support\/ticket\/([a-f0-9]{48}))"/.exec(res.text);
  const [atts] = await pool.query("SELECT a.id, a.orig_name FROM support_attachments a JOIN support_tickets t ON t.id=a.ticket_id WHERE t.subject='Attachment test ticket'");
  assert.deepEqual(atts.map((a) => a.orig_name), ['shot.png']); // the file whose first bytes are not a PNG was refused
  const url = '/support/attachment/' + atts[0].id;
  assert.equal((await req(jar('stranger'), 'GET', url)).status, 403); // no token, not the owner, not staff
  assert.equal((await req(g, 'GET', url + '?t=' + link[2])).status, 200); // the ticket's token opens it
});

test('an admin can mark a sender as spam and block them; blocked senders are dropped silently', { skip }, async () => {
  const sp = jar('spammer');
  await fileTicket(sp, { subject: 'Great offer for you', email: 'seo@spamco.invalid' });
  const [[t]] = await pool.query("SELECT id FROM support_tickets WHERE subject='Great offer for you'");
  const admin = jar('admin2');
  await req(admin, 'GET', '/auth/login', { expect: 200 });
  await req(admin, 'POST', '/auth/login', { form: { email: 'admin@example.invalid', password: 'correct-horse-1', next: '/admin/support' } });
  await req(admin, 'GET', '/admin/support', { expect: 200 });
  await req(admin, 'POST', `/admin/support/${t.id}/spam-block`, { form: {}, expect: 302 });
  assert.equal((await pool.query("SELECT COUNT(*) n FROM support_blocklist WHERE value='seo@spamco.invalid'"))[0][0].n, 1);
  const n = (await pool.query('SELECT COUNT(*) n FROM support_tickets'))[0][0].n;
  const again = await fileTicket(sp, { subject: 'Another offer', email: 'seo@spamco.invalid' });
  assert.equal(again.status, 200);
  assert.equal((await pool.query('SELECT COUNT(*) n FROM support_tickets'))[0][0].n, n);
  await pool.query("DELETE FROM support_blocklist WHERE kind='ip'"); // the test client shares one address with every other test
});

test('idle tickets close themselves with a message to the customer', { skip }, async () => {
  const support = require('../lib/support');
  const g = jar('idle');
  await fileTicket(g, { subject: 'Idle ticket for auto-close', email: 'idle@example.invalid' });
  await pool.query("UPDATE support_tickets SET created_at = DATE_SUB(NOW(), INTERVAL 3 DAY) WHERE subject='Idle ticket for auto-close'");
  await pool.query("UPDATE support_messages SET created_at = DATE_SUB(NOW(), INTERVAL 3 DAY) WHERE ticket_id=(SELECT id FROM support_tickets WHERE subject='Idle ticket for auto-close')");
  assert.ok((await support.autoClose(pool)) >= 1);
  const [[t]] = await pool.query("SELECT id, status FROM support_tickets WHERE subject='Idle ticket for auto-close'");
  assert.equal(t.status, 'closed');
  const [msgs] = await pool.query("SELECT body FROM support_messages WHERE ticket_id=? AND sender='staff'", [t.id]);
  assert.match(msgs[0].body, /closed automatically/);
});

test('health check, the home redirect and unknown pages', { skip }, async () => {
  const g = jar('misc');
  assert.equal((await req(g, 'GET', '/healthz')).status, 200);
  const home = await req(g, 'GET', '/');
  assert.equal(home.status, 302);
  assert.equal(home.location, '/support');
  assert.equal((await req(g, 'GET', '/no/such/page')).status, 404);
  assert.equal((await req(g, 'GET', '/admin/support/abc')).status, 404);
});
