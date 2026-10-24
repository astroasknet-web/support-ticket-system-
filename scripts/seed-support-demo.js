/**
 * Seeds THREE clearly-marked sample tickets so the admin dashboard has data to
 * look at on first open. Skips itself entirely if any real ticket exists.
 * Safe to re-run. Delete the demo tickets from /admin/support when done.
 * Run: node scripts/seed-support-demo.js
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
const support = require('../lib/support');

const DEMOS = [
  { cat: 'billing-payments', name: 'Demo Student One', email: 'demo1@example.invalid',
    subject: '[DEMO] Paid for my order but have not received a confirmation',
    body: 'I paid an hour ago but have not received a confirmation email yet. The payment reference is 123456789012. Please help.',
    order_ref: '1001', payment_ref: '123456789012', status: 'open' },
  { cat: 'order-delivery', name: 'Demo Parent Two', email: 'demo2@example.invalid',
    subject: '[DEMO] Need a receipt for my purchase',
    body: 'I bought the annual plan last week and need a receipt in a reimbursement format. Order 1002.',
    order_ref: '1002', payment_ref: null, status: 'waiting_customer' },
  { cat: 'suggestion', name: 'Demo Teacher Three', email: 'demo3@example.invalid',
    subject: '[DEMO] Please add a dark mode',
    body: 'The app is great. Any plan for a dark theme? I use it a lot in the evening.',
    order_ref: null, payment_ref: null, status: 'resolved' },
];

(async () => {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'support_tickets',
  });
  await support.ensureSchema(pool);

  const [[{ n }]] = await pool.query('SELECT COUNT(*) n FROM support_tickets');
  if (n > 0) { console.log(`Skipping demo seed — ${n} ticket(s) already exist.`); await pool.end(); return; }

  for (const d of DEMOS) {
    const [[cat]] = await pool.query('SELECT id, default_priority FROM support_categories WHERE slug=?', [d.cat]);
    const token = support.newAccessToken();
    const [ins] = await pool.query(
      `INSERT INTO support_tickets (name, email, phone, order_ref, payment_ref, category_id, subject,
         status, priority, access_token, browser_info, ip, resolved_at)
       VALUES (?,?,?,?,?,?,?,?,?,?, 'Demo seed (not a real browser)', '127.0.0.1',
               CASE WHEN ?='resolved' THEN NOW() ELSE NULL END)`,
      [d.name, d.email, null, d.order_ref, d.payment_ref, cat ? cat.id : null, d.subject,
       d.status, cat ? cat.default_priority : 'medium', token, d.status]);
    const no = await support.assignTicketNo(pool, ins.insertId);
    await pool.query(
      `INSERT INTO support_messages (ticket_id, sender, body, read_by_customer) VALUES (?, 'customer', ?, 1)`,
      [ins.insertId, d.body]);
    if (d.status !== 'open') {
      await pool.query(
        `INSERT INTO support_messages (ticket_id, sender, body, read_by_customer, read_by_admin) VALUES (?, 'staff', ?, 0, 1)`,
        [ins.insertId, 'Hello ' + d.name.split(' ')[0] + ', thanks for reaching out — this is a demo staff reply so you can see the conversation view.']);
    }
    await support.logEvent(pool, ins.insertId, 'system', 'created', 'demo ticket seeded');
    console.log('Seeded', no, '-', d.subject);
  }
  console.log('Done — 3 demo tickets. Delete them from /admin/support when finished exploring.');
  await pool.end();
})().catch(e => { console.error('seed-support-demo failed:', e.message); process.exit(1); });
