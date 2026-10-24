'use strict';
// routes/support.js — customer support ticket system routes.
// Mounted from server.js:  app.use(require('./routes/support')({ pool, requireLogin, requireAdmin, verifyCsrf }));
//
// Customer:
//   GET  /support                       ticket form + knowledge base (guest math-captcha)
//   POST /support                       create ticket (multipart, rate-limited, spam-scored)
//   GET  /support/ticket/:token         ticket conversation (token link works for guests)
//   POST /support/ticket/:token/reply   customer reply (+attachments)
//   POST /support/ticket/:token/rating  1–5 satisfaction rating on resolved/closed
//   GET  /dashboard/support             logged-in ticket list (+search)
//   GET  /support/unread                JSON unread-reply count (nav badge)
//   GET  /support/attachment/:id        gated attachment download (token / owner / admin)
// Admin:
//   GET  /admin/support                 dashboard cards + filterable list + settings
//   GET  /admin/support/export.csv      filtered CSV export
//   GET  /admin/support/:id             full ticket detail + timeline
//   GET  /admin/support/:id/print       print-friendly view (browser Save-as-PDF)
//   POST /admin/support/:id/reply       staff reply / internal note (+status change)
//   POST /admin/support/:id/status | /priority | /assign | /merge | /spam | /delete
//   POST /admin/support/settings/category | /template

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const support = require('../lib/support');
const antispam = require('../lib/antispam');
const { BRAND, BASE_URL, REPLY_WITHIN } = require('../config');

const UPLOAD_DIR = path.join(__dirname, '..', 'data', 'support-uploads');
const MAX_FILE   = 10 * 1024 * 1024; // 10 MB per file
const ALLOWED = {
  'image/jpeg':      { ext: ['.jpg', '.jpeg'], magic: [Buffer.from([0xFF, 0xD8])] },
  'image/png':       { ext: ['.png'],          magic: [Buffer.from([0x89, 0x50, 0x4E, 0x47])] },
  'application/pdf': { ext: ['.pdf'],          magic: [Buffer.from('%PDF')] },
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    cb(null, UPLOAD_DIR);
  },
  // Never trust the original filename — random name + validated extension only.
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    cb(null, Date.now() + '-' + crypto.randomBytes(8).toString('hex') + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE, files: 3 },
  fileFilter: (req, file, cb) => {
    const rule = ALLOWED[file.mimetype];
    const ext  = path.extname(file.originalname || '').toLowerCase();
    cb(null, !!(rule && rule.ext.includes(ext)));
  }
});
// Wrap a multer middleware so an oversize/extra file gets a clear 400, not a 500.
function safeUpload(mw) {
  return (req, res, next) => mw(req, res, (err) => {
    if (!err) return next();
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'One of your files is larger than the 10 MB limit.'
      : err.code === 'LIMIT_FILE_COUNT' ? 'Please attach at most 3 files.'
      : 'File upload was rejected — use JPG, PNG or PDF files up to 10 MB.';
    res.status(400).render('error', { title: 'Upload problem', metaDesc: '', canonical: null, message: msg });
  });
}

// Belt-and-braces: verify magic bytes on disk; delete anything that lied about its type.
function verifyMagicBytes(files) {
  const kept = [];
  for (const f of files || []) {
    try {
      const fd = fs.openSync(f.path, 'r');
      const head = Buffer.alloc(8);
      fs.readSync(fd, head, 0, 8, 0);
      fs.closeSync(fd);
      const rule = ALLOWED[f.mimetype];
      if (rule && rule.magic.some(m => head.slice(0, m.length).equals(m))) { kept.push(f); continue; }
    } catch (e) { /* fall through to delete */ }
    try { fs.unlinkSync(f.path); } catch (e) {}
  }
  return kept;
}

// Simple in-memory rate limiter (per IP): protects the public form without
// touching the site-wide limiter config.
// Per IP per hour. Override with SUPPORT_CREATE_LIMIT / SUPPORT_REPLY_LIMIT (the tests raise them).
const LIMIT_CREATE = parseInt(process.env.SUPPORT_CREATE_LIMIT, 10) || 5;
const LIMIT_REPLY = parseInt(process.env.SUPPORT_REPLY_LIMIT, 10) || 20;
const hits = new Map();
function rateLimit(kind, max) {
  return (req, res, next) => {
    const key = kind + ':' + (req.ip || 'x');
    const now = Date.now();
    const arr = (hits.get(key) || []).filter(t => now - t < 3600 * 1000);
    if (arr.length >= max) {
      return res.status(429).render('error', { title: 'Too many requests', metaDesc: '', canonical: null,
        message: 'You have made too many support requests in the last hour. Please wait a while and try again.' });
    }
    arr.push(now); hits.set(key, arr);
    next();
  };
}

// One captcha per ticket submission covers the form AND its file attachments
// (they are the same POST). Required for guests and logged-in users alike —
// registration is open, so a session alone is not proof of a human.
const CAPTCHA_TTL_MS = 15 * 60 * 1000;
function newSupportCaptcha(req) {
  const a = 2 + crypto.randomInt(8), b = 1 + crypto.randomInt(9);
  req.session.supportCaptcha = a + b;
  req.session.supportCaptchaAt = Date.now();
  return a + ' + ' + b;
}
function supportCaptchaOk(req, given) {
  const expected = req.session.supportCaptcha;
  const at = req.session.supportCaptchaAt || 0;
  delete req.session.supportCaptcha; delete req.session.supportCaptchaAt; // single-use
  return !!expected && Date.now() - at < CAPTCHA_TTL_MS && parseInt(given, 10) === expected;
}

// multer writes uploads to disk before CSRF can be checked (the token is in the
// multipart body). If the request is then rejected, delete what it left behind
// so an unauthenticated POST cannot fill the disk.
function csrfOrCleanup(verify) {
  return (req, res, next) => {
    res.once('finish', () => {
      if (res.statusCode >= 400) for (const f of req.files || []) { try { fs.unlinkSync(f.path); } catch (e) {} }
    });
    verify(req, res, next);
  };
}

module.exports = function supportRoutes({ pool, requireLogin, requireAdmin, verifyCsrf }) {
  const router = express.Router();

  // Schema is idempotent — ensure it exists on boot so a plain git-deploy is enough.
  support.ensureSchema(pool)
    .then(() => console.log('[support] schema ready'))
    .catch(e => console.error('[support] schema init failed:', e.message));

  // Auto-close idle tickets on a timer so they close even if no admin visits the
  // dashboard. Also runs opportunistically inside GET /admin/support.
  const autoCloseTick = () => support.autoClose(pool)
    .then(n => { if (n) console.log(`[support] auto-closed ${n} idle ticket(s)`); })
    .catch(e => console.error('[support] autoClose tick failed:', e.message));
  const bootTick = setTimeout(autoCloseTick, 30 * 1000); // once shortly after boot
  if (bootTick.unref) bootTick.unref();
  const autoCloseTimer = setInterval(autoCloseTick, 60 * 60 * 1000); // hourly
  if (autoCloseTimer.unref) autoCloseTimer.unref();

  // Shared view vocabulary — scoped so the rest of the site is untouched.
  router.use(['/support', '/dashboard/support', '/admin/support'], (req, res, next) => {
    res.locals.extraCss = '/css/support.css';
    res.locals.noindex = req.originalUrl.split('?')[0] !== '/support'; // only the public ticket form is for search engines
    res.locals.SUP = {
      STATUS_LABELS: support.STATUS_LABELS, PRIORITY_LABELS: support.PRIORITY_LABELS,
      STATUSES: support.STATUSES, PRIORITIES: support.PRIORITIES,
      fmt: d => d ? new Date(d).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—',
    };
    next();
  });

  async function activeCategories() {
    const [cats] = await pool.query(
      `SELECT id, name, slug, default_priority FROM support_categories WHERE is_active=1 ORDER BY sort_order, name`);
    return cats;
  }

  async function loadTicketByToken(token) {
    if (!/^[a-f0-9]{48}$/.test(String(token || ''))) return null;
    const [[t]] = await pool.query(
      `SELECT t.*, c.name AS category_name, c.slug AS category_slug FROM support_tickets t
       LEFT JOIN support_categories c ON c.id=t.category_id WHERE t.access_token=? LIMIT 1`, [token]);
    return t || null;
  }

  async function loadConversation(ticketId, includeInternal) {
    const [msgs] = await pool.query(
      `SELECT m.*, u.name AS staff_name FROM support_messages m
       LEFT JOIN users u ON u.id=m.user_id
       WHERE m.ticket_id=? ${includeInternal ? '' : 'AND m.is_internal=0'} ORDER BY m.created_at, m.id`, [ticketId]);
    const [atts] = await pool.query(
      `SELECT id, message_id, orig_name, mime, size FROM support_attachments WHERE ticket_id=?`, [ticketId]);
    const byMsg = {};
    for (const a of atts) (byMsg[a.message_id || 0] = byMsg[a.message_id || 0] || []).push(a);
    return { msgs, attachmentsByMsg: byMsg };
  }

  // ═══════════════════════════ CUSTOMER SIDE ═══════════════════════════════

  router.get('/support', async (req, res) => {
    try {
      const cats = await activeCategories();
      res.render('support/new', {
        title: 'Customer Support — Submit a Ticket',
        metaDesc: `Get help from ${BRAND}. Submit a support ticket and we reply within ${REPLY_WITHIN}.`,
        canonical: BASE_URL + '/support',
        cats, kb: support.KNOWLEDGE_BASE,
        captchaQ: newSupportCaptcha(req),
        form: {}, errors: [],
      });
    } catch (e) { console.error(e); res.status(500).render('error', { title: 'Error', metaDesc: '', canonical: null, message: 'Could not load the support page. Please try again.' }); }
  });

  router.post('/support', rateLimit('create', LIMIT_CREATE), safeUpload(upload.array('attachments', 3)), csrfOrCleanup(verifyCsrf), async (req, res) => {
    const b = req.body || {};
    const files = verifyMagicBytes(req.files);
    const cleanupFiles = () => { for (const f of files) { try { fs.unlinkSync(f.path); } catch (e) {} } };
    try {
      const cats = await activeCategories();
      const errors = [];
      const name = String(b.name || '').trim().slice(0, 120);
      const email = String(b.email || '').trim().toLowerCase().slice(0, 190);
      const phone = String(b.phone || '').trim().slice(0, 30);
      const subject = String(b.subject || '').trim().slice(0, 200);
      const description = String(b.description || '').trim().slice(0, 8000);
      const orderRef = String(b.order_ref || '').trim().slice(0, 60);
      const paymentRef = String(b.payment_ref || '').trim().slice(0, 80);
      const productTitle = String(b.product_title || '').trim().slice(0, 255);
      const cat = cats.find(c => c.id === parseInt(b.category_id));

      if (name.length < 2) errors.push('Please enter your full name.');
      if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,24}$/i.test(email)) errors.push('Please enter a valid email address.');
      if (/https?:\/\/|www\./i.test(name) || /\d{5,}/.test(name)) errors.push('Please enter your real name (no links or long numbers).');
      if (phone && !/^[+\d][\d\s-]{6,20}$/.test(phone)) errors.push('That mobile number does not look right.');
      if (!cat) errors.push('Please choose an issue category.');
      if (subject.length < 5) errors.push('Please give a short subject (at least 5 characters).');
      if (description.length < 15) errors.push('Please describe the issue in at least 15 characters.');

      // Captcha for everyone (covers the attachments too — same POST).
      if (!supportCaptchaOk(req, b.captcha)) {
        errors.push('The security answer was wrong or expired — please solve the small sum shown.');
      }

      if (errors.length) {
        cleanupFiles();
        return res.status(400).render('support/new', {
          title: 'Customer Support — Submit a Ticket', metaDesc: '', canonical: null,
          cats, kb: support.KNOWLEDGE_BASE,
          captchaQ: newSupportCaptcha(req),
          form: b, errors,
        });
      }

      // Duplicate: same email + subject in 24 h → don't open a second ticket.
      const dup = await support.findDuplicate(pool, email, subject);
      if (dup) {
        cleanupFiles();
        const [[full]] = await pool.query(`SELECT * FROM support_tickets WHERE id=?`, [dup.id]);
        if (full) await support.emailTicketCreated(pool, full); // re-send the link
        return res.render('support/created', {
          title: 'Ticket already open', metaDesc: '', canonical: null,
          ticket: full, duplicate: true,
        });
      }

      // Known spammer: pretend success, store nothing, email nobody.
      if (await support.isBlocked(pool, email, req.ip)) {
        cleanupFiles();
        console.warn('[antispam] blocked sender dropped:', email, req.ip);
        return res.render('support/created', {
          title: 'Ticket created', metaDesc: '', canonical: null,
          ticket: { ticket_no: 'SUP-' + new Date().getFullYear() + '-' + String(Math.floor(1000 + Math.random() * 9000)).padStart(6, '0'), subject, access_token: null, email }, duplicate: false,
        });
      }

      const score = support.spamScore({ honeypot: b.website, description, subject, name, email, tooFast: antispam.tooFast(b, 4) });
      // Obvious bots: pretend success, store nothing, email nobody — they cannot learn what tripped them.
      if (score >= 10) {
        cleanupFiles();
        delete req.session.supportCaptcha;
        console.warn("[antispam] dropped /support submission from", req.ip, "score=" + score);
        return res.render("support/created", {
          title: "Ticket created", metaDesc: "", canonical: null,
          ticket: { ticket_no: "SUP-" + new Date().getFullYear() + "-" + String(Math.floor(1000 + Math.random() * 9000)).padStart(6, "0"), subject, access_token: null, email }, duplicate: false,
        });
      }
      const token = support.newAccessToken();
      const priority = cat.default_priority || 'medium';
      const ua = String(b.browser_info || req.headers['user-agent'] || '').slice(0, 400);
      const device = String(b.device_info || '').slice(0, 255);

      const [ins] = await pool.query(
        `INSERT INTO support_tickets
           (user_id, name, email, phone, order_ref, payment_ref, product_title, category_id,
            subject, status, priority, access_token, browser_info, device_info, ip, spam_score, is_spam)
         VALUES (?,?,?,?,?,?,?,?,?, 'open', ?, ?, ?, ?, ?, ?, ?)`,
        [req.session.user ? req.session.user.id : null, name, email, phone || null,
         orderRef || null, paymentRef || null, productTitle || null, cat.id,
         subject, priority, token, ua, device || null, req.ip || null, score, score >= 8 ? 1 : 0]);
      const id = ins.insertId;
      const ticketNo = await support.assignTicketNo(pool, id);

      const [msgIns] = await pool.query(
        `INSERT INTO support_messages (ticket_id, sender, user_id, body, read_by_customer) VALUES (?,?,?,?,1)`,
        [id, 'customer', req.session.user ? req.session.user.id : null, description]);
      for (const f of files) {
        await pool.query(
          `INSERT INTO support_attachments (ticket_id, message_id, orig_name, stored_name, mime, size, uploaded_by)
           VALUES (?,?,?,?,?,?, 'customer')`,
          [id, msgIns.insertId, String(f.originalname || 'file').slice(0, 255), f.filename, f.mimetype, f.size]);
      }
      await support.logEvent(pool, id, name, 'created', `category=${cat.slug}, priority=${priority}${score ? ', spam_score=' + score : ''}`);
      delete req.session.supportCaptcha;

      const [[t]] = await pool.query(`SELECT * FROM support_tickets WHERE id=?`, [id]);
      if (!t.is_spam) await support.emailTicketCreated(pool, t);

      res.render('support/created', {
        title: `Ticket ${ticketNo} created`, metaDesc: '', canonical: null,
        ticket: t, duplicate: false,
      });
    } catch (e) {
      cleanupFiles();
      console.error('[support] create failed:', e);
      res.status(500).render('error', { title: 'Error', metaDesc: '', canonical: null,
        message: 'We could not submit your ticket. Please try again, or email us directly.' });
    }
  });

  router.get('/support/ticket/:token', async (req, res) => {
    try {
      const t = await loadTicketByToken(req.params.token);
      if (!t) return res.status(404).render('error', { title: 'Ticket not found', metaDesc: '', canonical: null, message: 'This ticket link is not valid.' });
      await pool.query(`UPDATE support_messages SET read_by_customer=1 WHERE ticket_id=? AND sender='staff' AND is_internal=0`, [t.id]);
      const { msgs, attachmentsByMsg } = await loadConversation(t.id, false);
      res.render('support/ticket', {
        title: `${t.ticket_no} — ${t.subject}`, metaDesc: '', canonical: null,
        t, msgs, attachmentsByMsg,
      });
    } catch (e) { console.error(e); res.status(500).render('error', { title: 'Error', metaDesc: '', canonical: null, message: 'Could not load the ticket.' }); }
  });

  router.post('/support/ticket/:token/reply', rateLimit('reply', LIMIT_REPLY), safeUpload(upload.array('attachments', 3)), csrfOrCleanup(verifyCsrf), async (req, res) => {
    const files = verifyMagicBytes(req.files);
    try {
      const t = await loadTicketByToken(req.params.token);
      if (!t) { for (const f of files) { try { fs.unlinkSync(f.path); } catch (e) {} } return res.status(404).send('Not found'); }

      // A closed ticket cannot be reopened by the customer — only an admin can.
      // (Tickets auto-close after inactivity; see lib/support.autoClose.)
      if (t.status === 'closed') {
        for (const f of files) { try { fs.unlinkSync(f.path); } catch (e) {} }
        return res.status(403).render('error', {
          title: 'Ticket closed', metaDesc: '', canonical: null,
          message: 'This ticket has been closed and can no longer be replied to. If you still need help, please open a new support ticket.',
        });
      }

      const body = String((req.body && req.body.message) || '').trim().slice(0, 8000);
      if (body.length < 2 && files.length === 0) return res.redirect('/support/ticket/' + t.access_token);

      const [msgIns] = await pool.query(
        `INSERT INTO support_messages (ticket_id, sender, user_id, body, read_by_customer) VALUES (?, 'customer', ?, ?, 1)`,
        [t.id, req.session.user ? req.session.user.id : null, body || '(attachment)']);
      for (const f of files) {
        await pool.query(
          `INSERT INTO support_attachments (ticket_id, message_id, orig_name, stored_name, mime, size, uploaded_by)
           VALUES (?,?,?,?,?,?, 'customer')`,
          [t.id, msgIns.insertId, String(f.originalname || 'file').slice(0, 255), f.filename, f.mimetype, f.size]);
      }
      // A customer reply reopens a ticket that was waiting on them or marked
      // resolved. It can NOT reopen a 'closed' ticket — that path is blocked above.
      if (['resolved', 'waiting_customer'].includes(t.status)) {
        await pool.query(`UPDATE support_tickets SET status='open', resolved_at=NULL, closed_at=NULL WHERE id=?`, [t.id]);
        await support.logEvent(pool, t.id, t.name, 'status', `reopened by customer reply (was ${t.status})`);
      }
      await support.logEvent(pool, t.id, t.name, 'reply', 'customer replied' + (files.length ? ` (+${files.length} file)` : ''));
      await support.emailCustomerReplied(pool, t);
      res.redirect('/support/ticket/' + t.access_token + '#latest');
    } catch (e) { console.error(e); res.status(500).send('Reply failed — please go back and try again.'); }
  });

  router.post('/support/ticket/:token/rating', verifyCsrf, async (req, res) => {
    try {
      const t = await loadTicketByToken(req.params.token);
      if (!t || !['resolved', 'closed'].includes(t.status)) return res.redirect('/support');
      const rating = parseInt(req.body.rating, 10);
      if (rating >= 1 && rating <= 5) {
        await pool.query(`UPDATE support_tickets SET rating=?, rating_comment=? WHERE id=?`,
          [rating, String(req.body.rating_comment || '').trim().slice(0, 500) || null, t.id]);
        await support.logEvent(pool, t.id, t.name, 'rating', `${rating}/5`);
      }
      res.redirect('/support/ticket/' + t.access_token);
    } catch (e) { console.error(e); res.redirect('/support'); }
  });

  router.get('/dashboard/support', requireLogin, async (req, res) => {
    try {
      const me = req.session.user;
      const q = String(req.query.q || '').trim().slice(0, 100);
      const params = [me.id, me.email];
      let where = `(t.user_id=? OR t.email=?)`;
      if (q) { where += ` AND (t.ticket_no LIKE ? OR t.subject LIKE ? OR t.order_ref LIKE ?)`; params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
      const [tickets] = await pool.query(
        `SELECT t.*, c.name AS category_name,
                (SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id=t.id AND m.sender='staff' AND m.is_internal=0 AND m.read_by_customer=0) AS unread
         FROM support_tickets t LEFT JOIN support_categories c ON c.id=t.category_id
         WHERE ${where} ORDER BY t.updated_at DESC LIMIT 100`, params);
      res.render('support/my-tickets', {
        title: 'My Support Tickets', metaDesc: '', canonical: null, tickets, q,
      });
    } catch (e) { console.error(e); res.status(500).render('error', { title: 'Error', metaDesc: '', canonical: null, message: 'Could not load your tickets.' }); }
  });

  router.get('/support/unread', requireLogin, async (req, res) => {
    try {
      const me = req.session.user;
      const [[{ n }]] = await pool.query(
        `SELECT COUNT(*) n FROM support_messages m JOIN support_tickets t ON t.id=m.ticket_id
         WHERE (t.user_id=? OR t.email=?) AND m.sender='staff' AND m.is_internal=0 AND m.read_by_customer=0`,
        [me.id, me.email]);
      res.json({ unread: n });
    } catch (e) { res.json({ unread: 0 }); }
  });

  // Attachment download — token holder, ticket owner, or admin only.
  router.get('/support/attachment/:id', async (req, res) => {
    try {
      const [[a]] = await pool.query(
        `SELECT a.*, t.access_token, t.email, t.user_id FROM support_attachments a
         JOIN support_tickets t ON t.id=a.ticket_id WHERE a.id=? LIMIT 1`, [parseInt(req.params.id) || 0]);
      if (!a) return res.status(404).send('Not found');
      const u = req.session.user;
      const isAdmin = u && ['admin', 'super_admin'].includes(u.role);
      const isOwner = u && (u.id === a.user_id || u.email === a.email);
      const hasToken = req.query.t && String(req.query.t) === a.access_token;
      if (!isAdmin && !isOwner && !hasToken) return res.status(403).send('Access denied');
      const file = path.join(UPLOAD_DIR, path.basename(a.stored_name));
      if (!fs.existsSync(file)) return res.status(404).send('File missing');
      await support.logEvent(pool, a.ticket_id, isAdmin ? ('staff:' + u.name) : 'customer', 'download', a.orig_name);
      res.setHeader('Content-Type', a.mime);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      const inline = a.mime.startsWith('image/') || req.query.preview === '1';
      res.setHeader('Content-Disposition', (inline ? 'inline' : 'attachment') + `; filename="${a.orig_name.replace(/[^\w.\- ]/g, '_')}"`);
      fs.createReadStream(file).pipe(res);
    } catch (e) { console.error(e); res.status(500).send('Download failed'); }
  });

  // ═══════════════════════════ ADMIN SIDE ═══════════════════════════════════

  router.get('/admin/support', requireAdmin, async (req, res) => {
    try {
      await support.autoClose(pool); // opportunistic; cheap on an indexed table

      const [[stats]] = await pool.query(
        `SELECT COUNT(*) total,
                SUM(status='open') open_n, SUM(status='pending') pending_n,
                SUM(status='waiting_customer') waiting_n,
                SUM(status='resolved') resolved_n, SUM(status='closed') closed_n,
                SUM(DATE(created_at)=CURDATE()) today_n,
                SUM(priority='critical' AND status NOT IN ('resolved','closed')) critical_n,
                ROUND(AVG(CASE WHEN resolved_at IS NOT NULL THEN TIMESTAMPDIFF(MINUTE, created_at, resolved_at) END)/60, 1) avg_res_hours,
                ROUND(AVG(rating), 2) avg_rating
         FROM support_tickets WHERE is_spam=0`);

      const f = {
        status: support.STATUSES.includes(req.query.status) ? req.query.status : '',
        priority: support.PRIORITIES.includes(req.query.priority) ? req.query.priority : '',
        cat: parseInt(req.query.cat) || 0,
        q: String(req.query.q || '').trim().slice(0, 100),
        spam: req.query.spam === '1',
      };
      const params = [];
      let where = f.spam ? 't.is_spam=1' : 't.is_spam=0';
      if (f.status) { where += ' AND t.status=?'; params.push(f.status); }
      if (f.priority) { where += ' AND t.priority=?'; params.push(f.priority); }
      if (f.cat) { where += ' AND t.category_id=?'; params.push(f.cat); }
      if (f.q) {
        where += ' AND (t.ticket_no LIKE ? OR t.name LIKE ? OR t.email LIKE ? OR t.subject LIKE ? OR t.order_ref LIKE ? OR t.payment_ref LIKE ?)';
        for (let i = 0; i < 6; i++) params.push(`%${f.q}%`);
      }
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const PER = 50;
      const [[{ n: totalRows }]] = await pool.query(`SELECT COUNT(*) n FROM support_tickets t WHERE ${where}`, params);
      const [tickets] = await pool.query(
        `SELECT t.*, c.name AS category_name, s.name AS staff_name,
                (SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id=t.id AND m.sender='customer' AND m.read_by_admin=0) AS unread
         FROM support_tickets t
         LEFT JOIN support_categories c ON c.id=t.category_id
         LEFT JOIN users s ON s.id=t.assigned_to
         WHERE ${where}
         ORDER BY FIELD(t.priority,'critical','high','medium','low'), t.updated_at DESC
         LIMIT ? OFFSET ?`, [...params, PER, (page - 1) * PER]);

      const [cats] = await pool.query(`SELECT * FROM support_categories ORDER BY sort_order, name`);
      const [templates] = await pool.query(`SELECT * FROM support_templates ORDER BY is_active DESC, id`);
      const [blocklist] = await pool.query('SELECT * FROM support_blocklist ORDER BY id DESC LIMIT 100');
      const [[{ n: spamCount }]] = await pool.query(`SELECT COUNT(*) n FROM support_tickets WHERE is_spam=1`);

      res.render('admin/support-list', {
        title: 'Support Tickets — Admin', metaDesc: '', canonical: null,
        stats, tickets, cats, templates, f, page, pages: Math.ceil(totalRows / PER), totalRows, spamCount, blocklist,
      });
    } catch (e) { console.error(e); res.status(500).render('error', { title: 'Error', metaDesc: '', canonical: null, message: 'Could not load the support dashboard.' }); }
  });

  router.get('/admin/support/export.csv', requireAdmin, async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT t.ticket_no, t.created_at, t.name, t.email, t.phone, c.name AS category, t.subject,
                t.status, t.priority, t.order_ref, t.payment_ref, t.rating, t.resolved_at, t.closed_at
         FROM support_tickets t LEFT JOIN support_categories c ON c.id=t.category_id
         WHERE t.is_spam=0 ORDER BY t.id DESC LIMIT 5000`);
      const cols = ['ticket_no', 'created_at', 'name', 'email', 'phone', 'category', 'subject', 'status', 'priority', 'order_ref', 'payment_ref', 'rating', 'resolved_at', 'closed_at'];
      const csvCell = v => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
      const csv = [cols.join(',')].concat(rows.map(r => cols.map(c => csvCell(r[c] instanceof Date ? r[c].toISOString() : r[c])).join(','))).join('\r\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="support-tickets.csv"');
      res.send('﻿' + csv); // BOM so Excel opens UTF-8 correctly
    } catch (e) { console.error(e); res.status(500).send('Export failed'); }
  });

  async function loadAdminTicket(id) {
    const [[t]] = await pool.query(
      `SELECT t.*, c.name AS category_name, s.name AS staff_name FROM support_tickets t
       LEFT JOIN support_categories c ON c.id=t.category_id
       LEFT JOIN users s ON s.id=t.assigned_to
       WHERE t.id=? LIMIT 1`, [parseInt(id) || 0]);
    return t || null;
  }

  router.get('/admin/support/:id(\\d+)', requireAdmin, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.status(404).render('error', { title: 'Not found', metaDesc: '', canonical: null, message: 'No such ticket.' });
      await pool.query(`UPDATE support_messages SET read_by_admin=1 WHERE ticket_id=?`, [t.id]);
      const { msgs, attachmentsByMsg } = await loadConversation(t.id, true);
      const [events] = await pool.query(`SELECT * FROM support_events WHERE ticket_id=? ORDER BY created_at, id`, [t.id]);
      const [templates] = await pool.query(`SELECT * FROM support_templates WHERE is_active=1 ORDER BY id`);
      const [staff] = await pool.query(`SELECT id, name FROM users WHERE role IN ('admin','super_admin') AND is_active=1 ORDER BY name`);
      const [history] = await pool.query(
        `SELECT id, ticket_no, subject, status, created_at FROM support_tickets WHERE email=? AND id<>? ORDER BY id DESC LIMIT 10`,
        [t.email, t.id]);
      const order = null; // this app has no orders table; the reference the customer typed is shown as text
      res.render('admin/support-ticket', {
        title: `${t.ticket_no} — Admin`, metaDesc: '', canonical: null,
        t, msgs, attachmentsByMsg, events, templates, staff, history, order,
      });
    } catch (e) { console.error(e); res.status(500).render('error', { title: 'Error', metaDesc: '', canonical: null, message: 'Could not load the ticket.' }); }
  });

  router.get('/admin/support/:id(\\d+)/print', requireAdmin, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.status(404).send('Not found');
      const { msgs, attachmentsByMsg } = await loadConversation(t.id, true);
      const [events] = await pool.query(`SELECT * FROM support_events WHERE ticket_id=? ORDER BY created_at, id`, [t.id]);
      res.render('admin/support-print', { layout: false, t, msgs, attachmentsByMsg, events,
        SUP: { STATUS_LABELS: support.STATUS_LABELS, PRIORITY_LABELS: support.PRIORITY_LABELS,
               fmt: d => d ? new Date(d).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—' } });
    } catch (e) { console.error(e); res.status(500).send('Print view failed'); }
  });

  router.post('/admin/support/:id(\\d+)/reply', requireAdmin, safeUpload(upload.array('attachments', 3)), verifyCsrf, async (req, res) => {
    const files = verifyMagicBytes(req.files);
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.status(404).send('Not found');
      const me = req.session.user;
      const body = String((req.body && req.body.message) || '').trim().slice(0, 8000);
      const internal = req.body.is_internal === '1';
      if (body.length < 1 && files.length === 0) return res.redirect('/admin/support/' + t.id);

      const [msgIns] = await pool.query(
        `INSERT INTO support_messages (ticket_id, sender, user_id, body, is_internal, read_by_admin, read_by_customer)
         VALUES (?, 'staff', ?, ?, ?, 1, ?)`,
        [t.id, me.id, body || '(attachment)', internal ? 1 : 0, internal ? 1 : 0]);
      for (const f of files) {
        await pool.query(
          `INSERT INTO support_attachments (ticket_id, message_id, orig_name, stored_name, mime, size, uploaded_by)
           VALUES (?,?,?,?,?,?, 'staff')`,
          [t.id, msgIns.insertId, String(f.originalname || 'file').slice(0, 255), f.filename, f.mimetype, f.size]);
      }
      await support.logEvent(pool, t.id, 'staff:' + me.name, internal ? 'note' : 'reply', internal ? 'internal note added' : 'staff replied');

      // Optional combined status change ("reply & mark …")
      const ns = req.body.new_status;
      let newStatus = t.status;
      if (ns && support.STATUSES.includes(ns) && ns !== t.status) {
        newStatus = ns;
      } else if (!internal && ['open'].includes(t.status)) {
        newStatus = 'waiting_customer'; // replied, ball in customer's court
      }
      if (newStatus !== t.status) {
        await pool.query(
          `UPDATE support_tickets SET status=?,
             resolved_at = CASE WHEN ?='resolved' THEN NOW() ELSE resolved_at END,
             closed_at   = CASE WHEN ?='closed'   THEN NOW() ELSE closed_at END
           WHERE id=?`, [newStatus, newStatus, newStatus, t.id]);
        await support.logEvent(pool, t.id, 'staff:' + me.name, 'status', `${t.status} → ${newStatus}`);
      }
      if (!internal) {
        const [[fresh]] = await pool.query(`SELECT * FROM support_tickets WHERE id=?`, [t.id]);
        await support.emailStaffReplied(pool, fresh);
        if (['resolved', 'closed'].includes(fresh.status)) await support.emailStatusChanged(pool, fresh);
      }
      res.redirect('/admin/support/' + t.id + '#latest');
    } catch (e) { console.error(e); res.status(500).send('Reply failed'); }
  });

  router.post('/admin/support/:id(\\d+)/status', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      const ns = req.body.status;
      if (!t || !support.STATUSES.includes(ns)) return res.redirect('/admin/support');
      await pool.query(
        `UPDATE support_tickets SET status=?,
           resolved_at = CASE WHEN ?='resolved' THEN NOW() ELSE resolved_at END,
           closed_at   = CASE WHEN ?='closed'   THEN NOW() ELSE closed_at END
         WHERE id=?`, [ns, ns, ns, t.id]);
      await support.logEvent(pool, t.id, 'staff:' + req.session.user.name, ns === 'open' && ['resolved', 'closed'].includes(t.status) ? 'reopen' : 'status', `${t.status} → ${ns}`);
      const [[fresh]] = await pool.query(`SELECT * FROM support_tickets WHERE id=?`, [t.id]);
      await support.emailStatusChanged(pool, fresh);
      res.redirect(req.body.back === 'list' ? '/admin/support' : '/admin/support/' + t.id);
    } catch (e) { console.error(e); res.status(500).send('Status change failed'); }
  });

  router.post('/admin/support/:id(\\d+)/priority', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      const p = req.body.priority;
      if (!t || !support.PRIORITIES.includes(p)) return res.redirect('/admin/support');
      await pool.query(`UPDATE support_tickets SET priority=? WHERE id=?`, [p, t.id]);
      await support.logEvent(pool, t.id, 'staff:' + req.session.user.name, 'priority', `${t.priority} → ${p}`);
      res.redirect('/admin/support/' + t.id);
    } catch (e) { console.error(e); res.status(500).send('Priority change failed'); }
  });

  router.post('/admin/support/:id(\\d+)/assign', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.redirect('/admin/support');
      const staffId = parseInt(req.body.assigned_to) || null;
      let staffName = 'nobody';
      if (staffId) {
        const [[s]] = await pool.query(`SELECT id, name FROM users WHERE id=? AND role IN ('admin','super_admin') LIMIT 1`, [staffId]);
        if (!s) return res.redirect('/admin/support/' + t.id);
        staffName = s.name;
      }
      await pool.query(`UPDATE support_tickets SET assigned_to=? WHERE id=?`, [staffId, t.id]);
      await support.logEvent(pool, t.id, 'staff:' + req.session.user.name, 'assign', `assigned to ${staffName}`);
      res.redirect('/admin/support/' + t.id);
    } catch (e) { console.error(e); res.status(500).send('Assign failed'); }
  });

  router.post('/admin/support/:id(\\d+)/merge', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.redirect('/admin/support');
      const targetNo = String(req.body.merge_into || '').trim().toUpperCase();
      const [[target]] = await pool.query(`SELECT id, ticket_no FROM support_tickets WHERE ticket_no=? AND id<>? LIMIT 1`, [targetNo, t.id]);
      if (!target) return res.redirect('/admin/support/' + t.id);
      await pool.query(`UPDATE support_tickets SET merged_into=?, status='closed', closed_at=NOW() WHERE id=?`, [target.id, t.id]);
      await support.logEvent(pool, t.id, 'staff:' + req.session.user.name, 'merge', `merged into ${target.ticket_no}`);
      await support.logEvent(pool, target.id, 'staff:' + req.session.user.name, 'merge', `absorbed ${t.ticket_no}`);
      res.redirect('/admin/support/' + target.id);
    } catch (e) { console.error(e); res.status(500).send('Merge failed'); }
  });

  router.post('/admin/support/:id(\\d+)/spam', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.redirect('/admin/support');
      await pool.query(`UPDATE support_tickets SET is_spam=? WHERE id=?`, [t.is_spam ? 0 : 1, t.id]);
      await support.logEvent(pool, t.id, 'staff:' + req.session.user.name, 'spam', t.is_spam ? 'unmarked as spam' : 'marked as spam');
      res.redirect('/admin/support/' + t.id);
    } catch (e) { console.error(e); res.status(500).send('Spam toggle failed'); }
  });

  router.post('/admin/support/:id(\\d+)/spam-block', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.redirect('/admin/support');
      const actor = 'staff:' + req.session.user.name;
      const b = await support.blockSender(pool, t, actor);
      await support.logEvent(pool, t.id, actor, 'spam', 'marked spam + blocked ' + [b.email, b.domain, b.ip].filter(Boolean).join(', '));
      res.redirect('/admin/support/' + t.id);
    } catch (e) { console.error(e); res.status(500).send('Block failed'); }
  });

  router.post('/admin/support/blocklist/:id(\\d+)/remove', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      await pool.query('DELETE FROM support_blocklist WHERE id=?', [req.params.id]);
      res.redirect('/admin/support');
    } catch (e) { console.error(e); res.status(500).send('Unblock failed'); }
  });

  router.post('/admin/support/:id(\\d+)/delete', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      const t = await loadAdminTicket(req.params.id);
      if (!t) return res.redirect('/admin/support');
      const [atts] = await pool.query(`SELECT stored_name FROM support_attachments WHERE ticket_id=?`, [t.id]);
      for (const a of atts) { try { fs.unlinkSync(path.join(UPLOAD_DIR, path.basename(a.stored_name))); } catch (e) {} }
      await pool.query(`DELETE FROM support_tickets WHERE id=?`, [t.id]); // messages/attachments/events cascade
      console.log(`[support] ticket ${t.ticket_no} deleted by ${req.session.user.name}`);
      res.redirect('/admin/support');
    } catch (e) { console.error(e); res.status(500).send('Delete failed'); }
  });

  // Settings: categories + reply templates (admin-configurable)
  router.post('/admin/support/settings/category', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      if (req.body.toggle_id) {
        await pool.query(`UPDATE support_categories SET is_active = 1 - is_active WHERE id=?`, [parseInt(req.body.toggle_id) || 0]);
      } else {
        const name = String(req.body.name || '').trim().slice(0, 80);
        const prio = support.PRIORITIES.includes(req.body.default_priority) ? req.body.default_priority : 'medium';
        if (name.length >= 2) {
          const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
          await pool.query(`INSERT IGNORE INTO support_categories (name, slug, default_priority, sort_order) VALUES (?,?,?,50)`, [name, slug, prio]);
        }
      }
      res.redirect('/admin/support');
    } catch (e) { console.error(e); res.status(500).send('Category update failed'); }
  });

  router.post('/admin/support/settings/template', requireAdmin, verifyCsrf, async (req, res) => {
    try {
      if (req.body.toggle_id) {
        await pool.query(`UPDATE support_templates SET is_active = 1 - is_active WHERE id=?`, [parseInt(req.body.toggle_id) || 0]);
      } else {
        const title = String(req.body.title || '').trim().slice(0, 120);
        const body = String(req.body.body || '').trim().slice(0, 8000);
        if (title.length >= 2 && body.length >= 5) {
          await pool.query(`INSERT INTO support_templates (title, body) VALUES (?,?)`, [title, body]);
        }
      }
      res.redirect('/admin/support');
    } catch (e) { console.error(e); res.status(500).send('Template update failed'); }
  });

  return router;
};
