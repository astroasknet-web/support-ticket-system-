'use strict';
// server.js — the support ticket system as a stand-alone Express app.
//   npm start            (reads .env, see .env.example)
// The ticket system itself lives in routes/support.js and lib/support.js; this file only provides what it needs from a host
// application: a MySQL pool, sessions, CSRF protection, login, and the requireLogin / requireAdmin guards.
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const password = require('./lib/password');
const antispam = require('./lib/antispam');
const support = require('./lib/support');

function createApp(pool, sessionStore) {
  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(expressLayouts);
  app.set('layout', 'layout');
  app.set('trust proxy', 1); // behind Nginx / Cloudflare / the Hostinger proxy: TLS is terminated upstream
  app.locals.BRAND = config.BRAND;
  app.locals.REPLY_WITHIN = config.REPLY_WITHIN;
  app.locals.ALLOW_REGISTRATION = config.ALLOW_REGISTRATION;
  app.locals.assetVer = Date.now().toString(36);

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        scriptSrcAttr: ["'unsafe-inline'"],
      },
    },
    hsts: process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
  }));

  app.use(express.urlencoded({ extended: false, limit: '200kb' }));
  app.use(express.json({ limit: '200kb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET must be set in production (.env). Refusing to start.');
    process.exit(1);
  }
  app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'support-dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 },
  }));

  // ── CSRF: one token per session, exposed to every view ──────────────────────
  app.use((req, res, next) => {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    res.locals.csrfToken = req.session.csrfToken;
    res.locals.user = req.session.user || null;
    next();
  });
  function verifyCsrf(req, res, next) {
    const sent = (req.body && req.body._csrf) || req.headers['x-csrf-token'] || '';
    const expected = req.session && req.session.csrfToken;
    let ok = false;
    if (expected && typeof sent === 'string' && sent.length === expected.length) {
      try { ok = crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected)); } catch (e) { ok = false; }
    }
    if (ok) return next();
    return res.status(403).render('error', { title: '403: Security check failed', message: 'Your security token was missing or expired. Please go back, refresh the page, and try again.' });
  }

  function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/auth/login?next=' + encodeURIComponent(req.originalUrl));
    next();
  }
  function requireAdmin(req, res, next) {
    if (!req.session.user || !['admin', 'super_admin'].includes(req.session.user.role)) {
      return res.status(403).render('error', { title: '403 Forbidden', message: 'Admin access required.' });
    }
    next();
  }
  // Only same-site relative redirects (blocks //evil.com and /\evil.com).
  const safeNext = (next, fallback = '/dashboard/support') =>
    typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : fallback;

  // ── Auth ────────────────────────────────────────────────────────────────────
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: 'Too many login attempts. Please try again in 15 minutes.' });
  const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
    handler: (req, res) => res.status(429).render('error', { title: 'Too many sign-ups', message: 'Too many sign-up attempts from this connection. Please try again later.' }) });

  app.get('/', (req, res) => res.redirect('/support'));
  app.get('/dashboard', (req, res) => res.redirect('/dashboard/support'));
  app.get('/healthz', async (req, res) => { try { await pool.query('SELECT 1'); res.json({ ok: true }); } catch (e) { res.status(503).json({ ok: false }); } });

  app.get('/auth/login', (req, res) => res.render('auth/login', { title: 'Log in', error: null, next: req.query.next || '/dashboard/support' }));
  app.post('/auth/login', loginLimiter, verifyCsrf, async (req, res) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    const pw = String(req.body.password || '');
    const next = req.body.next;
    const again = (error) => res.render('auth/login', { title: 'Log in', error, next: next || '/dashboard/support' });
    if (!email || !pw) return again('Please fill all fields.');
    try {
      const [[user]] = await pool.query('SELECT id, name, email, role, is_active, password_hash FROM users WHERE email=?', [email]);
      const check = user ? await password.verify(pw, user.password_hash) : { ok: false };
      if (!user || !user.is_active || !check.ok) return again('Invalid email or password.');
      if (check.needsRehash) { try { await pool.query('UPDATE users SET password_hash=? WHERE id=?', [await password.hash(pw), user.id]); } catch (e) { /* keep going */ } }
      // New session id on login (prevents session fixation); keep nothing from the anonymous session.
      req.session.regenerate((err) => {
        if (err) return again('Server error. Try again.');
        req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
        res.redirect(safeNext(next, ['admin', 'super_admin'].includes(user.role) ? '/admin/support' : '/dashboard/support'));
      });
    } catch (e) { console.error(e); again('Server error. Try again.'); }
  });

  const registerView = (req, res, error) => res.render('auth/register', { title: 'Sign up', error: error || null, captchaQ: antispam.newCaptcha(req, 'registerCaptcha') });
  app.get('/auth/register', (req, res) => (config.ALLOW_REGISTRATION ? registerView(req, res) : res.status(404).render('error', { title: 'Not available', message: 'Sign-up is turned off. You can still submit a ticket without an account.' })));
  app.post('/auth/register', registerLimiter, verifyCsrf, async (req, res) => {
    if (!config.ALLOW_REGISTRATION) return res.status(404).render('error', { title: 'Not available', message: 'Sign-up is turned off.' });
    const { name, confirm_password } = req.body;
    const email = String(req.body.email || '').toLowerCase().trim();
    const pw = String(req.body.password || '');
    if (antispam.honeypotHit(req.body) || antispam.tooFast(req.body, 3)) return registerView(req, res, 'Something went wrong. Please try again.');
    if (!antispam.captchaOk(req, 'registerCaptcha', req.body.captcha)) return registerView(req, res, 'The security answer was wrong. Please solve the small sum shown.');
    if (!name || !email || !pw) return registerView(req, res, 'Please fill all fields.');
    if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,24}$/i.test(email)) return registerView(req, res, 'Please enter a valid email address.');
    if (pw !== confirm_password) return registerView(req, res, 'Passwords do not match.');
    if (pw.length < 8) return registerView(req, res, 'Password must be at least 8 characters.');
    try {
      const [ins] = await pool.query('INSERT INTO users (name, email, password_hash) VALUES (?,?,?)', [String(name).trim().slice(0, 120), email, await password.hash(pw)]);
      req.session.regenerate((err) => {
        if (err) return res.redirect('/auth/login');
        req.session.user = { id: ins.insertId, name: String(name).trim().slice(0, 120), email, role: 'user' };
        res.redirect('/dashboard/support');
      });
    } catch (e) {
      if (e && e.code === 'ER_DUP_ENTRY') return registerView(req, res, 'An account with that email already exists. Try logging in.');
      console.error(e); registerView(req, res, 'Server error. Try again.');
    }
  });
  app.post('/auth/logout', verifyCsrf, (req, res) => req.session.destroy(() => res.redirect('/support')));

  // ── The ticket system ───────────────────────────────────────────────────────
  app.use(require('./routes/support')({ pool, requireLogin, requireAdmin, verifyCsrf }));

  app.use((req, res) => res.status(404).render('error', { title: 'Page not found', message: 'We could not find that page.' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => { console.error(err); res.status(500).render('error', { title: 'Something went wrong', message: 'An unexpected error occurred. Please try again.' }); });
  return app;
}

function makePool() {
  return mysql.createPool({ ...config.db, waitForConnections: true, connectionLimit: 10 });
}

module.exports = { createApp, makePool };

if (require.main === module) {
  const pool = makePool();
  const store = new MySQLStore({ ...config.db, createDatabaseTable: true, schema: { tableName: 'sessions' } });
  support.ensureSchema(pool)
    .then(() => {
      const app = createApp(pool, store);
      app.listen(config.PORT, () => console.log(`[${config.BRAND}] listening on ${config.BASE_URL} (port ${config.PORT})`));
    })
    .catch((e) => { console.error('Could not start. Is MySQL running and is .env correct?', e.message); process.exit(1); });
}
