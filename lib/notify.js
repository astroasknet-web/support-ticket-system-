'use strict';
// lib/notify.js — e-mail sending over SMTP (nodemailer). Every send is wrapped so a misconfigured mail server can never break a request:
// it logs why nothing was sent and returns { skipped } or { error } instead of throwing.
// Configure in .env: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM, ADMIN_EMAIL.
const { BRAND, ADMIN_EMAIL } = require('../config');

let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch (e) { /* optional */ }

let _transport = null;
function transport() {
  if (_transport !== null) return _transport;
  if (!nodemailer || !process.env.SMTP_HOST || !process.env.SMTP_USER) { _transport = false; return false; }
  _transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: String(process.env.SMTP_PORT) === '465',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  return _transport;
}

async function sendEmail(to, subject, html) {
  const t = transport();
  if (!t || !to) {
    // Say WHY nothing was sent: a silent skip is invisible in production.
    const missing = [
      !process.env.SMTP_HOST && 'SMTP_HOST',
      !process.env.SMTP_USER && 'SMTP_USER',
      !process.env.SMTP_PASS && 'SMTP_PASS',
      !to && 'recipient (ADMIN_EMAIL?)',
    ].filter(Boolean).join(', ');
    console.error(`[notify] EMAIL SKIPPED (${subject}): not configured. Missing: ${missing}`);
    return { skipped: 'email-not-configured', missing };
  }
  try {
    const from = process.env.MAIL_FROM || `${BRAND} <${process.env.SMTP_USER}>`;
    await t.sendMail({ from, to, subject, html });
    console.log(`[notify] email sent to ${to}: ${subject}`);
    return { ok: true };
  } catch (e) { console.error('[notify] email error:', e.message); return { error: e.message }; }
}

function smtpStatus() {
  return {
    nodemailer_installed: !!nodemailer,
    smtp_host: process.env.SMTP_HOST || null,
    smtp_port: parseInt(process.env.SMTP_PORT, 10) || 587,
    smtp_user_set: !!process.env.SMTP_USER,
    smtp_pass_set: !!process.env.SMTP_PASS,
    mail_from: process.env.MAIL_FROM || (process.env.SMTP_USER ? `${BRAND} <${process.env.SMTP_USER}>` : null),
    admin_email: ADMIN_EMAIL || null,
    configured: !!(nodemailer && process.env.SMTP_HOST && process.env.SMTP_USER),
  };
}

module.exports = { sendEmail, smtpStatus };
