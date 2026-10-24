'use strict';
// config.js — everything that makes this installation "yours". All values come from the environment (.env).
require('dotenv').config();

const BASE_URL = (process.env.BASE_URL || 'http://localhost:' + (process.env.PORT || 3001)).replace(/\/+$/, '');

module.exports = {
  /** Shown in the page title, the header, every email and the printed ticket. */
  BRAND: process.env.APP_NAME || 'Support Desk',
  /** Public address of this app; used for links inside emails. */
  BASE_URL,
  PORT: parseInt(process.env.PORT, 10) || 3001,
  /** Staff who get "new ticket" and "customer replied" emails. */
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || '',
  /** Idle tickets are closed automatically after this many hours. */
  TICKET_TTL_HOURS: parseInt(process.env.SUPPORT_TICKET_TTL_HOURS, 10) || 24,
  /** Shown on the ticket form and in the confirmation email. */
  REPLY_WITHIN: process.env.SUPPORT_REPLY_WITHIN || '24 hours',
  /** Set to 0 to stop people creating their own accounts at /auth/register. */
  ALLOW_REGISTRATION: process.env.ALLOW_REGISTRATION !== '0',
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'support_tickets',
  },
};
