# Support Ticket System

A self-hosted helpdesk: customers open tickets (with attachments), follow the conversation from a private link, and staff work them from an admin inbox. Node.js, Express, EJS and MySQL. No front-end build step.

It started as the support module inside the MathStudy.in shop and is now a stand-alone app: its own login, sessions, database and settings. Nothing in it depends on the shop.

## What it does

- **Customers**: ticket form with up to 3 attachments (JPG, PNG, PDF, 10 MB each), a private ticket link for guests, a "My tickets" page and unread-reply badge for people with an account, a 1 to 5 star rating after a ticket is resolved, a knowledge base shown before they submit.
- **Staff**: inbox with filters, search and pagination; statistics cards; reply, internal notes, reply templates with `{name}` and `{order}` placeholders; change status or priority; assign to a staff member; merge duplicates; mark spam or block a sender; delete; print view (Save as PDF); CSV export; full audit timeline.
- **Rules**: ticket numbers `SUP-YYYY-000001`; priority comes from the category; duplicate detection (same email and subject within a day); idle tickets close themselves after a configurable number of hours; a closed ticket can only be reopened by staff.
- **Email** (optional): confirmation, staff replied, resolved and closed notices to the customer, and new-ticket and customer-replied alerts to staff. Every send or skip is logged on the ticket.
- **Anti-spam**: honeypot field, time trap, maths captcha, spam scoring, sender blocklist, per-IP rate limits.
- **Security**: CSRF token on every POST, prepared SQL statements everywhere, escaped output, Helmet headers, uploads checked by type, extension and magic bytes and stored outside the web root, gated attachment downloads, session regeneration on login, bcrypt passwords, login rate limit.

## Run it

You need Node.js 18 or newer and a MySQL or MariaDB database.

```bash
npm install
cp .env.example .env        # fill in the database, SESSION_SECRET, BASE_URL, APP_NAME
npm run create-admin -- you@example.com "Your Name"    # prints a one-time password
npm start
```

Open `http://localhost:3001/support` (the public form) and log in at `/auth/login`; staff land on `/admin/support`. The tables are created automatically on start; `npm run migrate` does the same by hand. `npm run seed-demo` adds three clearly marked sample tickets.

### Deploying (for example Hostinger Node hosting)

1. Create a MySQL database and user in the control panel.
2. Upload the code (or connect the Git repository), set the environment variables from `.env.example`, set `NODE_ENV=production` and a long random `SESSION_SECRET`.
3. Install dependencies, set the start command to `node server.js`, start the app.
4. Run `node scripts/create-admin.js you@example.com "Your Name"` once (from the console), then log in.
5. Check `/healthz` returns `{"ok":true}`.

Uploaded files go to `data/support-uploads/`. Keep that folder on persistent storage and back it up with the database.

## Settings

All in the environment (see `.env.example`): `APP_NAME`, `BASE_URL`, database, SMTP, `ADMIN_EMAIL`, `SUPPORT_TICKET_TTL_HOURS`, `SUPPORT_REPLY_WITHIN`, `ALLOW_REGISTRATION`, and the per-hour limits `SUPPORT_CREATE_LIMIT` and `SUPPORT_REPLY_LIMIT`.

Categories and reply templates are edited in the admin screen. The knowledge base is `data/knowledge-base.json`.

## Tests

`npm test` runs an end-to-end test of the real app against a real database. It needs a database it may empty:

```bash
TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=3306 TEST_DB_USER=root TEST_DB_NAME=support_ticket_test npm test
```

Without `TEST_DB_NAME` the database tests are skipped. They cover: guest ticket and private link, captcha, honeypot and CSRF refusals, duplicates, admin-only access, the full staff workflow (reply, internal note, status, priority, rating, audit trail, CSV, print), attachment checks, spam blocking, and auto-close.

## Layout

```
server.js          app, sessions, CSRF, login and the guards the ticket system needs
config.js          settings from the environment
routes/support.js  all ticket routes (customer and admin)
lib/support.js     schema, rules, spam scoring, auto-close, email templates
lib/notify.js      SMTP sending
views/, public/    EJS pages, CSS, small browser script
scripts/           migrate, create-admin, seed-support-demo
test/              end-to-end test
docs/SUPPORT.md    URLs, data model and design notes
```

## Differences from the original module

- Own `users` table and a small login, sign-up and logout, instead of the shop's accounts.
- Generic categories, templates and knowledge base (the shop-specific ones are gone), all editable.
- Removed the shop-only pieces: the UPI "payment confirmation reminder" and the matched-order panel, which needed the shop's `orders` table. The order reference a customer types is still stored and shown as text.
- Branding, reply time and idle-close time come from settings instead of being written into the pages.
