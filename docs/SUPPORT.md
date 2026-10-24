# Support ticket system: URLs, data and design notes

## URLs

| URL | Who | What |
|---|---|---|
| `/support` | everyone | Submit-ticket form and knowledge base (math captcha) |
| `/support/ticket/<token>` | link holder | Conversation, replies, attachments, rating |
| `/dashboard/support` | logged-in customer | My tickets, search, unread badges |
| `/support/unread` | logged-in customer | JSON unread count (polled by the header badge) |
| `/support/attachment/<id>` | owner, token holder or admin | Gated attachment download (logged) |
| `/admin/support` | staff | Statistics, filters, search, pagination, spam folder, settings |
| `/admin/support/<id>` | staff | Detail, conversation with internal notes, actions, audit timeline |
| `/admin/support/<id>/print` | staff | Print view (browser "Save as PDF") |
| `/admin/support/export.csv` | staff | CSV export |
| `/auth/login`, `/auth/register`, `POST /auth/logout` | everyone | Accounts |
| `/healthz` | monitors | `{"ok":true}` when the database answers |

## Tables (created on start, `lib/support.js` `ensureSchema`)

| Table | Holds |
|---|---|
| `users` | customers and staff; `role` is `user`, `admin` or `super_admin` |
| `support_tickets` | number `SUP-YYYY-000001`, status, priority, category, assignee, private access token, browser and IP, spam score, merge and duplicate links, rating, resolved and closed times |
| `support_messages` | each message; `is_internal = 1` rows are staff-only notes; read flags for both sides |
| `support_attachments` | file metadata (files are on disk in `data/support-uploads/`) |
| `support_events` | one journal: created, status, priority, assign, merge, reply, note, email, download, rating, spam |
| `support_categories` | name, slug and default priority (drives automatic prioritisation); admin-editable |
| `support_templates` | staff reply templates |
| `support_blocklist` | blocked sender emails, domains and IPs |
| `sessions` | login sessions (created by `express-mysql-session`) |

All queries use prepared statements. Foreign keys cascade, so deleting a ticket removes its messages, attachments rows and events (the files are removed by the delete action).

## Rules

- **Statuses**: Open, Pending, Waiting for Customer, Resolved, Closed. A customer reply reopens Resolved and Waiting tickets; a staff public reply on an Open ticket moves it to Waiting for Customer; a Closed ticket cannot be reopened by the customer.
- **Priority** comes from the category and can be changed per ticket.
- **Duplicates**: the same email and subject within 24 hours does not create a second ticket; the link is re-sent.
- **Auto-close**: tickets idle for `SUPPORT_TICKET_TTL_HOURS` hours are closed with a message to the customer. It runs hourly and when the admin list loads.
- **Spam**: a score from the honeypot, a form-time trap, links, keywords and promotional wording. Score 10 or more is dropped silently (the sender sees a normal confirmation and nothing is stored); 8 or more is quarantined in the spam folder; "Spam and block sender" blocks the email, its domain (unless a free mail provider) and the IP.
- **Rate limits** per IP per hour: 5 new tickets and 20 replies (configurable).

## Security

- CSRF token verified on every POST (multipart routes verify after the upload is parsed, and delete what a rejected request left on disk).
- Output is escaped; SQL is parameterised.
- Uploads: type and extension allow-list, 10 MB and 3 files, magic bytes checked on disk, random stored names, outside the web root, served only through the gated route with `X-Content-Type-Options: nosniff`.
- Guests reach a ticket only through a 48-character random token. Staff pages need an `admin` or `super_admin` account.
- Sessions are regenerated on login; passwords use bcrypt; login attempts are rate limited.
- In production the app refuses to start without `SESSION_SECRET`.

## Known limits

- No live "typing" indicator (needs WebSockets); unread badges poll once a minute.
- PDF export is the print view saved from the browser.
- The rate limiter and the spam captcha state use process memory and the session store, so with several app instances behind a load balancer the limits apply per instance.
- Email is optional; without SMTP settings tickets work and each skipped email is logged on the ticket timeline.
