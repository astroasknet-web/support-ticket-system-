/**
 * lib/antispam.js — shared anti-spam toolkit for every public form.
 *
 * Layers (use all of them together on any form a stranger can submit):
 *   1. Math captcha    — a small sum kept in the session (same pattern the
 *                        checkout and support forms already use).
 *   2. Honeypot        — an off-screen "website" field; humans never fill it,
 *                        naive bots almost always do.
 *   3. Time trap       — a server-rendered form_ts; a POST that arrives with
 *                        no timestamp (direct POST, no page load) or faster
 *                        than a human could type is a bot.
 *   4. Link heuristic  — enquiry/review text stuffed with URLs is spam.
 *
 * Nothing here needs external services or API keys, so it works on the
 * Hostinger box as-is and never blocks a reader because a third party is down.
 */

// ── 1. Session math captcha ──────────────────────────────────────────────────
// newCaptcha(req,'contactCaptcha') -> "4 + 7" (answer stored in the session)
function newCaptcha(req, key) {
  const a = 2 + Math.floor(Math.random() * 8);   // 2..9
  const b = 2 + Math.floor(Math.random() * 8);   // 2..9
  req.session[key] = a + b;
  return a + ' + ' + b;
}

// captchaOk(req,'contactCaptcha', req.body.captcha) — single-use: the stored
// answer is cleared whether the guess was right or wrong.
function captchaOk(req, key, given) {
  const expected = req.session ? req.session[key] : null;
  if (req.session) delete req.session[key];
  return !!expected && parseInt(given, 10) === expected;
}

// ── 2. Honeypot ──────────────────────────────────────────────────────────────
// The form carries an invisible <input name="website">; any value = bot.
function honeypotHit(body, field) {
  return !!(body && String(body[field || 'website'] || '').trim() !== '');
}

// ── 3. Time trap ─────────────────────────────────────────────────────────────
// Views render <input type="hidden" name="form_ts" value="<%= Date.now() %>">.
// Reject when the field is missing/bogus or the form came back inhumanly fast.
function tooFast(body, minSeconds) {
  const ts = parseInt(body && body.form_ts, 10);
  if (!ts || !isFinite(ts)) return true;                       // direct POST, no page load
  const age = (Date.now() - ts) / 1000;
  return age >= 0 && age < (minSeconds || 3);
}

// ── 4. Link heuristic ────────────────────────────────────────────────────────
function countLinks(text) {
  return (String(text || '').match(/https?:\/\/|www\./gi) || []).length;
}

module.exports = { newCaptcha, captchaOk, honeypotHit, tooFast, countLinks };
