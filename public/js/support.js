/* support.js — client-side helpers for the support ticket system. No libraries. */
(function () {
  'use strict';

  /* Auto-capture browser + device info into hidden fields on the ticket form. */
  var bi = document.getElementById('supBrowserInfo');
  var di = document.getElementById('supDeviceInfo');
  if (bi) bi.value = (navigator.userAgent || '').slice(0, 400);
  if (di) {
    var parts = [];
    try {
      parts.push((navigator.platform || '') + '');
      parts.push('screen ' + window.screen.width + 'x' + window.screen.height);
      parts.push('lang ' + (navigator.language || ''));
      if (navigator.maxTouchPoints > 0) parts.push('touch');
    } catch (e) { /* ignore */ }
    di.value = parts.filter(Boolean).join(' | ').slice(0, 255);
  }

  /* Client-side guard on attachment size/count (server re-validates). */
  function bytesNice(n) { return (n / (1024 * 1024)).toFixed(1) + ' MB'; }
  Array.prototype.forEach.call(document.querySelectorAll('input[type=file][name=attachments]'), function (inp) {
    inp.addEventListener('change', function () {
      var warn = document.getElementById('supFileWarn');
      var bad = [];
      if (inp.files.length > 3) bad.push('Please choose at most 3 files.');
      Array.prototype.forEach.call(inp.files, function (f) {
        if (f.size > 10 * 1024 * 1024) bad.push(f.name + ' is ' + bytesNice(f.size) + ' — the limit is 10 MB.');
        if (!/\.(jpe?g|png|pdf)$/i.test(f.name)) bad.push(f.name + ' is not a JPG, PNG or PDF.');
      });
      if (bad.length) {
        inp.value = '';
        if (warn) { warn.textContent = bad.join(' '); warn.style.display = 'block'; }
        else alert(bad.join('\n'));
      } else if (warn) { warn.style.display = 'none'; }
    });
  });

  /* Knowledge base: float the entries matching the chosen category to the top. */
  var catSel = document.getElementById('supCat');
  var kb = document.getElementById('supKb');
  if (catSel && kb) {
    catSel.addEventListener('change', function () {
      var slug = catSel.options[catSel.selectedIndex] && catSel.options[catSel.selectedIndex].getAttribute('data-slug');
      var items = Array.prototype.slice.call(kb.querySelectorAll('details'));
      items.forEach(function (d) {
        var match = slug && (d.getAttribute('data-cats') || '').split(' ').indexOf(slug) !== -1;
        d.style.order = match ? '0' : '1';
        d.style.borderColor = match ? '#0f766e' : '';
        if (match) d.open = true;
      });
      kb.style.display = 'flex';
      kb.style.flexDirection = 'column';
      var h = kb.querySelector('h2'); if (h) h.style.order = '-1';
    });
  }

  /* Admin: insert a reply template into the reply box, with placeholders filled. */
  var tplSel = document.getElementById('supTemplate');
  var replyBox = document.getElementById('supReplyBox');
  if (tplSel && replyBox) {
    tplSel.addEventListener('change', function () {
      if (!tplSel.value) return;
      var text = tplSel.value
        .replace(/\{name\}/g, tplSel.getAttribute('data-name') || '')
        .replace(/\{order\}/g, tplSel.getAttribute('data-order') || '');
      replyBox.value = (replyBox.value ? replyBox.value + '\n\n' : '') + text;
      replyBox.focus();
      tplSel.selectedIndex = 0;
    });
  }

  /* Star rating: light up stars left-to-right as the user picks. */
  var rate = document.getElementById('supRate');
  if (rate) {
    rate.addEventListener('change', function () {
      var checked = rate.querySelector('input:checked');
      var val = checked ? parseInt(checked.value, 10) : 0;
      Array.prototype.forEach.call(rate.querySelectorAll('label.star'), function (l) {
        l.classList.toggle('on', parseInt(l.getAttribute('data-star'), 10) <= val);
      });
    });
  }

  /* Jump to the newest message if the URL asks for it. */
  if (window.location.hash === '#latest') {
    var el = document.getElementById('latest');
    if (el) el.scrollIntoView({ block: 'center' });
  }

  /* Logged-in nav badge: poll unread staff replies once a minute. */
  var ordersLink = document.querySelector('.nav-right a[href="/dashboard/support"]');
  function pollUnread() {
    fetch('/support/unread', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : { unread: 0 }; })
      .then(function (d) {
        if (!ordersLink || !d.unread) return;
        var b = document.getElementById('supNavBadge');
        if (!b) {
          b = document.createElement('span');
          b.id = 'supNavBadge';
          b.className = 'sup-unread';
          b.style.marginLeft = '4px';
          ordersLink.appendChild(b);
        }
        b.textContent = d.unread;
        b.title = d.unread + ' unread support replies';
      })
      .catch(function () { /* offline — ignore */ });
  }
  if (ordersLink && document.querySelector('meta[name="csrf-token"]')) {
    pollUnread();
    setInterval(pollUnread, 60000);
  }
})();
