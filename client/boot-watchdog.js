// Syn Wallet boot watchdog + verified loader. Plain ES5, no modules,
// no dependencies — it must run even when the app bundle cannot.
//
// Since the integrity release this file is the bundle's ONLY loader
// (the built index.html carries no direct module tag). At build time
// scripts/stamp-integrity.mjs stamps the release's bundle path and
// SHA-256 into the placeholders below and generates the served copy
// at public/boot-watchdog.js. The watchdog:
//   1. fetches the bundle and verifies its SHA-256 against the pin
//      BEFORE any wallet code executes — a mismatch (tampered or
//      corrupted bytes) refuses to load the wallet and shows the
//      integrity error state; one cache-busted re-fetch distinguishes
//      a poisoned cache entry from genuinely wrong bytes;
//   2. injects the verified bundle as a module;
//   3. watches the boot: if the app has not finished within budget,
//      it makes ONE recovery attempt (service workers + Cache Storage
//      purged — localStorage, which holds the vault, is NEVER
//      touched) and otherwise replaces the splash with an error state
//      naming the failed step, with a Retry button. An eternal splash
//      is never acceptable output.
(function () {
  var BUNDLE_PATH = '__SYN_BUNDLE_PATH__';
  var BUNDLE_SHA256 = '__SYN_BUNDLE_SHA256__';
  var BUDGET_MS = 15000;
  var RECOVERY_KEY = 'syn-boot-recovery-once';
  var startedAt = Date.now();
  var failed = false;

  function bootEl() { return document.getElementById('splash'); }
  function stepName() { return window.__synBootStep || 'load'; }

  function fail(kind) {
    if (failed || window.__synBooted) return;
    failed = true;
    // The watchdog runs from <head>; a fast failure can land before
    // the parser has produced #boot. Dropping the error state here
    // would recreate the eternal splash this file exists to kill —
    // so when the element is not there yet, render the moment it is.
    if (!bootEl()) {
      var ivf = setInterval(function () {
        if (window.__synBooted) { clearInterval(ivf); return; }
        if (bootEl()) { clearInterval(ivf); renderFail(kind); }
      }, 100);
      setTimeout(function () { clearInterval(ivf); }, 10000);
      return;
    }
    renderFail(kind);
  }

  function renderFail(kind) {
    var el = bootEl();
    if (!el) return;
    var integrity = kind === 'integrity';
    el.innerHTML =
      '<div style="max-width:320px;text-align:center;padding:24px">' +
      '<div style="font-size:15px;font-weight:600;color:#eef2f7;letter-spacing:.02em">' +
      (integrity ? 'Integrity check failed' : 'The app didn\u2019t finish loading') + '</div>' +
      '<div style="margin-top:10px;font-size:13px;line-height:1.55;color:#93a9c0">' +
      (integrity
        ? 'The app code served to this device does not match the release build, so the wallet was not loaded and nothing was unlocked. Check your connection and tap Retry. If this keeps happening, do not use this copy of the wallet.'
        : 'Something stalled while starting (step: ' + kind + '). Your wallet data on this device is untouched. Check your connection and try again.') +
      '</div>' +
      '<button id="bootRetry" style="margin-top:18px;appearance:none;border:1px solid rgba(147,169,192,.45);background:rgba(199,208,218,.08);color:#eef2f7;font:600 14px -apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;padding:11px 26px;border-radius:999px;cursor:pointer">Retry</button>' +
      '</div>';
    el.style.flexDirection = 'column';
    var btn = document.getElementById('bootRetry');
    if (btn) btn.addEventListener('click', function () { location.reload(); });
  }

  function purgeAndReload() {
    var jobs = [];
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
        jobs.push(navigator.serviceWorker.getRegistrations().then(function (regs) {
          var un = []; for (var i = 0; i < regs.length; i++) un.push(regs[i].unregister());
          return Promise.all(un);
        }));
      }
    } catch (e) { /* ignore */ }
    try {
      if (window.caches && caches.keys) {
        jobs.push(caches.keys().then(function (keys) {
          var del = []; for (var i = 0; i < keys.length; i++) del.push(caches.delete(keys[i]));
          return Promise.all(del);
        }));
      }
    } catch (e) { /* ignore */ }
    var done = false;
    function go() { if (!done) { done = true; location.reload(); } }
    Promise.all(jobs).then(go, go);
    setTimeout(go, 1500);
  }

  // ---- stall watchdog (covers verify, load and app boot) ----
  var timer = setTimeout(function () {
    if (window.__synBooted || failed) return;
    if (window.__synBootStarted) { fail(stepName()); return; }
    try {
      if (!sessionStorage.getItem(RECOVERY_KEY)) {
        sessionStorage.setItem(RECOVERY_KEY, '1');
        purgeAndReload();
        return;
      }
    } catch (e) { /* storage unavailable — fall through to the error state */ }
    fail('load');
  }, BUDGET_MS);
  var iv = setInterval(function () {
    if (window.__synBooted) {
      clearInterval(iv);
      clearTimeout(timer);
      try { sessionStorage.removeItem(RECOVERY_KEY); } catch (e) { /* ignore */ }
    }
  }, 250);

  // ---- verified load ----
  function inject(src) {
    var s = document.createElement('script');
    s.type = 'module';
    s.src = src;
    s.onerror = function () { if (!window.__synBootStarted && !failed) fail('load'); };
    document.head.appendChild(s);
  }
  function sha256Hex(buf) {
    return crypto.subtle.digest('SHA-256', buf).then(function (d) {
      var b = new Uint8Array(d); var h = '';
      for (var i = 0; i < b.length; i++) { var x = b[i].toString(16); if (x.length < 2) h += '0'; h += x; }
      return h;
    });
  }
  function fetchBundle(bust) {
    var u = bust ? BUNDLE_PATH + (BUNDLE_PATH.indexOf('?') < 0 ? '?' : '&') + 'v=' + startedAt : BUNDLE_PATH;
    return fetch(u, bust ? { cache: 'no-store' } : {}).then(function (r) {
      if (!r.ok) throw new Error('http ' + r.status);
      return r.arrayBuffer();
    }).then(function (buf) { return { buf: buf, url: u }; });
  }
  function verifyAndInject(res, isRetry) {
    return sha256Hex(res.buf).then(function (h) {
      if (h === BUNDLE_SHA256) { inject(res.url === BUNDLE_PATH ? BUNDLE_PATH : res.url); return; }
      if (!isRetry) {
        // One fresh fetch: a corrupted cache entry must not be
        // mistaken for tampering — and tampering must not be
        // excused as corruption if the fresh bytes also mismatch.
        return fetchBundle(true).then(function (res2) { return verifyAndInject(res2, true); }, function () { fail('integrity'); });
      }
      fail('integrity');
    });
  }
  function load() {
    if (!window.crypto || !crypto.subtle || !window.fetch) { fail('integrity'); return; }
    fetchBundle(false).then(function (res) { return verifyAndInject(res, false); }, function () {
      return fetchBundle(true).then(function (res) { return verifyAndInject(res, true); }, function () { fail('load'); });
    });
  }
  load();
})();
