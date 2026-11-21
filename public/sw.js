// Syn Wallet service worker — KILL SWITCH (replaces the v1–v7 workers).
//
// The owner removed the service worker entirely, matching the other Syn
// projects: no worker, no Cache Storage — the server is the single source
// of truth and every load is the current version. This file exists only so
// browsers still running a v≤7 worker (which check /sw.js for updates —
// it has been served no-cache since the v7 deploy, so they WILL fetch
// this) receive a worker whose whole job is to remove itself:
//
//   install  → skipWaiting, so it activates immediately;
//   activate → delete EVERY cache under this origin, then unregister
//              itself. After it runs once, the origin has no worker.
//
// It deliberately does NOT touch open pages: no clients.navigate, no
// reload message, nothing that could yank a page showing a recovery
// phrase or sitting mid-send. The already-loaded document keeps running
// the code it loaded with; the NEXT load or reload comes straight from
// the network with no worker and no cache in between — current version,
// and no version can ever go stale again. There is no fetch handler:
// this worker never intercepts a request.
self.addEventListener('install', (e) => {
  e.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    try {
      const ks = await caches.keys();
      await Promise.all(ks.map((k) => caches.delete(k)));
    } catch { /* best-effort: unregister below is the essential step */ }
    try { await self.registration.unregister(); } catch { /* already gone */ }
  })());
});
