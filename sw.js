// Scrapeer service worker: makes the app installable and shows notifications even when the app is closed.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});  // always online: no offline cache (sending needs the internet anyway)

self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = {title: "Scrapeer", body: e.data ? e.data.text() : ""}; }
  e.waitUntil(self.registration.showNotification(d.title || "Scrapeer", {
    body: d.body || "", icon: "/icon-192.png", badge: "/badge-96.png", tag: d.title, renotify: true, data: {url: d.url || "/#inbox"}}));
});

self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = e.notification.data?.url || "/#inbox";
  e.waitUntil((async () => {
    const open = await self.clients.matchAll({type: "window", includeUncontrolled: true});
    if (open.length) { open[0].postMessage({open: "inbox"}); return open[0].focus(); }
    return self.clients.openWindow(url);
  })());
});
