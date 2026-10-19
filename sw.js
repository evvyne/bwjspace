// Lets Bwjspace open without internet. Always tries the network first so you get updates.
const CACHE = 'bwjspace-v30';
const FILES = ['./', 'index.html', 'config.js', 'supabase.js', 'qr.js', 'jspdf.js', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png', 'favicon.png', 'icon-maskable-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE && k !== 'bwjspace-img').map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const req = e.request; const url = new URL(req.url);
  if (req.method !== 'GET') return;
  if (url.hostname.endsWith('supabase.co') && url.pathname.includes('/storage/v1/object/public/')) {
    // photos never change once uploaded: show the saved copy, fetch only the first time
    e.respondWith(caches.open('bwjspace-img').then(c => c.match(req).then(hit => hit || fetch(req).then(res => { if (res.ok) c.put(req, res.clone()); return res; }))));
    return;
  }
  if (url.hostname.endsWith('supabase.co')) return; // never cache your data requests
  const sameOrigin = url.origin === location.origin;
  const isFont = url.hostname.includes('fonts.g');
  if (!sameOrigin && !isFont) return;
  e.respondWith(fetch(req, sameOrigin ? { cache: 'no-cache' } : undefined).then(res => { if (res.ok || res.type === 'opaque') { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); } return res; })
    .catch(() => caches.match(req).then(r => r || (req.mode === 'navigate' ? caches.match('index.html') : undefined))));
});
