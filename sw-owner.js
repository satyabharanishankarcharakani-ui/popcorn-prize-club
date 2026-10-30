// sw-owner.js
// Dedicated Service Worker for LR Popcorn Owner Portal (LR Owner PWA)
// STRICT SECURITY REQUIREMENT:
// ONLY caches safe, static UI shell assets (HTML shell, icons, manifest).
// NEVER caches private API responses, owner financial data, auth sessions, or customer records.

const CACHE_NAME = 'lr-owner-static-v1';

const STATIC_ASSETS = [
  '/owner',
  '/manifest-owner.json',
  '/owner-icon-192.png',
  '/owner-icon-512.png',
  '/owner-icon-maskable-192.png',
  '/owner-icon-maskable-512.png',
  '/owner-icon.svg',
];

// Install Event: Pre-cache static shell assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[SW-Owner] Pre-cache warning:', err);
      });
    })
  );
  self.skipWaiting();
});

// Activate Event: Clean up outdated caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch Event: Strict routing & security enforcement
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // 1. Only handle GET requests; all mutations (POST, PUT, DELETE, PATCH) bypass SW
  if (req.method !== 'GET') {
    return;
  }

  // 2. CRITICAL SECURITY GUARD: NEVER CACHE ANY /api/* ROUTES
  // Financial metrics, authentication sessions, sales, expenses, and reward data
  // MUST ALWAYS be fetched live directly from the network.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(req));
    return;
  }

  // 3. Customer-facing pages or external links bypass owner SW
  if (url.pathname === '/' || url.pathname === '/index.html') {
    return;
  }

  // 4. HTML Navigation for Owner Portal: Network-first, fallback to cached shell
  if (req.mode === 'navigate' && (url.pathname === '/owner' || url.pathname === '/owner.html')) {
    event.respondWith(
      fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const resClone = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          }
          return networkRes;
        })
        .catch(() => {
          // If offline, serve the cached static shell
          return caches.match('/owner').then((cached) => cached || caches.match('/owner.html'));
        })
    );
    return;
  }

  // 5. Static assets (icons, manifest, fonts): Stale-while-revalidate / Cache-first
  if (
    url.pathname.startsWith('/owner-icon') ||
    url.pathname === '/manifest-owner.json' ||
    url.hostname === 'fonts.googleapis.com' ||
    url.hostname === 'fonts.gstatic.com'
  ) {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) {
          // Return cached and update in background
          fetch(req)
            .then((fresh) => {
              if (fresh && fresh.status === 200) {
                caches.open(CACHE_NAME).then((cache) => cache.put(req, fresh));
              }
            })
            .catch(() => {});
          return cached;
        }
        return fetch(req).then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const resClone = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          }
          return networkRes;
        });
      })
    );
    return;
  }

  // Default: pass through to network
  event.respondWith(fetch(req));
});
