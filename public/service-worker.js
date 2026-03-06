const CACHE_NAME = 'injaz-cache-v1';
const ASSETS = [
  '/',
  '/manifest.webmanifest',
  '/assets/css/style.css',
  '/assets/js/common.js',
  '/employee/login.html',
  '/employee/attendance.html',
  '/employee/salary.html',
  '/admin/login.html',
  '/admin/dashboard.html',
  '/admin/employees.html',
  '/admin/payroll.html',
  '/admin/reports.html',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || caches.match('/employee/login.html')))
  );
});
