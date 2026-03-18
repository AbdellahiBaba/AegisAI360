const CACHE_NAME = 'aegisai360-v8.2.1';
const STATIC_ASSETS = [
  '/favicon.png',
  '/favicon.svg',
  '/apple-touch-icon.png',
  '/og-image.png',
  '/manifest.json'
];

function notifyClients(message) {
  self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clients) {
    clients.forEach(function(client) {
      client.postMessage(message);
    });
  });
}

self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(STATIC_ASSETS).then(function() {
        notifyClients({ type: 'SW_INSTALLED', timestamp: Date.now() });
        return self.skipWaiting();
      });
    })
  );
});

self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.filter(function(name) {
          return name !== CACHE_NAME;
        }).map(function(name) {
          return caches.delete(name);
        })
      );
    }).then(function() {
      notifyClients({ type: 'SW_ACTIVATED', timestamp: Date.now() });
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', function(event) {
  var url = new URL(event.request.url);

  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).then(function(response) {
        return response;
      }).catch(function() {
        return new Response(JSON.stringify({ error: 'offline' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  if (event.request.method !== 'GET') {
    return;
  }

  var acceptHeader = event.request.headers.get('Accept') || '';

  var isViteAsset = url.pathname.startsWith('/@') ||
                    url.pathname.startsWith('/node_modules/') ||
                    url.searchParams.has('v') ||
                    url.searchParams.has('t') ||
                    url.pathname.includes('__vite');

  if (isViteAsset) {
    return;
  }

  var isContentHashedAsset = /\.[a-f0-9]{8,}\.(js|css|woff2?|ttf|eot)$/i.test(url.pathname);

  if (isContentHashedAsset) {
    event.respondWith(
      caches.match(event.request).then(function(cached) {
        if (cached) return cached;
        return fetch(event.request).then(function(response) {
          if (response && response.status === 200 && response.type === 'basic') {
            var responseClone = response.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        });
      })
    );
    return;
  }

  var isStaticAsset = /\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i.test(url.pathname);

  if (isStaticAsset) {
    event.respondWith(
      caches.match(event.request).then(function(cached) {
        var networkFetch = fetch(event.request).then(function(response) {
          if (response && response.status === 200 && response.type === 'basic') {
            var responseClone = response.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        }).catch(function() { return cached; });
        return cached || networkFetch;
      })
    );
    return;
  }

  if (acceptHeader.includes('text/html')) {
    event.respondWith(
      fetch(event.request).then(function(response) {
        if (response && response.status === 200 && url.pathname === '/') {
          var responseClone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(event.request, responseClone);
          });
        }
        return response;
      }).catch(function() {
        return caches.match('/');
      })
    );
    return;
  }
});

self.addEventListener('push', function(event) {
  var data = { title: 'AegisAI360', body: 'New security alert', icon: '/favicon.png', badge: '/favicon.png' };

  if (event.data) {
    try {
      var payload = event.data.json();
      data = Object.assign(data, payload);
    } catch (e) {
      data.body = event.data.text();
    }
  }

  var options = {
    body: data.body,
    icon: data.icon || '/favicon.png',
    badge: data.badge || '/favicon.png',
    vibrate: [200, 100, 200],
    tag: data.tag || 'aegisai360-notification',
    renotify: true,
    data: {
      url: data.url || '/',
      timestamp: Date.now()
    }
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'AegisAI360', options).then(function() {
      notifyClients({ type: 'PUSH_RECEIVED', timestamp: Date.now(), data: data });
    })
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  var targetUrl = (event.notification.data && event.notification.data.url) || '/';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clients) {
      for (var i = 0; i < clients.length; i++) {
        if (clients[i].url.includes(self.location.origin) && 'focus' in clients[i]) {
          clients[i].navigate(targetUrl);
          return clients[i].focus();
        }
      }
      return self.clients.openWindow(targetUrl);
    })
  );
});

self.addEventListener('sync', function(event) {
  if (event.tag === 'aegis-telemetry-sync') {
    event.waitUntil(
      fetch('/api/sw/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          eventType: 'background_sync',
          eventData: { tag: event.tag, timestamp: Date.now() }
        })
      }).then(function() {
        notifyClients({ type: 'SYNC_COMPLETE', tag: event.tag, timestamp: Date.now() });
      }).catch(function() {
        notifyClients({ type: 'SYNC_FAILED', tag: event.tag, timestamp: Date.now() });
      })
    );
  }

  if (event.tag === 'aegis-alert-sync') {
    event.waitUntil(
      fetch('/api/sw/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          eventType: 'alert_sync',
          eventData: { tag: event.tag, timestamp: Date.now() }
        })
      }).then(function() {
        notifyClients({ type: 'SYNC_COMPLETE', tag: event.tag, timestamp: Date.now() });
      }).catch(function() {
        notifyClients({ type: 'SYNC_FAILED', tag: event.tag, timestamp: Date.now() });
      })
    );
  }
});

self.addEventListener('periodicsync', function(event) {
  if (event.tag === 'aegis-periodic-telemetry') {
    event.waitUntil(
      fetch('/api/sw/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          eventType: 'periodic_sync',
          eventData: { tag: event.tag, timestamp: Date.now() }
        })
      }).then(function() {
        notifyClients({ type: 'PERIODIC_SYNC_COMPLETE', tag: event.tag, timestamp: Date.now() });
      }).catch(function() {
        notifyClients({ type: 'PERIODIC_SYNC_FAILED', tag: event.tag, timestamp: Date.now() });
      })
    );
  }
});

self.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'GET_SW_STATUS') {
    var status = {
      type: 'SW_STATUS',
      state: 'active',
      cacheName: CACHE_NAME,
      timestamp: Date.now()
    };

    caches.keys().then(function(names) {
      status.cacheNames = names;
      return caches.open(CACHE_NAME).then(function(cache) {
        return cache.keys();
      });
    }).then(function(keys) {
      status.cachedAssets = keys.length;
      if (event.source) {
        event.source.postMessage(status);
      }
    });
  }

  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
