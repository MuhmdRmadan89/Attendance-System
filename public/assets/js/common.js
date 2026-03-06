function qs(id) {
  return document.getElementById(id);
}

function getToken() {
  return localStorage.getItem('token');
}

function saveToken(token) {
  localStorage.setItem('token', token);
}

function clearAuth() {
  localStorage.removeItem('token');
}

function getDeviceId() {
  let value = localStorage.getItem('device_id');
  if (!value) {
    value = `dev_${crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2)}`;
    localStorage.setItem('device_id', value);
  }
  return value;
}

function go(url) {
  window.location.href = url;
}

function setMsg(message, success = false) {
  const el = qs('msg');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = success ? '#14b86f' : '#ff6b6b';
}

async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    clearAuth();
    throw new Error('Unauthorized');
  }

  if (!res.ok) {
    let payload = null;
    try {
      payload = await res.json();
    } catch {
      payload = null;
    }
    throw new Error(payload?.error || `Request failed (${res.status})`);
  }

  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    return null;
  }
  return res.json();
}

function getLocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('GPS is not available in this browser'));
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (p) => {
        resolve({
          lat: p.coords.latitude,
          lng: p.coords.longitude,
          accuracy: p.coords.accuracy,
        });
      },
      () => reject(new Error('Location permission denied or unavailable')),
      {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 0,
      }
    );
  });
}

function loadQueue() {
  try {
    return JSON.parse(localStorage.getItem('attendance_queue') || '[]');
  } catch {
    return [];
  }
}

function saveQueue(queue) {
  localStorage.setItem('attendance_queue', JSON.stringify(queue));
}

function queueAttendanceAction(action, loc) {
  const queue = loadQueue();
  queue.push({ action, loc, createdAt: new Date().toISOString() });
  saveQueue(queue);
}

async function flushAttendanceQueue() {
  const queue = loadQueue();
  if (!queue.length || !navigator.onLine) return { sent: 0, pending: queue.length };

  let sent = 0;
  const pending = [];

  for (const item of queue) {
    try {
      await api(`/api/employee/${item.action}`, {
        method: 'POST',
        body: JSON.stringify(item.loc),
      });
      sent += 1;
    } catch (error) {
      pending.push(item);
    }
  }

  saveQueue(pending);
  return { sent, pending: pending.length };
}

function ensureAuthOrRedirect(loginPath) {
  if (!getToken()) {
    go(loginPath);
    return false;
  }
  return true;
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/service-worker.js').catch(() => {});
  });
}

window.addEventListener('online', () => {
  flushAttendanceQueue().catch(() => {});
});
