// Dates — backend
// Almost zero dependencies — the one exception is 'web-push', needed to
// send real push notifications. Deploy with: node server.js
// IMPORTANT: because of that one dependency, Render's Build Command must
// now be `npm install` (not blank like before) — see server/README.md.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const webpush = require('web-push');

const DB_FILE = path.join(__dirname, 'invites.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const VAPID_FILE = path.join(__dirname, 'vapid.json');
const PORT = process.env.PORT || 3000;

// Sessions live in memory only — they reset if the server restarts.
// That just means a logged-in sender has to log in again after a redeploy.
const sessions = new Map(); // token -> userId

function loadJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return {}; }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
const loadInvites = () => loadJSON(DB_FILE);
const saveInvites = db => saveJSON(DB_FILE, db);
const loadUsers = () => loadJSON(USERS_FILE);
const saveUsers = db => saveJSON(USERS_FILE, db);

// ---- Push notifications: VAPID keys identify OUR server to the push
// ---- services (Apple/Google/Mozilla). Generated once, then reused
// ---- forever — regenerating them would silently break every existing
// ---- subscription, so we persist them to a file. ----
function loadOrCreateVapidKeys() {
  const existing = loadJSON(VAPID_FILE);
  if (existing.publicKey && existing.privateKey) return existing;
  const keys = webpush.generateVAPIDKeys();
  saveJSON(VAPID_FILE, keys);
  return keys;
}
const vapidKeys = loadOrCreateVapidKeys();
webpush.setVapidDetails('mailto:dates-app@example.com', vapidKeys.publicKey, vapidKeys.privateKey);

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 1e6) { // 1MB safety cap
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function clean(value, max) {
  return String(value || '').trim().slice(0, max);
}

// ---- Passwords: salted scrypt, no external libraries needed ----
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(attempt, 'hex');
  const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function getAuthUserId(req) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  return sessions.get(token) || null;
}

function normalizeUsername(name) {
  return String(name || '').trim().toLowerCase();
}

// Allowed reminder lead times, in hours. 0 means "no reminder".
const ALLOWED_REMINDER_HOURS = [0, 1, 3, 24, 48, 168];
const ALLOWED_CATEGORIES = ['date', 'friends', 'professional', 'group'];

// We only collect a day/month/year for the date, not a time of day, so
// reminders are computed against a fixed reference point: noon UTC on the
// chosen day. This is a simplification — good enough for "the morning of"
// or "a few days before" style reminders, not minute-precise scheduling.
function computeReminderAt(response, reminderHours) {
  if (!reminderHours) return null;
  const eventMoment = Date.UTC(response.year, response.month - 1, response.day, 12, 0, 0);
  const reminderAt = eventMoment - reminderHours * 3600 * 1000;
  return reminderAt > Date.now() ? reminderAt : null; // don't schedule reminders in the past
}

// ---- Background scheduler: checks once a minute for reminders that are
// ---- due, and sends a real push notification for each one. ----
function checkAndSendReminders() {
  const db = loadInvites();
  let changed = false;

  Object.entries(db).forEach(([id, inv]) => {
    if (!inv.reminderAt || inv.reminderSent || !inv.pushSubscription) return;
    if (inv.reminderAt > Date.now()) return;

    const CATEGORY_NOUN = {
      date: 'date',
      friends: 'hangout',
      professional: 'meeting',
      group: 'get-together',
    };
    const noun = CATEGORY_NOUN[inv.category] || 'plan';

    const payload = JSON.stringify({
      title: 'Dates',
      body: `Reminder: your ${noun} with ${inv.from} at ${inv.place} is coming up.`,
      url: '/?id=' + id,
    });

    webpush.sendNotification(inv.pushSubscription, payload)
      .then(() => {
        const fresh = loadInvites();
        if (fresh[id]) {
          fresh[id].reminderSent = true;
          saveInvites(fresh);
        }
      })
      .catch(err => {
        console.error('Push failed for invite', id, err.message);
        // 404/410 means the subscription is gone for good (uninstalled,
        // permissions revoked) — stop trying so we don't retry forever.
        const fresh = loadInvites();
        if (fresh[id] && (err.statusCode === 404 || err.statusCode === 410)) {
          fresh[id].reminderSent = true;
          fresh[id].pushSubscription = null;
          saveInvites(fresh);
        }
      });
  });
}
setInterval(checkAndSendReminders, 60 * 1000);

// ---- Static app files served directly, so people visit a real address
// ---- instead of dealing with local files. dates.html is the app itself;
// ---- manifest.json + sw.js are what make "Add to Home Screen" and push
// ---- notifications possible, generated here so no extra repo files are
// ---- needed. ----
const HTML_FILE = path.join(__dirname, 'dates.html');

const MANIFEST_JSON = JSON.stringify({
  name: 'Dates',
  short_name: 'Dates',
  start_url: '/',
  display: 'standalone',
  background_color: '#150F2A',
  theme_color: '#241645',
  icons: [
    { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' }
  ]
});

const ICON_SVG = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='#241645'/><path d='M20 35 h60 v30 a8 8 0 0 0 0 16 v9 h-60 v-9 a8 8 0 0 0 0-16 z' fill='none' stroke='#E8B84B' stroke-width='4'/><text x='50' y='56' font-family='Georgia,serif' font-style='italic' font-size='22' fill='#FF4D8D' text-anchor='middle'>♥</text></svg>`;

// The service worker: listens for a push event, shows the notification,
// and focuses/opens the app if the person taps it.
const SERVICE_WORKER_JS = `
self.addEventListener('push', function (event) {
  let data = { title: 'Dates', body: 'You have a reminder.', url: '/' };
  try { data = event.data.json(); } catch (e) {}
  event.waitUntil(
    self.registration.showNotification(data.title || 'Dates', {
      body: data.body || '',
      icon: '/icon.svg',
      badge: '/icon.svg',
      data: { url: data.url || '/' }
    })
  );
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (windowClients) {
      for (const client of windowClients) {
        if ('focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
`;

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const parts = url.pathname.split('/').filter(Boolean);

  if (req.method === 'GET' && (parts.length === 0 || (parts.length === 1 && parts[0] === 'dates.html'))) {
    try {
      const html = fs.readFileSync(HTML_FILE, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      return res.end('dates.html was not found next to server.js — make sure both files are in the same folder/repo.');
    }
  }

  if (req.method === 'GET' && parts.length === 1 && parts[0] === 'manifest.json') {
    res.writeHead(200, { 'Content-Type': 'application/manifest+json' });
    return res.end(MANIFEST_JSON);
  }

  if (req.method === 'GET' && parts.length === 1 && parts[0] === 'icon.svg') {
    res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
    return res.end(ICON_SVG);
  }

  // Service workers must be served from the root scope with no caching
  // surprises, or the browser won't let them control the page.
  if (req.method === 'GET' && parts.length === 1 && parts[0] === 'sw.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript', 'Service-Worker-Allowed': '/' });
    return res.end(SERVICE_WORKER_JS);
  }

  try {
    // ---- GET /api/vapid-public-key (public — needed before subscribing) ----
    if (req.method === 'GET' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'vapid-public-key') {
      return send(res, 200, { publicKey: vapidKeys.publicKey });
    }

    // ---- POST /api/signup ----
    if (req.method === 'POST' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'signup') {
      const body = await readBody(req);
      const username = normalizeUsername(body.username);
      const password = String(body.password || '');
      const displayName = clean(body.displayName, 60) || username;

      if (username.length < 3) return send(res, 400, { error: 'Username must be at least 3 characters' });
      if (password.length < 6) return send(res, 400, { error: 'Password must be at least 6 characters' });

      const users = loadUsers();
      if (users[username]) return send(res, 409, { error: 'That username is already taken' });

      const { salt, hash } = hashPassword(password);
      const userId = crypto.randomBytes(8).toString('hex');
      users[username] = { userId, salt, hash, displayName, createdAt: Date.now() };
      saveUsers(users);

      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, userId);

      return send(res, 200, { token, userId, displayName });
    }

    // ---- POST /api/login ----
    if (req.method === 'POST' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'login') {
      const body = await readBody(req);
      const username = normalizeUsername(body.username);
      const password = String(body.password || '');

      const users = loadUsers();
      const user = users[username];
      if (!user || !verifyPassword(password, user.salt, user.hash)) {
        return send(res, 401, { error: 'Incorrect username or password' });
      }

      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, user.userId);

      return send(res, 200, { token, userId: user.userId, displayName: user.displayName });
    }

    // ---- POST /api/logout ----
    if (req.method === 'POST' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'logout') {
      const header = req.headers['authorization'] || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : null;
      if (token) sessions.delete(token);
      return send(res, 200, { ok: true });
    }

    // ---- GET /api/users/me/invites  (the sender's portal list) ----
    if (req.method === 'GET' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'users' && parts[2] === 'me' && parts[3] === 'invites') {
      const userId = getAuthUserId(req);
      if (!userId) return send(res, 401, { error: 'Please log in again' });

      const db = loadInvites();
      const mine = Object.entries(db)
        .filter(([id, inv]) => inv.userId === userId)
        .map(([id, inv]) => ({
          id,
          to: inv.to,
          place: inv.place,
          month: inv.month,
          response: inv.response,
          createdAt: inv.createdAt,
        }))
        .sort((a, b) => b.createdAt - a.createdAt);

      return send(res, 200, { invites: mine });
    }

    // ---- POST /api/invites  (create — now requires login) ----
    if (req.method === 'POST' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'invites') {
      const userId = getAuthUserId(req);
      if (!userId) return send(res, 401, { error: 'Please log in again' });

      const body = await readBody(req);
      const { from, to, place, month, plan } = body;
      let reminderHours = Number(body.reminderHours);
      if (!ALLOWED_REMINDER_HOURS.includes(reminderHours)) reminderHours = 0;
      let category = String(body.category || 'date');
      if (!ALLOWED_CATEGORIES.includes(category)) category = 'date';

      if (!isNonEmptyString(from) || !isNonEmptyString(place) || !isNonEmptyString(month)) {
        return send(res, 400, { error: 'from, place, and month are required' });
      }
      if (!/^\d{4}-\d{2}$/.test(month)) {
        return send(res, 400, { error: 'month must be in YYYY-MM format' });
      }

      const id = crypto.randomBytes(6).toString('hex');
      const db = loadInvites();
      db[id] = {
        userId,
        category,
        from: from.trim().slice(0, 80),
        to: (to || '').trim().slice(0, 80),
        place: place.trim().slice(0, 120),
        month,
        plan: (plan || '').trim().slice(0, 500),
        reminderHours,
        reminderAt: null,
        reminderSent: false,
        pushSubscription: null,
        response: null,
        senderPublicKey: null,
        recipientPublicKey: null,
        messages: [],
        createdAt: Date.now(),
      };
      saveInvites(db);
      return send(res, 200, { id });
    }

    // ---- GET /api/invites/:id  (public — the recipient needs no account) ----
    if (req.method === 'GET' && parts.length === 3 && parts[0] === 'api' && parts[1] === 'invites') {
      const db = loadInvites();
      const invite = db[parts[2]];
      if (!invite) return send(res, 404, { error: 'Invitation not found' });
      // Chat keys/messages have their own endpoints — keep this response lean
      // and don't leak sender-only data (userId, the raw push subscription).
      const { userId, pushSubscription, senderPublicKey, recipientPublicKey, messages, ...publicInvite } = invite;
      return send(res, 200, publicInvite);
    }

    // ---- POST /api/invites/:id/response  (public — recipient submits their day) ----
    if (req.method === 'POST' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'invites' && parts[3] === 'response') {
      const db = loadInvites();
      const invite = db[parts[2]];
      if (!invite) return send(res, 404, { error: 'Invitation not found' });

      const body = await readBody(req);
      const { day, month, year } = body;
      if (!Number.isInteger(day) || !Number.isInteger(month) || !Number.isInteger(year)) {
        return send(res, 400, { error: 'day, month, and year must be integers' });
      }

      invite.response = { day, month, year };
      invite.reminderAt = computeReminderAt(invite.response, invite.reminderHours);
      invite.reminderSent = false;
      saveInvites(db);
      const { userId, pushSubscription, senderPublicKey, recipientPublicKey, messages, ...publicInvite } = invite;
      return send(res, 200, publicInvite);
    }

    // ---- POST /api/invites/:id/publickey  (public — either party publishes
    // ---- their chat public key; the server never sees a private key) ----
    if (req.method === 'POST' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'invites' && parts[3] === 'publickey') {
      const db = loadInvites();
      const invite = db[parts[2]];
      if (!invite) return send(res, 404, { error: 'Invitation not found' });

      const body = await readBody(req);
      const role = body.role;
      if (role !== 'sender' && role !== 'recipient') {
        return send(res, 400, { error: 'role must be "sender" or "recipient"' });
      }
      if (!body.publicKeyJwk || typeof body.publicKeyJwk !== 'object' || body.publicKeyJwk.kty !== 'EC') {
        return send(res, 400, { error: 'A valid EC public key (JWK) is required' });
      }

      invite[role === 'sender' ? 'senderPublicKey' : 'recipientPublicKey'] = body.publicKeyJwk;
      saveInvites(db);
      return send(res, 200, {
        senderPublicKey: invite.senderPublicKey,
        recipientPublicKey: invite.recipientPublicKey,
      });
    }

    // ---- GET /api/invites/:id/messages  (public — fetch the chat thread) ----
    // Only ever returns ciphertext + the two public keys. The server has no
    // way to read message content — that's the whole point.
    if (req.method === 'GET' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'invites' && parts[3] === 'messages') {
      const db = loadInvites();
      const invite = db[parts[2]];
      if (!invite) return send(res, 404, { error: 'Invitation not found' });
      return send(res, 200, {
        senderPublicKey: invite.senderPublicKey,
        recipientPublicKey: invite.recipientPublicKey,
        messages: invite.messages || [],
      });
    }

    // ---- POST /api/invites/:id/messages  (public — send an already-encrypted message) ----
    if (req.method === 'POST' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'invites' && parts[3] === 'messages') {
      const db = loadInvites();
      const invite = db[parts[2]];
      if (!invite) return send(res, 404, { error: 'Invitation not found' });

      const body = await readBody(req);
      const role = body.role;
      if (role !== 'sender' && role !== 'recipient') {
        return send(res, 400, { error: 'role must be "sender" or "recipient"' });
      }
      if (!isNonEmptyString(body.iv) || !isNonEmptyString(body.ciphertext)) {
        return send(res, 400, { error: 'iv and ciphertext are required' });
      }
      if (body.ciphertext.length > 20000) {
        return send(res, 400, { error: 'Message too long' });
      }

      const message = {
        id: crypto.randomBytes(6).toString('hex'),
        role,
        iv: body.iv,
        ciphertext: body.ciphertext,
        createdAt: Date.now(),
      };

      invite.messages = invite.messages || [];
      invite.messages.push(message);
      // Cap history so the JSON file can't grow without bound.
      if (invite.messages.length > 300) {
        invite.messages = invite.messages.slice(-300);
      }
      saveInvites(db);
      return send(res, 200, message);
    }

    // ---- POST /api/invites/:id/subscribe  (public — recipient enables reminders) ----
    if (req.method === 'POST' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'invites' && parts[3] === 'subscribe') {
      const db = loadInvites();
      const invite = db[parts[2]];
      if (!invite) return send(res, 404, { error: 'Invitation not found' });

      const body = await readBody(req);
      if (!body.subscription || !body.subscription.endpoint) {
        return send(res, 400, { error: 'A valid push subscription is required' });
      }

      invite.pushSubscription = body.subscription;
      // If a response (and therefore a reminder time) already exists but
      // hadn't been scheduled yet because there was no subscription, compute it now.
      if (invite.response && invite.reminderHours && !invite.reminderAt) {
        invite.reminderAt = computeReminderAt(invite.response, invite.reminderHours);
      }
      saveInvites(db);
      return send(res, 200, { ok: true, reminderAt: invite.reminderAt });
    }

    send(res, 404, { error: 'Not found' });
  } catch (e) {
    send(res, 400, { error: 'Bad request: ' + e.message });
  }
});

server.listen(PORT, () => {
  console.log(`Dates server running on port ${PORT}`);
});
