// Dates — backend
// Zero dependencies: just Node's built-in modules, so `npm install` has
// nothing to fetch and nothing to break. Deploy with: node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_FILE = path.join(__dirname, 'invites.json');
const USERS_FILE = path.join(__dirname, 'users.json');
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

const HTML_FILE = path.join(__dirname, 'dates.html');

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

  // ---- Serve the app itself: visiting the server's URL directly (or
  // ---- /dates.html) returns the actual page, so people open a real
  // ---- https:// address instead of wrestling with a local file. ----
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

  try {
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
        from: from.trim().slice(0, 80),
        to: (to || '').trim().slice(0, 80),
        place: place.trim().slice(0, 120),
        month,
        plan: (plan || '').trim().slice(0, 500),
        response: null,
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
      const { userId, ...publicInvite } = invite; // don't leak the sender's userId
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
      saveInvites(db);
      const { userId, ...publicInvite } = invite;
      return send(res, 200, publicInvite);
    }

    send(res, 404, { error: 'Not found' });
  } catch (e) {
    send(res, 400, { error: 'Bad request: ' + e.message });
  }
});

server.listen(PORT, () => {
  console.log(`Dates server running on port ${PORT}`);
});
