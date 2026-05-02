'use strict';

const express     = require('express');
const session     = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const bcrypt      = require('bcryptjs');
const Database    = require('better-sqlite3');
const path        = require('path');
const fs          = require('fs');
const crypto      = require('crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

function initDb(dbPath) {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      username       TEXT    NOT NULL UNIQUE,
      email          TEXT,
      password_hash  TEXT    NOT NULL,
      role           TEXT    NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
      webhook_secret TEXT    NOT NULL UNIQUE,
      created_at     TEXT    NOT NULL,
      last_active    TEXT
    );

    CREATE TABLE IF NOT EXISTS reports (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      received_at     TEXT    NOT NULL,
      build_id        TEXT    NOT NULL UNIQUE,
      branch          TEXT    NOT NULL,
      commit_sha      TEXT    NOT NULL,
      commit_message  TEXT,
      author          TEXT,
      status          TEXT    NOT NULL,
      duration_ms     INTEGER,
      pipeline_name   TEXT,
      pipeline_url    TEXT,
      test_passed     INTEGER NOT NULL DEFAULT 0,
      test_failed     INTEGER NOT NULL DEFAULT 0,
      test_skipped    INTEGER NOT NULL DEFAULT 0,
      raw_json        TEXT    NOT NULL,
      owner_id        INTEGER REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_branch      ON reports (branch);
    CREATE INDEX IF NOT EXISTS idx_received_at ON reports (received_at);
    CREATE INDEX IF NOT EXISTS idx_owner_id    ON reports (owner_id);
  `);

  // Migration: add owner_id to DBs created before v2
  const cols = db.prepare('PRAGMA table_info(reports)').all();
  if (!cols.some(c => c.name === 'owner_id')) {
    db.exec('ALTER TABLE reports ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL');
    db.exec('CREATE INDEX IF NOT EXISTS idx_owner_id ON reports (owner_id)');
  }

  return db;
}

// ---------------------------------------------------------------------------
// Seed admin
// ---------------------------------------------------------------------------

async function seedAdmin(db, username, password) {
  if (!username || !password) return;
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return;

  const hash   = await bcrypt.hash(password, 12);
  const secret = crypto.randomBytes(32).toString('hex');
  const now    = new Date().toISOString();

  db.prepare(`
    INSERT INTO users (username, email, password_hash, role, webhook_secret, created_at)
    VALUES (?, ?, ?, 'admin', ?, ?)
  `).run(username, `${username}@localhost`, hash, secret, now);

  const admin = db.prepare('SELECT webhook_secret FROM users WHERE username = ?').get(username);
  console.log(`[seed] Admin account created: ${username}`);
  console.log(`[seed] Webhook secret: ${admin.webhook_secret}`);
}

// ---------------------------------------------------------------------------
// App factory
// ---------------------------------------------------------------------------

function createApp(db, opts = {}) {
  const app = express();

  // -- middleware -------------------------------------------------------------

  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));

  const sessionSecret = opts.sessionSecret || 'dev-insecure-secret-change-me';
  if (!opts.sessionSecret) {
    console.warn('[warn] SESSION_SECRET not set — using insecure default');
  }

  app.use(session({
    store: new SqliteStore({ client: db, expired: { clear: true, intervalMs: 900_000 } }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    name: 'ci-dash.sid',
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 },
  }));

  // -- helpers ----------------------------------------------------------------

  function secureCompare(a, b) {
    const ba = Buffer.from(a), bb = Buffer.from(b);
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  }

  function safeJson(obj) {
    return JSON.stringify(obj).replace(/<\//g, '<\\/');
  }

  function renderTemplate(name, placeholder, data) {
    const tpl = fs.readFileSync(path.join(__dirname, 'views', name), 'utf8');
    return tpl.replace('/*DATA_PLACEHOLDER*/', `const ${placeholder} = ${safeJson(data)};`);
  }

  function formatReport(row) {
    return {
      id: row.id,
      receivedAt: row.received_at,
      buildId: row.build_id,
      branch: row.branch,
      commit: { sha: row.commit_sha, message: row.commit_message, author: row.author },
      status: row.status,
      duration: row.duration_ms,
      pipeline: row.pipeline_name ? { name: row.pipeline_name, url: row.pipeline_url } : null,
      testResults: { passed: row.test_passed, failed: row.test_failed, skipped: row.test_skipped },
      owner: row.owner_username || null,
      raw: JSON.parse(row.raw_json),
    };
  }

  const VALID_STATUSES = new Set(['success', 'failure', 'cancelled']);

  function validateReport(body) {
    const errors = [];
    for (const f of ['buildId', 'branch', 'commit', 'status', 'timestamp']) {
      if (body[f] == null || body[f] === '') errors.push(`Missing required field: ${f}`);
    }
    if (body.status && !VALID_STATUSES.has(body.status)) {
      errors.push('status must be one of: success, failure, cancelled');
    }
    if (body.commit && typeof body.commit === 'object') {
      if (!body.commit.sha)    errors.push('commit.sha is required');
      if (!body.commit.author) errors.push('commit.author is required');
    } else if (body.commit != null) {
      errors.push('commit must be an object');
    }
    return errors;
  }

  // Build a WHERE clause that scopes to owner for members.
  // Extra conditions are ANDed in; all use r.* aliases.
  function buildScope(isAdmin, userId, extraConds = [], extraParams = []) {
    const conds  = isAdmin ? [...extraConds] : ['r.owner_id = ?', ...extraConds];
    const params = isAdmin ? [...extraParams] : [userId, ...extraParams];
    const where  = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    return { where, params };
  }

  // -- auth guards -----------------------------------------------------------

  function requireAuth(req, res, next) {
    const uid = req.session?.userId;
    if (!uid) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Authentication required' });
      req.session.returnTo = req.originalUrl;
      return res.redirect('/login');
    }
    const user = db.prepare('SELECT id, role, username FROM users WHERE id = ?').get(uid);
    if (!user) {
      req.session.destroy(() => {});
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Authentication required' });
      return res.redirect('/login');
    }
    // Sync role/username in case an admin changed them
    req.session.role     = user.role;
    req.session.username = user.username;
    next();
  }

  function requireAdmin(req, res, next) {
    if (req.session?.role === 'admin') return next();
    res.redirect('/dashboard');
  }

  // -- public: health --------------------------------------------------------

  app.get('/api/health', (req, res) => {
    const { count } = db.prepare('SELECT COUNT(*) AS count FROM reports').get();
    res.json({ status: 'ok', uptime: Math.floor(process.uptime()), reportCount: count, timestamp: new Date().toISOString() });
  });

  // -- public: login / logout ------------------------------------------------

  app.get('/login', (req, res) => {
    if (req.session?.userId) return res.redirect('/dashboard');
    const tpl = fs.readFileSync(path.join(__dirname, 'views', 'login.html'), 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(tpl.replace('<!--ERROR-->', ''));
  });

  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = username ? db.prepare('SELECT * FROM users WHERE username = ?').get(username) : null;

    if (!user || !(await bcrypt.compare(password || '', user.password_hash))) {
      const tpl = fs.readFileSync(path.join(__dirname, 'views', 'login.html'), 'utf8');
      return res.status(401)
        .setHeader('Content-Type', 'text/html; charset=utf-8')
        .send(tpl.replace('<!--ERROR-->', '<p class="error">Invalid username or password.</p>'));
    }

    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;

    db.prepare('UPDATE users SET last_active = ? WHERE id = ?').run(new Date().toISOString(), user.id);

    const dest = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    res.redirect(dest);
  });

  app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
  });

  // -- webhook (per-user secret, no session) ---------------------------------

  app.post('/api/reports', (req, res) => {
    const provided = req.headers['x-webhook-secret'];
    if (!provided) {
      return res.status(401).json({ error: 'Missing X-Webhook-Secret header' });
    }

    // Lookup owner by secret — timing-safe comparison prevents enumeration
    const users = db.prepare('SELECT id, webhook_secret FROM users').all();
    const owner = users.find(u => secureCompare(provided, u.webhook_secret));
    if (!owner) {
      return res.status(401).json({ error: 'Invalid X-Webhook-Secret' });
    }

    const body   = req.body;
    const errors = validateReport(body);
    if (errors.length) return res.status(422).json({ error: 'Validation failed', details: errors });

    const receivedAt = new Date().toISOString();
    const insert = db.prepare(`
      INSERT INTO reports
        (received_at, build_id, branch, commit_sha, commit_message, author,
         status, duration_ms, pipeline_name, pipeline_url,
         test_passed, test_failed, test_skipped, raw_json, owner_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `);

    let info;
    try {
      info = insert.run(
        receivedAt, String(body.buildId), body.branch,
        body.commit.sha, body.commit.message || null, body.commit.author,
        body.status,
        body.duration != null ? Number(body.duration) : null,
        body.pipeline?.name  || null,
        body.pipeline?.url   || null,
        body.testResults?.passed  ?? 0,
        body.testResults?.failed  ?? 0,
        body.testResults?.skipped ?? 0,
        JSON.stringify(body),
        owner.id,
      );
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: `Report with buildId "${body.buildId}" already exists` });
      }
      throw err;
    }

    const row = db.prepare(`
      SELECT r.*, u.username AS owner_username
      FROM reports r LEFT JOIN users u ON r.owner_id = u.id
      WHERE r.id = ?
    `).get(info.lastInsertRowid);

    return res.status(201).json(formatReport(row));
  });

  // -- apply session auth to everything below --------------------------------

  app.use(requireAuth);

  // -- GET /api/reports ------------------------------------------------------

  app.get('/api/reports', (req, res) => {
    const isAdmin = req.session.role === 'admin';
    const page    = Math.max(1, parseInt(req.query.page)  || 1);
    const limit   = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const offset  = (page - 1) * limit;

    const extraConds = [], extraParams = [];
    if (req.query.branch) { extraConds.push('r.branch = ?');  extraParams.push(req.query.branch); }
    if (req.query.status) { extraConds.push('r.status = ?');  extraParams.push(req.query.status); }

    const { where, params } = buildScope(isAdmin, req.session.userId, extraConds, extraParams);

    const { count: total } = db.prepare(`SELECT COUNT(*) AS count FROM reports r ${where}`).get(...params);
    const rows = db.prepare(`
      SELECT r.*, u.username AS owner_username
      FROM reports r LEFT JOIN users u ON r.owner_id = u.id
      ${where} ORDER BY r.received_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ data: rows.map(formatReport), pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  });

  // -- GET /api/reports/:buildId ---------------------------------------------

  app.get('/api/reports/:buildId', (req, res) => {
    const isAdmin = req.session.role === 'admin';
    const { where, params } = buildScope(isAdmin, req.session.userId, ['r.build_id = ?'], [req.params.buildId]);

    const row = db.prepare(`
      SELECT r.*, u.username AS owner_username
      FROM reports r LEFT JOIN users u ON r.owner_id = u.id
      ${where}
    `).get(...params);

    if (!row) return res.status(404).json({ error: 'Report not found' });
    res.json(formatReport(row));
  });

  // -- GET /dashboard --------------------------------------------------------

  app.get('/dashboard', (req, res) => {
    const isAdmin    = req.session.role === 'admin';
    const thirtyAgo  = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const { where: allWhere,    params: allParams    } = buildScope(isAdmin, req.session.userId);
    const { where: recentWhere, params: recentParams } = buildScope(isAdmin, req.session.userId, ['r.received_at >= ?'], [thirtyAgo]);

    const { count: totalBuilds } = db.prepare(`SELECT COUNT(*) AS count FROM reports r ${allWhere}`).get(...allParams);
    const recentRows = db.prepare(`SELECT r.status, r.duration_ms FROM reports r ${recentWhere}`).all(...recentParams);
    const allRows    = db.prepare(`
      SELECT r.*, u.username AS owner_username
      FROM reports r LEFT JOIN users u ON r.owner_id = u.id
      ${allWhere} ORDER BY r.received_at DESC
    `).all(...allParams);
    const lastRow    = db.prepare(`SELECT r.status FROM reports r ${allWhere} ORDER BY r.received_at DESC LIMIT 1`).get(...allParams);

    const successCount = recentRows.filter(r => r.status === 'success').length;
    const successRate  = recentRows.length ? Math.round((successCount / recentRows.length) * 100) : null;
    const durations    = allRows.filter(r => r.duration_ms != null).map(r => r.duration_ms);
    const avgDuration  = durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : null;

    const data = {
      summary: { totalBuilds, successRate, avgDuration, lastStatus: lastRow?.status ?? null },
      builds: allRows.map(formatReport),
      user: { username: req.session.username, role: req.session.role },
    };

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderTemplate('dashboard.html', 'DASHBOARD_DATA', data));
  });

  // -- GET /admin ------------------------------------------------------------

  app.get('/admin', requireAdmin, (req, res) => {
    const users = db.prepare(`
      SELECT u.id, u.username, u.email, u.role, u.webhook_secret, u.created_at, u.last_active,
             COUNT(r.id) AS report_count
      FROM users u
      LEFT JOIN reports r ON r.owner_id = u.id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `).all();

    const data = {
      users,
      currentUser: { id: req.session.userId, username: req.session.username, role: req.session.role },
      flash: { invited: req.query.invited || null, error: req.query.error || null },
    };

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderTemplate('admin.html', 'ADMIN_DATA', data));
  });

  // -- POST /admin/invite ----------------------------------------------------

  app.post('/admin/invite', requireAdmin, async (req, res) => {
    const username = (req.body.username || '').trim();
    const email    = (req.body.email    || '').trim() || null;

    if (!username) return res.redirect('/admin?error=username-required');
    if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
      return res.redirect('/admin?error=duplicate-username');
    }

    const tempPassword = crypto.randomBytes(6).toString('hex');
    const hash         = await bcrypt.hash(tempPassword, 12);
    const secret       = crypto.randomBytes(32).toString('hex');
    const now          = new Date().toISOString();

    db.prepare(`
      INSERT INTO users (username, email, password_hash, role, webhook_secret, created_at)
      VALUES (?, ?, ?, 'member', ?, ?)
    `).run(username, email, hash, secret, now);

    console.log(`[admin] Invited user: ${username}  temp password: ${tempPassword}`);
    res.redirect(`/admin?invited=${encodeURIComponent(username)}`);
  });

  // -- POST /admin/users/:id/role --------------------------------------------

  app.post('/admin/users/:id/role', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (id === req.session.userId) return res.redirect('/admin?error=cannot-change-own-role');

    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(id);
    if (!user) return res.redirect('/admin?error=user-not-found');

    const newRole = user.role === 'admin' ? 'member' : 'admin';
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(newRole, id);
    res.redirect('/admin');
  });

  // -- POST /admin/users/:id/delete ------------------------------------------

  app.post('/admin/users/:id/delete', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (id === req.session.userId) return res.redirect('/admin?error=cannot-delete-self');

    // Reassign all their reports to the current admin
    db.prepare('UPDATE reports SET owner_id = ? WHERE owner_id = ?').run(req.session.userId, id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    res.redirect('/admin');
  });

  // -- POST /admin/users/:id/regenerate-secret -------------------------------

  app.post('/admin/users/:id/regenerate-secret', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!db.prepare('SELECT id FROM users WHERE id = ?').get(id)) {
      return res.redirect('/admin?error=user-not-found');
    }
    const newSecret = crypto.randomBytes(32).toString('hex');
    db.prepare('UPDATE users SET webhook_secret = ? WHERE id = ?').run(newSecret, id);
    res.redirect('/admin');
  });

  // -- error handler ---------------------------------------------------------

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (require.main === module) {
  (async () => {
    const dbPath = process.env.DB_PATH || path.join(__dirname, 'reports.db');
    const db     = initDb(dbPath);

    await seedAdmin(db, process.env.ADMIN_USERNAME, process.env.ADMIN_PASSWORD);

    const app = createApp(db, { sessionSecret: process.env.SESSION_SECRET });
    app.listen(PORT, () => {
      console.log(`CI Dashboard →  http://localhost:${PORT}/dashboard`);
      console.log(`Webhook       →  POST http://localhost:${PORT}/api/reports`);
      console.log(`Admin panel   →  http://localhost:${PORT}/admin`);
      console.log(`Health        →  http://localhost:${PORT}/api/health`);
    });
  })().catch(err => { console.error(err); process.exit(1); });
}

module.exports = { createApp, initDb, seedAdmin };
