'use strict';

const { test, before, after, describe } = require('node:test');
const assert  = require('node:assert/strict');
const http    = require('node:http');
const bcrypt  = require('bcryptjs');
const crypto  = require('node:crypto');
const { createApp, initDb } = require('../server');

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ADMIN_WEBHOOK_SECRET  = 'admin-webhook-secret-aaaa1111';
const MEMBER_WEBHOOK_SECRET = 'member-webhook-secret-bbbb2222';
const ADMIN_PASSWORD        = 'admin-pass-correct';
const MEMBER_PASSWORD       = 'member-pass-correct';

const db = initDb(':memory:');
let adminId, memberId;

// Insert test users synchronously before app starts (low bcrypt cost for speed)
{
  const now = new Date().toISOString();
  const r1 = db.prepare(`
    INSERT INTO users (username, email, password_hash, role, webhook_secret, created_at)
    VALUES (?, ?, ?, 'admin', ?, ?)
  `).run('testadmin', 'admin@test.com', bcrypt.hashSync(ADMIN_PASSWORD, 1), ADMIN_WEBHOOK_SECRET, now);
  adminId = r1.lastInsertRowid;

  const r2 = db.prepare(`
    INSERT INTO users (username, email, password_hash, role, webhook_secret, created_at)
    VALUES (?, ?, ?, 'member', ?, ?)
  `).run('testmember', 'member@test.com', bcrypt.hashSync(MEMBER_PASSWORD, 1), MEMBER_WEBHOOK_SECRET, now);
  memberId = r2.lastInsertRowid;
}

const app = createApp(db, { sessionSecret: 'test-session-secret' });

let server;
let base;

// Session cookies acquired at login time
let adminCookie;
let memberCookie;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

before(async () => {
  server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;

  adminCookie  = await loginCookie('testadmin',  ADMIN_PASSWORD);
  memberCookie = await loginCookie('testmember', MEMBER_PASSWORD);
});

after(() => new Promise(resolve => server.close(resolve)));

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/** JSON API call — returns { status, body, headers } */
function req(method, pathname, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const url  = new URL(pathname, base);
    const data = body !== undefined ? JSON.stringify(body) : undefined;
    const opts = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
    };
    const r = http.request(opts, res => {
      let raw = '';
      res.on('data', d => (raw += d));
      res.on('end', () => {
        let parsed; try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        resolve({ status: res.statusCode, body: parsed, headers: res.headers });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

/** Form POST — returns { status, location, cookie, body } */
function formPost(pathname, data, extraHeaders = {}) {
  const body = new URLSearchParams(data).toString();
  return new Promise((resolve, reject) => {
    const url  = new URL(pathname, base);
    const opts = {
      method: 'POST',
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        ...extraHeaders,
      },
    };
    const r = http.request(opts, res => {
      let raw = '';
      res.on('data', d => (raw += d));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          location: res.headers['location'],
          cookie: (res.headers['set-cookie']?.[0] || '').split(';')[0],
          body: raw,
        });
      });
    });
    r.on('error', reject);
    r.write(body);
    r.end();
  });
}

/** Log in and return the session cookie string. */
async function loginCookie(username, password) {
  const { cookie } = await formPost('/login', { username, password });
  assert.ok(cookie, `login failed for ${username}`);
  return cookie;
}

/** Convenience: authenticated JSON GET */
const GET = (path, cookie) => req('GET', path, { headers: { Cookie: cookie } });

// ---------------------------------------------------------------------------
// Report fixture
// ---------------------------------------------------------------------------

const VALID_REPORT = {
  buildId: 'build-001',
  branch: 'main',
  commit: { sha: 'abc1234def5678', message: 'feat: add webhook', author: 'alice' },
  status: 'success',
  timestamp: new Date().toISOString(),
  duration: 42000,
  pipeline: { name: 'GitHub Actions', url: 'https://github.com/org/repo/actions/runs/1' },
  testResults: { passed: 10, failed: 0, skipped: 2 },
};

const post = (body, secret = ADMIN_WEBHOOK_SECRET) =>
  req('POST', '/api/reports', { body, headers: { 'X-Webhook-Secret': secret } });

// ---------------------------------------------------------------------------
// GET /api/health (public — no auth)
// ---------------------------------------------------------------------------

describe('GET /api/health', () => {
  test('returns 200 without authentication', async () => {
    const { status, body } = await req('GET', '/api/health');
    assert.equal(status, 200);
    assert.equal(body.status, 'ok');
    assert.equal(typeof body.uptime, 'number');
    assert.ok(body.reportCount >= 0);
    assert.ok(body.timestamp);
  });
});

// ---------------------------------------------------------------------------
// Login / Logout
// ---------------------------------------------------------------------------

describe('GET /login', () => {
  test('shows login form', async () => {
    const { status, body } = await req('GET', '/login');
    assert.equal(status, 200);
    assert.ok(typeof body === 'string' && body.includes('Sign in'));
  });

  test('redirects to /dashboard when already authenticated', async () => {
    const { status, headers } = await req('GET', '/login', { headers: { Cookie: adminCookie } });
    assert.equal(status, 302);
    assert.equal(headers.location, '/dashboard');
  });
});

describe('POST /login', () => {
  test('returns 302 and sets cookie on correct credentials', async () => {
    const { status, cookie, location } = await formPost('/login', {
      username: 'testadmin', password: ADMIN_PASSWORD,
    });
    assert.equal(status, 302);
    assert.equal(location, '/dashboard');
    assert.ok(cookie.startsWith('ci-dash.sid='));
  });

  test('returns 401 on wrong password', async () => {
    const { status, body } = await formPost('/login', { username: 'testadmin', password: 'wrong' });
    assert.equal(status, 401);
    assert.ok(body.includes('Invalid username or password'));
  });

  test('returns 401 on unknown username', async () => {
    const { status } = await formPost('/login', { username: 'nobody', password: 'x' });
    assert.equal(status, 401);
  });
});

describe('POST /logout', () => {
  test('destroys session and redirects to /login', async () => {
    // Get a fresh session
    const { cookie } = await formPost('/login', { username: 'testadmin', password: ADMIN_PASSWORD });
    const { status, location } = await formPost('/logout', {}, { Cookie: cookie });
    assert.equal(status, 302);
    assert.equal(location, '/login');

    // Former cookie no longer grants access
    const { status: after } = await GET('/dashboard', cookie);
    assert.equal(after, 302); // redirect back to login
  });
});

// ---------------------------------------------------------------------------
// Auth guard
// ---------------------------------------------------------------------------

describe('Auth guard', () => {
  test('GET /api/reports returns 401 without session', async () => {
    const { status } = await req('GET', '/api/reports');
    assert.equal(status, 401);
  });

  test('GET /dashboard redirects to /login without session', async () => {
    const { status, headers } = await req('GET', '/dashboard');
    assert.equal(status, 302);
    assert.match(headers.location, /\/login/);
  });

  test('GET /admin redirects to /login without session', async () => {
    const { status } = await req('GET', '/admin');
    assert.equal(status, 302);
  });

  test('GET /admin redirects members to /dashboard', async () => {
    const { status, headers } = await GET('/admin', memberCookie);
    assert.equal(status, 302);
    assert.equal(headers.location, '/dashboard');
  });
});

// ---------------------------------------------------------------------------
// POST /api/reports — webhook auth (per-user secret)
// ---------------------------------------------------------------------------

describe('POST /api/reports — auth', () => {
  test('returns 401 when X-Webhook-Secret is missing', async () => {
    const { status, body } = await req('POST', '/api/reports', { body: VALID_REPORT });
    assert.equal(status, 401);
    assert.match(body.error, /missing/i);
  });

  test('returns 401 when X-Webhook-Secret does not match any user', async () => {
    const { status } = await req('POST', '/api/reports', {
      body: VALID_REPORT,
      headers: { 'X-Webhook-Secret': 'completely-wrong-secret' },
    });
    assert.equal(status, 401);
  });
});

// ---------------------------------------------------------------------------
// POST /api/reports — validation
// ---------------------------------------------------------------------------

describe('POST /api/reports — validation', () => {
  test('returns 422 when buildId is missing', async () => {
    const { buildId: _, ...without } = VALID_REPORT;
    const { status, body } = await post(without);
    assert.equal(status, 422);
    assert.ok(body.details.some(e => e.includes('buildId')));
  });

  test('returns 422 when commit.sha is missing', async () => {
    const { status, body } = await post({ ...VALID_REPORT, buildId: 'val-001', commit: { author: 'alice' } });
    assert.equal(status, 422);
    assert.ok(body.details.some(e => e.includes('commit.sha')));
  });

  test('returns 422 when status is invalid', async () => {
    const { status, body } = await post({ ...VALID_REPORT, buildId: 'val-002', status: 'pending' });
    assert.equal(status, 422);
    assert.ok(body.details.some(e => e.includes('status')));
  });

  test('returns 422 when branch is missing', async () => {
    const { branch: _, ...without } = VALID_REPORT;
    const { status, body } = await post({ ...without, buildId: 'val-003' });
    assert.equal(status, 422);
    assert.ok(body.details.some(e => e.includes('branch')));
  });
});

// ---------------------------------------------------------------------------
// POST /api/reports — happy path
// ---------------------------------------------------------------------------

describe('POST /api/reports — success', () => {
  test('returns 201, assigns owner from webhook secret', async () => {
    const { status, body } = await post(VALID_REPORT);
    assert.equal(status, 201);
    assert.equal(body.buildId, VALID_REPORT.buildId);
    assert.equal(body.status, 'success');
    assert.equal(body.branch, 'main');
    assert.equal(body.commit.sha, VALID_REPORT.commit.sha);
    assert.equal(body.testResults.passed, 10);
    assert.equal(body.testResults.skipped, 2);
    assert.equal(body.owner, 'testadmin');
    assert.ok(body.receivedAt);
    assert.ok(body.id);
  });

  test('member webhook secret assigns member as owner', async () => {
    const payload = { ...VALID_REPORT, buildId: 'build-member-001', branch: 'feature/x' };
    const { status, body } = await post(payload, MEMBER_WEBHOOK_SECRET);
    assert.equal(status, 201);
    assert.equal(body.owner, 'testmember');
  });

  test('returns 409 on duplicate buildId', async () => {
    const { status } = await post(VALID_REPORT);
    assert.equal(status, 409);
  });

  test('accepts failure and cancelled statuses', async () => {
    for (const [i, s] of ['failure', 'cancelled'].entries()) {
      const { status, body } = await post({ ...VALID_REPORT, buildId: `build-status-${i}`, status: s });
      assert.equal(status, 201);
      assert.equal(body.status, s);
    }
  });

  test('stores optional metadata without error', async () => {
    const { status } = await post({
      ...VALID_REPORT, buildId: 'build-meta',
      metadata: { environment: 'staging', triggeredBy: 'push' },
    });
    assert.equal(status, 201);
  });
});

// ---------------------------------------------------------------------------
// GET /api/reports — scoping
// ---------------------------------------------------------------------------

describe('GET /api/reports — scoping', () => {
  test('admin sees all reports', async () => {
    const { status, body } = await GET('/api/reports', adminCookie);
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.data));
    const owners = new Set(body.data.map(r => r.owner));
    assert.ok(owners.has('testadmin'));
    assert.ok(owners.has('testmember'));
  });

  test('member sees only their own reports', async () => {
    const { status, body } = await GET('/api/reports', memberCookie);
    assert.equal(status, 200);
    assert.ok(body.data.every(r => r.owner === 'testmember'));
  });

  test('filters by branch', async () => {
    const { body } = await GET('/api/reports?branch=main', adminCookie);
    assert.ok(body.data.every(r => r.branch === 'main'));
  });

  test('filters by status', async () => {
    const { body } = await GET('/api/reports?status=success', adminCookie);
    assert.ok(body.data.every(r => r.status === 'success'));
  });

  test('respects limit param', async () => {
    const { body } = await GET('/api/reports?limit=2', adminCookie);
    assert.ok(body.data.length <= 2);
    assert.equal(body.pagination.limit, 2);
  });

  test('pagination meta is present', async () => {
    const { body } = await GET('/api/reports', adminCookie);
    assert.ok(body.pagination);
    assert.ok(body.pagination.total >= 0);
  });
});

// ---------------------------------------------------------------------------
// GET /api/reports/:buildId
// ---------------------------------------------------------------------------

describe('GET /api/reports/:buildId', () => {
  test('admin can fetch any report', async () => {
    const { status, body } = await GET(`/api/reports/${VALID_REPORT.buildId}`, adminCookie);
    assert.equal(status, 200);
    assert.equal(body.buildId, VALID_REPORT.buildId);
  });

  test('member cannot fetch another user\'s report', async () => {
    // VALID_REPORT was submitted with admin secret
    const { status } = await GET(`/api/reports/${VALID_REPORT.buildId}`, memberCookie);
    assert.equal(status, 404);
  });

  test('member can fetch their own report', async () => {
    const { status, body } = await GET('/api/reports/build-member-001', memberCookie);
    assert.equal(status, 200);
    assert.equal(body.buildId, 'build-member-001');
  });

  test('returns 404 for unknown buildId', async () => {
    const { status } = await GET('/api/reports/does-not-exist-xyz', adminCookie);
    assert.equal(status, 404);
  });
});

// ---------------------------------------------------------------------------
// GET /dashboard
// ---------------------------------------------------------------------------

describe('GET /dashboard', () => {
  test('returns HTML with DASHBOARD_DATA injected', async () => {
    const { status, body, headers } = await GET('/dashboard', adminCookie);
    assert.equal(status, 200);
    assert.ok(headers['content-type'].includes('text/html'));
    assert.ok(typeof body === 'string' && body.includes('DASHBOARD_DATA'));
    assert.ok(body.includes('CI Build Dashboard'));
  });

  test('DASHBOARD_DATA contains user info', async () => {
    const { body } = await GET('/dashboard', adminCookie);
    assert.ok(body.includes('"username":"testadmin"'));
    assert.ok(body.includes('"role":"admin"'));
  });
});

// ---------------------------------------------------------------------------
// GET /admin
// ---------------------------------------------------------------------------

describe('GET /admin', () => {
  test('admin gets admin panel HTML', async () => {
    const { status, body, headers } = await GET('/admin', adminCookie);
    assert.equal(status, 200);
    assert.ok(headers['content-type'].includes('text/html'));
    assert.ok(body.includes('ADMIN_DATA'));
    assert.ok(body.includes('testadmin'));
  });
});

// ---------------------------------------------------------------------------
// Admin panel actions
// ---------------------------------------------------------------------------

describe('Admin panel actions', () => {
  test('POST /admin/invite creates a new member user', async () => {
    const { status, location } = await formPost(
      '/admin/invite',
      { username: 'newbie', email: 'newbie@test.com' },
      { Cookie: adminCookie },
    );
    assert.equal(status, 302);
    assert.match(location, /invited=newbie/);

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get('newbie');
    assert.ok(user);
    assert.equal(user.role, 'member');
    assert.ok(user.webhook_secret);
  });

  test('POST /admin/invite rejects duplicate username', async () => {
    const { location } = await formPost(
      '/admin/invite',
      { username: 'newbie' },
      { Cookie: adminCookie },
    );
    assert.match(location, /error=duplicate-username/);
  });

  test('POST /admin/users/:id/role toggles role', async () => {
    const before = db.prepare('SELECT role FROM users WHERE id = ?').get(memberId);
    assert.equal(before.role, 'member');

    const { status } = await formPost(
      `/admin/users/${memberId}/role`, {},
      { Cookie: adminCookie },
    );
    assert.equal(status, 302);

    const after = db.prepare('SELECT role FROM users WHERE id = ?').get(memberId);
    assert.equal(after.role, 'admin');

    // Toggle back
    await formPost(`/admin/users/${memberId}/role`, {}, { Cookie: adminCookie });
    const restored = db.prepare('SELECT role FROM users WHERE id = ?').get(memberId);
    assert.equal(restored.role, 'member');
  });

  test('admin cannot change their own role', async () => {
    const { location } = await formPost(
      `/admin/users/${adminId}/role`, {},
      { Cookie: adminCookie },
    );
    assert.match(location, /error=cannot-change-own-role/);
  });

  test('POST /admin/users/:id/regenerate-secret changes the secret', async () => {
    const before = db.prepare('SELECT webhook_secret FROM users WHERE id = ?').get(memberId).webhook_secret;
    await formPost(`/admin/users/${memberId}/regenerate-secret`, {}, { Cookie: adminCookie });
    const after = db.prepare('SELECT webhook_secret FROM users WHERE id = ?').get(memberId).webhook_secret;
    assert.notEqual(before, after);
    assert.equal(after.length, 64); // 32 bytes hex
  });

  test('POST /admin/users/:id/delete reassigns reports and removes user', async () => {
    // Create a temp user with a report
    const hash   = bcrypt.hashSync('tmp', 1);
    const secret = crypto.randomBytes(16).toString('hex');
    const r      = db.prepare(`
      INSERT INTO users (username, email, password_hash, role, webhook_secret, created_at)
      VALUES (?, ?, ?, 'member', ?, ?)
    `).run('tmpuser', null, hash, secret, new Date().toISOString());
    const tmpId  = r.lastInsertRowid;

    db.prepare(`
      INSERT INTO reports (received_at, build_id, branch, commit_sha, author, status, raw_json, owner_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(new Date().toISOString(), 'tmp-build', 'main', 'abc', 'x', 'success', '{}', tmpId);

    const { status } = await formPost(
      `/admin/users/${tmpId}/delete`, {},
      { Cookie: adminCookie },
    );
    assert.equal(status, 302);

    // User gone
    assert.equal(db.prepare('SELECT id FROM users WHERE id = ?').get(tmpId), undefined);
    // Report reassigned to admin
    const report = db.prepare('SELECT owner_id FROM reports WHERE build_id = ?').get('tmp-build');
    assert.equal(report.owner_id, adminId);
  });

  test('admin cannot delete themselves', async () => {
    const { location } = await formPost(
      `/admin/users/${adminId}/delete`, {},
      { Cookie: adminCookie },
    );
    assert.match(location, /error=cannot-delete-self/);
  });
});
