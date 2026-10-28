// tests/rbac.test.js
// Automated Role-Based Access Control & Fail-Closed Enforcement Verification
const assert = require('assert');
const authHandler = require('../api/auth');
const auditHandler = require('../api/audit');
const { createSessionToken } = require('../api/_security');

// Mock request / response helpers
function createMockReq({ method = 'GET', headers = {}, body = {}, query = {} }) {
  return {
    method,
    headers: { ...headers },
    body,
    query,
    socket: { remoteAddress: '127.0.0.1' },
  };
}

function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    data: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
      return this;
    },
    json(payload) {
      this.data = payload;
      return this;
    },
  };
  return res;
}

async function runRBACTests() {
  console.log('--- RUNNING ROLE-BASED ACCESS CONTROL (RBAC) TESTS ---');

  const staffToken = createSessionToken({
    id: 'usr-staff-1',
    username: 'staff_alice',
    full_name: 'Alice Staff',
    role: 'STAFF',
  });

  const ownerToken = createSessionToken({
    id: 'usr-owner-mom',
    username: 'mom',
    full_name: 'Mom',
    role: 'OWNER',
  });

  // 1. Unauthenticated request to audit logs must be rejected with 401
  {
    const req = createMockReq({ method: 'GET' });
    const res = createMockRes();
    await auditHandler(req, res);
    assert.strictEqual(res.statusCode, 401, 'Unauthenticated access to audit logs must return 401');
    console.log('✓ Unauthenticated audit request correctly blocked (401).');
  }

  // 2. Staff user attempting to access audit logs must be rejected with 403 Forbidden
  {
    const req = createMockReq({
      method: 'GET',
      headers: { authorization: `Bearer ${staffToken}` },
    });
    const res = createMockRes();
    await auditHandler(req, res);
    assert.strictEqual(res.statusCode, 403, 'Staff user must be denied audit access with 403 Forbidden');
    console.log('✓ Staff user forbidden from audit trail (403).');
  }

  // 3. Staff user attempting to create new user accounts must be rejected with 403 Forbidden
  {
    const req = createMockReq({
      method: 'POST',
      headers: { authorization: `Bearer ${staffToken}` },
      body: { action: 'create-user', username: 'bob', full_name: 'Bob', password: 'password123' },
    });
    const res = createMockRes();
    await authHandler(req, res);
    assert.strictEqual(res.statusCode, 403, 'Staff user cannot create accounts (403)');
    console.log('✓ Staff user forbidden from account creation (403).');
  }

  // 4. Primary Owner user can access audit logs successfully
  {
    const req = createMockReq({
      method: 'GET',
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    const res = createMockRes();
    await auditHandler(req, res);
    assert.strictEqual(res.statusCode, 200, 'Owner user must be permitted to view audit logs');
    assert.ok(res.data.success, 'Response must be success');
    console.log('✓ Owner permitted to inspect audit trail (200).');
  }

  console.log('ALL RBAC TESTS PASSED SUCCESSFULLY! ✓\n');
}

runRBACTests().catch(err => {
  console.error('RBAC test failure:', err);
  process.exit(1);
});
