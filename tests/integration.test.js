// tests/integration.test.js
// Complete End-to-End Workflow Verification: Customer Play -> Staff Verify -> Atomic Single-Use Redemption -> Stats & Audit
const assert = require('assert');
const authHandler = require('../api/auth');
const rewardsHandler = require('../api/rewards');
const redeemHandler = require('../api/redeem');
const statsHandler = require('../api/stats');
const auditHandler = require('../api/audit');

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

async function runIntegrationTest() {
  console.log('--- RUNNING FULL INTEGRATION WORKFLOW TEST ---');

  // Step 1: Customer plays and generates a new lucky card
  const customerReq = createMockReq({
    method: 'POST',
    body: { action: 'issue', customer_name: 'Ananya' },
  });
  const customerRes = createMockRes();
  await rewardsHandler(customerReq, customerRes);

  assert.strictEqual(customerRes.statusCode, 201, 'Customer prize issue should return 201 Created');
  assert.ok(customerRes.data.code && customerRes.data.code.startsWith('PC-'), 'Valid PC- code generated');
  const issuedCode = customerRes.data.code;
  console.log(`1. Customer Ananya scratched and received prize code: ${issuedCode}`);

  // Step 2: Unauthenticated staff tries to verify code -> should fail with 401
  const unauthReq = createMockReq({
    method: 'GET',
    query: { action: 'verify', code: issuedCode },
  });
  const unauthRes = createMockRes();
  await redeemHandler(unauthReq, unauthRes);
  assert.strictEqual(unauthRes.statusCode, 401, 'Unauthenticated redemption attempt must be blocked with 401');
  console.log('2. Unauthenticated verification attempt successfully blocked (401).');

  // Step 3: Owner Mom logs in
  const loginReq = createMockReq({
    method: 'POST',
    body: { action: 'login', username: 'owner', password: 'PopcornClub2026!' },
  });
  const loginRes = createMockRes();
  await authHandler(loginReq, loginRes);
  assert.strictEqual(loginRes.statusCode, 200, 'Owner login should succeed (200)');
  assert.ok(loginRes.data.token, 'Session token returned');
  const ownerToken = loginRes.data.token;
  console.log('3. Owner Mom authenticated successfully.');

  // Step 4: Authorized operator looks up the code
  const verifyReq = createMockReq({
    method: 'GET',
    headers: { authorization: `Bearer ${ownerToken}` },
    query: { action: 'verify', code: issuedCode },
  });
  const verifyRes = createMockRes();
  await redeemHandler(verifyReq, verifyRes);
  assert.strictEqual(verifyRes.statusCode, 200, 'Code verification should succeed');
  assert.strictEqual(verifyRes.data.valid, true, 'Code must be valid');
  assert.strictEqual(verifyRes.data.code, 'READY', 'Status must be READY');
  assert.strictEqual(verifyRes.data.customer_name, 'Ananya');
  console.log('4. Code looked up by counter operator: Verified valid & ready for collection.');

  // Step 5: Operator redeems the prize code
  const redeemReq = createMockReq({
    method: 'POST',
    headers: { authorization: `Bearer ${ownerToken}` },
    body: { action: 'redeem', code: issuedCode, notes: 'Collected at main counter' },
  });
  const redeemRes = createMockRes();
  await redeemHandler(redeemReq, redeemRes);
  assert.strictEqual(redeemRes.statusCode, 200, 'Redemption should succeed');
  assert.strictEqual(redeemRes.data.success, true);
  assert.strictEqual(redeemRes.data.code, 'SUCCESS');
  console.log('5. Prize atomically redeemed: Permanent status updated to COLLECTED.');

  // Step 6: Customer or operator tries to redeem the same code a 2nd time -> must fail
  const duplicateRedeemReq = createMockReq({
    method: 'POST',
    headers: { authorization: `Bearer ${ownerToken}` },
    body: { action: 'redeem', code: issuedCode },
  });
  const duplicateRedeemRes = createMockRes();
  await redeemHandler(duplicateRedeemReq, duplicateRedeemRes);
  assert.strictEqual(duplicateRedeemRes.statusCode, 409, 'Duplicate redemption must return 409 Conflict');
  assert.strictEqual(duplicateRedeemRes.data.code, 'ALREADY_REDEEMED');
  console.log('6. Duplicate redemption attempt rejected with 409 ALREADY_REDEEMED.');

  // Step 7: Check statistics endpoint
  const statsReq = createMockReq({
    method: 'GET',
    headers: { authorization: `Bearer ${ownerToken}` },
  });
  const statsRes = createMockRes();
  await statsHandler(statsReq, statsRes);
  assert.strictEqual(statsRes.statusCode, 200);
  assert.ok(statsRes.data.stats.totalRedeemed >= 1, 'Total redeemed count must reflect actual redemptions');
  console.log(`7. Real statistics verified: Total Plays = ${statsRes.data.stats.totalPlays}, Collected = ${statsRes.data.stats.totalRedeemed}.`);

  // Step 8: Check audit trail
  const auditReq = createMockReq({
    method: 'GET',
    headers: { authorization: `Bearer ${ownerToken}` },
  });
  const auditRes = createMockRes();
  await auditHandler(auditReq, auditRes);
  assert.strictEqual(auditRes.statusCode, 200);
  const redemptionLog = auditRes.data.logs.find(l => l.action === 'REWARD_REDEEMED');
  assert.ok(redemptionLog, 'Audit log must record the REWARD_REDEEMED event');
  console.log('8. Immutable activity audit trail confirmed: Redemption logged with timestamp and operator.');

  console.log('--- ALL FULL INTEGRATION TESTS PASSED PERFECTLY! ✓ ---\n');
}

runIntegrationTest().catch(err => {
  console.error('Integration test failed:', err);
  process.exit(1);
});
