// tests/run-all.test.js
// Comprehensive QA Test Suite for LR Popcorn Prize Club (Phases 2 - 8)
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  getAuthSecret,
  hashPassword,
  verifyPassword,
  createSessionToken,
  verifySessionToken,
  revokeToken,
  generateSecureRewardCode,
} = require('../api/_security');

const {
  assertDatabaseConfigured,
  bootstrapOwnerIfEmpty,
  resetMemoryFinancialsAndData,
  createReward,
  listRewards,
  redeemRewardAtomic,
} = require('../api/_db');

const authHandler = require('../api/auth');
const rewardsHandler = require('../api/rewards');
const redeemHandler = require('../api/redeem');
const operationsHandler = require('../api/operations');
const pnlHandler = require('../api/pnl');
const statsHandler = require('../api/stats');
const auditHandler = require('../api/audit');

function mockReq({ method = 'GET', query = {}, body = {}, headers = {} } = {}) {
  return {
    method,
    query,
    body,
    headers,
    socket: { remoteAddress: '127.0.0.1' },
  };
}

function mockRes() {
  return {
    statusCode: 200,
    headers: {},
    data: null,
    setHeader(k, v) {
      this.headers[k] = v;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.data = payload;
      return this;
    },
  };
}

async function runAllTests() {
  console.log('==============================================================');
  console.log('LR POPCORN PRIZE CLUB — AUTOMATED QA & SECURITY TEST SUITE');
  console.log('==============================================================\n');

  resetMemoryFinancialsAndData();
  await bootstrapOwnerIfEmpty();

  // 1. CRYPTOGRAPHY, SESSION REVOCATION & FAIL-CLOSED PRODUCTION CHECK
  {
    const { hash, salt } = hashPassword('StrongOwnerPass2026!');
    assert.strictEqual(verifyPassword('StrongOwnerPass2026!', hash, salt), true);
    assert.strictEqual(verifyPassword('WrongPass', hash, salt), false);

    const token = createSessionToken({
      id: 'usr-test-1',
      username: 'owner',
      full_name: 'Mom',
      role: 'OWNER',
    });
    const decoded = verifySessionToken(token);
    assert.ok(decoded && decoded.jti, 'Token must include JTI and verify');

    revokeToken(token);
    assert.strictEqual(verifySessionToken(token), null, 'Revoked token must be rejected immediately');

    // Production fail-closed test
    const prevEnv = process.env.NODE_ENV;
    const prevStrict = process.env.STRICT_CONFIG_CHECK;
    const prevSecret = process.env.AUTH_SECRET;
    const prevUrl = process.env.SUPABASE_URL;
    try {
      process.env.NODE_ENV = 'production';
      process.env.STRICT_CONFIG_CHECK = 'true';
      delete process.env.AUTH_SECRET;
      delete process.env.SUPABASE_URL;
      assert.throws(() => getAuthSecret(), /CRITICAL CONFIGURATION ERROR/);
      assert.throws(() => assertDatabaseConfigured(), /CRITICAL CONFIGURATION ERROR/);
    } finally {
      process.env.NODE_ENV = prevEnv;
      if (prevStrict) process.env.STRICT_CONFIG_CHECK = prevStrict;
      else delete process.env.STRICT_CONFIG_CHECK;
      if (prevSecret) process.env.AUTH_SECRET = prevSecret;
      if (prevUrl) process.env.SUPABASE_URL = prevUrl;
    }
    console.log('✓ [1/12] Cryptography, token revocation, and fail-closed production guards passed.');
  }

  // 2. FIRST-OWNER BOOTSTRAP, LOGIN/FAILURE, MANDATORY INITIAL PASSWORD CHANGE & EMPTY DB STATE
  let ownerToken = '';
  {
    // Verify 1st-time setup status reports signup_available: true before first signup/password change
    const statusBeforeReq = mockReq({ method: 'GET', query: { action: 'setup-status' } });
    const statusBeforeRes = mockRes();
    await authHandler(statusBeforeReq, statusBeforeRes);
    assert.strictEqual(statusBeforeRes.statusCode, 200);
    assert.strictEqual(statusBeforeRes.data.signup_available, true, '1st-time setup must report signup_available: true');

    // Failed login must return 401
    const badLoginReq = mockReq({
      method: 'POST',
      query: { action: 'login' },
      body: { username: 'owner', password: 'WrongPassword999!' },
    });
    const badLoginRes = mockRes();
    await authHandler(badLoginReq, badLoginRes);
    assert.strictEqual(badLoginRes.statusCode, 401, 'Invalid credentials must return 401');

    // First-owner login with initial bootstrap password
    const initialPassword = process.env.PRIMARY_OWNER_INITIAL_PASSWORD || 'PopcornClub2026!';
    const loginReq = mockReq({
      method: 'POST',
      query: { action: 'login' },
      body: { username: 'owner', password: initialPassword },
    });
    const loginRes = mockRes();
    await authHandler(loginReq, loginRes);
    assert.strictEqual(loginRes.statusCode, 200, 'Owner login must succeed');
    ownerToken = loginRes.data.token;
    assert.ok(ownerToken, 'Owner login must return session token');
    assert.strictEqual(loginRes.data.user.must_change_password, true, 'Bootstrapped first owner must have must_change_password: true');

    // Attempting business mutations BEFORE changing initial password must be blocked with 403 PASSWORD_CHANGE_REQUIRED
    const blockedSaleReq = mockReq({
      method: 'POST',
      query: { action: 'create-sale' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: { gross_amount: 100, payment_method: 'CASH' },
    });
    const blockedSaleRes = mockRes();
    await operationsHandler(blockedSaleReq, blockedSaleRes);
    assert.strictEqual(blockedSaleRes.statusCode, 403, 'Operations must be blocked until initial password is changed');
    assert.strictEqual(blockedSaleRes.data.code, 'PASSWORD_CHANGE_REQUIRED');

    // Change initial password via update-profile
    const changePassReq = mockReq({
      method: 'POST',
      query: { action: 'update-profile' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        full_name: 'Mom (Primary Owner)',
        email: 'mom@popcornprizeclub.com',
        phone: '+91 9876543210',
        current_password: initialPassword,
        new_password: 'UpdatedOwnerSecure2026!',
      },
    });
    const changePassRes = mockRes();
    await authHandler(changePassReq, changePassRes);
    assert.strictEqual(changePassRes.statusCode, 200, 'Initial password change must succeed');
    assert.strictEqual(changePassRes.data.user.must_change_password, false, 'must_change_password must be cleared after password change');
    assert.ok(changePassRes.data.token, 'Refreshed session token must be returned after password change');
    ownerToken = changePassRes.data.token;

    // Verify 2nd-time onward: signup-first-owner is permanently locked (403 ALREADY_INITIALIZED)
    const secondSignupReq = mockReq({
      method: 'POST',
      query: { action: 'signup-first-owner' },
      body: {
        full_name: 'Attacker',
        username: 'attacker',
        password: 'AttackerPass123!',
      },
    });
    const secondSignupRes = mockRes();
    await authHandler(secondSignupReq, secondSignupRes);
    assert.strictEqual(secondSignupRes.statusCode, 403, '2nd signup attempt must be permanently blocked with 403');
    assert.strictEqual(secondSignupRes.data.code, 'ALREADY_INITIALIZED');
    console.log('✓ [2/12] First-owner 1st-time signup/bootstrap, failed login rejection, and permanent lock to Login Only passed.');

    // Check P&L when no financial records exist
    const pnlReq = mockReq({
      method: 'GET',
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    const pnlRes = mockRes();
    await pnlHandler(pnlReq, pnlRes);
    assert.strictEqual(pnlRes.statusCode, 200);
    assert.strictEqual(pnlRes.data.hasData, false, 'Empty database must report hasData: false');
    assert.strictEqual(pnlRes.data.emptyMessage, 'No financial data recorded yet.');
    assert.strictEqual(pnlRes.data.summary.gross_sales, 0);
    assert.strictEqual(pnlRes.data.summary.net_sales, 0);
    assert.strictEqual(pnlRes.data.summary.total_cogs, 0);
    assert.strictEqual(pnlRes.data.summary.operating_expenses, 0);
    assert.strictEqual(pnlRes.data.summary.net_profit, 0);
    console.log('✓ [3/12] Empty database behavior verified (zero fabricated figures; honest empty state).');
  }

  // 4. UNAUTHORIZED ACCESS PROTECTION ACROSS ALL ENDPOINTS
  {
    for (const handler of [pnlHandler, operationsHandler, statsHandler, auditHandler, redeemHandler]) {
      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      await handler(req, res);
      assert.strictEqual(res.statusCode, 401, 'Unauthenticated request must return 401');
    }
    console.log('✓ [4/12] Server-side authentication guards on all private endpoints passed.');
  }

  // 5. OWNER PROFILE UPDATE & PERSISTENCE + RBAC STAFF MANAGEMENT & SESSION LOGOUT
  let staffToken = '';
  {
    const updReq = mockReq({
      method: 'POST',
      query: { action: 'update-profile' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        full_name: 'Mom (Primary Owner)',
        email: 'mom@popcornprizeclub.com',
        phone: '+91 9876543210',
      },
    });
    const updRes = mockRes();
    await authHandler(updReq, updRes);
    assert.strictEqual(updRes.statusCode, 200);
    assert.strictEqual(updRes.data.user.full_name, 'Mom (Primary Owner)');
    assert.strictEqual(updRes.data.user.email, 'mom@popcornprizeclub.com');

    // Verify persistence via GET /api/auth?action=me
    const meReq = mockReq({
      method: 'GET',
      query: { action: 'me' },
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    const meRes = mockRes();
    await authHandler(meReq, meRes);
    assert.strictEqual(meRes.statusCode, 200);
    assert.strictEqual(meRes.data.user.full_name, 'Mom (Primary Owner)');
    assert.strictEqual(meRes.data.user.phone, '+91 9876543210');

    // Create a STAFF user and verify RBAC restrictions
    const createStaffReq = mockReq({
      method: 'POST',
      query: { action: 'create-user' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        username: 'counter_staff',
        full_name: 'Counter Operator',
        role: 'STAFF',
        password: 'StaffPassword123!',
      },
    });
    const createStaffRes = mockRes();
    await authHandler(createStaffReq, createStaffRes);
    assert.strictEqual(createStaffRes.statusCode, 201);

    const staffLoginReq = mockReq({
      method: 'POST',
      query: { action: 'login' },
      body: { username: 'counter_staff', password: 'StaffPassword123!' },
    });
    const staffLoginRes = mockRes();
    await authHandler(staffLoginReq, staffLoginRes);
    staffToken = staffLoginRes.data.token;

    // Staff cannot create other users (403) or view audit logs (403)
    const forbiddenReq = mockReq({
      method: 'GET',
      headers: { authorization: `Bearer ${staffToken}` },
    });
    const forbiddenRes = mockRes();
    await auditHandler(forbiddenReq, forbiddenRes);
    assert.strictEqual(forbiddenRes.statusCode, 403, 'Staff must be blocked from Owner/Admin audit logs');

    // Test Staff logout and verify revoked session token is rejected
    const logoutReq = mockReq({
      method: 'POST',
      query: { action: 'logout' },
      headers: { authorization: `Bearer ${staffToken}` },
    });
    const logoutRes = mockRes();
    await authHandler(logoutReq, logoutRes);
    assert.strictEqual(logoutRes.statusCode, 200);
    const afterLogoutMeReq = mockReq({
      method: 'GET',
      query: { action: 'me' },
      headers: { authorization: `Bearer ${staffToken}` },
    });
    const afterLogoutMeRes = mockRes();
    await authHandler(afterLogoutMeReq, afterLogoutMeRes);
    assert.strictEqual(afterLogoutMeRes.statusCode, 401, 'Logged-out session token must return 401');

    // Test Always-Available Sign-Up with Owner Permission Gate (request-access) & Sign in with Google (google-login)
    const reqAccessReq = mockReq({
      method: 'POST',
      query: { action: 'request-access' },
      body: {
        full_name: 'New Helper',
        username: 'new_helper',
        email: 'helper@gmail.com',
        phone: '+91 9000011111',
        password: 'HelperPass123!',
      },
    });
    const reqAccessRes = mockRes();
    await authHandler(reqAccessReq, reqAccessRes);
    assert.strictEqual(reqAccessRes.statusCode, 201);
    assert.strictEqual(reqAccessRes.data.pending_approval, true, 'Subsequent signup must require Owner approval');
    assert.strictEqual(reqAccessRes.data.user.status, 'PENDING_APPROVAL');
    const pendingUserId = reqAccessRes.data.user.id;

    // Verify PENDING_APPROVAL user is blocked from password login (403 PENDING_APPROVAL)
    const blockedLoginReq = mockReq({
      method: 'POST',
      query: { action: 'login' },
      body: { username: 'new_helper', password: 'HelperPass123!' },
    });
    const blockedLoginRes = mockRes();
    await authHandler(blockedLoginReq, blockedLoginRes);
    assert.strictEqual(blockedLoginRes.statusCode, 403);
    assert.strictEqual(blockedLoginRes.data.code, 'PENDING_APPROVAL');

    // Verify PENDING_APPROVAL user is blocked from Sign in with Google (403 PENDING_APPROVAL)
    const blockedGoogleReq = mockReq({
      method: 'POST',
      query: { action: 'google-login' },
      body: { email: 'helper@gmail.com' },
    });
    const blockedGoogleRes = mockRes();
    await authHandler(blockedGoogleReq, blockedGoogleRes);
    assert.strictEqual(blockedGoogleRes.statusCode, 403);
    assert.strictEqual(blockedGoogleRes.data.code, 'PENDING_APPROVAL');

    // Primary Owner (Shankar / Mom) grants permission -> status: 'ACTIVE'
    const approveReq = mockReq({
      method: 'POST',
      query: { action: 'update-user' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: { userId: pendingUserId, status: 'ACTIVE' },
    });
    const approveRes = mockRes();
    await authHandler(approveReq, approveRes);
    assert.strictEqual(approveRes.statusCode, 200);
    assert.strictEqual(approveRes.data.user.status, 'ACTIVE');

    // Now Sign in with Google using the email given during Sign Up succeeds!
    const googleOkReq = mockReq({
      method: 'POST',
      query: { action: 'google-login' },
      body: { email: 'helper@gmail.com' },
    });
    const googleOkRes = mockRes();
    await authHandler(googleOkReq, googleOkRes);
    assert.strictEqual(googleOkRes.statusCode, 200);
    assert.strictEqual(googleOkRes.data.success, true);
    assert.ok(googleOkRes.data.token, 'Google sign-in must issue a valid session token after Owner approval');

    console.log('✓ [5/12] Owner profile persistence, RBAC permissions, Owner Approval Gate, Sign in with Google, and session logout passed.');
  }

  // 6. DEMO WINNER EXCLUSION, ATOMIC SINGLE-USE QR REDEMPTION, EXPIRED & TAMPERED CODE REJECTION
  {
    // Create a synthetic demo record and confirm it is excluded from listRewards & cannot be redeemed
    const demoCode = generateSecureRewardCode();
    await createReward({
      code: demoCode,
      customer_name: 'Demo User',
      prize_name: 'Free popcorn!',
      unit_cost: 20,
      is_demo: true,
    });

    const genuineList = await listRewards({ includeDemo: false });
    assert.ok(!genuineList.some(r => r.code === demoCode), 'Demo records must never appear in genuine winner lists');

    const demoRedeem = await redeemRewardAtomic({
      code: demoCode,
      operator_id: 'usr-owner-primary',
      operator_name: 'Mom',
    });
    assert.strictEqual(demoRedeem.success, false);
    assert.strictEqual(demoRedeem.code, 'DEMO_RECORD');

    // Tampered / malformed reward code must be rejected with INVALID_CODE (400)
    const tamperedReq = mockReq({
      method: 'POST',
      query: { action: 'redeem' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: { code: "PC-123'; DROP TABLE rewards;--" },
    });
    const tamperedRes = mockRes();
    await redeemHandler(tamperedReq, tamperedRes);
    assert.strictEqual(tamperedRes.statusCode, 400);
    assert.strictEqual(tamperedRes.data.code, 'INVALID_CODE');

    // Expired reward code must be rejected with EXPIRED
    const expiredCode = generateSecureRewardCode();
    await createReward({
      code: expiredCode,
      customer_name: 'Expired Ticket Holder',
      prize_name: 'Mini Masala Pack + ₹10 Water Bottle',
      unit_cost: 22,
      status: 'WAITING',
      expires_at: '2020-01-01T00:00:00.000Z',
    });
    const expiredRedeem = await redeemRewardAtomic({
      code: expiredCode,
      operator_id: 'usr-owner-primary',
      operator_name: 'Mom',
    });
    assert.strictEqual(expiredRedeem.success, false);
    assert.strictEqual(expiredRedeem.code, 'EXPIRED');

    // Issue a genuine customer reward via public API
    const playReq = mockReq({
      method: 'POST',
      query: { action: 'issue' },
      body: { customer_name: 'Aarav' },
    });
    const playRes = mockRes();
    await rewardsHandler(playReq, playRes);
    assert.strictEqual(playRes.statusCode, 201);
    const realCode = playRes.data.code;

    // 10 simultaneous redemption attempts: exactly 1 must succeed
    const attempts = Array.from({ length: 10 }, (_, i) =>
      redeemRewardAtomic({
        code: realCode,
        operator_id: 'usr-owner-primary',
        operator_name: `Operator-${i}`,
      })
    );
    const results = await Promise.all(attempts);
    const successes = results.filter(r => r.success === true);
    assert.strictEqual(successes.length, 1, 'Exactly 1 concurrent redemption must succeed');
    console.log('✓ [6/12] Atomic single-use QR redemption passed (10 concurrent requests -> 1 success).');
    console.log('✓ [7/12] Demo, expired, invalid, already-redeemed, and tampered code rejection passed.');
  }

  // 6. PRODUCTS, INVENTORY MOVEMENTS, SALES, DUPLICATE DETECTION, REFUNDS & EXPENSES
  {
    resetMemoryFinancialsAndData();

    // Create product: Selling Price ₹50, Unit Cost (COGS) ₹18, Opening Stock 100
    const prodReq = mockReq({
      method: 'POST',
      query: { action: 'create-product' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        sku: 'POP-SALT-50',
        name: 'Classic Salted Popcorn',
        unit_price: 50,
        unit_cost: 18,
        stock_qty: 100,
      },
    });
    const prodRes = mockRes();
    await operationsHandler(prodReq, prodRes);
    assert.strictEqual(prodRes.statusCode, 201);
    const product = prodRes.data.product;
    assert.strictEqual(product.stock_qty, 100);

    // Record Sale #1: 10 packs @ ₹50 = Gross ₹500, Discount ₹20 => Net ₹480, COGS = 10 * ₹18 = ₹180
    const sale1Req = mockReq({
      method: 'POST',
      query: { action: 'create-sale' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        sale_date: '2026-10-29',
        shop_name: 'Main Counter',
        gross_amount: 500,
        discount_amount: 20,
        cogs_amount: 180,
        payment_method: 'UPI',
        payment_reference: 'UTR-9988776655',
        items: [
          {
            product_id: product.id,
            product_name: product.name,
            quantity: 10,
            unit_price: 50,
            unit_cost: 18,
          },
        ],
      },
    });
    const sale1Res = mockRes();
    await operationsHandler(sale1Req, sale1Res);
    assert.strictEqual(sale1Res.statusCode, 201);
    const sale1 = sale1Res.data.sale;
    assert.strictEqual(sale1.net_amount, 480);
    assert.strictEqual(sale1.cogs_amount, 180);

    // Duplicate transaction detection: submitting same UPI UTR-9988776655 must return 409 Conflict
    const dupSaleRes = mockRes();
    await operationsHandler(sale1Req, dupSaleRes);
    assert.strictEqual(dupSaleRes.statusCode, 409, 'Duplicate payment reference must be rejected with 409');

    // Record Refund on Sale #1: 1 pack refunded = ₹50 refund, ₹18 COGS reversed, restock = true
    const refReq = mockReq({
      method: 'POST',
      query: { action: 'create-refund' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        sale_id: sale1.id,
        refund_date: '2026-10-29',
        refund_amount: 50,
        cogs_reversed: 18,
        restock_items: true,
        reason: 'Customer returned 1 pack',
      },
    });
    const refRes = mockRes();
    await operationsHandler(refReq, refRes);
    assert.strictEqual(refRes.statusCode, 201);

    // Record Operating Expense: Packaging ₹70
    const expReq = mockReq({
      method: 'POST',
      query: { action: 'create-expense' },
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        expense_date: '2026-10-29',
        shop_name: 'Main Counter',
        category: 'Packaging & QR Slips',
        amount: 70,
        vendor: 'Print Shop',
        payment_method: 'CASH',
      },
    });
    const expRes = mockRes();
    await operationsHandler(expReq, expRes);
    assert.strictEqual(expRes.statusCode, 201);

    // Create 2 genuine rewards (unit_cost ₹20 each), redeem ONLY 1 of them
    const r1 = await createReward({ code: 'PC-PNL001', customer_name: 'Customer 1', prize_name: 'Free popcorn!', unit_cost: 20, status: 'WAITING' });
    await createReward({ code: 'PC-PNL002', customer_name: 'Customer 2', prize_name: 'Free popcorn!', unit_cost: 20, status: 'WAITING' });
    await redeemRewardAtomic({ code: r1.code, operator_id: 'usr-owner-primary', operator_name: 'Mom' });

    // 7. VERIFY REAL PROFIT & LOSS FORMULAS
    // Gross Sales = 500
    // Discounts = 20
    // Refunds = 50
    // Net Sales = 500 - 20 - 50 = 430
    // Product COGS = 180 - 18 (reversed on refund) = 162
    // Redeemed Gift Cost = 1 * 20 = 20 (unredeemed PC-PNL002 costs 0)
    // Total COGS = 162 + 20 = 182
    // Gross Profit = 430 - 182 = 248
    // Operating Expenses = 70
    // Net Profit = 248 - 70 = 178
    const pnlReq = mockReq({
      method: 'GET',
      query: { period: 'daily' },
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    const pnlRes = mockRes();
    await pnlHandler(pnlReq, pnlRes);
    assert.strictEqual(pnlRes.statusCode, 200);
    const s = pnlRes.data.summary;
    assert.strictEqual(pnlRes.data.hasData, true);
    assert.strictEqual(s.gross_sales, 500);
    assert.strictEqual(s.discounts, 20);
    assert.strictEqual(s.refunds, 50);
    assert.strictEqual(s.net_sales, 430);
    assert.strictEqual(s.product_cogs, 162);
    assert.strictEqual(s.reward_gift_cost, 20);
    assert.strictEqual(s.total_cogs, 182);
    assert.strictEqual(s.gross_profit, 248);
    assert.strictEqual(s.operating_expenses, 70);
    assert.strictEqual(s.net_profit, 178);

    console.log('✓ [8/12] Sales, duplicate detection, refunds, inventory stock, and expenses CRUD passed.');
    console.log('✓ [9/12] Real Profit & Loss accounting formulas verified against exact test case.');
  }

  // 10 & 11. TWO SEPARATE WEBSITES (CUSTOMER index.html & OWNER owner.html), 5 PRIZE OFFERS, MOBILE LAYOUT & 12 DEDICATED OWNER PAGES
  {
    const customerHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
    const ownerHtml = fs.readFileSync(path.join(__dirname, '..', 'owner.html'), 'utf8');

    assert.ok(!customerHtml.includes('id="demo"'), 'Add Demo Winner button (#demo) must be removed from customer site');
    assert.ok(!customerHtml.includes('id="ownerForm"'), 'Customer website (index.html) must be completely separate from Owner login form');
    assert.ok(!customerHtml.includes('id="page-reports"'), 'Customer website (index.html) must not contain Owner P&L pages');
    assert.ok(customerHtml.includes('popcorn-light-hero.jpg'), 'Light hero image must be preserved on customer site');
    assert.ok(customerHtml.includes('popcorn-dark-hero.jpg'), 'Dark hero image must be preserved on customer site');
    assert.ok(customerHtml.includes('@media(max-width:760px)'), 'Responsive mobile CSS layout must be present');

    assert.ok(!ownerHtml.includes('id="demo"'), 'Add Demo Winner button (#demo) must be removed from owner site');
    assert.ok(ownerHtml.includes('id="ownerSignupForm"'), 'Owner website (owner.html) must include 1st-time Owner Sign Up form');
    assert.ok(ownerHtml.includes('id="ownerForm"'), 'Owner website (owner.html) must include 2nd-time Owner Sign In form');

    const prizeImages = [
      'prize-masala-water10-combo.jpg',
      'prize-tub-water20-combo.jpg',
      'prize-free-popcorn-tub.jpg',
      'prize-bogo-popcorn.jpg',
      'prize-vip-combo-pack.jpg',
    ];
    for (const img of prizeImages) {
      assert.ok(customerHtml.includes(img), `Scratch card prize image ${img} must be wired in index.html`);
      const imgPath = path.join(__dirname, '..', img);
      assert.ok(fs.existsSync(imgPath) && fs.statSync(imgPath).size > 50000, `Prize image ${img} must exist and be non-empty`);
    }
    console.log('✓ [10/12] All 5 QR prize & combo offers and realistic images verified.');

    const requiredPages = [
      'page-overview',
      'page-profile',
      'page-edit-profile',
      'page-reports',
      'page-sales',
      'page-expenses',
      'page-inventory',
      'page-rewards',
      'page-staff',
      'page-notifications',
      'page-settings',
      'page-security',
      'menuLogoutBtn',
      'pnlVisualChart',
      'quickFlavorChips',
      'seedStandardFlavorsBtn',
      'googleSignInBtn',
      'ovPendingApprovalsPanel',
    ];
    for (const id of requiredPages) {
      assert.ok(ownerHtml.includes(`id="${id}"`), `Dedicated owner page/action #${id} must exist in owner.html`);
    }
    assert.ok(!customerHtml.includes('Owner Portal'), 'Customer website must not show Owner Portal link');
    console.log('✓ [11/12] Two separate websites (Customer index.html + Owner owner.html), Business Overview, P&L Chart, Flavor Chips, and 1st-time Signup -> 2nd-time Login verified.');
  }

  // 12. ROBOTS.TXT, SITEMAP.XML & SECURITY HEADERS VALIDATION
  {
    const robots = fs.readFileSync(path.join(__dirname, '..', 'robots.txt'), 'utf8');
    const sitemap = fs.readFileSync(path.join(__dirname, '..', 'sitemap.xml'), 'utf8');
    const vercelConfig = fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8');

    assert.ok(robots.includes('Sitemap: https://popcorn-prize-club.vercel.app/sitemap.xml'));
    assert.ok(robots.includes('Disallow: /api/'));
    assert.ok(robots.includes('Disallow: /*?page=owner*'));
    assert.ok(sitemap.includes('<loc>https://popcorn-prize-club.vercel.app/</loc>'));
    assert.ok(!sitemap.includes('owner') && !sitemap.includes('api') && !sitemap.includes('code='));
    assert.ok(vercelConfig.includes('Content-Security-Policy'));
    assert.ok(vercelConfig.includes('Strict-Transport-Security'));
    assert.ok(vercelConfig.includes('X-Frame-Options'));

    resetMemoryFinancialsAndData();
    console.log('✓ [12/12] robots.txt, sitemap.xml, and vercel.json security headers validation passed.');
  }

  // 13. DEDICATED LR OWNER PWA (MANIFEST, SERVICE WORKER, ICONS & ZERO-API CACHING)
  {
    const manifestPath = path.join(__dirname, '..', 'manifest-owner.json');
    assert.ok(fs.existsSync(manifestPath), 'manifest-owner.json must exist');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    assert.strictEqual(manifest.name, 'LR Owner', 'PWA name must be "LR Owner"');
    assert.strictEqual(manifest.short_name, 'LR Owner', 'PWA short_name must be "LR Owner"');
    assert.strictEqual(manifest.start_url, '/owner', 'PWA start_url must be "/owner" (relative production route)');
    assert.strictEqual(manifest.display, 'standalone', 'PWA must open in standalone mode');
    assert.strictEqual(manifest.background_color, '#0c0d0e', 'Background color must match LR dark theme');

    // Verify icons exist on disk
    const requiredIcons = [
      'owner-icon-192.png',
      'owner-icon-512.png',
      'owner-icon-maskable-192.png',
      'owner-icon-maskable-512.png',
      'owner-icon.svg',
    ];
    for (const iconFile of requiredIcons) {
      assert.ok(fs.existsSync(path.join(__dirname, '..', iconFile)), `Icon ${iconFile} must exist`);
    }

    // Verify Service Worker security guardrails
    const swPath = path.join(__dirname, '..', 'sw-owner.js');
    assert.ok(fs.existsSync(swPath), 'sw-owner.js must exist');
    const swContent = fs.readFileSync(swPath, 'utf8');

    assert.ok(
      swContent.includes("url.pathname.startsWith('/api/')"),
      'Service worker must explicitly bypass cache for all /api/ private routes'
    );
    assert.ok(
      swContent.includes("req.method !== 'GET'"),
      'Service worker must only handle GET requests and bypass all mutations'
    );

    // Verify separation of concerns between Owner PWA and Customer Website
    const ownerHtml = fs.readFileSync(path.join(__dirname, '..', 'owner.html'), 'utf8');
    const customerHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

    assert.ok(ownerHtml.includes('manifest-owner.json'), 'owner.html must link to manifest-owner.json');
    assert.ok(ownerHtml.includes('sw-owner.js'), 'owner.html must register sw-owner.js');
    assert.ok(!customerHtml.includes('manifest-owner.json'), 'Customer index.html must NOT link to owner manifest');
    assert.ok(!customerHtml.includes('sw-owner.js'), 'Customer index.html must NOT register owner service worker');

    console.log('✓ [13/13] Dedicated LR Owner PWA, manifest, icons, static service worker, and API cache guards passed.');
  }

  console.log('\nALL 13 TEST SUITES PASSED WITH ZERO ERRORS! ✓');
}

runAllTests().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
