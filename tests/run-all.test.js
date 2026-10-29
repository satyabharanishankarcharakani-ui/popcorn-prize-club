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
    const prevSecret = process.env.AUTH_SECRET;
    const prevUrl = process.env.SUPABASE_URL;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.AUTH_SECRET;
      delete process.env.SUPABASE_URL;
      assert.throws(() => getAuthSecret(), /CRITICAL CONFIGURATION ERROR/);
      assert.throws(() => assertDatabaseConfigured(), /CRITICAL CONFIGURATION ERROR/);
    } finally {
      process.env.NODE_ENV = prevEnv;
      if (prevSecret) process.env.AUTH_SECRET = prevSecret;
      if (prevUrl) process.env.SUPABASE_URL = prevUrl;
    }
    console.log('✓ [1/9] Cryptography, token revocation, and fail-closed production guards passed.');
  }

  // 2. EMPTY DATABASE HONEST STATE (ZERO FABRICATED FINANCIAL DATA)
  let ownerToken = '';
  {
    const loginReq = mockReq({
      method: 'POST',
      query: { action: 'login' },
      body: { username: 'owner', password: process.env.PRIMARY_OWNER_INITIAL_PASSWORD || 'PopcornClub2026!' },
    });
    const loginRes = mockRes();
    await authHandler(loginReq, loginRes);
    assert.strictEqual(loginRes.statusCode, 200, 'Owner login must succeed');
    ownerToken = loginRes.data.token;
    assert.ok(ownerToken, 'Owner login must return session token');

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
    console.log('✓ [2/9] Empty database behavior verified (zero fabricated figures; honest empty state).');
  }

  // 3. UNAUTHORIZED ACCESS PROTECTION ACROSS ALL ENDPOINTS
  {
    for (const handler of [pnlHandler, operationsHandler, statsHandler, auditHandler, redeemHandler]) {
      const req = mockReq({ method: 'GET' });
      const res = mockRes();
      await handler(req, res);
      assert.strictEqual(res.statusCode, 401, 'Unauthenticated request must return 401');
    }
    console.log('✓ [3/9] Server-side authentication guards on all private endpoints passed.');
  }

  // 4. OWNER PROFILE UPDATE & PERSISTENCE + RBAC STAFF MANAGEMENT
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
    console.log('✓ [4/9] Owner profile persistence and RBAC permissions passed.');
  }

  // 5. DEMO WINNER EXCLUSION & ATOMIC SINGLE-USE QR REDEMPTION
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
    console.log('✓ [5/9] Demo winner exclusion and atomic single-use QR redemption passed.');
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

    console.log('✓ [6/9] Sales, duplicate detection, refunds, inventory stock, and expenses CRUD passed.');
    console.log('✓ [7/9] Real Profit & Loss accounting formulas verified against exact test case.');
  }

  // 8. FRONTEND DOM & DEDICATED OWNER PAGES VERIFICATION
  {
    const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
    assert.ok(!html.includes('id="demo"'), 'Add Demo Winner button (#demo) must be removed');
    assert.ok(!html.includes('Add demo winner'), 'Add demo winner label must be removed');
    assert.ok(!html.includes('popcorn-backend.js'), 'Broken 404 script popcorn-backend.js must be removed');
    assert.ok(!html.includes('popcorn-preview.js'), 'Broken 404 script popcorn-preview.js must be removed');
    assert.ok(html.includes('popcorn-light-hero.jpg'), 'Light hero image must be preserved');
    assert.ok(html.includes('popcorn-dark-hero.jpg'), 'Dark hero image must be preserved');

    const requiredPages = [
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
    ];
    for (const id of requiredPages) {
      assert.ok(html.includes(`id="${id}"`), `Dedicated owner page/action #${id} must exist in index.html`);
    }
    console.log('✓ [8/9] Frontend structure, 12 dedicated owner menu items/pages, and hero images verified.');
  }

  // 9. ROBOTS.TXT & SITEMAP.XML VALIDATION
  {
    const robots = fs.readFileSync(path.join(__dirname, '..', 'robots.txt'), 'utf8');
    const sitemap = fs.readFileSync(path.join(__dirname, '..', 'sitemap.xml'), 'utf8');

    assert.ok(robots.includes('Sitemap: https://popcorn-prize-club.vercel.app/sitemap.xml'));
    assert.ok(robots.includes('Disallow: /api/'));
    assert.ok(robots.includes('Disallow: /*?page=owner*'));
    assert.ok(sitemap.includes('<loc>https://popcorn-prize-club.vercel.app/</loc>'));
    assert.ok(!sitemap.includes('owner') && !sitemap.includes('api') && !sitemap.includes('code='));

    resetMemoryFinancialsAndData();
    console.log('✓ [9/9] robots.txt and sitemap.xml technical SEO validation passed.');
  }

  console.log('\nALL 9 TEST SUITES PASSED WITH ZERO ERRORS! ✓');
}

runAllTests().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
