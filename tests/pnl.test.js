// tests/pnl.test.js
// Automated Verification for Offers Profit & Loss Calculations, Concurrency, and RBAC
const assert = require('assert');
const pnlHandler = require('../api/pnl');
const { createSessionToken } = require('../api/_security');
const {
  createReward,
  redeemRewardAtomic,
  updateCampaignFinances,
  getOffersProfitLoss,
  bootstrapOwnerIfEmpty,
} = require('../api/_db');

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

async function runPnlTests() {
  console.log('--- RUNNING OFFERS PROFIT & LOSS TESTS ---');
  await bootstrapOwnerIfEmpty();

  const ownerToken = createSessionToken({
    id: 'usr-owner-mom',
    username: 'owner',
    full_name: 'Mom',
    role: 'OWNER',
  });

  const staffToken = createSessionToken({
    id: 'usr-staff-alex',
    username: 'alex',
    full_name: 'Alex Staff',
    role: 'STAFF',
  });

  // 1. Accurate Calculations: Net Profit, Margin, and ROI
  {
    const campaignId = 'cmp-test-pnl-1';
    await updateCampaignFinances(
      campaignId,
      {
        campaign_name: 'Summer Movie Popcorn Fest',
        status: 'ACTIVE',
        start_date: '2026-06-01',
        end_date: '2026-06-30',
        attributed_sales: 1000.0,
        product_cost: 300.0,
        packaging_cost: 50.0,
        other_expenses: 50.0,
        unit_reward_cost: 2.0, // $2 per collected gift
        is_estimate: false,
      },
      'Mom (Owner)'
    );

    // Create 3 rewards for this campaign: 2 collected, 1 waiting
    const r1 = await createReward({
      code: 'PC-PNL1',
      customer_name: 'Winner 1',
      campaign_id: campaignId,
    });
    const r2 = await createReward({
      code: 'PC-PNL2',
      customer_name: 'Winner 2',
      campaign_id: campaignId,
    });
    const r3 = await createReward({
      code: 'PC-PNL3',
      customer_name: 'Winner 3',
      campaign_id: campaignId,
    });

    // Redeem exactly 2 rewards atomically
    await redeemRewardAtomic({
      code: r1.code,
      operator_id: 'usr-staff-alex',
      operator_name: 'Alex Staff',
    });
    await redeemRewardAtomic({
      code: r2.code,
      operator_id: 'usr-staff-alex',
      operator_name: 'Alex Staff',
    });
    // r3 remains WAITING

    const report = await getOffersProfitLoss({ campaignId });
    const offer = report.offers.find(o => o.campaign_id === campaignId);

    assert.ok(offer, 'Offer must exist in report');
    assert.strictEqual(offer.qr_generated, 3, '3 QR codes generated/won');
    assert.strictEqual(offer.rewards_redeemed, 2, 'Exactly 2 rewards redeemed');

    // Expected calculations:
    // Gift Reward Costs = 2 * $2.00 = $4.00 (waiting r3 costs $0!)
    assert.strictEqual(offer.gift_reward_cost, 4.0, 'Gift reward cost must reflect ONLY collected rewards');

    // Total Expenses = Product ($300) + Gift ($4) + Packaging ($50) + Other ($50) = $404
    assert.strictEqual(offer.total_investment, 404.0, 'Total investment must equal $404.00');

    // Net Offer Profit = Sales ($1000) − Total Expenses ($404) = $596.00
    assert.strictEqual(offer.net_profit, 596.0, 'Net profit must be $596.00');

    // Profit Margin % = ($596 / $1000) * 100 = 59.60%
    assert.strictEqual(offer.profit_margin, 59.6, 'Profit margin must be 59.6%');

    // ROI % = ($596 / $404) * 100 = 147.52%
    assert.strictEqual(offer.roi, 147.52, 'ROI must be 147.52%');

    console.log('✓ Accurate Net Profit, Profit Margin, and ROI calculation formulas verified.');
    console.log('✓ Verified that unredeemed lucky cards do NOT count as gift costs.');
  }

  // 2. Zero-Sales Edge Case: Prevents Division by Zero / NaN
  {
    const zeroSalesId = 'cmp-zero-sales';
    await updateCampaignFinances(
      zeroSalesId,
      {
        campaign_name: 'Early Teaser Campaign',
        status: 'PAUSED',
        attributed_sales: 0,
        product_cost: 100.0,
        packaging_cost: 20.0,
        other_expenses: 10.0,
        unit_reward_cost: 1.0,
      },
      'Mom'
    );

    const report = await getOffersProfitLoss({ campaignId: zeroSalesId });
    const offer = report.offers.find(o => o.campaign_id === zeroSalesId);

    assert.strictEqual(offer.attributed_sales, 0);
    assert.strictEqual(offer.net_profit, -130.0, 'Net loss should be -$130.00');
    assert.strictEqual(offer.profit_margin, 0, 'Zero sales must result in 0% margin (no NaN)');
    assert.strictEqual(offer.roi, -100.0, 'ROI calculation handles loss properly');

    console.log('✓ Zero-sales edge case handled safely without NaN or division by zero.');
  }

  // 3. Zero-Investment Edge Case: Prevents Division by Zero / Infinity
  {
    const zeroInvId = 'cmp-zero-investment';
    await updateCampaignFinances(
      zeroInvId,
      {
        campaign_name: 'Digital Free Promo',
        status: 'ACTIVE',
        attributed_sales: 200.0,
        product_cost: 0,
        packaging_cost: 0,
        other_expenses: 0,
        unit_reward_cost: 0,
      },
      'Mom'
    );

    const report = await getOffersProfitLoss({ campaignId: zeroInvId });
    const offer = report.offers.find(o => o.campaign_id === zeroInvId);

    assert.strictEqual(offer.total_investment, 0);
    assert.strictEqual(offer.roi, 0, 'Zero investment must return 0% ROI (no Infinity)');
    assert.strictEqual(offer.profit_margin, 100.0, 'Profit margin should be 100%');

    console.log('✓ Zero-investment edge case handled safely without Infinity.');
  }

  // 4. Role-Based Access Control (RBAC) on Financial Endpoints
  {
    // A: Unauthenticated request must return 401
    const unauthReq = createMockReq({ method: 'GET' });
    const unauthRes = createMockRes();
    await pnlHandler(unauthReq, unauthRes);
    assert.strictEqual(unauthRes.statusCode, 401, 'Unauthenticated P&L request must return 401');

    // B: Staff user can read P&L
    const staffReadReq = createMockReq({
      method: 'GET',
      headers: { authorization: `Bearer ${staffToken}` },
    });
    const staffReadRes = createMockRes();
    await pnlHandler(staffReadReq, staffReadRes);
    assert.strictEqual(staffReadRes.statusCode, 200, 'Staff can read P&L');

    // C: Staff user CANNOT modify financial numbers (403 Forbidden)
    const staffWriteReq = createMockReq({
      method: 'POST',
      headers: { authorization: `Bearer ${staffToken}` },
      body: {
        action: 'update',
        campaign_id: 'cmp-test-pnl-1',
        attributed_sales: 5000,
      },
    });
    const staffWriteRes = createMockRes();
    await pnlHandler(staffWriteReq, staffWriteRes);
    assert.strictEqual(staffWriteRes.statusCode, 403, 'Staff cannot edit financials (403 Forbidden)');

    // D: Owner Mom can modify financial numbers (200 OK)
    const ownerWriteReq = createMockReq({
      method: 'POST',
      headers: { authorization: `Bearer ${ownerToken}` },
      body: {
        action: 'update',
        campaign_id: 'cmp-test-pnl-1',
        attributed_sales: 1500,
        notes: 'Verified actual POS register sales',
        is_estimate: false,
      },
    });
    const ownerWriteRes = createMockRes();
    await pnlHandler(ownerWriteReq, ownerWriteRes);
    assert.strictEqual(ownerWriteRes.statusCode, 200, 'Owner can edit financials (200 OK)');
    assert.strictEqual(ownerWriteRes.data.success, true);

    console.log('✓ Role-Based Access Control on financial modifications enforced (Fail-Closed).');
  }

  console.log('ALL OFFERS PROFIT & LOSS TESTS PASSED SUCCESSFULLY! ✓\n');
}

runPnlTests().catch(err => {
  console.error('P&L test failure:', err);
  process.exit(1);
});
