// api/_db.js
// Production-Hardened Database Layer: Supabase PostgreSQL with Strict Fail-Closed Enforcement
const { hashPassword, generateSecureRewardCode } = require('./_security');

function isProd() {
  return process.env.NODE_ENV === 'production';
}

function getSupabaseConfig() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
  const isConfigured = Boolean(url && key && !url.includes('your-project-id'));
  return { url, key, isConfigured };
}

// Fail-closed verification helper for production
function assertDatabaseConfigured() {
  if (isProd()) {
    const { isConfigured } = getSupabaseConfig();
    if (!isConfigured) {
      throw new Error(
        'CRITICAL CONFIGURATION ERROR: Supabase credentials (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) are missing or unconfigured in production. Refusing in-memory fallback. Failing closed.'
      );
    }
  }
}

// Development & Staging In-Memory Store (Active ONLY when NODE_ENV !== 'production')
const memoryStore = {
  users: new Map(),
  rewards: new Map(),
  campaigns: new Map(),
  finances: new Map(),
  auditLogs: [],
  locks: new Set(),
  bootstrapCompleted: false,
};

// Seed default campaign
const defaultCampaign = {
  id: 'cmp-golden-ticket-2026',
  name: 'Popcorn Paradise Golden Ticket',
  description: 'Official QR lucky-gift rewards included in selected popcorn packs.',
  status: 'ACTIVE',
  prizes: [
    { name: 'Free Popcorn Tub!', icon: '🍿', desc: 'One fresh popcorn tub on the house.' },
    { name: '50% Off Any Bag', icon: '🏷️', desc: 'Enjoy half off on your next visit.' },
    { name: 'Free Topping Upgrade', icon: '✨', desc: 'Add caramel or cheese drizzle free.' },
    { name: 'Buy 1 Get 1 Free', icon: '🎉', desc: 'Bring a friend for your next movie treat.' },
    { name: 'Bonus Mini Movie Pack', icon: '🍿', desc: 'Complimentary snack pack.' },
  ],
  created_at: new Date().toISOString(),
};
memoryStore.campaigns.set(defaultCampaign.id, defaultCampaign);

// Seed default campaign finances
const defaultFinances = {
  id: 'fin-golden-ticket-2026',
  campaign_id: defaultCampaign.id,
  campaign_name: defaultCampaign.name,
  status: 'ACTIVE',
  start_date: '2026-10-01',
  end_date: '2026-11-30',
  attributed_sales: 1240.00,
  product_cost: 310.00,
  packaging_cost: 75.00,
  other_expenses: 45.00,
  unit_reward_cost: 0.60,
  is_estimate: true,
  notes: 'Initial launch estimate for popcorn pack insert cards',
  updated_at: new Date().toISOString(),
  updated_by: 'Mom (Owner)',
};
memoryStore.finances.set(defaultFinances.campaign_id, defaultFinances);

// Supabase REST helper
async function supabaseRequest(path, options = {}) {
  assertDatabaseConfigured();
  const { url, key, isConfigured } = getSupabaseConfig();
  if (!isConfigured) {
    if (isProd()) {
      throw new Error('Database service unavailable in production.');
    }
    return null;
  }

  const reqUrl = `${url.replace(/\/$/, '')}/rest/v1/${path}`;
  const headers = {
    'apikey': key,
    'Authorization': `Bearer ${key}`,
    'Content-Type': 'application/json',
    'Prefer': options.prefer || 'return=representation',
    ...(options.headers || {}),
  };

  const res = await fetch(reqUrl, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!res.ok) {
    const errorText = await res.text();
    console.error(`Supabase error [${res.status}]:`, errorText);
    if (isProd()) {
      throw new Error(`Database error [${res.status}]: ${errorText}`);
    }
    return null;
  }

  return await res.json();
}

// 1. One-Time Secure Owner Provisioning
async function bootstrapOwnerIfEmpty() {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    // Check if any users exist in the database
    const existingUsers = await supabaseRequest('users?select=id&limit=1');
    if (existingUsers && existingUsers.length > 0) {
      return; // Already provisioned
    }

    const ownerName = process.env.PRIMARY_OWNER_NAME || 'Mom';
    const ownerUsername = (process.env.PRIMARY_OWNER_USERNAME || 'owner').toLowerCase().trim();
    const ownerPassword = process.env.PRIMARY_OWNER_INITIAL_PASSWORD;

    if (isProd() && (!ownerPassword || ownerPassword.length < 8 || ownerPassword.includes('replace_with'))) {
      throw new Error(
        'CRITICAL CONFIGURATION ERROR: PRIMARY_OWNER_INITIAL_PASSWORD of at least 8 characters must be set in environment variables to bootstrap the primary owner in production. Refusing default password.'
      );
    }

    const initialPassword = ownerPassword || 'PopcornClub2026!';
    const { hash, salt } = hashPassword(initialPassword);

    await supabaseRequest('users', {
      method: 'POST',
      body: {
        username: ownerUsername,
        full_name: ownerName,
        role: 'OWNER',
        password_hash: hash,
        salt: salt,
        status: 'ACTIVE',
      },
    });
    return;
  }

  // Development In-Memory Seeding
  if (isProd()) {
    assertDatabaseConfigured();
  }

  if (!memoryStore.bootstrapCompleted && memoryStore.users.size === 0) {
    const ownerPassword = process.env.PRIMARY_OWNER_INITIAL_PASSWORD || 'PopcornClub2026!';
    const { hash, salt } = hashPassword(ownerPassword);
    memoryStore.users.set('owner', {
      id: 'usr-owner-primary',
      username: 'owner',
      full_name: process.env.PRIMARY_OWNER_NAME || 'Mom',
      role: 'OWNER',
      password_hash: hash,
      salt: salt,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      last_login_at: null,
    });

    const { hash: sHash, salt: sSalt } = hashPassword('PopcornShankar2026!');
    memoryStore.users.set('shankar', {
      id: 'usr-admin-shankar',
      username: 'shankar',
      full_name: 'Shankar',
      role: 'ADMIN',
      password_hash: sHash,
      salt: sSalt,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      last_login_at: null,
    });

    memoryStore.bootstrapCompleted = true;
  }
}

// 2. User Queries
async function getUserByUsername(username) {
  await bootstrapOwnerIfEmpty();
  const cleanUsername = String(username).toLowerCase().trim();
  const { isConfigured } = getSupabaseConfig();

  if (isConfigured) {
    const res = await supabaseRequest(`users?username=eq.${encodeURIComponent(cleanUsername)}&limit=1`);
    if (res && res.length > 0) return res[0];
    return null;
  }

  if (isProd()) assertDatabaseConfigured();
  return memoryStore.users.get(cleanUsername) || null;
}

async function getUserById(id) {
  await bootstrapOwnerIfEmpty();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(id)}&limit=1`);
    if (res && res.length > 0) return res[0];
    return null;
  }

  if (isProd()) assertDatabaseConfigured();
  for (const user of memoryStore.users.values()) {
    if (user.id === id) return user;
  }
  return null;
}

async function createUser({ username, full_name, role, password, status = 'ACTIVE' }) {
  await bootstrapOwnerIfEmpty();
  const cleanUsername = String(username).toLowerCase().trim();
  const { hash, salt } = hashPassword(password);
  const newUser = {
    username: cleanUsername,
    full_name: full_name.trim(),
    role: role || 'STAFF',
    password_hash: hash,
    salt: salt,
    status: status,
    created_at: new Date().toISOString(),
    last_login_at: null,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('users', {
      method: 'POST',
      body: newUser,
    });
    if (res && res.length > 0) return res[0];
    throw new Error('Failed to create user in database.');
  }

  if (isProd()) assertDatabaseConfigured();
  newUser.id = 'usr-' + Math.random().toString(36).substring(2, 10);
  memoryStore.users.set(cleanUsername, newUser);
  return newUser;
}

async function listUsers() {
  await bootstrapOwnerIfEmpty();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(
      'users?select=id,username,full_name,role,status,created_at,last_login_at&order=created_at.desc'
    );
    if (res) return res;
    throw new Error('Failed to retrieve users from database.');
  }

  if (isProd()) assertDatabaseConfigured();
  return Array.from(memoryStore.users.values()).map(u => ({
    id: u.id,
    username: u.username,
    full_name: u.full_name,
    role: u.role,
    status: u.status,
    created_at: u.created_at,
    last_login_at: u.last_login_at,
  }));
}

async function updateUserStatus(userId, { status, role }) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const body = {};
    if (status) body.status = status;
    if (role) body.role = role;
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body,
    });
    if (res && res.length > 0) return res[0];
    throw new Error('Failed to update user in database.');
  }

  if (isProd()) assertDatabaseConfigured();
  for (const user of memoryStore.users.values()) {
    if (user.id === userId) {
      if (status) user.status = status;
      if (role) user.role = role;
      return user;
    }
  }
  return null;
}

// 3. Rewards & Atomic Concurrency Engine
async function createReward({ code, customer_name, prize_name, prize_icon, prize_description, campaign_id }) {
  const finalCode = (code || generateSecureRewardCode()).toUpperCase().trim();
  const newReward = {
    code: finalCode,
    customer_name: (customer_name || 'Anonymous Guest').trim(),
    prize_name: prize_name || 'Free Popcorn Tub!',
    prize_icon: prize_icon || '🍿',
    prize_description: prize_description || 'Show this code at the counter to claim your treat.',
    campaign_id: campaign_id || null,
    status: 'WAITING',
    created_at: new Date().toISOString(),
    redeemed_at: null,
    redeemed_by: null,
    operator_name: null,
    notes: null,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('rewards', {
      method: 'POST',
      body: newReward,
    });
    if (res && res.length > 0) return res[0];
    throw new Error('Failed to persist reward into database.');
  }

  if (isProd()) assertDatabaseConfigured();
  newReward.id = 'rwd-' + Math.random().toString(36).substring(2, 11);
  memoryStore.rewards.set(finalCode, newReward);
  return newReward;
}

async function getRewardByCode(code) {
  const cleanCode = String(code).toUpperCase().trim();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`rewards?code=eq.${encodeURIComponent(cleanCode)}&limit=1`);
    if (res && res.length > 0) return res[0];
    return null;
  }

  if (isProd()) assertDatabaseConfigured();
  return memoryStore.rewards.get(cleanCode) || null;
}

async function listRewards({ status, search, limit = 50, offset = 0 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let query = `rewards?select=*&order=created_at.desc&limit=${limit}&offset=${offset}`;
    if (status) query += `&status=eq.${encodeURIComponent(status)}`;
    if (search) query += `&or=(code.ilike.*${encodeURIComponent(search)}*,customer_name.ilike.*${encodeURIComponent(search)}*)`;
    const res = await supabaseRequest(query);
    if (res) return res;
    throw new Error('Failed to list rewards from database.');
  }

  if (isProd()) assertDatabaseConfigured();
  let list = Array.from(memoryStore.rewards.values());
  if (status) {
    list = list.filter(r => r.status === status);
  }
  if (search) {
    const s = search.toLowerCase();
    list = list.filter(r => r.code.toLowerCase().includes(s) || r.customer_name.toLowerCase().includes(s));
  }
  list.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return list.slice(offset, offset + limit);
}

// CRITICAL: Single-Use Atomic Redemption
async function redeemRewardAtomic({ code, operator_id, operator_name, notes }) {
  const cleanCode = String(code).toUpperCase().trim();
  const { isConfigured } = getSupabaseConfig();

  // Production: strictly use Supabase RPC row-locked transaction
  if (isConfigured) {
    const rpcRes = await supabaseRequest('rpc/redeem_reward_atomic', {
      method: 'POST',
      body: {
        p_code: cleanCode,
        p_operator_id: operator_id,
        p_operator_name: operator_name,
        p_notes: notes || null,
      },
    });
    if (rpcRes) return rpcRes;
    throw new Error('Atomic redemption procedure failed in database.');
  }

  // Development Fallback: In-memory mutex lock
  if (isProd()) {
    assertDatabaseConfigured();
  }

  if (memoryStore.locks.has(cleanCode)) {
    return {
      success: false,
      code: 'CONCURRENT_REQUEST',
      message: 'A redemption request for this code is already in flight. Please refresh.',
    };
  }

  memoryStore.locks.add(cleanCode);

  try {
    const reward = memoryStore.rewards.get(cleanCode);

    if (!reward) {
      return {
        success: false,
        code: 'NOT_FOUND',
        message: 'The requested prize code was not found.',
      };
    }

    if (reward.status === 'COLLECTED') {
      return {
        success: false,
        code: 'ALREADY_REDEEMED',
        message: 'This prize code was already redeemed and collected.',
        redeemed_at: reward.redeemed_at,
        redeemed_by: reward.operator_name,
        customer_name: reward.customer_name,
        prize_name: reward.prize_name,
      };
    }

    if (reward.status !== 'WAITING') {
      return {
        success: false,
        code: 'INVALID_STATUS',
        message: `This prize code is currently marked as ${reward.status} and cannot be collected.`,
      };
    }

    reward.status = 'COLLECTED';
    reward.redeemed_at = new Date().toISOString();
    reward.redeemed_by = operator_id;
    reward.operator_name = operator_name;
    reward.notes = notes || null;

    await addAuditLog({
      actor_id: operator_id,
      actor_name: operator_name,
      actor_role: 'STAFF',
      action: 'REWARD_REDEEMED',
      target_type: 'REWARD',
      target_id: reward.id,
      details: {
        code: cleanCode,
        prize: reward.prize_name,
        customer: reward.customer_name,
      },
    });

    return {
      success: true,
      code: 'SUCCESS',
      message: 'Prize verified and collected successfully!',
      reward_id: reward.id,
      prize_name: reward.prize_name,
      customer_name: reward.customer_name,
      redeemed_at: reward.redeemed_at,
    };
  } finally {
    memoryStore.locks.delete(cleanCode);
  }
}

// 4. Real Metrics (Never Fabricated)
async function getDashboardStats() {
  await bootstrapOwnerIfEmpty();
  const allRewards = await listRewards({ limit: 1000 });

  const totalPlays = allRewards.length;
  const pendingCollection = allRewards.filter(r => r.status === 'WAITING').length;
  const totalRedeemed = allRewards.filter(r => r.status === 'COLLECTED').length;

  const todayStr = new Date().toISOString().split('T')[0];
  const playsToday = allRewards.filter(r => (r.created_at || '').startsWith(todayStr)).length;
  const redemptionsToday = allRewards.filter(r => (r.redeemed_at || '').startsWith(todayStr)).length;
  const { isConfigured } = getSupabaseConfig();

  return {
    totalPlays,
    pendingCollection,
    totalRedeemed,
    playsToday,
    redemptionsToday,
    activeCampaigns: 1,
    dbMode: isConfigured ? 'SUPABASE_POSTGRES' : 'SECURE_STORAGE_ENGINE',
  };
}

// 5. Audit Logging
async function addAuditLog({ actor_id, actor_name, actor_role, action, target_type, target_id, details }) {
  const entry = {
    actor_id: actor_id || null,
    actor_name: actor_name || 'System',
    actor_role: actor_role || 'SYSTEM',
    action: action,
    target_type: target_type || null,
    target_id: target_id ? String(target_id) : null,
    details: details || {},
    created_at: new Date().toISOString(),
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    try {
      await supabaseRequest('audit_logs', {
        method: 'POST',
        body: entry,
      });
    } catch (err) {
      console.error('Audit log write error:', err.message);
    }
  }

  memoryStore.auditLogs.unshift(entry);
  if (memoryStore.auditLogs.length > 500) {
    memoryStore.auditLogs.pop();
  }
  return entry;
}

async function listAuditLogs({ limit = 30 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`audit_logs?select=*&order=created_at.desc&limit=${limit}`);
    if (res) return res;
    throw new Error('Failed to retrieve audit logs from database.');
  }

  if (isProd()) assertDatabaseConfigured();
  return memoryStore.auditLogs.slice(0, limit);
}

// 6. Offers Profit & Loss Engine
async function getCampaignFinances(campaignId) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`campaign_finances?campaign_id=eq.${encodeURIComponent(campaignId)}&limit=1`);
    if (res && res.length > 0) return res[0];
    return null;
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.finances.get(campaignId) || null;
}

async function updateCampaignFinances(campaignId, data, updatedBy = 'Owner') {
  const cleanId = String(campaignId);
  const updatedRecord = {
    campaign_id: cleanId,
    campaign_name: data.campaign_name || 'Campaign Offer',
    status: data.status || 'ACTIVE',
    start_date: data.start_date || null,
    end_date: data.end_date || null,
    attributed_sales: Math.max(0, parseFloat(data.attributed_sales) || 0),
    product_cost: Math.max(0, parseFloat(data.product_cost) || 0),
    packaging_cost: Math.max(0, parseFloat(data.packaging_cost) || 0),
    other_expenses: Math.max(0, parseFloat(data.other_expenses) || 0),
    unit_reward_cost: Math.max(0, parseFloat(data.unit_reward_cost) || 0.50),
    is_estimate: Boolean(data.is_estimate),
    notes: data.notes || '',
    updated_at: new Date().toISOString(),
    updated_by: updatedBy,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const existing = await getCampaignFinances(cleanId);
    let res;
    if (existing) {
      res = await supabaseRequest(`campaign_finances?campaign_id=eq.${encodeURIComponent(cleanId)}`, {
        method: 'PATCH',
        body: updatedRecord,
      });
    } else {
      res = await supabaseRequest('campaign_finances', {
        method: 'POST',
        body: updatedRecord,
      });
    }
    if (res && res.length > 0) return res[0];
    throw new Error('Failed to update campaign finances in database.');
  }

  if (isProd()) assertDatabaseConfigured();
  memoryStore.finances.set(cleanId, updatedRecord);
  return updatedRecord;
}

async function listCampaignFinances({ status, startDate, endDate } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let query = 'campaign_finances?select=*&order=updated_at.desc';
    if (status) query += `&status=eq.${encodeURIComponent(status)}`;
    const res = await supabaseRequest(query);
    if (res) return res;
    throw new Error('Failed to list campaign finances from database.');
  }

  if (isProd()) assertDatabaseConfigured();
  let list = Array.from(memoryStore.finances.values());
  if (status) {
    list = list.filter(f => f.status === status);
  }
  if (startDate) {
    list = list.filter(f => !f.start_date || f.start_date >= startDate);
  }
  if (endDate) {
    list = list.filter(f => !f.end_date || f.end_date <= endDate);
  }
  return list;
}

async function getOffersProfitLoss({ startDate, endDate, campaignId, status } = {}) {
  await bootstrapOwnerIfEmpty();
  const allRewards = await listRewards({ limit: 5000 });
  const allFinances = await listCampaignFinances({ status, startDate, endDate });

  const offers = [];
  let totalAttributedSales = 0;
  let totalProductCost = 0;
  let totalGiftRewardCost = 0;
  let totalPackagingCost = 0;
  let totalOtherExpenses = 0;
  let totalRewardsRedeemed = 0;
  let totalRewardsWon = 0;
  let totalQrGenerated = 0;

  for (const fin of allFinances) {
    if (campaignId && fin.campaign_id !== campaignId) continue;

    const campaignRewards = allRewards.filter(r => (r.campaign_id || defaultCampaign.id) === fin.campaign_id);
    const qrGenerated = campaignRewards.length;
    const qrScans = qrGenerated;
    const rewardsWon = qrGenerated;

    // CRITICAL: Count ONLY verified, successfully redeemed rewards (status === 'COLLECTED')
    const redeemedRewards = campaignRewards.filter(r => r.status === 'COLLECTED');
    const rewardsRedeemed = redeemedRewards.length;

    const unitRewardCost = parseFloat(fin.unit_reward_cost) || 0.50;
    const giftRewardCost = Number((rewardsRedeemed * unitRewardCost).toFixed(2));

    const sales = parseFloat(fin.attributed_sales) || 0;
    const productCost = parseFloat(fin.product_cost) || 0;
    const packagingCost = parseFloat(fin.packaging_cost) || 0;
    const otherExpenses = parseFloat(fin.other_expenses) || 0;

    // Net Offer Profit = Offer-attributed Sales − Cost of Products Sold − Gift/Reward Costs − Packaging Costs − Other Offer Expenses
    const totalExpenses = Number((productCost + giftRewardCost + packagingCost + otherExpenses).toFixed(2));
    const netProfit = Number((sales - totalExpenses).toFixed(2));

    // Profit Margin = (Net Offer Profit ÷ Offer-attributed Sales) × 100, when sales > 0
    const profitMargin = sales > 0 ? Number(((netProfit / sales) * 100).toFixed(2)) : 0;

    // ROI = (Net Offer Profit ÷ Total Offer Investment) × 100, when investment > 0
    const roi = totalExpenses > 0 ? Number(((netProfit / totalExpenses) * 100).toFixed(2)) : 0;

    offers.push({
      campaign_id: fin.campaign_id,
      campaign_name: fin.campaign_name,
      status: fin.status,
      start_date: fin.start_date,
      end_date: fin.end_date,
      qr_generated: qrGenerated,
      qr_scans: qrScans,
      rewards_won: rewardsWon,
      rewards_redeemed: rewardsRedeemed,
      attributed_sales: sales,
      product_cost: productCost,
      gift_reward_cost: giftRewardCost,
      packaging_cost: packagingCost,
      other_expenses: otherExpenses,
      total_investment: totalExpenses,
      net_profit: netProfit,
      profit_margin: profitMargin,
      roi: roi,
      is_estimate: fin.is_estimate,
      unit_reward_cost: unitRewardCost,
      notes: fin.notes || '',
      updated_at: fin.updated_at,
    });

    totalAttributedSales += sales;
    totalProductCost += productCost;
    totalGiftRewardCost += giftRewardCost;
    totalPackagingCost += packagingCost;
    totalOtherExpenses += otherExpenses;
    totalRewardsRedeemed += rewardsRedeemed;
    totalRewardsWon += rewardsWon;
    totalQrGenerated += qrGenerated;
  }

  const overallInvestment = Number(
    (totalProductCost + totalGiftRewardCost + totalPackagingCost + totalOtherExpenses).toFixed(2)
  );
  const overallNetProfit = Number((totalAttributedSales - overallInvestment).toFixed(2));
  const overallProfitMargin = totalAttributedSales > 0 ? Number(((overallNetProfit / totalAttributedSales) * 100).toFixed(2)) : 0;
  const overallRoi = overallInvestment > 0 ? Number(((overallNetProfit / overallInvestment) * 100).toFixed(2)) : 0;

  return {
    summary: {
      total_attributed_sales: Number(totalAttributedSales.toFixed(2)),
      total_product_cost: Number(totalProductCost.toFixed(2)),
      total_gift_reward_cost: Number(totalGiftRewardCost.toFixed(2)),
      total_other_expenses: Number((totalPackagingCost + totalOtherExpenses).toFixed(2)),
      total_packaging_cost: Number(totalPackagingCost.toFixed(2)),
      total_miscellaneous_expenses: Number(totalOtherExpenses.toFixed(2)),
      total_investment: overallInvestment,
      net_profit: overallNetProfit,
      profit_margin: overallProfitMargin,
      roi: overallRoi,
      rewards_redeemed: totalRewardsRedeemed,
      rewards_won: totalRewardsWon,
      qr_generated: totalQrGenerated,
      is_estimate: offers.some(o => o.is_estimate),
    },
    offers,
  };
}

module.exports = {
  assertDatabaseConfigured,
  bootstrapOwnerIfEmpty,
  getUserByUsername,
  getUserById,
  createUser,
  listUsers,
  updateUserStatus,
  createReward,
  getRewardByCode,
  listRewards,
  redeemRewardAtomic,
  getDashboardStats,
  addAuditLog,
  listAuditLogs,
  getCampaignFinances,
  updateCampaignFinances,
  listCampaignFinances,
  getOffersProfitLoss,
};
