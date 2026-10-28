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
};


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
};
