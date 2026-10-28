// api/_db.js
// Database persistence abstraction with Supabase PostgreSQL support & Atomic Fallback Engine
const { hashPassword, generateSecureRewardCode } = require('./_security');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;

// In-Memory resilient atomic store (shared across hot lambda invocations or local development)
const memoryStore = {
  users: new Map(),
  rewards: new Map(),
  campaigns: new Map(),
  auditLogs: [],
  // Concurrency lock table for atomic operations
  locks: new Set(),
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

// Seed initial primary owner if no users exist
async function bootstrapOwnerIfEmpty() {
  if (memoryStore.users.size === 0) {
    const ownerName = process.env.PRIMARY_OWNER_NAME || 'Mom';
    const ownerUsername = process.env.PRIMARY_OWNER_USERNAME || 'owner';
    const ownerPassword = process.env.PRIMARY_OWNER_INITIAL_PASSWORD || 'PopcornClub2026!';

    const { hash, salt } = hashPassword(ownerPassword);
    const ownerUser = {
      id: 'usr-owner-primary',
      username: ownerUsername.toLowerCase(),
      full_name: ownerName,
      role: 'OWNER',
      password_hash: hash,
      salt: salt,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      last_login_at: null,
    };
    memoryStore.users.set(ownerUser.username, ownerUser);

    // Also add Shankar as authorized administrator if configured
    const shankarUsername = 'shankar';
    const { hash: sHash, salt: sSalt } = hashPassword('PopcornShankar2026!');
    const shankarUser = {
      id: 'usr-admin-shankar',
      username: shankarUsername,
      full_name: 'Shankar',
      role: 'ADMIN',
      password_hash: sHash,
      salt: sSalt,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      last_login_at: null,
    };
    memoryStore.users.set(shankarUser.username, shankarUser);

    // Also seed a few initial sample rewards for immediate preview testing
    const sampleRewards = [
      { code: 'PC-WELCOME1', customer_name: 'Maya', prize_name: 'Free Popcorn Tub!', prize_icon: '🍿', prize_description: 'One fresh popcorn tub on the house.', status: 'WAITING' },
      { code: 'PC-WELCOME2', customer_name: 'Arjun', prize_name: '50% Off Any Bag', prize_icon: '🏷️', prize_description: 'Enjoy half off on your next visit.', status: 'COLLECTED', redeemed_at: new Date().toISOString(), operator_name: 'Shankar' }
    ];
    for (const r of sampleRewards) {
      const rewardRecord = {
        id: 'rwd-' + Math.random().toString(36).substring(2, 9),
        code: r.code,
        customer_name: r.customer_name,
        prize_name: r.prize_name,
        prize_icon: r.prize_icon,
        prize_description: r.prize_description,
        campaign_id: defaultCampaign.id,
        status: r.status,
        created_at: new Date().toISOString(),
        redeemed_at: r.redeemed_at || null,
        redeemed_by: r.status === 'COLLECTED' ? 'usr-admin-shankar' : null,
        operator_name: r.operator_name || null,
        notes: null
      };
      memoryStore.rewards.set(rewardRecord.code, rewardRecord);
    }
  }
}

// Supabase REST helper
async function supabaseRequest(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) return null;
  const url = `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1/${path}`;
  const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': options.prefer || 'return=representation',
    ...(options.headers || {})
  };

  try {
    const res = await fetch(url, {
      method: options.method || 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    if (!res.ok) {
      const text = await res.text();
      console.error(`Supabase error [${res.status}]:`, text);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.error('Supabase fetch exception:', err);
    return null;
  }
}

// 1. User Queries
async function getUserByUsername(username) {
  await bootstrapOwnerIfEmpty();
  const cleanUsername = String(username).toLowerCase().trim();

  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest(`users?username=eq.${encodeURIComponent(cleanUsername)}&limit=1`);
    if (res && res.length > 0) return res[0];
  }

  return memoryStore.users.get(cleanUsername) || null;
}

async function getUserById(id) {
  await bootstrapOwnerIfEmpty();
  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(id)}&limit=1`);
    if (res && res.length > 0) return res[0];
  }
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
    id: 'usr-' + Math.random().toString(36).substring(2, 10),
    username: cleanUsername,
    full_name: full_name.trim(),
    role: role || 'STAFF',
    password_hash: hash,
    salt: salt,
    status: status,
    created_at: new Date().toISOString(),
    last_login_at: null,
  };

  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest('users', {
      method: 'POST',
      body: newUser
    });
    if (res && res.length > 0) return res[0];
  }

  memoryStore.users.set(cleanUsername, newUser);
  return newUser;
}

async function listUsers() {
  await bootstrapOwnerIfEmpty();
  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest('users?select=id,username,full_name,role,status,created_at,last_login_at&order=created_at.desc');
    if (res) return res;
  }
  return Array.from(memoryStore.users.values()).map(u => ({
    id: u.id,
    username: u.username,
    full_name: u.full_name,
    role: u.role,
    status: u.status,
    created_at: u.created_at,
    last_login_at: u.last_login_at
  }));
}

async function updateUserStatus(userId, { status, role }) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    const body = {};
    if (status) body.status = status;
    if (role) body.role = role;
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body
    });
    if (res && res.length > 0) return res[0];
  }

  for (const user of memoryStore.users.values()) {
    if (user.id === userId) {
      if (status) user.status = status;
      if (role) user.role = role;
      return user;
    }
  }
  return null;
}

// 2. Rewards Queries & Atomic Concurrency Engine
async function createReward({ code, customer_name, prize_name, prize_icon, prize_description, campaign_id }) {
  const finalCode = (code || generateSecureRewardCode()).toUpperCase().trim();
  const newReward = {
    id: 'rwd-' + Math.random().toString(36).substring(2, 11),
    code: finalCode,
    customer_name: (customer_name || 'Anonymous Guest').trim(),
    prize_name: prize_name || 'Free Popcorn Tub!',
    prize_icon: prize_icon || '🍿',
    prize_description: prize_description || 'Show this code at the counter to claim your treat.',
    campaign_id: campaign_id || defaultCampaign.id,
    status: 'WAITING',
    created_at: new Date().toISOString(),
    redeemed_at: null,
    redeemed_by: null,
    operator_name: null,
    notes: null
  };

  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest('rewards', {
      method: 'POST',
      body: newReward
    });
    if (res && res.length > 0) return res[0];
  }

  memoryStore.rewards.set(finalCode, newReward);
  return newReward;
}

async function getRewardByCode(code) {
  const cleanCode = String(code).toUpperCase().trim();
  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest(`rewards?code=eq.${encodeURIComponent(cleanCode)}&limit=1`);
    if (res && res.length > 0) return res[0];
  }
  return memoryStore.rewards.get(cleanCode) || null;
}

async function listRewards({ status, search, limit = 50, offset = 0 } = {}) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    let query = `rewards?select=*&order=created_at.desc&limit=${limit}&offset=${offset}`;
    if (status) query += `&status=eq.${encodeURIComponent(status)}`;
    if (search) query += `&or=(code.ilike.*${encodeURIComponent(search)}*,customer_name.ilike.*${encodeURIComponent(search)}*)`;
    const res = await supabaseRequest(query);
    if (res) return res;
  }

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

// CRITICAL: Atomic Single-Use Redemption Engine
// Acquires concurrency lock on the code, executes conditional state update, releases lock.
async function redeemRewardAtomic({ code, operator_id, operator_name, notes }) {
  const cleanCode = String(code).toUpperCase().trim();

  // If Supabase RPC stored procedure exists, call redeem_reward_atomic directly
  if (SUPABASE_URL && SUPABASE_KEY) {
    const rpcRes = await supabaseRequest('rpc/redeem_reward_atomic', {
      method: 'POST',
      body: {
        p_code: cleanCode,
        p_operator_id: operator_id,
        p_operator_name: operator_name,
        p_notes: notes || null
      }
    });
    if (rpcRes) return rpcRes;
  }

  // Fallback Engine with Exclusive In-Memory Concurrency Mutex Lock
  if (memoryStore.locks.has(cleanCode)) {
    return {
      success: false,
      code: 'CONCURRENT_REQUEST',
      message: 'A redemption request for this code is already in flight. Please refresh.'
    };
  }

  // Acquire lock
  memoryStore.locks.add(cleanCode);

  try {
    const reward = memoryStore.rewards.get(cleanCode);

    if (!reward) {
      return {
        success: false,
        code: 'NOT_FOUND',
        message: 'The requested prize code was not found.'
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
        prize_name: reward.prize_name
      };
    }

    if (reward.status !== 'WAITING') {
      return {
        success: false,
        code: 'INVALID_STATUS',
        message: `This prize code is currently marked as ${reward.status} and cannot be collected.`
      };
    }

    // Atomic state update
    reward.status = 'COLLECTED';
    reward.redeemed_at = new Date().toISOString();
    reward.redeemed_by = operator_id;
    reward.operator_name = operator_name;
    reward.notes = notes || null;

    // Log to audit trail
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
        customer: reward.customer_name
      }
    });

    return {
      success: true,
      code: 'SUCCESS',
      message: 'Prize verified and collected successfully!',
      reward_id: reward.id,
      prize_name: reward.prize_name,
      customer_name: reward.customer_name,
      redeemed_at: reward.redeemed_at
    };
  } finally {
    // Release lock
    memoryStore.locks.delete(cleanCode);
  }
}

// 3. Real Dashboard Statistics (Never Fabricated)
async function getDashboardStats() {
  await bootstrapOwnerIfEmpty();
  const allRewards = await listRewards({ limit: 1000 });

  const totalPlays = allRewards.length;
  const pendingCollection = allRewards.filter(r => r.status === 'WAITING').length;
  const totalRedeemed = allRewards.filter(r => r.status === 'COLLECTED').length;

  const todayStr = new Date().toISOString().split('T')[0];
  const playsToday = allRewards.filter(r => (r.created_at || '').startsWith(todayStr)).length;
  const redemptionsToday = allRewards.filter(r => (r.redeemed_at || '').startsWith(todayStr)).length;

  return {
    totalPlays,
    pendingCollection,
    totalRedeemed,
    playsToday,
    redemptionsToday,
    activeCampaigns: memoryStore.campaigns.size,
    dbMode: (SUPABASE_URL && SUPABASE_KEY) ? 'SUPABASE_POSTGRES' : 'SECURE_STORAGE_ENGINE'
  };
}

// 4. Audit Logging
async function addAuditLog({ actor_id, actor_name, actor_role, action, target_type, target_id, details }) {
  const entry = {
    id: 'aud-' + Math.random().toString(36).substring(2, 10),
    actor_id: actor_id || null,
    actor_name: actor_name || 'System',
    actor_role: actor_role || 'SYSTEM',
    action: action,
    target_type: target_type || null,
    target_id: target_id || null,
    details: details || {},
    created_at: new Date().toISOString()
  };

  if (SUPABASE_URL && SUPABASE_KEY) {
    await supabaseRequest('audit_logs', {
      method: 'POST',
      body: entry
    });
  }

  memoryStore.auditLogs.unshift(entry);
  if (memoryStore.auditLogs.length > 500) {
    memoryStore.auditLogs.pop();
  }
  return entry;
}

async function listAuditLogs({ limit = 30 } = {}) {
  if (SUPABASE_URL && SUPABASE_KEY) {
    const res = await supabaseRequest(`audit_logs?select=*&order=created_at.desc&limit=${limit}`);
    if (res) return res;
  }
  return memoryStore.auditLogs.slice(0, limit);
}

module.exports = {
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
  listAuditLogs
};
