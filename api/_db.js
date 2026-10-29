// api/_db.js
// Production-Hardened Database Layer (Supabase PostgreSQL + Fail-Closed Enforcement)
// Strictly zero fabricated financial figures or fake winner records.
const crypto = require('crypto');
const { hashPassword, generateSecureRewardCode, revokeJti } = require('./_security');

function isProd() {
  return process.env.NODE_ENV === 'production';
}

function getSupabaseConfig() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
  const isConfigured = Boolean(url && key && !url.includes('your-project'));
  return { url, key, isConfigured };
}

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

// Local / Test Store (Active ONLY when NODE_ENV !== 'production')
// Contains ZERO fabricated sales, expenses, refunds, or winner records.
const memoryStore = {
  users: new Map(),
  sessions: new Map(),
  shops: new Map(),
  products: new Map(),
  inventoryMovements: [],
  sales: new Map(),
  saleItems: new Map(),
  refunds: new Map(),
  expenses: new Map(),
  campaigns: new Map(),
  rewards: new Map(),
  notifications: [],
  settings: new Map(),
  auditLogs: [],
  locks: new Set(),
  bootstrapCompleted: false,
};

function seedStructuralDefaults() {
  if (memoryStore.shops.size === 0) {
    const defaultShop = {
      id: 'shp-main-counter',
      code: 'MAIN',
      name: 'Main Counter',
      location: 'LR Popcorn Prize Club Storefront',
      phone: '',
      is_active: true,
      created_at: new Date().toISOString(),
    };
    memoryStore.shops.set(defaultShop.id, defaultShop);
  }

  if (memoryStore.campaigns.size === 0) {
    const defaultCampaign = {
      id: 'cmp-golden-ticket-2026',
      code: 'GOLDEN-2026',
      name: 'LR Popcorn Lucky Card Campaign',
      description: 'Official QR lucky-gift rewards included in selected popcorn packs.',
      status: 'ACTIVE',
      prizes: [
        { name: 'Free popcorn!', icon: '🍿', desc: 'One fresh popcorn, on us.', unit_cost: 20 },
        { name: '50% off your next bag', icon: '🏷️', desc: 'A little something for your next visit.', unit_cost: 15 },
        { name: 'Free topping upgrade', icon: '✨', desc: 'Make your next popcorn extra special.', unit_cost: 10 },
        { name: 'Buy one, get one', icon: '🎉', desc: 'Bring a friend for your next snack.', unit_cost: 25 },
        { name: 'A bonus mini pack', icon: '🍿', desc: 'A mini pack for your next movie moment.', unit_cost: 15 },
      ],
      created_at: new Date().toISOString(),
    };
    memoryStore.campaigns.set(defaultCampaign.id, defaultCampaign);
  }

  if (!memoryStore.settings.has('general')) {
    memoryStore.settings.set('general', {
      business_name: 'LR Popcorn Prize Club',
      currency: 'INR',
      currency_symbol: '₹',
      payment_integration_status: 'MANUAL_AND_CSV_RECONCILIATION',
      payment_integration_note:
        'Live PhonePe/BharatPe private API scraping is disabled for security. Record verified counter payments or reconcile exported settlement CSVs.',
      updated_at: new Date().toISOString(),
      updated_by: 'System',
    });
  }
}
seedStructuralDefaults();

function resetMemoryFinancialsAndData() {
  memoryStore.sales.clear();
  memoryStore.saleItems.clear();
  memoryStore.refunds.clear();
  memoryStore.expenses.clear();
  memoryStore.products.clear();
  memoryStore.inventoryMovements.length = 0;
  memoryStore.rewards.clear();
  memoryStore.notifications.length = 0;
  memoryStore.auditLogs.length = 0;
  seedStructuralDefaults();
}

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
    apikey: key,
    Authorization: `Bearer ${key}`,
    'Content-Type': 'application/json',
    Prefer: options.prefer || 'return=representation',
    ...(options.headers || {}),
  };

  const res = await fetch(reqUrl, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Database error [${res.status}]: ${errorText}`);
  }

  const text = await res.text();
  return text ? JSON.parse(text) : [];
}

// 1. Owner Bootstrap
async function bootstrapOwnerIfEmpty() {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const existingUsers = await supabaseRequest('users?select=id&limit=1');
    if (existingUsers && existingUsers.length > 0) return;

    const ownerName = process.env.PRIMARY_OWNER_NAME || 'Mom';
    const ownerUsername = (process.env.PRIMARY_OWNER_USERNAME || 'owner').toLowerCase().trim();
    const ownerEmail = (process.env.PRIMARY_OWNER_EMAIL || '').trim() || null;
    const ownerPassword = process.env.PRIMARY_OWNER_INITIAL_PASSWORD;

    if (isProd() && (!ownerPassword || ownerPassword.length < 8 || ownerPassword.includes('replace_with'))) {
      throw new Error(
        'CRITICAL CONFIGURATION ERROR: PRIMARY_OWNER_INITIAL_PASSWORD of at least 8 characters must be set in environment variables to bootstrap the primary owner in production.'
      );
    }

    const initialPassword = ownerPassword || 'PopcornClub2026!';
    const { hash, salt } = hashPassword(initialPassword);

    await supabaseRequest('users', {
      method: 'POST',
      body: {
        username: ownerUsername,
        email: ownerEmail,
        full_name: ownerName,
        role: 'OWNER',
        password_hash: hash,
        salt,
        status: 'ACTIVE',
      },
    });
    return;
  }

  if (isProd()) assertDatabaseConfigured();

  if (!memoryStore.bootstrapCompleted && memoryStore.users.size === 0) {
    const ownerPassword = process.env.PRIMARY_OWNER_INITIAL_PASSWORD || 'PopcornClub2026!';
    const { hash, salt } = hashPassword(ownerPassword);
    memoryStore.users.set('owner', {
      id: 'usr-owner-primary',
      username: 'owner',
      email: 'owner@popcornclub.local',
      phone: '',
      full_name: process.env.PRIMARY_OWNER_NAME || 'Mom',
      avatar_url: '',
      role: 'OWNER',
      password_hash: hash,
      salt,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_login_at: null,
    });

    const { hash: sHash, salt: sSalt } = hashPassword('PopcornShankar2026!');
    memoryStore.users.set('shankar', {
      id: 'usr-admin-shankar',
      username: 'shankar',
      email: 'shankar@popcornclub.local',
      phone: '',
      full_name: 'Shankar',
      avatar_url: '',
      role: 'ADMIN',
      password_hash: sHash,
      salt: sSalt,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_login_at: null,
    });

    memoryStore.bootstrapCompleted = true;
  }
}

// 2. Users & Owner Profile
async function getUserByUsername(username) {
  await bootstrapOwnerIfEmpty();
  const cleanUsername = String(username || '').toLowerCase().trim();
  const { isConfigured } = getSupabaseConfig();

  if (isConfigured) {
    const res = await supabaseRequest(`users?username=eq.${encodeURIComponent(cleanUsername)}&limit=1`);
    return res && res.length > 0 ? res[0] : null;
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.users.get(cleanUsername) || null;
}

async function getUserById(id) {
  await bootstrapOwnerIfEmpty();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(id)}&limit=1`);
    return res && res.length > 0 ? res[0] : null;
  }
  if (isProd()) assertDatabaseConfigured();
  for (const u of memoryStore.users.values()) {
    if (u.id === id) return u;
  }
  return null;
}

async function updateUserLastLogin(userId) {
  const now = new Date().toISOString();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: { last_login_at: now },
    });
    return;
  }
  for (const u of memoryStore.users.values()) {
    if (u.id === userId) u.last_login_at = now;
  }
}

async function updateUserProfile(userId, { full_name, email, phone, avatar_url, new_password }) {
  await bootstrapOwnerIfEmpty();
  const updates = { updated_at: new Date().toISOString() };
  if (typeof full_name === 'string' && full_name.trim()) updates.full_name = full_name.trim();
  if (typeof email === 'string') updates.email = email.trim() || null;
  if (typeof phone === 'string') updates.phone = phone.trim() || null;
  if (typeof avatar_url === 'string') updates.avatar_url = avatar_url.trim() || null;
  if (new_password) {
    const { hash, salt } = hashPassword(new_password);
    updates.password_hash = hash;
    updates.salt = salt;
  }

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: updates,
    });
    if (res && res.length > 0) return sanitizeUserRecord(res[0]);
    throw new Error('Failed to update user profile in database.');
  }

  if (isProd()) assertDatabaseConfigured();
  for (const u of memoryStore.users.values()) {
    if (u.id === userId) {
      Object.assign(u, updates);
      return sanitizeUserRecord(u);
    }
  }
  throw new Error('User not found.');
}

function sanitizeUserRecord(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    email: u.email || '',
    phone: u.phone || '',
    full_name: u.full_name,
    avatar_url: u.avatar_url || '',
    role: u.role,
    status: u.status,
    created_at: u.created_at,
    updated_at: u.updated_at || u.created_at,
    last_login_at: u.last_login_at || null,
  };
}

async function createUser({ username, full_name, email, phone, role, password, status = 'ACTIVE' }) {
  await bootstrapOwnerIfEmpty();
  const cleanUsername = String(username).toLowerCase().trim();
  const { hash, salt } = hashPassword(password);
  const now = new Date().toISOString();
  const newUser = {
    username: cleanUsername,
    email: email ? String(email).trim() : null,
    phone: phone ? String(phone).trim() : null,
    full_name: full_name.trim(),
    role: role || 'STAFF',
    password_hash: hash,
    salt,
    status,
    created_at: now,
    updated_at: now,
    last_login_at: null,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('users', { method: 'POST', body: newUser });
    if (res && res.length > 0) return sanitizeUserRecord(res[0]);
    throw new Error('Failed to create user in database.');
  }

  if (isProd()) assertDatabaseConfigured();
  newUser.id = 'usr-' + crypto.randomBytes(6).toString('hex');
  memoryStore.users.set(cleanUsername, newUser);
  return sanitizeUserRecord(newUser);
}

async function listUsers() {
  await bootstrapOwnerIfEmpty();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(
      'users?select=id,username,email,phone,full_name,avatar_url,role,status,created_at,updated_at,last_login_at&order=created_at.desc'
    );
    return (res || []).map(sanitizeUserRecord);
  }
  if (isProd()) assertDatabaseConfigured();
  return Array.from(memoryStore.users.values()).map(sanitizeUserRecord);
}

async function updateUserStatus(userId, { status, role }) {
  const { isConfigured } = getSupabaseConfig();
  const body = { updated_at: new Date().toISOString() };
  if (status) body.status = status;
  if (role) body.role = role;

  if (isConfigured) {
    const res = await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body,
    });
    return res && res.length > 0 ? sanitizeUserRecord(res[0]) : null;
  }

  if (isProd()) assertDatabaseConfigured();
  for (const user of memoryStore.users.values()) {
    if (user.id === userId) {
      if (status) user.status = status;
      if (role) user.role = role;
      user.updated_at = body.updated_at;
      return sanitizeUserRecord(user);
    }
  }
  return null;
}

// 3. Active Sessions Tracking & Revocation
async function recordUserSession({ jti, user, ip_address, user_agent, expires_at }) {
  const sessionRecord = {
    jti,
    user_id: user.id,
    username: user.username,
    role: user.role,
    ip_address: ip_address || '127.0.0.1',
    user_agent: (user_agent || 'Browser').slice(0, 200),
    created_at: new Date().toISOString(),
    expires_at: expires_at || new Date(Date.now() + 12 * 3600 * 1000).toISOString(),
    revoked_at: null,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    try {
      await supabaseRequest('user_sessions', { method: 'POST', body: sessionRecord });
    } catch {}
    return sessionRecord;
  }
  if (isProd()) assertDatabaseConfigured();
  sessionRecord.id = 'ses-' + crypto.randomBytes(6).toString('hex');
  memoryStore.sessions.set(jti, sessionRecord);
  return sessionRecord;
}

async function listUserSessions(userId) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    try {
      const res = await supabaseRequest(
        `user_sessions?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc&limit=25`
      );
      return res || [];
    } catch {
      return [];
    }
  }
  if (isProd()) assertDatabaseConfigured();
  return Array.from(memoryStore.sessions.values())
    .filter(s => s.user_id === userId)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
}

async function revokeUserSessionByJti(jti, userId = null) {
  if (!jti) return false;
  revokeJti(jti);
  const now = new Date().toISOString();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    try {
      let q = `user_sessions?jti=eq.${encodeURIComponent(jti)}`;
      if (userId) q += `&user_id=eq.${encodeURIComponent(userId)}`;
      await supabaseRequest(q, { method: 'PATCH', body: { revoked_at: now } });
    } catch {}
    return true;
  }
  if (isProd()) assertDatabaseConfigured();
  const ses = memoryStore.sessions.get(jti);
  if (ses && (!userId || ses.user_id === userId)) {
    ses.revoked_at = now;
    return true;
  }
  return false;
}

// 4. Shops Management
async function listShops() {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('shops?select=*&order=created_at.asc');
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  return Array.from(memoryStore.shops.values());
}

async function createShop({ code, name, location, phone }) {
  const cleanCode = String(code || 'SHOP-' + crypto.randomBytes(2).toString('hex')).toUpperCase().trim();
  const record = {
    code: cleanCode,
    name: String(name || 'Counter').trim(),
    location: String(location || '').trim(),
    phone: String(phone || '').trim(),
    is_active: true,
    created_at: new Date().toISOString(),
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('shops', { method: 'POST', body: record });
    if (res && res.length > 0) return res[0];
    throw new Error('Failed to create shop.');
  }
  if (isProd()) assertDatabaseConfigured();
  record.id = 'shp-' + crypto.randomBytes(6).toString('hex');
  memoryStore.shops.set(record.id, record);
  return record;
}

// 5. Products & Inventory Movements
async function listProducts() {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('products?select=*&order=name.asc');
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  return Array.from(memoryStore.products.values());
}

async function getProductById(productId) {
  if (!productId) return null;
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`products?id=eq.${encodeURIComponent(productId)}&limit=1`);
    return res && res.length > 0 ? res[0] : null;
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.products.get(productId) || null;
}

async function createProduct({ sku, name, category, unit_price, unit_cost, stock_qty, reorder_level, created_by }) {
  const cleanSku = String(sku || 'SKU-' + crypto.randomBytes(3).toString('hex')).toUpperCase().trim();
  const price = Math.max(0, Number(parseFloat(unit_price || 0).toFixed(2)));
  const cost = Math.max(0, Number(parseFloat(unit_cost || 0).toFixed(2)));
  const initialStock = Math.max(0, parseInt(stock_qty || 0, 10));
  const reorder = Math.max(0, parseInt(reorder_level ?? 10, 10));
  const now = new Date().toISOString();

  const product = {
    sku: cleanSku,
    name: String(name).trim(),
    category: String(category || 'Popcorn').trim(),
    unit_price: price,
    unit_cost: cost,
    stock_qty: initialStock,
    reorder_level: reorder,
    is_active: true,
    created_at: now,
    updated_at: now,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const existing = await supabaseRequest(`products?sku=eq.${encodeURIComponent(cleanSku)}&limit=1`);
    if (existing && existing.length > 0) {
      const err = new Error(`Product with SKU "${cleanSku}" already exists.`);
      err.statusCode = 409;
      throw err;
    }
    const res = await supabaseRequest('products', { method: 'POST', body: product });
    const created = res[0];
    if (initialStock > 0) {
      await recordInventoryMovement({
        product_id: created.id,
        movement_type: 'IN',
        quantity: initialStock,
        unit_cost: cost,
        notes: 'Initial opening stock',
        created_by: created_by || 'Owner',
        skipStockUpdate: true,
      });
    }
    return created;
  }

  if (isProd()) assertDatabaseConfigured();
  for (const p of memoryStore.products.values()) {
    if (p.sku.toUpperCase() === cleanSku) {
      const err = new Error(`Product with SKU "${cleanSku}" already exists.`);
      err.statusCode = 409;
      throw err;
    }
  }
  product.id = 'prd-' + crypto.randomBytes(6).toString('hex');
  memoryStore.products.set(product.id, product);

  if (initialStock > 0) {
    memoryStore.inventoryMovements.unshift({
      id: 'inv-' + crypto.randomBytes(6).toString('hex'),
      product_id: product.id,
      product_name: product.name,
      movement_type: 'IN',
      quantity: initialStock,
      unit_cost: cost,
      reference_id: 'OPENING-STOCK',
      notes: 'Initial opening stock',
      created_by: created_by || 'Owner',
      created_at: now,
    });
  }
  return product;
}

async function updateProduct(productId, updates) {
  const product = await getProductById(productId);
  if (!product) {
    const err = new Error('Product not found.');
    err.statusCode = 404;
    throw err;
  }

  const patch = { updated_at: new Date().toISOString() };
  if (updates.name !== undefined) patch.name = String(updates.name).trim();
  if (updates.category !== undefined) patch.category = String(updates.category).trim();
  if (updates.unit_price !== undefined) patch.unit_price = Math.max(0, Number(parseFloat(updates.unit_price).toFixed(2)));
  if (updates.unit_cost !== undefined) patch.unit_cost = Math.max(0, Number(parseFloat(updates.unit_cost).toFixed(2)));
  if (updates.reorder_level !== undefined) patch.reorder_level = Math.max(0, parseInt(updates.reorder_level, 10));
  if (updates.is_active !== undefined) patch.is_active = Boolean(updates.is_active);

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`products?id=eq.${encodeURIComponent(productId)}`, {
      method: 'PATCH',
      body: patch,
    });
    return res && res.length > 0 ? res[0] : null;
  }

  if (isProd()) assertDatabaseConfigured();
  Object.assign(product, patch);
  return product;
}

async function recordInventoryMovement({
  product_id,
  shop_id,
  movement_type,
  quantity,
  unit_cost,
  reference_id,
  notes,
  created_by,
  skipStockUpdate = false,
}) {
  const product = await getProductById(product_id);
  if (!product) {
    const err = new Error('Product not found for inventory movement.');
    err.statusCode = 404;
    throw err;
  }

  const qty = parseInt(quantity, 10);
  if (!qty || isNaN(qty)) {
    const err = new Error('Movement quantity must be a non-zero integer.');
    err.statusCode = 400;
    throw err;
  }

  let delta = qty;
  if (movement_type === 'OUT' || movement_type === 'SALE' || movement_type === 'REWARD_REDEMPTION') {
    delta = -Math.abs(qty);
  } else if (movement_type === 'IN' || movement_type === 'REFUND') {
    delta = Math.abs(qty);
  }

  const newStock = skipStockUpdate ? product.stock_qty : product.stock_qty + delta;
  if (!skipStockUpdate && newStock < 0) {
    const err = new Error(`Insufficient stock for "${product.name}". Available: ${product.stock_qty}, Requested: ${Math.abs(delta)}.`);
    err.statusCode = 400;
    throw err;
  }

  const movRecord = {
    product_id: product.id,
    shop_id: shop_id || null,
    movement_type,
    quantity: delta,
    unit_cost: unit_cost !== undefined ? Math.max(0, Number(parseFloat(unit_cost).toFixed(2))) : product.unit_cost,
    reference_id: reference_id || null,
    notes: notes || null,
    created_by: created_by || 'Owner',
    created_at: new Date().toISOString(),
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    if (!skipStockUpdate) {
      await supabaseRequest(`products?id=eq.${encodeURIComponent(product.id)}`, {
        method: 'PATCH',
        body: { stock_qty: newStock, updated_at: new Date().toISOString() },
      });
    }
    const res = await supabaseRequest('inventory_movements', { method: 'POST', body: movRecord });
    return res && res.length > 0 ? res[0] : movRecord;
  }

  if (isProd()) assertDatabaseConfigured();
  if (!skipStockUpdate) {
    product.stock_qty = newStock;
    product.updated_at = new Date().toISOString();
  }
  movRecord.id = 'inv-' + crypto.randomBytes(6).toString('hex');
  movRecord.product_name = product.name;
  memoryStore.inventoryMovements.unshift(movRecord);

  if (product.stock_qty <= product.reorder_level) {
    await createNotification({
      type: 'LOW_STOCK',
      title: `Low Stock Alert: ${product.name}`,
      message: `${product.name} (${product.sku}) has ${product.stock_qty} units remaining (reorder level: ${product.reorder_level}).`,
    });
  }
  return movRecord;
}

async function listInventoryMovements({ product_id, limit = 50 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let q = `inventory_movements?select=*&order=created_at.desc&limit=${limit}`;
    if (product_id) q += `&product_id=eq.${encodeURIComponent(product_id)}`;
    const res = await supabaseRequest(q);
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  let list = memoryStore.inventoryMovements;
  if (product_id) list = list.filter(m => m.product_id === product_id);
  return list.slice(0, limit);
}

// 6. Sales, Sale Items & Duplicate Transaction Detection
async function createSale({
  sale_date,
  shop_id,
  shop_name,
  items = [],
  gross_amount,
  discount_amount = 0,
  cogs_amount,
  payment_method = 'CASH',
  payment_reference = '',
  external_tx_id = null,
  source = 'MANUAL',
  notes = '',
  created_by = 'Owner',
}) {
  const cleanRef = payment_reference ? String(payment_reference).trim() : '';
  const cleanExtId = external_tx_id ? String(external_tx_id).trim() : (cleanRef ? `${payment_method}-${cleanRef}` : null);

  // Duplicate transaction check
  const existingSales = await listSales({ limit: 1000 });
  if (cleanExtId) {
    const dup = existingSales.find(
      s =>
        (s.external_tx_id && s.external_tx_id.toLowerCase() === cleanExtId.toLowerCase()) ||
        (cleanRef &&
          s.payment_reference &&
          s.payment_reference.toLowerCase() === cleanRef.toLowerCase() &&
          s.payment_method === payment_method)
    );
    if (dup) {
      const err = new Error(
        `Duplicate transaction detected: payment reference "${cleanRef || cleanExtId}" is already recorded under Sale #${dup.sale_number}.`
      );
      err.statusCode = 409;
      err.code = 'DUPLICATE_TRANSACTION';
      throw err;
    }
  }

  let computedGross = 0;
  let computedCogs = 0;
  const resolvedItems = [];

  if (Array.isArray(items) && items.length > 0) {
    for (const item of items) {
      const qty = Math.max(1, parseInt(item.quantity || 1, 10));
      let prod = item.product_id ? await getProductById(item.product_id) : null;
      const unitPrice = Math.max(0, Number(parseFloat(item.unit_price ?? (prod ? prod.unit_price : 0)).toFixed(2)));
      const unitCost = Math.max(0, Number(parseFloat(item.unit_cost ?? (prod ? prod.unit_cost : 0)).toFixed(2)));
      const lineTotal = Number((qty * unitPrice).toFixed(2));
      const lineCogs = Number((qty * unitCost).toFixed(2));

      computedGross += lineTotal;
      computedCogs += lineCogs;

      resolvedItems.push({
        product_id: prod ? prod.id : null,
        product_name: item.product_name || (prod ? prod.name : 'Popcorn Item'),
        quantity: qty,
        unit_price: unitPrice,
        unit_cost: unitCost,
        line_total: lineTotal,
        line_cogs: lineCogs,
      });
    }
  } else {
    computedGross = Math.max(0, Number(parseFloat(gross_amount || 0).toFixed(2)));
    computedCogs = Math.max(0, Number(parseFloat(cogs_amount || 0).toFixed(2)));
  }

  const finalGross = Number(computedGross.toFixed(2));
  if (finalGross <= 0) {
    const err = new Error('Gross sale amount must be greater than zero.');
    err.statusCode = 400;
    throw err;
  }

  const finalDiscount = Math.min(finalGross, Math.max(0, Number(parseFloat(discount_amount || 0).toFixed(2))));
  const finalNet = Number((finalGross - finalDiscount).toFixed(2));
  const finalCogs = Number(computedCogs.toFixed(2));
  const saleNumber = 'SL-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
  const saleDateStr = sale_date || new Date().toISOString().split('T')[0];
  const now = new Date().toISOString();

  const saleRecord = {
    sale_number: saleNumber,
    sale_date: saleDateStr,
    shop_id: shop_id || null,
    shop_name: shop_name || 'Main Counter',
    gross_amount: finalGross,
    discount_amount: finalDiscount,
    net_amount: finalNet,
    cogs_amount: finalCogs,
    payment_method: ['CASH', 'UPI', 'CARD', 'OTHER'].includes(payment_method) ? payment_method : 'CASH',
    payment_reference: cleanRef || null,
    external_tx_id: cleanExtId || null,
    source: source === 'IMPORTED' ? 'IMPORTED' : 'MANUAL',
    notes: notes || null,
    created_by,
    created_at: now,
    updated_at: now,
  };

  // Deduct inventory for linked products first (validates stock)
  for (const line of resolvedItems) {
    if (line.product_id) {
      await recordInventoryMovement({
        product_id: line.product_id,
        shop_id: shop_id || null,
        movement_type: 'SALE',
        quantity: line.quantity,
        unit_cost: line.unit_cost,
        reference_id: saleNumber,
        notes: `Sale ${saleNumber}`,
        created_by,
      });
    }
  }

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('sales', { method: 'POST', body: saleRecord });
    const createdSale = res[0];
    for (const line of resolvedItems) {
      await supabaseRequest('sale_items', {
        method: 'POST',
        body: { ...line, sale_id: createdSale.id },
      });
    }
    return { ...createdSale, items: resolvedItems };
  }

  if (isProd()) assertDatabaseConfigured();
  saleRecord.id = 'sal-' + crypto.randomBytes(6).toString('hex');
  memoryStore.sales.set(saleRecord.id, saleRecord);
  memoryStore.saleItems.set(saleRecord.id, resolvedItems);
  return { ...saleRecord, items: resolvedItems };
}

async function listSales({ startDate, endDate, shopId, paymentMethod, limit = 200 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let q = `sales?select=*&order=sale_date.desc,created_at.desc&limit=${limit}`;
    if (startDate) q += `&sale_date=gte.${encodeURIComponent(startDate)}`;
    if (endDate) q += `&sale_date=lte.${encodeURIComponent(endDate)}`;
    if (shopId) q += `&shop_id=eq.${encodeURIComponent(shopId)}`;
    if (paymentMethod) q += `&payment_method=eq.${encodeURIComponent(paymentMethod)}`;
    const res = await supabaseRequest(q);
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  let list = Array.from(memoryStore.sales.values());
  if (startDate) list = list.filter(s => s.sale_date >= startDate);
  if (endDate) list = list.filter(s => s.sale_date <= endDate);
  if (shopId) list = list.filter(s => s.shop_id === shopId || s.shop_name === shopId);
  if (paymentMethod) list = list.filter(s => s.payment_method === paymentMethod);
  list.sort((a, b) => (b.sale_date || '').localeCompare(a.sale_date || '') || new Date(b.created_at) - new Date(a.created_at));
  return list.slice(0, limit).map(s => ({
    ...s,
    items: memoryStore.saleItems.get(s.id) || [],
  }));
}

// 7. Refunds
async function createRefund({
  sale_id,
  shop_id,
  shop_name,
  refund_date,
  refund_amount,
  cogs_reversed = 0,
  restock_items = false,
  reason,
  payment_reference,
  created_by = 'Owner',
}) {
  const amount = Number(parseFloat(refund_amount || 0).toFixed(2));
  if (amount <= 0) {
    const err = new Error('Refund amount must be greater than zero.');
    err.statusCode = 400;
    throw err;
  }
  if (!reason || !String(reason).trim()) {
    const err = new Error('Refund reason is required.');
    err.statusCode = 400;
    throw err;
  }

  let linkedSale = null;
  if (sale_id) {
    const allSales = await listSales({ limit: 1000 });
    linkedSale = allSales.find(s => s.id === sale_id || s.sale_number === sale_id);
    if (!linkedSale) {
      const err = new Error('Referenced sale record was not found.');
      err.statusCode = 404;
      throw err;
    }
    const existingRefunds = await listRefunds({ saleId: linkedSale.id });
    const alreadyRefunded = existingRefunds.reduce((sum, r) => sum + Number(r.refund_amount || 0), 0);
    if (alreadyRefunded + amount > Number(linkedSale.net_amount) + 0.001) {
      const err = new Error(
        `Refund amount (₹${amount}) exceeds remaining refundable net sale balance (₹${(linkedSale.net_amount - alreadyRefunded).toFixed(2)}).`
      );
      err.statusCode = 400;
      throw err;
    }
  }

  let finalCogsReversed = Math.max(0, Number(parseFloat(cogs_reversed || 0).toFixed(2)));
  if (linkedSale && restock_items && finalCogsReversed === 0 && linkedSale.net_amount > 0) {
    const ratio = Math.min(1, amount / linkedSale.net_amount);
    finalCogsReversed = Number((linkedSale.cogs_amount * ratio).toFixed(2));
  }

  const refundRecord = {
    sale_id: linkedSale ? linkedSale.id : null,
    shop_id: shop_id || (linkedSale ? linkedSale.shop_id : null),
    shop_name: shop_name || (linkedSale ? linkedSale.shop_name : 'Main Counter'),
    refund_date: refund_date || new Date().toISOString().split('T')[0],
    refund_amount: amount,
    cogs_reversed: finalCogsReversed,
    restock_items: Boolean(restock_items),
    reason: String(reason).trim(),
    payment_reference: payment_reference || null,
    created_by,
    created_at: new Date().toISOString(),
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('refunds', { method: 'POST', body: refundRecord });
    return res[0];
  }

  if (isProd()) assertDatabaseConfigured();
  refundRecord.id = 'ref-' + crypto.randomBytes(6).toString('hex');
  memoryStore.refunds.set(refundRecord.id, refundRecord);

  if (linkedSale && restock_items) {
    const items = memoryStore.saleItems.get(linkedSale.id) || [];
    for (const line of items) {
      if (line.product_id) {
        await recordInventoryMovement({
          product_id: line.product_id,
          shop_id: refundRecord.shop_id,
          movement_type: 'REFUND',
          quantity: line.quantity,
          unit_cost: line.unit_cost,
          reference_id: refundRecord.id,
          notes: `Restock from refund on ${linkedSale.sale_number}`,
          created_by,
        });
      }
    }
  }

  return refundRecord;
}

async function listRefunds({ startDate, endDate, shopId, saleId, limit = 200 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let q = `refunds?select=*&order=refund_date.desc,created_at.desc&limit=${limit}`;
    if (startDate) q += `&refund_date=gte.${encodeURIComponent(startDate)}`;
    if (endDate) q += `&refund_date=lte.${encodeURIComponent(endDate)}`;
    if (shopId) q += `&shop_id=eq.${encodeURIComponent(shopId)}`;
    if (saleId) q += `&sale_id=eq.${encodeURIComponent(saleId)}`;
    const res = await supabaseRequest(q);
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  let list = Array.from(memoryStore.refunds.values());
  if (startDate) list = list.filter(r => r.refund_date >= startDate);
  if (endDate) list = list.filter(r => r.refund_date <= endDate);
  if (shopId) list = list.filter(r => r.shop_id === shopId || r.shop_name === shopId);
  if (saleId) list = list.filter(r => r.sale_id === saleId);
  list.sort((a, b) => (b.refund_date || '').localeCompare(a.refund_date || '') || new Date(b.created_at) - new Date(a.created_at));
  return list.slice(0, limit);
}

// 8. Operating Expenses
async function createExpense({
  expense_date,
  shop_id,
  shop_name,
  category,
  amount,
  vendor = '',
  payment_method = 'CASH',
  reference = '',
  receipt_url = '',
  notes = '',
  source = 'MANUAL',
  created_by = 'Owner',
}) {
  const val = Number(parseFloat(amount || 0).toFixed(2));
  if (val <= 0) {
    const err = new Error('Expense amount must be greater than zero.');
    err.statusCode = 400;
    throw err;
  }
  if (!category || !String(category).trim()) {
    const err = new Error('Expense category is required.');
    err.statusCode = 400;
    throw err;
  }

  const now = new Date().toISOString();
  const expenseRecord = {
    expense_date: expense_date || now.split('T')[0],
    shop_id: shop_id || null,
    shop_name: shop_name || 'Main Counter',
    category: String(category).trim(),
    amount: val,
    vendor: String(vendor || '').trim() || null,
    payment_method: String(payment_method || 'CASH').toUpperCase(),
    reference: String(reference || '').trim() || null,
    receipt_url: String(receipt_url || '').trim() || null,
    notes: String(notes || '').trim() || null,
    source: source === 'IMPORTED' ? 'IMPORTED' : 'MANUAL',
    created_by,
    created_at: now,
    updated_at: now,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('expenses', { method: 'POST', body: expenseRecord });
    return res[0];
  }

  if (isProd()) assertDatabaseConfigured();
  expenseRecord.id = 'exp-' + crypto.randomBytes(6).toString('hex');
  memoryStore.expenses.set(expenseRecord.id, expenseRecord);
  return expenseRecord;
}

async function updateExpense(expenseId, updates) {
  const { isConfigured } = getSupabaseConfig();
  const patch = { updated_at: new Date().toISOString() };
  if (updates.expense_date) patch.expense_date = updates.expense_date;
  if (updates.category) patch.category = String(updates.category).trim();
  if (updates.amount !== undefined) {
    const val = Number(parseFloat(updates.amount).toFixed(2));
    if (val <= 0) throw new Error('Expense amount must be positive.');
    patch.amount = val;
  }
  if (updates.vendor !== undefined) patch.vendor = String(updates.vendor).trim() || null;
  if (updates.payment_method !== undefined) patch.payment_method = String(updates.payment_method).toUpperCase();
  if (updates.reference !== undefined) patch.reference = String(updates.reference).trim() || null;
  if (updates.notes !== undefined) patch.notes = String(updates.notes).trim() || null;

  if (isConfigured) {
    const res = await supabaseRequest(`expenses?id=eq.${encodeURIComponent(expenseId)}`, {
      method: 'PATCH',
      body: patch,
    });
    return res && res.length > 0 ? res[0] : null;
  }

  if (isProd()) assertDatabaseConfigured();
  const existing = memoryStore.expenses.get(expenseId);
  if (!existing) return null;
  Object.assign(existing, patch);
  return existing;
}

async function listExpenses({ startDate, endDate, shopId, category, limit = 200 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let q = `expenses?select=*&order=expense_date.desc,created_at.desc&limit=${limit}`;
    if (startDate) q += `&expense_date=gte.${encodeURIComponent(startDate)}`;
    if (endDate) q += `&expense_date=lte.${encodeURIComponent(endDate)}`;
    if (shopId) q += `&shop_id=eq.${encodeURIComponent(shopId)}`;
    if (category) q += `&category=eq.${encodeURIComponent(category)}`;
    const res = await supabaseRequest(q);
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  let list = Array.from(memoryStore.expenses.values());
  if (startDate) list = list.filter(e => e.expense_date >= startDate);
  if (endDate) list = list.filter(e => e.expense_date <= endDate);
  if (shopId) list = list.filter(e => e.shop_id === shopId || e.shop_name === shopId);
  if (category) list = list.filter(e => e.category.toLowerCase() === category.toLowerCase());
  list.sort((a, b) => (b.expense_date || '').localeCompare(a.expense_date || '') || new Date(b.created_at) - new Date(a.created_at));
  return list.slice(0, limit);
}

// 9. QR Rewards & Atomic Single-Use Redemption (No Demo Winner Pollution)
async function createReward({
  code,
  customer_name,
  prize_name,
  prize_icon,
  prize_description,
  unit_cost = 15,
  campaign_id = null,
  shop_id = null,
  batch_name = null,
  status = 'WAITING',
  is_demo = false,
}) {
  const finalCode = (code || generateSecureRewardCode()).toUpperCase().trim();
  const now = new Date().toISOString();
  const newReward = {
    code: finalCode,
    customer_name: (customer_name || 'Customer').trim(),
    prize_name: prize_name || 'Free popcorn!',
    prize_icon: prize_icon || '🍿',
    prize_description: prize_description || 'Show this code at the counter to claim your treat.',
    unit_cost: Math.max(0, Number(parseFloat(unit_cost || 0).toFixed(2))),
    campaign_id: campaign_id || null,
    shop_id: shop_id || null,
    batch_name: batch_name || null,
    is_demo: Boolean(is_demo),
    status: ['GENERATED', 'WAITING', 'COLLECTED', 'EXPIRED', 'REVOKED'].includes(status) ? status : 'WAITING',
    created_at: now,
    scratched_at: status === 'WAITING' ? now : null,
    redeemed_at: null,
    redeemed_by: null,
    operator_name: null,
    notes: null,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('rewards', { method: 'POST', body: newReward });
    if (res && res.length > 0) return res[0];
    throw new Error('Failed to persist reward in database.');
  }

  if (isProd()) assertDatabaseConfigured();
  if (memoryStore.rewards.has(finalCode)) {
    const err = new Error(`Reward code ${finalCode} already exists.`);
    err.statusCode = 409;
    throw err;
  }
  newReward.id = 'rwd-' + crypto.randomBytes(6).toString('hex');
  memoryStore.rewards.set(finalCode, newReward);
  return newReward;
}

async function claimPreGeneratedSlip(code, customerName) {
  const cleanCode = String(code || '').toUpperCase().trim();
  const existing = await getRewardByCode(cleanCode);
  if (!existing) return null;
  if (existing.is_demo) return null;

  if (existing.status === 'GENERATED') {
    const now = new Date().toISOString();
    const cleanName = (customerName || existing.customer_name || 'Customer').trim();
    const { isConfigured } = getSupabaseConfig();
    if (isConfigured) {
      const res = await supabaseRequest(`rewards?code=eq.${encodeURIComponent(cleanCode)}`, {
        method: 'PATCH',
        body: { customer_name: cleanName, status: 'WAITING', scratched_at: now },
      });
      return res && res.length > 0 ? res[0] : existing;
    }
    existing.customer_name = cleanName;
    existing.status = 'WAITING';
    existing.scratched_at = now;
  }
  return existing;
}

async function getRewardByCode(code) {
  const cleanCode = String(code || '').toUpperCase().trim();
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`rewards?code=eq.${encodeURIComponent(cleanCode)}&limit=1`);
    return res && res.length > 0 ? res[0] : null;
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.rewards.get(cleanCode) || null;
}

async function listRewards({ status, search, includeDemo = false, limit = 100, offset = 0 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    let query = `rewards?select=*&order=created_at.desc&limit=${limit}&offset=${offset}`;
    if (!includeDemo) query += `&is_demo=eq.false`;
    if (status) query += `&status=eq.${encodeURIComponent(status)}`;
    if (search) {
      query += `&or=(code.ilike.*${encodeURIComponent(search)}*,customer_name.ilike.*${encodeURIComponent(search)}*)`;
    }
    const res = await supabaseRequest(query);
    return res || [];
  }

  if (isProd()) assertDatabaseConfigured();
  let list = Array.from(memoryStore.rewards.values());
  if (!includeDemo) {
    list = list.filter(r => !r.is_demo);
  }
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

async function redeemRewardAtomic({ code, operator_id, operator_name, notes }) {
  const cleanCode = String(code || '').toUpperCase().trim();
  const { isConfigured } = getSupabaseConfig();

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

  if (isProd()) assertDatabaseConfigured();

  if (memoryStore.locks.has(cleanCode)) {
    return {
      success: false,
      code: 'CONCURRENT_REQUEST',
      message: 'A redemption request for this code is already in flight.',
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

    if (reward.is_demo) {
      return {
        success: false,
        code: 'DEMO_RECORD',
        message: 'Demo records cannot be redeemed as genuine customer prizes.',
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

    if (reward.status !== 'WAITING' && reward.status !== 'GENERATED') {
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
        unit_cost: reward.unit_cost,
      },
    });

    return {
      success: true,
      code: 'SUCCESS',
      message: 'Prize verified and collected successfully!',
      reward_id: reward.id,
      prize_name: reward.prize_name,
      customer_name: reward.customer_name,
      unit_cost: reward.unit_cost,
      redeemed_at: reward.redeemed_at,
    };
  } finally {
    memoryStore.locks.delete(cleanCode);
  }
}

// 10. Real Profit & Loss Engine (Strictly Genuine Persisted Records — Zero Fabricated Data)
function getIsoWeekKey(dateStr) {
  const d = new Date(dateStr + 'T00:00:00Z');
  if (isNaN(d.getTime())) return dateStr;
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`;
}

function getPeriodKey(dateStr, period = 'daily') {
  if (!dateStr) return 'Unknown';
  if (period === 'monthly') return dateStr.slice(0, 7);
  if (period === 'weekly') return getIsoWeekKey(dateStr);
  return dateStr.slice(0, 10);
}

async function getRealProfitAndLoss({ startDate, endDate, shopId, period = 'daily' } = {}) {
  await bootstrapOwnerIfEmpty();
  const [sales, refunds, expenses, allRewards] = await Promise.all([
    listSales({ startDate, endDate, shopId, limit: 5000 }),
    listRefunds({ startDate, endDate, shopId, limit: 5000 }),
    listExpenses({ startDate, endDate, shopId, limit: 5000 }),
    listRewards({ includeDemo: false, limit: 5000 }),
  ]);

  const redeemedRewards = allRewards.filter(r => {
    if (r.status !== 'COLLECTED' || r.is_demo) return false;
    const rDate = (r.redeemed_at || r.created_at || '').slice(0, 10);
    if (startDate && rDate < startDate) return false;
    if (endDate && rDate > endDate) return false;
    if (shopId && r.shop_id && r.shop_id !== shopId) return false;
    return true;
  });

  const hasData =
    sales.length > 0 || refunds.length > 0 || expenses.length > 0 || redeemedRewards.length > 0;

  // Accounting Formulas:
  // Gross Sales = Sum of sales.gross_amount
  // Discounts = Sum of sales.discount_amount
  // Refunds = Sum of refunds.refund_amount
  // Net Sales = Gross Sales - Discounts - Refunds
  // Product COGS = Sum of sales.cogs_amount - Sum of refunds.cogs_reversed
  // Redeemed Reward Gift Costs = Sum of redeemed_rewards.unit_cost
  // Total COGS = Product COGS + Redeemed Reward Gift Costs
  // Gross Profit = Net Sales - Total COGS
  // Operating Expenses = Sum of expenses.amount
  // Net Profit / Loss = Gross Profit - Operating Expenses

  const grossSales = Number(sales.reduce((acc, s) => acc + Number(s.gross_amount || 0), 0).toFixed(2));
  const discounts = Number(sales.reduce((acc, s) => acc + Number(s.discount_amount || 0), 0).toFixed(2));
  const totalRefunds = Number(refunds.reduce((acc, r) => acc + Number(r.refund_amount || 0), 0).toFixed(2));
  const netSales = Number((grossSales - discounts - totalRefunds).toFixed(2));

  const rawProductCogs = sales.reduce((acc, s) => acc + Number(s.cogs_amount || 0), 0);
  const reversedCogs = refunds.reduce((acc, r) => acc + Number(r.cogs_reversed || 0), 0);
  const productCogs = Number(Math.max(0, rawProductCogs - reversedCogs).toFixed(2));

  const rewardGiftCost = Number(
    redeemedRewards.reduce((acc, r) => acc + Number(r.unit_cost || 0), 0).toFixed(2)
  );
  const totalCogs = Number((productCogs + rewardGiftCost).toFixed(2));

  const grossProfit = Number((netSales - totalCogs).toFixed(2));
  const operatingExpenses = Number(
    expenses.reduce((acc, e) => acc + Number(e.amount || 0), 0).toFixed(2)
  );
  const netProfit = Number((grossProfit - operatingExpenses).toFixed(2));

  const grossMarginPct = netSales > 0 ? Number(((grossProfit / netSales) * 100).toFixed(2)) : 0;
  const netMarginPct = netSales > 0 ? Number(((netProfit / netSales) * 100).toFixed(2)) : 0;

  // Period Breakdown (Daily / Weekly / Monthly)
  const buckets = new Map();
  const ensureBucket = key => {
    if (!buckets.has(key)) {
      buckets.set(key, {
        period: key,
        gross_sales: 0,
        discounts: 0,
        refunds: 0,
        net_sales: 0,
        product_cogs: 0,
        reward_gift_cost: 0,
        total_cogs: 0,
        gross_profit: 0,
        operating_expenses: 0,
        net_profit: 0,
        sales_count: 0,
        expenses_count: 0,
        refunds_count: 0,
      });
    }
    return buckets.get(key);
  };

  for (const s of sales) {
    const b = ensureBucket(getPeriodKey(s.sale_date, period));
    b.gross_sales += Number(s.gross_amount || 0);
    b.discounts += Number(s.discount_amount || 0);
    b.product_cogs += Number(s.cogs_amount || 0);
    b.sales_count += 1;
  }
  for (const r of refunds) {
    const b = ensureBucket(getPeriodKey(r.refund_date, period));
    b.refunds += Number(r.refund_amount || 0);
    b.product_cogs = Math.max(0, b.product_cogs - Number(r.cogs_reversed || 0));
    b.refunds_count += 1;
  }
  for (const rwd of redeemedRewards) {
    const dStr = (rwd.redeemed_at || rwd.created_at || '').slice(0, 10);
    const b = ensureBucket(getPeriodKey(dStr, period));
    b.reward_gift_cost += Number(rwd.unit_cost || 0);
  }
  for (const e of expenses) {
    const b = ensureBucket(getPeriodKey(e.expense_date, period));
    b.operating_expenses += Number(e.amount || 0);
    b.expenses_count += 1;
  }

  const periodSummaries = Array.from(buckets.values())
    .map(b => {
      const gs = Number(b.gross_sales.toFixed(2));
      const disc = Number(b.discounts.toFixed(2));
      const ref = Number(b.refunds.toFixed(2));
      const ns = Number((gs - disc - ref).toFixed(2));
      const pcogs = Number(Math.max(0, b.product_cogs).toFixed(2));
      const rcogs = Number(b.reward_gift_cost.toFixed(2));
      const tcogs = Number((pcogs + rcogs).toFixed(2));
      const gp = Number((ns - tcogs).toFixed(2));
      const opex = Number(b.operating_expenses.toFixed(2));
      const np = Number((gp - opex).toFixed(2));
      return {
        period: b.period,
        gross_sales: gs,
        discounts: disc,
        refunds: ref,
        net_sales: ns,
        product_cogs: pcogs,
        reward_gift_cost: rcogs,
        total_cogs: tcogs,
        gross_profit: gp,
        operating_expenses: opex,
        net_profit: np,
        sales_count: b.sales_count,
        expenses_count: b.expenses_count,
        refunds_count: b.refunds_count,
      };
    })
    .sort((a, b) => b.period.localeCompare(a.period));

  // Shop-wise Breakdown
  const shopMap = new Map();
  const ensureShop = name => {
    const key = name || 'Main Counter';
    if (!shopMap.has(key)) {
      shopMap.set(key, {
        shop_name: key,
        gross_sales: 0,
        discounts: 0,
        refunds: 0,
        net_sales: 0,
        cogs: 0,
        operating_expenses: 0,
        net_profit: 0,
      });
    }
    return shopMap.get(key);
  };
  for (const s of sales) {
    const sh = ensureShop(s.shop_name);
    sh.gross_sales += Number(s.gross_amount || 0);
    sh.discounts += Number(s.discount_amount || 0);
    sh.cogs += Number(s.cogs_amount || 0);
  }
  for (const r of refunds) {
    const sh = ensureShop(r.shop_name);
    sh.refunds += Number(r.refund_amount || 0);
    sh.cogs = Math.max(0, sh.cogs - Number(r.cogs_reversed || 0));
  }
  for (const e of expenses) {
    const sh = ensureShop(e.shop_name);
    sh.operating_expenses += Number(e.amount || 0);
  }
  const shopBreakdown = Array.from(shopMap.values()).map(sh => {
    const gs = Number(sh.gross_sales.toFixed(2));
    const disc = Number(sh.discounts.toFixed(2));
    const ref = Number(sh.refunds.toFixed(2));
    const ns = Number((gs - disc - ref).toFixed(2));
    const cogs = Number(sh.cogs.toFixed(2));
    const opex = Number(sh.operating_expenses.toFixed(2));
    const np = Number((ns - cogs - opex).toFixed(2));
    return {
      shop_name: sh.shop_name,
      gross_sales: gs,
      discounts: disc,
      refunds: ref,
      net_sales: ns,
      cogs,
      operating_expenses: opex,
      net_profit: np,
    };
  });

  // Payment Method Breakdown (Recorded Sales Only — never treated as profit)
  const paymentMethodTotals = { CASH: 0, UPI: 0, CARD: 0, OTHER: 0 };
  for (const s of sales) {
    const m = paymentMethodTotals[s.payment_method] !== undefined ? s.payment_method : 'OTHER';
    paymentMethodTotals[m] = Number((paymentMethodTotals[m] + Number(s.net_amount || 0)).toFixed(2));
  }

  return {
    hasData,
    emptyMessage: hasData ? null : 'No financial data recorded yet.',
    formulas: {
      net_sales: 'Gross Sales − Discounts − Refunds',
      total_cogs: 'Recorded Product COGS − Reversed Refund COGS + Redeemed QR Reward Costs',
      gross_profit: 'Net Sales − Total Cost of Goods Sold (COGS)',
      net_profit: 'Gross Profit − Operating Expenses',
    },
    summary: {
      gross_sales: grossSales,
      discounts,
      refunds: totalRefunds,
      net_sales: netSales,
      product_cogs: productCogs,
      reward_gift_cost: rewardGiftCost,
      total_cogs: totalCogs,
      gross_profit: grossProfit,
      operating_expenses: operatingExpenses,
      net_profit: netProfit,
      gross_margin_pct: grossMarginPct,
      net_margin_pct: netMarginPct,
      sales_count: sales.length,
      refunds_count: refunds.length,
      expenses_count: expenses.length,
      redeemed_rewards_count: redeemedRewards.length,
      payment_method_totals: paymentMethodTotals,
    },
    periodSummaries,
    shopBreakdown,
  };
}

// 11. Notifications, Settings, Dashboard Stats & Audit Logs
async function createNotification({ user_id = null, type = 'INFO', title, message }) {
  const entry = {
    user_id,
    type,
    title: String(title || 'Notification').trim(),
    message: String(message || '').trim(),
    is_read: false,
    created_at: new Date().toISOString(),
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    try {
      const res = await supabaseRequest('notifications', { method: 'POST', body: entry });
      return res[0];
    } catch {
      return entry;
    }
  }
  if (isProd()) assertDatabaseConfigured();
  entry.id = 'ntf-' + crypto.randomBytes(6).toString('hex');
  memoryStore.notifications.unshift(entry);
  return entry;
}

async function listNotifications() {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('notifications?select=*&order=created_at.desc&limit=50');
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.notifications.slice(0, 50);
}

async function markNotificationRead(id) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    await supabaseRequest(`notifications?id=eq.${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: { is_read: true },
    });
    return true;
  }
  if (isProd()) assertDatabaseConfigured();
  const found = memoryStore.notifications.find(n => n.id === id);
  if (found) found.is_read = true;
  return Boolean(found);
}

async function getBusinessSettings() {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest('business_settings?key=eq.general&limit=1');
    if (res && res.length > 0) return res[0].value;
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.settings.get('general');
}

async function updateBusinessSettings(newValues, updatedBy = 'Owner') {
  const current = (await getBusinessSettings()) || {};
  const merged = {
    ...current,
    ...newValues,
    updated_at: new Date().toISOString(),
    updated_by: updatedBy,
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    await supabaseRequest('business_settings', {
      method: 'POST',
      headers: { Prefer: 'resolution=merge-duplicates,return=representation' },
      body: { key: 'general', value: merged, updated_by: updatedBy, updated_at: merged.updated_at },
    });
    return merged;
  }
  if (isProd()) assertDatabaseConfigured();
  memoryStore.settings.set('general', merged);
  return merged;
}

async function getDashboardStats() {
  await bootstrapOwnerIfEmpty();
  const [allRewards, products, pnl] = await Promise.all([
    listRewards({ includeDemo: false, limit: 2000 }),
    listProducts(),
    getRealProfitAndLoss(),
  ]);

  const totalGenerated = allRewards.length;
  const totalPlays = allRewards.filter(r => r.status === 'WAITING' || r.status === 'COLLECTED').length;
  const pendingCollection = allRewards.filter(r => r.status === 'WAITING').length;
  const totalRedeemed = allRewards.filter(r => r.status === 'COLLECTED').length;

  const todayStr = new Date().toISOString().split('T')[0];
  const playsToday = allRewards.filter(r => (r.scratched_at || r.created_at || '').startsWith(todayStr)).length;
  const redemptionsToday = allRewards.filter(r => (r.redeemed_at || '').startsWith(todayStr)).length;
  const lowStockCount = products.filter(p => p.stock_qty <= p.reorder_level).length;
  const { isConfigured } = getSupabaseConfig();

  return {
    totalGenerated,
    totalPlays,
    pendingCollection,
    totalRedeemed,
    playsToday,
    redemptionsToday,
    lowStockCount,
    totalProducts: products.length,
    hasFinancialData: pnl.hasData,
    netSales: pnl.summary.net_sales,
    netProfit: pnl.summary.net_profit,
    dbMode: isConfigured ? 'SUPABASE_POSTGRES' : 'DEV_MEMORY_STORE',
  };
}

async function addAuditLog({ actor_id, actor_name, actor_role, action, target_type, target_id, details }) {
  const entry = {
    actor_id: actor_id || null,
    actor_name: actor_name || 'System',
    actor_role: actor_role || 'SYSTEM',
    action,
    target_type: target_type || null,
    target_id: target_id ? String(target_id) : null,
    details: details || {},
    created_at: new Date().toISOString(),
  };

  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    try {
      await supabaseRequest('audit_logs', { method: 'POST', body: entry });
    } catch (err) {
      console.error('Audit log write error:', err.message);
    }
  }

  entry.id = entry.id || 'aud-' + crypto.randomBytes(6).toString('hex');
  memoryStore.auditLogs.unshift(entry);
  if (memoryStore.auditLogs.length > 500) memoryStore.auditLogs.pop();
  return entry;
}

async function listAuditLogs({ limit = 40 } = {}) {
  const { isConfigured } = getSupabaseConfig();
  if (isConfigured) {
    const res = await supabaseRequest(`audit_logs?select=*&order=created_at.desc&limit=${limit}`);
    return res || [];
  }
  if (isProd()) assertDatabaseConfigured();
  return memoryStore.auditLogs.slice(0, limit);
}

module.exports = {
  getSupabaseConfig,
  assertDatabaseConfigured,
  bootstrapOwnerIfEmpty,
  resetMemoryFinancialsAndData,
  getUserByUsername,
  getUserById,
  updateUserLastLogin,
  updateUserProfile,
  createUser,
  listUsers,
  updateUserStatus,
  recordUserSession,
  listUserSessions,
  revokeUserSessionByJti,
  listShops,
  createShop,
  listProducts,
  getProductById,
  createProduct,
  updateProduct,
  recordInventoryMovement,
  listInventoryMovements,
  createSale,
  listSales,
  createRefund,
  listRefunds,
  createExpense,
  updateExpense,
  listExpenses,
  createReward,
  claimPreGeneratedSlip,
  getRewardByCode,
  listRewards,
  redeemRewardAtomic,
  getRealProfitAndLoss,
  createNotification,
  listNotifications,
  markNotificationRead,
  getBusinessSettings,
  updateBusinessSettings,
  getDashboardStats,
  addAuditLog,
  listAuditLogs,
};
