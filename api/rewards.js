// api/rewards.js
// Customer QR Prize Issuance, Slip Claiming, Batch QR Generation & Winner Registry
// Strictly excludes demo records from winner listings.
const {
  getSessionFromRequest,
  generateSecureRewardCode,
  isValidRewardCodeFormat,
  checkRateLimit,
  sanitizeString,
} = require('./_security');
const {
  createReward,
  claimPreGeneratedSlip,
  listRewards,
  getRewardByCode,
  addAuditLog,
} = require('./_db');

const PRIZE_CATALOG = [
  { name: 'Mini Masala Pack + ₹10 Water Bottle', icon: '🍿💧', desc: 'One spicy mini masala popcorn pack + chilled ₹10 water bottle combo!', unit_cost: 22, image: 'prize-masala-water10-combo.jpg' },
  { name: 'Popcorn Tub + ₹20 Water Bottle Combo', icon: '🍿💧', desc: 'Fresh gourmet popcorn tub paired with a chilled ₹20 water bottle!', unit_cost: 35, image: 'prize-tub-water20-combo.jpg' },
  { name: 'Free Fresh Popcorn Tub!', icon: '🍿', desc: 'One fresh hot gourmet popcorn tub, on us.', unit_cost: 20, image: 'prize-free-popcorn-tub.jpg' },
  { name: 'Buy 1 Get 1 Free Masala & Cheese Duo', icon: '🎉', desc: 'Two overflowing tubs of masala and cheese popcorn for your next visit.', unit_cost: 25, image: 'prize-bogo-popcorn.jpg' },
  { name: 'Mini Masala Pack + 50% Off VIP Token', icon: '🏷️', desc: 'Complimentary mini masala pack plus 50% off your next bag.', unit_cost: 18, image: 'prize-vip-combo-pack.jpg' },
];

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const ip = req.headers?.['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  body = body || {};

  const action = req.query?.action || body.action;

  try {
    // 1. PUBLIC ACTION: Customer scratch card play or pre-printed QR slip claim
    if (req.method === 'POST' && (action === 'issue' || action === 'claim' || !action)) {
      const allowed = await checkRateLimit(`play-${ip}`, 10, 120000);
      if (!allowed) {
        return res.status(429).json({
          error: 'Playing too fast! Please wait a moment before trying another lucky card.',
        });
      }

      const rawName = body.customer_name || body.name || 'Friend';
      const customerName = sanitizeString(rawName, 32) || 'Friend';
      const preCode = body.code ? sanitizeString(String(body.code).toUpperCase(), 24) : '';

      if (preCode) {
        const claimed = await claimPreGeneratedSlip(preCode, customerName);
        if (claimed) {
          const pIdx = Math.max(
            0,
            PRIZE_CATALOG.findIndex(p => p.name.toLowerCase() === String(claimed.prize_name || '').toLowerCase())
          );
          return res.status(200).json({
            success: true,
            code: claimed.code,
            prize: {
              name: claimed.prize_name,
              icon: claimed.prize_icon,
              desc: claimed.prize_description,
              index: pIdx,
            },
            customer_name: claimed.customer_name,
            status: claimed.status,
          });
        }
      }

      let chosenPrize = null;
      let prizeIndex = 0;
      if (body.prize_name) {
        const foundIdx = PRIZE_CATALOG.findIndex(
          p => p.name.toLowerCase() === String(body.prize_name).toLowerCase()
        );
        if (foundIdx >= 0) {
          prizeIndex = foundIdx;
          chosenPrize = PRIZE_CATALOG[foundIdx];
        }
      }
      if (!chosenPrize) {
        prizeIndex = Math.floor(Math.random() * PRIZE_CATALOG.length);
        chosenPrize = PRIZE_CATALOG[prizeIndex];
      }
      const secureCode = (preCode && isValidRewardCodeFormat(preCode)) ? preCode : generateSecureRewardCode();

      const created = await createReward({
        code: secureCode,
        customer_name: customerName,
        prize_name: chosenPrize.name,
        prize_icon: chosenPrize.icon,
        prize_description: chosenPrize.desc,
        unit_cost: chosenPrize.unit_cost,
        status: 'WAITING',
        is_demo: false,
      });

      return res.status(201).json({
        success: true,
        code: created.code,
        prize: {
          name: created.prize_name,
          icon: created.prize_icon,
          desc: created.prize_description,
          index: prizeIndex,
        },
        customer_name: created.customer_name,
        status: created.status,
      });
    }

    // 2. PROTECTED ACTIONS: Require Staff, Admin, or Owner
    const session = getSessionFromRequest(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required to access reward management.' });
    }

    // GET /api/rewards?action=list (Never returns demo winners)
    if (req.method === 'GET' && (!action || action === 'list')) {
      const status = req.query?.status || body.status;
      const search = req.query?.search || body.search;
      const limit = Math.min(parseInt(req.query?.limit || body.limit || 100, 10), 200);

      const rewards = await listRewards({ status, search, includeDemo: false, limit });
      return res.status(200).json({ rewards });
    }

    if (action === 'list') {
      const status = req.query?.status || body.status;
      const search = req.query?.search || body.search;
      const limit = Math.min(parseInt(req.query?.limit || body.limit || 100, 10), 200);

      const rewards = await listRewards({ status, search, includeDemo: false, limit });
      return res.status(200).json({ rewards });
    }

    // GET /api/rewards?action=lookup&code=...
    if (action === 'lookup') {
      const code = req.query?.code || body.code;
      if (!code) return res.status(400).json({ error: 'Code is required.' });

      const reward = await getRewardByCode(code);
      if (!reward || reward.is_demo) {
        return res.status(404).json({ error: 'Code not found in genuine reward registry.' });
      }
      return res.status(200).json({ reward });
    }

    // POST /api/rewards?action=batch-generate (Owner & Admin only)
    if (action === 'batch-generate') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Unauthorized: Batch generation requires Admin or Owner role.' });
      }

      const batchName = sanitizeString(body.batch_name || 'Batch #1', 64);
      const count = Math.min(Math.max(1, parseInt(body.count || 10, 10)), 100);
      const generated = [];

      for (let i = 0; i < count; i++) {
        const prize = PRIZE_CATALOG[i % PRIZE_CATALOG.length];
        const code = generateSecureRewardCode();
        const rwd = await createReward({
          code,
          customer_name: `QR Slip (${batchName})`,
          prize_name: prize.name,
          prize_icon: prize.icon,
          prize_description: prize.desc,
          unit_cost: prize.unit_cost,
          batch_name: batchName,
          status: 'GENERATED',
          is_demo: false,
        });
        generated.push(rwd);
      }

      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'BATCH_REWARDS_GENERATED',
        details: { count: generated.length, batch_name: batchName },
      });

      return res.status(201).json({
        success: true,
        count: generated.length,
        rewards: generated,
      });
    }

    return res.status(400).json({ error: 'Invalid rewards action.' });
  } catch (err) {
    console.error('Rewards endpoint error:', err.message);
    const isConfigErr = err.message && err.message.includes('CRITICAL CONFIGURATION ERROR');
    return res.status(isConfigErr ? 503 : 500).json({
      error: err.message || 'An unexpected reward service error occurred.',
      code: isConfigErr ? 'DB_SETUP_REQUIRED' : 'REWARDS_ERROR',
    });
  }
};
