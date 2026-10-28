// api/rewards.js
// Vercel Serverless Function: Reward Code Generation, Public Issue & Campaign Management
const {
  getSessionFromRequest,
  generateSecureRewardCode,
  checkRateLimit,
  sanitizeString,
} = require('./_security');
const {
  createReward,
  listRewards,
  getRewardByCode,
  addAuditLog,
} = require('./_db');

const PRIZE_CATALOG = [
  { name: 'Free Popcorn Tub!', icon: '🍿', desc: 'One fresh popcorn tub on the house.' },
  { name: '50% Off Any Bag', icon: '🏷️', desc: 'Enjoy half off on your next visit.' },
  { name: 'Free Topping Upgrade', icon: '✨', desc: 'Add caramel or cheese drizzle free.' },
  { name: 'Buy 1 Get 1 Free', icon: '🎉', desc: 'Bring a friend for your next movie treat.' },
  { name: 'Bonus Mini Movie Pack', icon: '🍿', desc: 'Complimentary snack pack.' },
];

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  body = body || {};

  const action = req.query.action || body.action;

  try {
    // 1. PUBLIC ACTION: Customer scratch card play / prize issuance
    if (req.method === 'POST' && (action === 'issue' || !action)) {
      // Rate limit customer plays: max 8 plays per 2 minutes per IP
      if (!checkRateLimit(`play-${ip}`, 8, 120000)) {
        return res.status(429).json({
          error: 'Playing too fast! Please wait a moment before trying another lucky card.',
        });
      }

      const rawName = body.customer_name || body.name || 'Friend';
      const customerName = sanitizeString(rawName, 32);

      // Select randomized prize from catalog
      const prizeIndex = Math.floor(Math.random() * PRIZE_CATALOG.length);
      const chosenPrize = PRIZE_CATALOG[prizeIndex];
      const secureCode = generateSecureRewardCode();

      const created = await createReward({
        code: secureCode,
        customer_name: customerName,
        prize_name: chosenPrize.name,
        prize_icon: chosenPrize.icon,
        prize_description: chosenPrize.desc,
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

    // GET /api/rewards?action=list
    if (req.method === 'GET' || action === 'list') {
      const status = req.query.status || body.status;
      const search = req.query.search || body.search;
      const limit = Math.min(parseInt(req.query.limit || body.limit || 50, 10), 100);

      const rewards = await listRewards({ status, search, limit });
      return res.status(200).json({ rewards });
    }

    // GET /api/rewards?action=lookup&code=...
    if (action === 'lookup') {
      const code = req.query.code || body.code;
      if (!code) return res.status(400).json({ error: 'Code is required.' });

      const reward = await getRewardByCode(code);
      if (!reward) {
        return res.status(404).json({ error: 'Code not found in registry.' });
      }
      return res.status(200).json({ reward });
    }

    // POST /api/rewards?action=batch-generate (Owner & Admin only)
    if (action === 'batch-generate') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Unauthorized: Batch generation requires Admin or Owner role.' });
      }

      const count = Math.min(parseInt(body.count || 10, 10), 50);
      const generated = [];

      for (let i = 0; i < count; i++) {
        const prize = PRIZE_CATALOG[Math.floor(Math.random() * PRIZE_CATALOG.length)];
        const code = generateSecureRewardCode();
        const rwd = await createReward({
          code,
          customer_name: 'Lucky Pack Insert',
          prize_name: prize.name,
          prize_icon: prize.icon,
          prize_description: prize.desc,
        });
        generated.push(rwd);
      }

      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'BATCH_REWARDS_GENERATED',
        details: { count: generated.length },
      });

      return res.status(201).json({
        success: true,
        count: generated.length,
        rewards: generated,
      });
    }

    return res.status(400).json({ error: 'Invalid rewards action.' });
  } catch (err) {
    console.error('Rewards endpoint error:', err);
    return res.status(500).json({ error: 'An unexpected reward service error occurred.' });
  }
};
