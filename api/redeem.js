// api/redeem.js
// Atomic Single-Use Prize Verification & Redemption Endpoint
const { getSessionFromRequest, checkRateLimit, sanitizeString } = require('./_security');
const { redeemRewardAtomic, getRewardByCode } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const ip = req.headers?.['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';

  const allowed = await checkRateLimit(`redeem-${ip}`, 25, 60000);
  if (!allowed) {
    return res.status(429).json({
      error: 'Too many verification attempts. Please wait 60 seconds before trying again.',
    });
  }

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({
      error: 'Unauthorized: Counter operator authentication required to verify or redeem codes.',
    });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  body = body || {};

  const action = req.query?.action || body.action || 'redeem';
  const rawCode = body.code || req.query?.code;

  if (!rawCode) {
    return res.status(400).json({ error: 'Reward code is required.' });
  }

  const cleanCode = sanitizeString(String(rawCode).toUpperCase().trim(), 20);

  try {
    if (action === 'verify' || action === 'lookup') {
      const reward = await getRewardByCode(cleanCode);
      if (!reward || reward.is_demo) {
        return res.status(404).json({
          valid: false,
          code: 'NOT_FOUND',
          message: 'Code not found. Please double-check the characters.',
        });
      }

      if (reward.status === 'COLLECTED') {
        return res.status(200).json({
          valid: false,
          code: 'ALREADY_REDEEMED',
          message: 'This prize has already been collected.',
          customer_name: reward.customer_name,
          prize_name: reward.prize_name,
          redeemed_at: reward.redeemed_at,
          operator_name: reward.operator_name || 'Staff Member',
        });
      }

      if (reward.status !== 'WAITING' && reward.status !== 'GENERATED') {
        return res.status(200).json({
          valid: false,
          code: 'INVALID_STATUS',
          message: `This prize code is currently ${reward.status} and cannot be redeemed.`,
        });
      }

      return res.status(200).json({
        valid: true,
        code: 'READY',
        message: 'Valid prize code ready for collection.',
        customer_name: reward.customer_name,
        prize_name: reward.prize_name,
        prize_icon: reward.prize_icon,
        prize_description: reward.prize_description,
        unit_cost: reward.unit_cost,
        created_at: reward.created_at,
      });
    }

    if (action === 'redeem') {
      const notes = sanitizeString(body.notes || '', 120);
      const result = await redeemRewardAtomic({
        code: cleanCode,
        operator_id: session.id,
        operator_name: session.full_name,
        notes,
      });

      if (!result.success) {
        const status =
          result.code === 'ALREADY_REDEEMED' || result.code === 'CONCURRENT_REQUEST'
            ? 409
            : result.code === 'NOT_FOUND'
              ? 404
              : 400;
        return res.status(status).json(result);
      }

      return res.status(200).json(result);
    }

    return res.status(400).json({ error: 'Invalid redemption action.' });
  } catch (err) {
    console.error('Redeem endpoint error:', err.message);
    return res.status(500).json({
      error: 'An internal error occurred during redemption processing. The prize status was not modified.',
    });
  }
};
