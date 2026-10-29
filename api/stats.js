// api/stats.js
// Real Database-Backed Dashboard Metrics (No Fabricated Data)
const { getSessionFromRequest } = require('./_security');
const { getDashboardStats } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required to access dashboard metrics.' });
  }

  try {
    const stats = await getDashboardStats();
    return res.status(200).json({
      success: true,
      stats: {
        ...stats,
        conversionRate:
          stats.totalPlays > 0 ? ((stats.totalRedeemed / stats.totalPlays) * 100).toFixed(1) + '%' : '0.0%',
        serverTime: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error('Stats endpoint error:', err.message);
    return res.status(500).json({ error: 'Failed to compute dashboard metrics.' });
  }
};
