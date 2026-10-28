// api/stats.js
// Vercel Serverless Function: Real Database-Backed Business Metrics
const { getSessionFromRequest } = require('./_security');
const { getDashboardStats } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required to access dashboard metrics.' });
  }

  // Staff role has limited view, Admin and Owner have full view
  try {
    const stats = await getDashboardStats();

    return res.status(200).json({
      success: true,
      stats: {
        totalPlays: stats.totalPlays,
        pendingCollection: stats.pendingCollection,
        totalRedeemed: stats.totalRedeemed,
        playsToday: stats.playsToday,
        redemptionsToday: stats.redemptionsToday,
        activeCampaigns: stats.activeCampaigns,
        conversionRate: stats.totalPlays > 0 ? ((stats.totalRedeemed / stats.totalPlays) * 100).toFixed(1) + '%' : '0.0%',
        storageMode: stats.dbMode,
        serverTime: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error('Stats endpoint error:', err);
    return res.status(500).json({ error: 'Failed to compute dashboard metrics.' });
  }
};
