// api/pnl.js
// Real Profit & Loss Report Engine (Strictly Genuine Persisted Records — Zero Fabricated Data)
const { getSessionFromRequest } = require('./_security');
const { getRealProfitAndLoss } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required to access financial reports.' });
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

  try {
    const startDate = req.query?.startDate || body.startDate || null;
    const endDate = req.query?.endDate || body.endDate || null;
    const shopId = req.query?.shopId || body.shopId || null;
    const period = req.query?.period || body.period || 'daily';

    const report = await getRealProfitAndLoss({ startDate, endDate, shopId, period });

    return res.status(200).json({
      success: true,
      hasData: report.hasData,
      emptyMessage: report.emptyMessage,
      formulas: report.formulas,
      summary: report.summary,
      periodSummaries: report.periodSummaries,
      shopBreakdown: report.shopBreakdown,
      userRole: session.role,
    });
  } catch (err) {
    console.error('P&L endpoint error:', err.message);
    const isConfigErr = err.message && err.message.includes('CRITICAL CONFIGURATION ERROR');
    return res.status(isConfigErr ? 503 : 500).json({
      error: err.message || 'Failed to calculate Profit & Loss report.',
      code: isConfigErr ? 'DB_SETUP_REQUIRED' : 'PNL_ERROR',
    });
  }
};
