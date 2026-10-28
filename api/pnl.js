// api/pnl.js
// Vercel Serverless Function: Offers Profit & Loss Analysis Engine
const { getSessionFromRequest, sanitizeString } = require('./_security');
const { getOffersProfitLoss, updateCampaignFinances, addAuditLog } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required to access financial records.' });
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

  const action = req.query.action || body.action || 'get';

  try {
    // 1. GET /api/pnl (Read P&L Report with Filters)
    if (req.method === 'GET' || action === 'get') {
      const filters = {
        startDate: req.query.startDate || body.startDate,
        endDate: req.query.endDate || body.endDate,
        campaignId: req.query.campaignId || body.campaignId,
        status: req.query.status || body.status,
      };

      const result = await getOffersProfitLoss(filters);
      return res.status(200).json({
        success: true,
        summary: result.summary,
        offers: result.offers,
        userRole: session.role,
      });
    }

    // 2. POST /api/pnl?action=update (Update Financial Records - Owner/Admin Only)
    if (req.method === 'POST' && (action === 'update' || action === 'save')) {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({
          error: 'Unauthorized: Modifying financial records requires Owner or Admin role.',
        });
      }

      const campaignId = sanitizeString(body.campaign_id || body.campaignId, 64);
      if (!campaignId) {
        return res.status(400).json({ error: 'Campaign ID is required.' });
      }

      const attributedSales = Math.max(0, parseFloat(body.attributed_sales) || 0);
      const productCost = Math.max(0, parseFloat(body.product_cost) || 0);
      const packagingCost = Math.max(0, parseFloat(body.packaging_cost) || 0);
      const otherExpenses = Math.max(0, parseFloat(body.other_expenses) || 0);
      const unitRewardCost = Math.max(0, parseFloat(body.unit_reward_cost) || 0.50);
      const isEstimate = body.is_estimate === true || body.is_estimate === 'true';
      const notes = sanitizeString(body.notes || '', 300);

      const updated = await updateCampaignFinances(
        campaignId,
        {
          campaign_name: sanitizeString(body.campaign_name || 'Campaign Offer', 128),
          status: body.status === 'COMPLETED' ? 'COMPLETED' : (body.status === 'PAUSED' ? 'PAUSED' : 'ACTIVE'),
          start_date: body.start_date || null,
          end_date: body.end_date || null,
          attributed_sales: attributedSales,
          product_cost: productCost,
          packaging_cost: packagingCost,
          other_expenses: otherExpenses,
          unit_reward_cost: unitRewardCost,
          is_estimate: isEstimate,
          notes: notes,
        },
        session.full_name
      );

      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'FINANCES_UPDATED',
        target_type: 'CAMPAIGN_FINANCES',
        target_id: campaignId,
        details: {
          sales: attributedSales,
          productCost,
          packagingCost,
          otherExpenses,
          isEstimate,
        },
      });

      // Recalculate P&L with updated figures
      const refreshed = await getOffersProfitLoss({ campaignId });

      return res.status(200).json({
        success: true,
        message: 'Financial figures updated successfully.',
        updatedRecord: updated,
        refreshedPnl: refreshed.offers[0] || null,
      });
    }

    return res.status(400).json({ error: 'Invalid P&L action.' });
  } catch (err) {
    console.error('P&L endpoint error:', err.message);
    return res.status(500).json({ error: err.message || 'Failed to process Profit & Loss report.' });
  }
};
