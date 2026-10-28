// api/audit.js
// Vercel Serverless Function: Administrative Activity & Audit Trail
const { getSessionFromRequest } = require('./_security');
const { listAuditLogs } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  // Audit trail is strictly restricted to Owner and Admin roles
  if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Unauthorized: Audit trail inspection requires Owner or Admin role.' });
  }

  try {
    const limit = Math.min(parseInt(req.query.limit || 50, 10), 100);
    const logs = await listAuditLogs({ limit });

    return res.status(200).json({
      success: true,
      logs: logs.map(l => ({
        id: l.id,
        actor_name: l.actor_name,
        actor_role: l.actor_role,
        action: l.action,
        target_type: l.target_type,
        target_id: l.target_id,
        details: l.details,
        created_at: l.created_at,
      })),
    });
  } catch (err) {
    console.error('Audit endpoint error:', err);
    return res.status(500).json({ error: 'Failed to retrieve activity audit trail.' });
  }
};
