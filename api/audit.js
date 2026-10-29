// api/audit.js
// Immutable Security & Operational Audit Trail Endpoint
const { getSessionFromRequest } = require('./_security');
const { listAuditLogs } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Unauthorized: Audit trail inspection requires Owner or Admin role.' });
  }

  try {
    const limit = Math.min(parseInt(req.query?.limit || 50, 10), 100);
    const logs = await listAuditLogs({ limit });
    return res.status(200).json({
      success: true,
      logs,
    });
  } catch (err) {
    console.error('Audit endpoint error:', err.message);
    return res.status(500).json({ error: 'Failed to retrieve activity audit trail.' });
  }
};
