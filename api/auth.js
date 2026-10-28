// api/auth.js
// Vercel Serverless Function: Authentication & Team Authorization
const {
  verifyPassword,
  createSessionToken,
  getSessionFromRequest,
  getTokenFromRequest,
  revokeToken,
  checkRateLimit,
  sanitizeString,
} = require('./_security');
const {
  getUserByUsername,
  listUsers,
  createUser,
  updateUserStatus,
  addAuditLog,
  bootstrapOwnerIfEmpty,
} = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';

  // Rate Limiting on Auth attempts (max 10 per minute per IP)
  const isAllowed = await checkRateLimit(`auth-${ip}`, 12, 60000);
  if (req.method === 'POST' && !isAllowed) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: 'Too many authentication attempts. Please wait 60 seconds.',
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

  const action = req.query.action || body.action;

  try {
    await bootstrapOwnerIfEmpty();

    // 1. GET /api/auth?action=me (Check Current Session)
    if (req.method === 'GET' || action === 'me') {
      const session = getSessionFromRequest(req);
      if (!session) {
        return res.status(401).json({ authenticated: false });
      }
      return res.status(200).json({
        authenticated: true,
        user: {
          id: session.id,
          username: session.username,
          full_name: session.full_name,
          role: session.role,
        },
      });
    }

    // 2. POST /api/auth?action=login
    if (req.method === 'POST' && (action === 'login' || !action)) {
      const username = sanitizeString(body.username, 40);
      const password = String(body.password || '');

      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
      }

      const user = await getUserByUsername(username);
      if (!user) {
        await addAuditLog({
          actor_name: username,
          actor_role: 'ANONYMOUS',
          action: 'LOGIN_FAILED',
          details: { reason: 'User not found', ip },
        });
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      if (user.status !== 'ACTIVE') {
        return res.status(403).json({ error: 'This account has been deactivated. Please contact the owner.' });
      }

      const isValid = verifyPassword(password, user.password_hash, user.salt);
      if (!isValid) {
        await addAuditLog({
          actor_id: user.id,
          actor_name: user.full_name,
          actor_role: user.role,
          action: 'LOGIN_FAILED',
          details: { reason: 'Incorrect password', ip },
        });
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      const token = createSessionToken(user);
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieHeader = `popcorn_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${isProduction ? '; Secure' : ''}`;
      res.setHeader('Set-Cookie', cookieHeader);

      await addAuditLog({
        actor_id: user.id,
        actor_name: user.full_name,
        actor_role: user.role,
        action: 'LOGIN_SUCCESS',
        details: { ip },
      });

      return res.status(200).json({
        success: true,
        token: token,
        user: {
          id: user.id,
          username: user.username,
          full_name: user.full_name,
          role: user.role,
        },
      });
    }

    // 3. POST /api/auth?action=logout
    if (req.method === 'POST' && action === 'logout') {
      const session = getSessionFromRequest(req);
      const rawToken = getTokenFromRequest(req);
      if (rawToken) {
        revokeToken(rawToken);
      }
      if (session) {
        await addAuditLog({
          actor_id: session.id,
          actor_name: session.full_name,
          actor_role: session.role,
          action: 'LOGOUT',
          details: { ip },
        });
      }
      res.setHeader('Set-Cookie', 'popcorn_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
      return res.status(200).json({ success: true, message: 'Logged out successfully.' });
    }

    // 4. Protected RBAC Operations
    const session = getSessionFromRequest(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (action === 'list-users') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Unauthorized: Owner or Admin role required.' });
      }
      const users = await listUsers();
      return res.status(200).json({ users });
    }

    if (action === 'create-user') {
      if (session.role !== 'OWNER') {
        return res.status(403).json({ error: 'Unauthorized: Only the Primary Owner can create staff accounts.' });
      }
      const newUsername = sanitizeString(body.username, 30);
      const newFullName = sanitizeString(body.full_name, 60);
      const newRole = body.role === 'ADMIN' ? 'ADMIN' : 'STAFF';
      const newPassword = String(body.password || '');

      if (!newUsername || !newFullName || newPassword.length < 6) {
        return res.status(400).json({ error: 'Username, name, and a password of at least 6 characters are required.' });
      }

      const existing = await getUserByUsername(newUsername);
      if (existing) {
        return res.status(409).json({ error: 'That username is already taken.' });
      }

      const created = await createUser({
        username: newUsername,
        full_name: newFullName,
        role: newRole,
        password: newPassword,
      });

      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'USER_CREATED',
        target_type: 'USER',
        target_id: created.id,
        details: { username: newUsername, role: newRole },
      });

      return res.status(201).json({
        success: true,
        user: {
          id: created.id,
          username: created.username,
          full_name: created.full_name,
          role: created.role,
          status: created.status,
        },
      });
    }

    if (action === 'update-user') {
      if (session.role !== 'OWNER') {
        return res.status(403).json({ error: 'Unauthorized: Only the Primary Owner can modify account privileges.' });
      }
      const targetUserId = body.userId;
      const newStatus = body.status;
      const newRole = body.role;

      if (!targetUserId) {
        return res.status(400).json({ error: 'Target userId required.' });
      }

      const updated = await updateUserStatus(targetUserId, { status: newStatus, role: newRole });
      if (!updated) {
        return res.status(404).json({ error: 'User not found.' });
      }

      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'USER_UPDATED',
        target_type: 'USER',
        target_id: targetUserId,
        details: { status: newStatus, role: newRole },
      });

      return res.status(200).json({ success: true, user: updated });
    }

    return res.status(400).json({ error: 'Invalid auth action.' });
  } catch (err) {
    console.error('Auth endpoint error:', err.message);
    return res.status(500).json({ error: err.message || 'An unexpected authentication error occurred.' });
  }
};
