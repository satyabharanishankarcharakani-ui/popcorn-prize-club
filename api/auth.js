// api/auth.js
// Authentication, Owner Profile, Active Sessions & Staff RBAC Endpoint
const {
  verifyPassword,
  createSessionToken,
  verifySessionToken,
  getSessionFromRequest,
  getTokenFromRequest,
  revokeToken,
  checkRateLimit,
  sanitizeString,
} = require('./_security');
const {
  getUserByUsername,
  getUserById,
  updateUserLastLogin,
  updateUserProfile,
  listUsers,
  createUser,
  updateUserStatus,
  recordUserSession,
  listUserSessions,
  revokeUserSessionByJti,
  addAuditLog,
  bootstrapOwnerIfEmpty,
} = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const ip = req.headers?.['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';
  const userAgent = req.headers?.['user-agent'] || 'Browser';

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
    await bootstrapOwnerIfEmpty();

    // 1. GET /api/auth?action=me
    if ((req.method === 'GET' && (!action || action === 'me')) || action === 'me') {
      const session = getSessionFromRequest(req);
      if (!session) {
        return res.status(401).json({ authenticated: false });
      }
      const dbUser = await getUserById(session.id);
      if (!dbUser || dbUser.status !== 'ACTIVE') {
        return res.status(401).json({ authenticated: false });
      }
      return res.status(200).json({
        authenticated: true,
        session_jti: session.jti,
        user: {
          id: dbUser.id,
          username: dbUser.username,
          email: dbUser.email || '',
          phone: dbUser.phone || '',
          full_name: dbUser.full_name,
          avatar_url: dbUser.avatar_url || '',
          role: dbUser.role,
          status: dbUser.status,
          created_at: dbUser.created_at,
          last_login_at: dbUser.last_login_at,
        },
      });
    }

    // 2. POST /api/auth?action=login
    if (req.method === 'POST' && (action === 'login' || !action)) {
      const isAllowed = await checkRateLimit(`auth-${ip}`, 12, 60000);
      if (!isAllowed) {
        res.setHeader('Retry-After', '60');
        return res.status(429).json({
          error: 'Too many authentication attempts. Please wait 60 seconds.',
        });
      }

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
      const decoded = verifySessionToken(token);
      await updateUserLastLogin(user.id);
      if (decoded && decoded.jti) {
        await recordUserSession({
          jti: decoded.jti,
          user,
          ip_address: ip,
          user_agent: userAgent,
          expires_at: new Date(decoded.exp * 1000).toISOString(),
        });
      }

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
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email || '',
          phone: user.phone || '',
          full_name: user.full_name,
          avatar_url: user.avatar_url || '',
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
        if (session.jti) {
          await revokeUserSessionByJti(session.jti, session.id);
        }
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

    // All actions below require authentication
    const session = getSessionFromRequest(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    // 4. POST /api/auth?action=update-profile (Edit Profile Page)
    if (req.method === 'POST' && action === 'update-profile') {
      const fullName = sanitizeString(body.full_name, 80);
      const email = sanitizeString(body.email || '', 120);
      const phone = sanitizeString(body.phone || '', 32);
      const avatarUrl = sanitizeString(body.avatar_url || '', 300);
      const newPassword = body.new_password ? String(body.new_password) : '';
      const currentPassword = body.current_password ? String(body.current_password) : '';

      if (!fullName || fullName.length < 2) {
        return res.status(400).json({ error: 'Full name must be at least 2 characters.' });
      }
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
      }

      if (newPassword) {
        if (newPassword.length < 6) {
          return res.status(400).json({ error: 'New password must be at least 6 characters.' });
        }
        const currentUser = await getUserById(session.id);
        if (!currentUser || !verifyPassword(currentPassword, currentUser.password_hash, currentUser.salt)) {
          return res.status(401).json({ error: 'Current password is required and must match to set a new password.' });
        }
      }

      const updated = await updateUserProfile(session.id, {
        full_name: fullName,
        email,
        phone,
        avatar_url: avatarUrl,
        new_password: newPassword || undefined,
      });

      await addAuditLog({
        actor_id: session.id,
        actor_name: updated.full_name,
        actor_role: session.role,
        action: 'PROFILE_UPDATED',
        target_type: 'USER',
        target_id: session.id,
        details: { email: updated.email, phone: updated.phone, password_changed: Boolean(newPassword) },
      });

      return res.status(200).json({
        success: true,
        message: 'Profile saved to database.',
        user: updated,
      });
    }

    // 5. GET /api/auth?action=sessions (Security & Active Sessions Page)
    if (action === 'sessions') {
      const sessions = await listUserSessions(session.id);
      return res.status(200).json({
        success: true,
        current_jti: session.jti,
        sessions,
      });
    }

    // 6. POST /api/auth?action=revoke-session
    if (req.method === 'POST' && action === 'revoke-session') {
      const targetJti = sanitizeString(body.jti || '', 64);
      if (!targetJti) {
        return res.status(400).json({ error: 'Session identifier (jti) is required.' });
      }
      await revokeUserSessionByJti(targetJti, session.id);
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'SESSION_REVOKED',
        target_type: 'SESSION',
        target_id: targetJti,
      });
      return res.status(200).json({ success: true, message: 'Session revoked.' });
    }

    // 7. Staff & Permissions RBAC
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
      const newEmail = sanitizeString(body.email || '', 120);
      const newPhone = sanitizeString(body.phone || '', 32);
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
        email: newEmail,
        phone: newPhone,
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

      return res.status(201).json({ success: true, user: created });
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
    const isConfigErr = err.message && err.message.includes('CRITICAL CONFIGURATION ERROR');
    return res.status(isConfigErr ? 503 : 500).json({
      error: err.message || 'An unexpected authentication error occurred.',
      code: isConfigErr ? 'DB_SETUP_REQUIRED' : 'AUTH_ERROR',
    });
  }
};
