// api/auth.js
// Authentication, Owner Profile, Active Sessions & Staff RBAC Endpoint
const {
  verifyPassword,
  createSessionToken,
  verifySessionToken,
  createSignedOwnerVault,
  getOwnerVaultFromRequest,
  getSessionFromRequest,
  getTokenFromRequest,
  revokeToken,
  checkRateLimit,
  sanitizeString,
} = require('./_security');
const {
  getUserByUsername,
  getUserByEmail,
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
  isFirstOwnerSignupAvailable,
  registerFirstOwner,
  requestDashboardAccess,
  hydrateOwnerFromVault,
  getRawVaultSnapshot,
} = require('./_db');
const {
  getGoogleConfig,
  createState,
  verifyState,
  buildAuthUrl,
  exchangeCodeForProfile,
} = require('./_google');

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
    const vaultUser = getOwnerVaultFromRequest(req);
    if (vaultUser) {
      hydrateOwnerFromVault(vaultUser);
    }

    // 0. GET /api/auth?action=setup-status (Check whether 1st-time Owner Sign-Up is available)
    if (action === 'setup-status') {
      const signupAvailable = await isFirstOwnerSignupAvailable();
      return res.status(200).json({
        success: true,
        signup_available: signupAvailable,
        initialized: !signupAvailable,
      });
    }

    // 0b. POST /api/auth?action=signup-first-owner (One-time First Owner Sign-Up -> Permanently locks to Login after 1st use)
    if (req.method === 'POST' && action === 'signup-first-owner') {
      const isAllowed = await checkRateLimit(`signup-owner-${ip}`, 8, 60000);
      if (!isAllowed) {
        return res.status(429).json({ error: 'Too many attempts. Please wait 60 seconds.' });
      }

      const available = await isFirstOwnerSignupAvailable();
      if (!available) {
        return res.status(403).json({
          error: 'Primary Owner account is already registered. Sign-up is permanently disabled; please sign in on the Login page.',
          code: 'ALREADY_INITIALIZED',
        });
      }

      const fullName = sanitizeString(body.full_name || '', 80);
      const username = sanitizeString(body.username || '', 40).toLowerCase();
      const email = sanitizeString(body.email || '', 120);
      const phone = sanitizeString(body.phone || '', 32);
      const password = String(body.password || '');

      if (!fullName || fullName.length < 2) {
        return res.status(400).json({ error: 'Full name is required (at least 2 characters).' });
      }
      if (!username || username.length < 3) {
        return res.status(400).json({ error: 'Username is required (at least 3 characters).' });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
      }

      const ownerUser = await registerFirstOwner({
        username,
        full_name: fullName,
        email,
        phone,
        password,
      });

      const token = createSessionToken(ownerUser);
      const decoded = verifySessionToken(token);
      if (decoded && decoded.jti) {
        await recordUserSession({
          jti: decoded.jti,
          user: ownerUser,
          ip_address: ip,
          user_agent: userAgent,
          expires_at: new Date(decoded.exp * 1000).toISOString(),
        });
      }

      const isProduction = process.env.NODE_ENV === 'production';
      const { primaryOwner, teamUsers } = getRawVaultSnapshot();
      const rawOwner = primaryOwner || (await getUserById(ownerUser.id));
      const ownerVault = createSignedOwnerVault(rawOwner, teamUsers);
      const sessionCookie = `popcorn_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${isProduction ? '; Secure' : ''}`;
      const cookies = [sessionCookie];
      if (ownerVault) {
        cookies.push(`popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`);
      }
      res.setHeader('Set-Cookie', cookies);

      await addAuditLog({
        actor_id: ownerUser.id,
        actor_name: ownerUser.full_name,
        actor_role: 'OWNER',
        action: 'FIRST_OWNER_SIGNUP',
        target_type: 'USER',
        target_id: ownerUser.id,
        details: { username: ownerUser.username, ip },
      });

      return res.status(201).json({
        success: true,
        message: 'Primary Owner account created! Sign-up is now permanently locked to Login only.',
        token,
        owner_vault: ownerVault,
        user: ownerUser,
      });
    }

    // 0c. POST /api/auth?action=request-access (Always-available Sign-Up with Owner Permission Gate)
    if (req.method === 'POST' && action === 'request-access') {
      const isAllowed = await checkRateLimit(`signup-req-${ip}`, 10, 60000);
      if (!isAllowed) {
        return res.status(429).json({ error: 'Too many signup requests. Please wait 60 seconds.' });
      }

      const fullName = sanitizeString(body.full_name || '', 80);
      const username = sanitizeString(body.username || '', 40).toLowerCase();
      const email = sanitizeString(body.email || '', 120).toLowerCase();
      const phone = sanitizeString(body.phone || '', 32);
      const password = String(body.password || '');

      if (!fullName || fullName.length < 2) {
        return res.status(400).json({ error: 'Full name is required (at least 2 characters).' });
      }
      if (!username || username.length < 3) {
        return res.status(400).json({ error: 'Username is required (at least 3 characters).' });
      }
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'A valid Google / email address is required so you can also Sign in with Google.' });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
      }

      let result;
      try {
        result = await requestDashboardAccess({
          username,
          full_name: fullName,
          email,
          phone,
          password,
        });
      } catch (err) {
        return res.status(err.statusCode || 400).json({
          error: err.message,
          code: err.code || 'SIGNUP_ERROR',
          field: err.field,
        });
      }

      const isProduction = process.env.NODE_ENV === 'production';
      const { primaryOwner, teamUsers } = getRawVaultSnapshot();
      const ownerVault = primaryOwner ? createSignedOwnerVault(primaryOwner, teamUsers) : null;

      if (result.is_first_owner) {
        const ownerUser = result.user;
        const token = createSessionToken(ownerUser);
        const decoded = verifySessionToken(token);
        if (decoded && decoded.jti) {
          await recordUserSession({
            jti: decoded.jti,
            user: ownerUser,
            ip_address: ip,
            user_agent: userAgent,
            expires_at: new Date(decoded.exp * 1000).toISOString(),
          });
        }
        const cookies = [`popcorn_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${isProduction ? '; Secure' : ''}`];
        if (ownerVault) {
          cookies.push(`popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`);
        }
        res.setHeader('Set-Cookie', cookies);

        await addAuditLog({
          actor_id: ownerUser.id,
          actor_name: ownerUser.full_name,
          actor_role: 'OWNER',
          action: 'FIRST_OWNER_SIGNUP',
          target_type: 'USER',
          target_id: ownerUser.id,
          details: { username: ownerUser.username, email: ownerUser.email, ip },
        });

        return res.status(201).json({
          success: true,
          is_first_owner: true,
          pending_approval: false,
          message: 'Primary Owner account created! Welcome to the Owner Dashboard.',
          token,
          owner_vault: ownerVault,
          user: ownerUser,
        });
      }

      if (ownerVault) {
        res.setHeader(
          'Set-Cookie',
          `popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`
        );
      }

      await addAuditLog({
        actor_id: result.user.id,
        actor_name: result.user.full_name,
        actor_role: 'STAFF',
        action: 'ACCESS_REQUEST_SUBMITTED',
        target_type: 'USER',
        target_id: result.user.id,
        details: { username: result.user.username, email: result.user.email, status: 'PENDING_APPROVAL', ip },
      });

      return res.status(201).json({
        success: true,
        is_first_owner: false,
        pending_approval: true,
        code: 'PENDING_APPROVAL',
        message: 'Sign-up submitted! Your account is waiting for permission from Shankar & Mom (Primary Owners). Without their approval, access to the Owner Dashboard is locked.',
        owner_vault: ownerVault,
        user: result.user,
      });
    }

    // 0d. GET /api/auth?action=google-config (Is real Google Sign-In configured?)
    if (action === 'google-config') {
      const { enabled } = getGoogleConfig();
      return res.status(200).json({ success: true, google_enabled: enabled });
    }

    // 0e. GET /api/auth?action=google-start -> 302 redirect to Google's real account chooser page
    if (action === 'google-start') {
      const { enabled } = getGoogleConfig();
      if (!enabled) {
        return res.status(503).json({
          error: 'Google Sign-In is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Vercel Environment Variables.',
          code: 'GOOGLE_NOT_CONFIGURED',
        });
      }
      const isAllowed = await checkRateLimit(`google-start-${ip}`, 20, 60000);
      if (!isAllowed) {
        return res.status(429).json({ error: 'Too many sign-in attempts. Please wait 60 seconds.' });
      }
      const { state, cookieValue } = createState();
      const isProduction = process.env.NODE_ENV === 'production';
      res.setHeader(
        'Set-Cookie',
        `popcorn_google_state=${cookieValue}; Path=/api; HttpOnly; SameSite=Lax; Max-Age=600${isProduction ? '; Secure' : ''}`
      );
      res.statusCode = 302;
      res.setHeader('Location', buildAuthUrl(req, state));
      return res.end ? res.end() : res.status(302).json({ redirect: buildAuthUrl(req, state) });
    }

    // 0f. GET /api/google/callback (rewritten to /api/auth?action=google-callback)
    if (action === 'google-callback') {
      const isProduction = process.env.NODE_ENV === 'production';
      const clearState = `popcorn_google_state=; Path=/api; HttpOnly; SameSite=Lax; Max-Age=0${isProduction ? '; Secure' : ''}`;
      const redirectTo = (params, extraCookies = []) => {
        res.setHeader('Set-Cookie', [clearState, ...extraCookies]);
        res.statusCode = 302;
        res.setHeader('Location', `/owner?${new URLSearchParams(params).toString()}`);
        return res.end ? res.end() : res.status(302).json({ redirect: `/owner?${new URLSearchParams(params).toString()}` });
      };

      const { enabled } = getGoogleConfig();
      if (!enabled) return redirectTo({ google: 'not_configured' });
      if (req.query?.error) return redirectTo({ google: 'cancelled' });
      if (!verifyState(req.query?.state, req.headers?.cookie)) return redirectTo({ google: 'invalid_state' });
      if (!req.query?.code) return redirectTo({ google: 'error' });

      let profile;
      try {
        profile = await exchangeCodeForProfile(req, req.query.code);
      } catch (err) {
        console.error('Google OAuth error:', err.message);
        return redirectTo({ google: 'error' });
      }

      const user = await getUserByEmail(profile.email);
      if (!user) {
        await addAuditLog({
          actor_name: profile.email,
          actor_role: 'ANONYMOUS',
          action: 'GOOGLE_LOGIN_UNREGISTERED',
          details: { email: profile.email, ip },
        });
        return redirectTo({ google: 'signup', email: profile.email, name: profile.name });
      }

      if (user.status === 'PENDING_APPROVAL') {
        await addAuditLog({
          actor_id: user.id,
          actor_name: user.full_name,
          actor_role: user.role,
          action: 'GOOGLE_LOGIN_BLOCKED_PENDING',
          details: { email: profile.email, ip },
        });
        return redirectTo({ google: 'pending', email: profile.email });
      }
      if (user.status !== 'ACTIVE') {
        return redirectTo({ google: 'disabled', email: profile.email });
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
      await addAuditLog({
        actor_id: user.id,
        actor_name: user.full_name,
        actor_role: user.role,
        action: 'GOOGLE_LOGIN_SUCCESS',
        details: { email: profile.email, ip },
      });
      const sessionCookie = `popcorn_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${isProduction ? '; Secure' : ''}`;
      return redirectTo({ google: 'ok' }, [sessionCookie]);
    }

    // 0g. POST /api/auth?action=check-account (Does an account already exist for this username / email?)
    if (req.method === 'POST' && action === 'check-account') {
      const isAllowed = await checkRateLimit(`check-account-${ip}`, 20, 60000);
      if (!isAllowed) {
        return res.status(429).json({ error: 'Too many checks. Please wait 60 seconds.' });
      }
      const username = sanitizeString(body.username || '', 40).toLowerCase();
      const email = sanitizeString(body.email || '', 120).toLowerCase();
      const byUser = username ? await getUserByUsername(username) : null;
      const byEmail = email ? await getUserByEmail(email) : null;
      return res.status(200).json({
        success: true,
        username_taken: Boolean(byUser),
        email_taken: Boolean(byEmail),
        exists: Boolean(byUser || byEmail),
      });
    }

    // 0h. POST /api/auth?action=google-login (Direct API login using verified Google email or mock test)
    if (req.method === 'POST' && action === 'google-login') {
      const isAllowed = await checkRateLimit(`google-auth-${ip}`, 15, 60000);
      if (!isAllowed) {
        return res.status(429).json({ error: 'Too many authentication attempts. Please wait 60 seconds.' });
      }

      const email = sanitizeString(body.email || '', 120).toLowerCase();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Please enter a valid Google email address.' });
      }

      const user = await getUserByEmail(email);
      if (!user) {
        return res.status(404).json({
          error: `No account found for "${email}". Please Sign Up first.`,
          code: 'EMAIL_NOT_REGISTERED',
          email,
        });
      }

      if (user.status === 'PENDING_APPROVAL') {
        return res.status(403).json({
          error: `Permission Required: Your account (${email}) is waiting for approval from Shankar & Mom.`,
          code: 'PENDING_APPROVAL',
          user: {
            full_name: user.full_name,
            username: user.username,
            email: user.email,
            status: user.status,
          },
        });
      }

      if (user.status !== 'ACTIVE') {
        return res.status(403).json({
          error: 'Access Denied: This account has been rejected or disabled by the Primary Owner.',
          code: 'ACCOUNT_DISABLED',
        });
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
          must_change_password: Boolean(user.must_change_password),
        },
      });
    }

    // 1. GET /api/auth?action=me
    if ((req.method === 'GET' && (!action || action === 'me')) || action === 'me') {
      const signupAvailable = await isFirstOwnerSignupAvailable();
      const session = getSessionFromRequest(req);
      if (!session) {
        return res.status(401).json({ authenticated: false, signup_available: signupAvailable });
      }
      const dbUser = await getUserById(session.id);
      if (!dbUser || dbUser.status !== 'ACTIVE') {
        return res.status(401).json({ authenticated: false, signup_available: signupAvailable });
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
          must_change_password: Boolean(dbUser.must_change_password),
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

      const username = sanitizeString(body.username, 120);
      const password = String(body.password || '');

      if (!username || !password) {
        return res.status(400).json({ error: 'Username or email and password are required.' });
      }

      let user = await getUserByUsername(username);
      if (!user && username.includes('@')) {
        user = await getUserByEmail(username);
      }
      if (!user) {
        await addAuditLog({
          actor_name: username,
          actor_role: 'ANONYMOUS',
          action: 'LOGIN_FAILED',
          details: { reason: 'User not found', ip },
        });
        return res.status(401).json({ error: 'Invalid username or password.' });
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

      if (user.status === 'PENDING_APPROVAL') {
        await addAuditLog({
          actor_id: user.id,
          actor_name: user.full_name,
          actor_role: user.role,
          action: 'LOGIN_BLOCKED_PENDING_APPROVAL',
          details: { username: user.username, email: user.email, ip },
        });
        return res.status(403).json({
          error: 'Permission Required: Your account is waiting for approval from Shankar & Mom (Primary Owners). Without their permission, you cannot access the Owner Dashboard.',
          code: 'PENDING_APPROVAL',
          user: {
            full_name: user.full_name,
            username: user.username,
            email: user.email || '',
            status: user.status,
          },
        });
      }

      if (user.status !== 'ACTIVE') {
        return res.status(403).json({
          error: 'This account has been deactivated or rejected. Please contact Shankar & Mom.',
          code: 'ACCOUNT_DISABLED',
        });
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
          must_change_password: Boolean(user.must_change_password),
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

      let refreshedToken;
      let ownerVault;
      const { primaryOwner, teamUsers } = getRawVaultSnapshot();
      const rawUpdated = primaryOwner || (await getUserById(session.id));
      if (rawUpdated && rawUpdated.role === 'OWNER') {
        ownerVault = createSignedOwnerVault(rawUpdated, teamUsers);
      }
      if (newPassword) {
        refreshedToken = createSessionToken(updated);
        const isProduction = process.env.NODE_ENV === 'production';
        const cookies = [`popcorn_session=${refreshedToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${isProduction ? '; Secure' : ''}`];
        if (ownerVault) {
          cookies.push(`popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`);
        }
        res.setHeader('Set-Cookie', cookies);
      } else if (ownerVault) {
        const isProduction = process.env.NODE_ENV === 'production';
        res.setHeader(
          'Set-Cookie',
          `popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`
        );
      }

      return res.status(200).json({
        success: true,
        message: 'Profile saved to database.',
        token: refreshedToken,
        owner_vault: ownerVault,
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
      if (session.must_change_password) {
        return res.status(403).json({
          error: 'Security Policy: You must change your initial bootstrap password in Edit Profile before creating staff accounts.',
          code: 'PASSWORD_CHANGE_REQUIRED',
        });
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

      const { primaryOwner, teamUsers } = getRawVaultSnapshot();
      const ownerVault = primaryOwner ? createSignedOwnerVault(primaryOwner, teamUsers) : null;
      if (ownerVault) {
        const isProduction = process.env.NODE_ENV === 'production';
        res.setHeader(
          'Set-Cookie',
          `popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`
        );
      }

      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'USER_CREATED',
        target_type: 'USER',
        target_id: created.id,
        details: { username: newUsername, role: newRole },
      });

      return res.status(201).json({ success: true, user: created, owner_vault: ownerVault });
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

      const { primaryOwner, teamUsers } = getRawVaultSnapshot();
      const ownerVault = primaryOwner ? createSignedOwnerVault(primaryOwner, teamUsers) : null;
      if (ownerVault) {
        const isProduction = process.env.NODE_ENV === 'production';
        res.setHeader(
          'Set-Cookie',
          `popcorn_owner_vault=${ownerVault}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${isProduction ? '; Secure' : ''}`
        );
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

      return res.status(200).json({ success: true, user: updated, owner_vault: ownerVault });
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
