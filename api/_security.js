// api/_security.js
// Cryptographic, Session, Rate-Limiting, and Input Validation Layer
const crypto = require('crypto');

const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours

function isStrictProduction() {
  return process.env.STRICT_CONFIG_CHECK === 'true';
}

function isProdEnv() {
  return process.env.STRICT_CONFIG_CHECK === 'true';
}

function getAuthSecret() {
  const secret = process.env.AUTH_SECRET;
  if (isProdEnv()) {
    if (!secret || secret.length < 32 || secret.includes('replace_with')) {
      throw new Error(
        'CRITICAL CONFIGURATION ERROR: AUTH_SECRET must be configured with a random string of at least 32 characters in production. Failing closed.'
      );
    }
    return secret;
  }
  if (secret && secret.length >= 32 && !secret.includes('replace_with')) {
    return secret;
  }
  const seed = process.env.VERCEL_PROJECT_ID || process.env.VERCEL_GIT_REPO_SLUG || 'popcorn-club-local-dev-secret-2026';
  return crypto.createHash('sha256').update(`lr-popcorn-prize-club:${seed}`).digest('hex');
}

function hashPassword(password, existingSalt = null) {
  if (!password || typeof password !== 'string' || password.length < 6) {
    throw new Error('Password must be at least 6 characters.');
  }
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash: derivedKey, salt };
}

function verifyPassword(password, storedHash, salt) {
  if (!password || !storedHash || !salt) return false;
  try {
    const { hash } = hashPassword(password, salt);
    const hashBuf = Buffer.from(hash, 'hex');
    const storedBuf = Buffer.from(storedHash, 'hex');
    if (hashBuf.length !== storedBuf.length) return false;
    return crypto.timingSafeEqual(hashBuf, storedBuf);
  } catch {
    return false;
  }
}

function generateSecureRewardCode() {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(6);
  let result = 'PC-';
  for (let i = 0; i < 6; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

const revokedTokenSignatures = new Set();
const revokedJtis = new Set();

function revokeToken(token) {
  if (!token || typeof token !== 'string') return;
  const parts = token.split('.');
  if (parts.length === 3) {
    revokedTokenSignatures.add(parts[2]);
    try {
      const data = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (data.jti) revokedJtis.add(data.jti);
    } catch {}
    if (revokedTokenSignatures.size > 2000) {
      revokedTokenSignatures.delete(revokedTokenSignatures.values().next().value);
    }
  }
}

function revokeJti(jti) {
  if (jti) revokedJtis.add(String(jti));
}

function isJtiRevoked(jti) {
  return Boolean(jti && revokedJtis.has(String(jti)));
}

function createSessionToken(user) {
  const secret = getAuthSecret();
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomBytes(12).toString('hex');

  const payloadObj = {
    uid: user.id,
    usr: user.username,
    name: user.full_name,
    rol: user.role,
    mcp: Boolean(user.must_change_password),
    jti,
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
  };
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');

  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url');

  return `${header}.${payload}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  if (revokedTokenSignatures.has(signature)) return null;

  let secret;
  try {
    secret = getAuthSecret();
  } catch (err) {
    console.error('Session verification halted:', err.message);
    return null;
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url');

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expectedSignature);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (data.exp && data.exp < now) return null;
    if (data.jti && revokedJtis.has(data.jti)) return null;
    return {
      id: data.uid,
      username: data.usr,
      full_name: data.name,
      role: data.rol,
      must_change_password: Boolean(data.mcp),
      jti: data.jti,
      iat: data.iat,
      exp: data.exp,
    };
  } catch {
    return null;
  }
}

function getTokenFromRequest(req) {
  const authHeader = req.headers?.authorization || req.headers?.Authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (req.headers?.cookie) {
    const match = req.headers.cookie.match(/popcorn_session=([^;]+)/);
    if (match) return match[1];
  }
  return null;
}

function getSessionFromRequest(req) {
  const token = getTokenFromRequest(req);
  return verifySessionToken(token);
}

const rateLimitMap = new Map();
async function checkRateLimit(key, maxRequests = 20, windowMs = 60000) {
  const kvUrl = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const kvToken = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (kvUrl && kvToken) {
    try {
      const res = await fetch(`${kvUrl}/incr/${encodeURIComponent(key)}`, {
        headers: { Authorization: `Bearer ${kvToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        const currentCount = data.result;
        if (currentCount === 1) {
          await fetch(`${kvUrl}/expire/${encodeURIComponent(key)}/${Math.ceil(windowMs / 1000)}`, {
            headers: { Authorization: `Bearer ${kvToken}` },
          });
        }
        return currentCount <= maxRequests;
      }
    } catch {}
  }

  const now = Date.now();
  let record = rateLimitMap.get(key);
  if (!record || now - record.startTime > windowMs) {
    record = { startTime: now, count: 1 };
    rateLimitMap.set(key, record);
    return true;
  }
  record.count++;
  return record.count <= maxRequests;
}

function sanitizeString(str, maxLen = 120) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

function isValidRewardCodeFormat(code) {
  if (!code || typeof code !== 'string') return false;
  return /^PC-[A-Z0-9]{4,16}$/.test(code.trim().toUpperCase());
}

function createSignedOwnerVault(ownerRecord, teamUsers = []) {
  if (!ownerRecord || !ownerRecord.username || !ownerRecord.password_hash) return null;
  const secret = getAuthSecret();
  const cleanTeam = Array.isArray(teamUsers)
    ? teamUsers
        .filter(u => u && u.username && u.username !== ownerRecord.username && u.password_hash)
        .slice(0, 20)
        .map(u => ({
          id: u.id,
          username: u.username,
          email: u.email || '',
          phone: u.phone || '',
          full_name: u.full_name || u.username,
          avatar_url: u.avatar_url || '',
          role: u.role || 'STAFF',
          password_hash: u.password_hash,
          salt: u.salt,
          must_change_password: Boolean(u.must_change_password),
          status: u.status || 'PENDING_APPROVAL',
          created_at: u.created_at || new Date().toISOString(),
          updated_at: u.updated_at || new Date().toISOString(),
          last_login_at: u.last_login_at || null,
        }))
    : [];

  const payloadObj = {
    id: ownerRecord.id,
    username: ownerRecord.username,
    email: ownerRecord.email || '',
    phone: ownerRecord.phone || '',
    full_name: ownerRecord.full_name,
    avatar_url: ownerRecord.avatar_url || '',
    role: 'OWNER',
    password_hash: ownerRecord.password_hash,
    salt: ownerRecord.salt,
    must_change_password: Boolean(ownerRecord.must_change_password),
    status: ownerRecord.status || 'ACTIVE',
    created_at: ownerRecord.created_at || new Date().toISOString(),
    updated_at: ownerRecord.updated_at || new Date().toISOString(),
    last_login_at: ownerRecord.last_login_at || new Date().toISOString(),
    team_users: cleanTeam,
  };
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`vault.${payload}`).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySignedOwnerVault(vaultToken) {
  if (!vaultToken || typeof vaultToken !== 'string') return null;
  const parts = vaultToken.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  try {
    const secret = getAuthSecret();
    const expectedSig = crypto.createHmac('sha256', secret).update(`vault.${payload}`).digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || !data.username || !data.password_hash || !data.salt) return null;
    return data;
  } catch {
    return null;
  }
}

function getOwnerVaultFromRequest(req) {
  const headerVault = req.headers?.['x-owner-vault'] || req.headers?.['X-Owner-Vault'];
  if (headerVault) {
    const verified = verifySignedOwnerVault(String(headerVault).trim());
    if (verified) return verified;
  }
  if (req.headers?.cookie) {
    const match = req.headers.cookie.match(/popcorn_owner_vault=([^;]+)/);
    if (match) {
      const verified = verifySignedOwnerVault(match[1]);
      if (verified) return verified;
    }
  }
  return null;
}

module.exports = {
  SESSION_TTL_SECONDS,
  isStrictProduction,
  getAuthSecret,
  hashPassword,
  verifyPassword,
  generateSecureRewardCode,
  isValidRewardCodeFormat,
  createSessionToken,
  verifySessionToken,
  createSignedOwnerVault,
  verifySignedOwnerVault,
  getOwnerVaultFromRequest,
  revokeToken,
  revokeJti,
  isJtiRevoked,
  getSessionFromRequest,
  getTokenFromRequest,
  checkRateLimit,
  sanitizeString,
};
