// api/_security.js
// Cryptographic, session, rate-limiting, and validation security layer
const crypto = require('crypto');

function isProd() {
  return process.env.NODE_ENV === 'production';
}
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12-hour session

// 1. Session Token Secret Enforcer
function getAuthSecret() {
  const secret = process.env.AUTH_SECRET;
  if (isProd()) {
    if (!secret || secret.length < 32 || secret.includes('replace_with')) {
      throw new Error(
        'CRITICAL CONFIGURATION ERROR: AUTH_SECRET must be configured with a random string of at least 32 characters in production. Failing closed.'
      );
    }
    return secret;
  }
  // Safe development fallback only
  return secret || 'popcorn-club-local-dev-secret-do-not-use-in-production-2026';
}

// 2. Password Security: PBKDF2 with unique cryptographic salt
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

// 3. Cryptographically Secure Code Generator
function generateSecureRewardCode() {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(6);
  let result = 'PC-';
  for (let i = 0; i < 6; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

// 4. Revocation List for Logged-Out Sessions
const revokedTokenSignatures = new Set();
function revokeToken(token) {
  if (!token || typeof token !== 'string') return;
  const parts = token.split('.');
  if (parts.length === 3) {
    revokedTokenSignatures.add(parts[2]);
    // Cap memory footprint
    if (revokedTokenSignatures.size > 2000) {
      const first = revokedTokenSignatures.values().next().value;
      revokedTokenSignatures.delete(first);
    }
  }
}

// 5. HMAC-SHA256 Signed Session Token
function createSessionToken(user) {
  const secret = getAuthSecret();
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomBytes(8).toString('hex');

  const payload = Buffer.from(
    JSON.stringify({
      uid: user.id,
      usr: user.username,
      name: user.full_name,
      rol: user.role,
      jti: jti,
      iat: now,
      exp: now + SESSION_TTL_SECONDS,
    })
  ).toString('base64url');

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

  // Check if token was explicitly revoked
  if (revokedTokenSignatures.has(signature)) {
    return null;
  }

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
    if (data.exp && data.exp < now) {
      return null;
    }
    return {
      id: data.uid,
      username: data.usr,
      full_name: data.name,
      role: data.rol,
    };
  } catch {
    return null;
  }
}

// 6. Extract Session from Request
function getSessionFromRequest(req) {
  let token = null;
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.headers.cookie) {
    const match = req.headers.cookie.match(/popcorn_session=([^;]+)/);
    if (match) token = match[1];
  }
  return verifySessionToken(token);
}

function getTokenFromRequest(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  } else if (req.headers.cookie) {
    const match = req.headers.cookie.match(/popcorn_session=([^;]+)/);
    if (match) return match[1];
  }
  return null;
}

// 7. Rate Limiter (Instance-level with optional Upstash/Vercel KV Cloud backend)
const rateLimitMap = new Map();
async function checkRateLimit(key, maxRequests = 20, windowMs = 60000) {
  // If Upstash Redis or Vercel KV REST is configured, use distributed rate limiting
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
          // Set expiry
          await fetch(`${kvUrl}/expire/${encodeURIComponent(key)}/${Math.ceil(windowMs / 1000)}`, {
            headers: { Authorization: `Bearer ${kvToken}` },
          });
        }
        return currentCount <= maxRequests;
      }
    } catch (err) {
      console.warn('Distributed rate limiter error, falling back to local window:', err.message);
    }
  }

  // Local instance sliding window
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

// 8. Sanitizer
function sanitizeString(str, maxLen = 120) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

module.exports = {
  getAuthSecret,
  hashPassword,
  verifyPassword,
  generateSecureRewardCode,
  createSessionToken,
  verifySessionToken,
  revokeToken,
  getSessionFromRequest,
  getTokenFromRequest,
  checkRateLimit,
  sanitizeString,
};
