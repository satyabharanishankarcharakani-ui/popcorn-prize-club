// api/_security.js
// Cryptographic, session, rate-limiting, and validation security layer
const crypto = require('crypto');

const AUTH_SECRET = process.env.AUTH_SECRET || 'popcorn-club-hardened-session-secret-2026-secure-fallback';
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12-hour session

// 1. Password Security: PBKDF2 with unique cryptographic salt
function hashPassword(password, existingSalt = null) {
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash: derivedKey, salt };
}

function verifyPassword(password, storedHash, salt) {
  if (!password || !storedHash || !salt) return false;
  const { hash } = hashPassword(password, salt);
  const hashBuf = Buffer.from(hash, 'hex');
  const storedBuf = Buffer.from(storedHash, 'hex');
  if (hashBuf.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(hashBuf, storedBuf);
}

// 2. Cryptographically Secure Code Generator
function generateSecureRewardCode() {
  // Generates 6 random characters from unambiguous charset (A-Z, 2-9, excluding O, 0, I, 1)
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(6);
  let result = 'PC-';
  for (let i = 0; i < 6; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

// 3. HMAC-SHA256 Signed Session Token
function createSessionToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({
      uid: user.id,
      usr: user.username,
      name: user.full_name,
      rol: user.role,
      iat: now,
      exp: now + SESSION_TTL_SECONDS,
    })
  ).toString('base64url');

  const signature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');

  return `${header}.${payload}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const expectedSignature = crypto
    .createHmac('sha256', AUTH_SECRET)
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
      return null; // Expired
    }
    return {
      id: data.uid,
      username: data.usr,
      full_name: data.name,
      role: data.rol,
    };
  } catch (err) {
    return null;
  }
}

// 4. Extract Session from Request
function getSessionFromRequest(req) {
  let token = null;
  // Check Authorization header
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.headers.cookie) {
    // Check HttpOnly Cookie
    const match = req.headers.cookie.match(/popcorn_session=([^;]+)/);
    if (match) token = match[1];
  }
  return verifySessionToken(token);
}

// 5. In-Memory Sliding-Window Rate Limiter
const rateLimitMap = new Map();
function checkRateLimit(key, maxRequests = 20, windowMs = 60000) {
  const now = Date.now();
  let record = rateLimitMap.get(key);
  if (!record || now - record.startTime > windowMs) {
    record = { startTime: now, count: 1 };
    rateLimitMap.set(key, record);
    return true;
  }
  record.count++;
  if (record.count > maxRequests) {
    return false;
  }
  return true;
}

// 6. Clean periodic garbage collection for rateLimitMap
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitMap.entries()) {
      if (now - record.startTime > 300000) {
        rateLimitMap.delete(key);
      }
    }
  }, 120000).unref?.();
}

// 7. Sanitizer
function sanitizeString(str, maxLen = 120) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateSecureRewardCode,
  createSessionToken,
  verifySessionToken,
  getSessionFromRequest,
  checkRateLimit,
  sanitizeString,
};
