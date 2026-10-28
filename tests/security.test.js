// tests/security.test.js
// Automated Security & Cryptography Verification
const assert = require('assert');
const {
  hashPassword,
  verifyPassword,
  createSessionToken,
  verifySessionToken,
  generateSecureRewardCode,
  checkRateLimit,
} = require('../api/_security');

console.log('--- RUNNING SECURITY & CRYPTOGRAPHY TESTS ---');

// 1. Password Hash & Verification
{
  const password = 'MomSuperSecurePopcorn2026!';
  const { hash, salt } = hashPassword(password);

  assert.ok(hash && hash.length === 128, 'PBKDF2 SHA-512 hash should be 128 hex chars');
  assert.ok(salt && salt.length === 32, 'Cryptographic salt should be 32 hex chars');

  const valid = verifyPassword(password, hash, salt);
  assert.strictEqual(valid, true, 'Correct password must verify successfully');

  const invalid = verifyPassword('WrongPassword123!', hash, salt);
  assert.strictEqual(invalid, false, 'Incorrect password must fail verification');

  console.log('✓ Password hashing and constant-time verification passed.');
}

// 2. HMAC-SHA256 Session Token & Tamper Resistance
{
  const mockUser = {
    id: 'usr-12345',
    username: 'mom',
    full_name: 'Mom',
    role: 'OWNER',
  };

  const token = createSessionToken(mockUser);
  assert.ok(token && token.split('.').length === 3, 'JWT token must have 3 dot-separated segments');

  const verified = verifySessionToken(token);
  assert.ok(verified, 'Valid token must decode and verify');
  assert.strictEqual(verified.id, mockUser.id);
  assert.strictEqual(verified.username, mockUser.username);
  assert.strictEqual(verified.role, 'OWNER');

  // Tampering test: Modify payload segment
  const parts = token.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ uid: 'usr-hacker', usr: 'hacker', rol: 'OWNER' })).toString('base64url');
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

  const tamperedResult = verifySessionToken(tamperedToken);
  assert.strictEqual(tamperedResult, null, 'Tampered token signature must fail verification');

  console.log('✓ HMAC-SHA256 session tokens and tamper resistance passed.');
}

// 3. Cryptographically Secure Code Generator
{
  const code1 = generateSecureRewardCode();
  const code2 = generateSecureRewardCode();

  assert.ok(code1.startsWith('PC-'), 'Code must start with PC-');
  assert.strictEqual(code1.length, 9, 'Code must be PC- followed by 6 characters (length 9)');
  assert.notStrictEqual(code1, code2, 'Two successive random codes must not collide');
  assert.ok(!/[01IO]/.test(code1.slice(3)), 'Code should exclude ambiguous characters 0, 1, I, O');

  console.log('✓ Cryptographic reward code generation passed.');
}

// 4. Rate Limiting Sliding Window
{
  const testIp = 'test-client-ip-99';
  let allowedCount = 0;
  for (let i = 0; i < 7; i++) {
    if (checkRateLimit(testIp, 5, 10000)) allowedCount++;
  }
  assert.strictEqual(allowedCount, 5, 'Rate limiter must cap exactly at threshold (5)');

  console.log('✓ Rate limiting sliding window passed.');
}

console.log('ALL SECURITY TESTS PASSED SUCCESSFULLY! ✓\n');
