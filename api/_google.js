// api/_google.js
// Real Google OAuth 2.0 / OpenID Connect (Authorization Code flow, server-side).
// Clicking "Sign in with Google" redirects the browser to accounts.google.com (Google's own
// account chooser listing the Google accounts on the phone/browser). Google sends the user back
// to /api/google/callback with a one-time code, which is exchanged server-side for a verified ID token.
const crypto = require('crypto');
const { getAuthSecret } = require('./_security');

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const VALID_ISSUERS = new Set(['accounts.google.com', 'https://accounts.google.com']);
const STATE_TTL_SECONDS = 600;

function getGoogleConfig() {
  const clientId = (process.env.GOOGLE_CLIENT_ID || '').trim();
  const clientSecret = (process.env.GOOGLE_CLIENT_SECRET || '').trim();
  const enabled = Boolean(clientId && clientSecret && !clientId.includes('replace_with'));
  return { clientId, clientSecret, enabled };
}

function getBaseUrl(req) {
  const configured = (process.env.GOOGLE_REDIRECT_BASE_URL || '').trim().replace(/\/$/, '');
  if (configured) return configured;
  const host = req.headers?.['x-forwarded-host'] || req.headers?.host || 'localhost:3000';
  const proto = req.headers?.['x-forwarded-proto'] || (String(host).startsWith('localhost') ? 'http' : 'https');
  return `${proto}://${host}`;
}

function getRedirectUri(req) {
  return `${getBaseUrl(req)}/api/google/callback`;
}

function signValue(value) {
  return crypto.createHmac('sha256', getAuthSecret()).update(`google-state.${value}`).digest('base64url');
}

// Signed, short-lived CSRF state stored in an HttpOnly cookie and echoed through Google.
function createState() {
  const nonce = crypto.randomBytes(18).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS;
  const value = `${nonce}.${exp}`;
  return { state: nonce, cookieValue: `${value}.${signValue(value)}` };
}

function verifyState(stateParam, cookieHeader) {
  if (!stateParam || !cookieHeader) return false;
  const match = String(cookieHeader).match(/popcorn_google_state=([^;]+)/);
  if (!match) return false;
  const parts = match[1].split('.');
  if (parts.length !== 3) return false;
  const [nonce, exp, sig] = parts;
  const expected = signValue(`${nonce}.${exp}`);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  if (Number(exp) < Math.floor(Date.now() / 1000)) return false;
  const p = Buffer.from(String(stateParam));
  const n = Buffer.from(nonce);
  return p.length === n.length && crypto.timingSafeEqual(p, n);
}

function buildAuthUrl(req, state) {
  const { clientId } = getGoogleConfig();
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: getRedirectUri(req),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
    access_type: 'online',
    include_granted_scopes: 'true',
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

// Exchanges the one-time code for tokens directly with Google over TLS (authenticated with the
// client secret), then validates the ID token claims.
async function exchangeCodeForProfile(req, code) {
  const { clientId, clientSecret } = getGoogleConfig();
  const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code: String(code),
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: getRedirectUri(req),
      grant_type: 'authorization_code',
    }).toString(),
  });
  if (!tokenRes.ok) {
    throw new Error(`Google token exchange failed (${tokenRes.status}).`);
  }
  const tokens = await tokenRes.json();
  if (!tokens || !tokens.id_token) throw new Error('Google did not return an ID token.');

  const parts = String(tokens.id_token).split('.');
  if (parts.length !== 3) throw new Error('Malformed Google ID token.');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  const now = Math.floor(Date.now() / 1000);

  if (!VALID_ISSUERS.has(claims.iss)) throw new Error('Invalid Google token issuer.');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) throw new Error('Google token audience mismatch.');
  if (!claims.exp || claims.exp < now) throw new Error('Google token expired.');
  if (!claims.email || claims.email_verified !== true) {
    throw new Error('Your Google email address is not verified.');
  }

  return {
    sub: String(claims.sub),
    email: String(claims.email).toLowerCase().trim(),
    name: String(claims.name || claims.given_name || '').trim(),
    picture: String(claims.picture || ''),
  };
}

module.exports = {
  getGoogleConfig,
  getRedirectUri,
  createState,
  verifyState,
  buildAuthUrl,
  exchangeCodeForProfile,
};
