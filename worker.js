/**
 * Cloudflare Worker — Firebase Zero-Trust Auth Gateway
 * ─────────────────────────────────────────────────────
 * أضف هذه الـ Secrets في لوحة Cloudflare Worker → Settings → Variables:
 *   PRIVATE_KEY  = محتوى "private_key" من ملف Service Account JSON كاملاً
 *   CLIENT_EMAIL = "firebase-adminsdk-fbsvc@coachmhani.iam.gserviceaccount.com"
 */

const FIREBASE_API_KEY = 'AIzaSyCAr4FJXKPaafa7EuOH1I7PKZBos56adlU';
const FIREBASE_AUDIENCE = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

const attempts = new Map();

function b64url(data) {
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function importPrivateKey(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\\n/g, '')
    .replace(/\n/g, '')
    .replace(/\s/g, '');
  const binary = Uint8Array.from(atob(body), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8', binary.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );
}

async function generateCustomToken(uid, clientEmail, privateKeyPem) {
  const key = await importPrivateKey(privateKeyPem);
  const now = Math.floor(Date.now() / 1000);
  const header = b64url({ alg: 'RS256', typ: 'JWT' });
  const payload = b64url({
    iss: clientEmail,
    sub: clientEmail,
    aud: FIREBASE_AUDIENCE,
    uid: uid,
    iat: now,
    exp: now + 3600
  });
  const input = `${header}.${payload}`;
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', key,
    new TextEncoder().encode(input)
  );
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${input}.${sigB64}`;
}

async function verifyFirebasePassword(email, password) {
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    }
  );
  const data = await res.json();
  if (!res.ok || data.error) throw new Error('EMAIL_PASSWORD_INVALID');
  return data.localId;
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token',
    'Access-Control-Max-Age': '86400'
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== 'POST') {
      return Response.json({ error: 'Method not allowed' }, { status: 405, headers: cors });
    }

    let body;
    try { body = await request.json(); }
    catch { return Response.json({ error: 'Invalid JSON' }, { status: 400, headers: cors }); }

    const { email, password, csrfToken } = body || {};
    if (!email || !password || !csrfToken) {
      return Response.json({ error: 'MISSING_FIELDS' }, { status: 400, headers: cors });
    }

    // Brute-force protection (server-side per IP)
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const key = `${ip}:${email}`;
    const rec = attempts.get(key) || { count: 0, lockUntil: 0 };
    if (Date.now() < rec.lockUntil) {
      const remaining = Math.ceil((rec.lockUntil - Date.now()) / 1000);
      return Response.json({ error: 'LOCKED', remaining }, { status: 429, headers: cors });
    }

    try {
      if (!env.PRIVATE_KEY || !env.CLIENT_EMAIL) {
        throw new Error('Worker secrets not configured');
      }
      const uid = await verifyFirebasePassword(email, password);
      const token = await generateCustomToken(uid, env.CLIENT_EMAIL, env.PRIVATE_KEY);

      // Reset attempts on success
      attempts.delete(key);

      return Response.json({ token, csrfToken }, { headers: cors });
    } catch (err) {
      rec.count++;
      if (rec.count >= MAX_ATTEMPTS) {
        rec.lockUntil = Date.now() + LOCKOUT_MS;
        rec.count = 0;
      }
      attempts.set(key, rec);

      const left = MAX_ATTEMPTS - rec.count;
      return Response.json(
        { error: 'INVALID_CREDENTIALS', attemptsLeft: left > 0 ? left : 0 },
        { status: 401, headers: cors }
      );
    }
  }
};
